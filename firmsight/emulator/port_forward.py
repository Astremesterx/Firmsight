"""Port Forwarding and External HTTP Trigger Harness for Emulated IoT Devices.

Provisions bidirectional port forwarding between the host environment and the
emulated guest IoT sandbox (e.g. Host 127.0.0.1:8080 -> Guest 192.168.1.1:80).
Includes an automated HTTP/curl trigger test harness for dynamic endpoint verification,
web daemon responsiveness analysis, and security fuzzing triggers.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import select
import shutil
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.request

from firmsight.core.config import get_logger

logger = get_logger("PortForwarder")


@dataclass
class PortForwardRule:
    """Represents an active port forwarding rule between host and guest environments."""

    rule_id: str                           # e.g., 'pf-8080-80'
    host_ip: str = "127.0.0.1"
    host_port: int = 8080
    guest_ip: str = "192.168.1.1"
    guest_port: int = 80
    protocol: str = "tcp"
    mode: str = "socket-proxy"             # 'socket-proxy' or 'iptables-nat'
    is_active: bool = False
    created_at: str = ""
    bytes_transferred: int = 0
    connections_handled: int = 0

    def to_iptables_commands(self) -> List[str]:
        """Generates netfilter DNAT and MASQUERADE commands for privileged Linux."""
        return [
            f"iptables -t nat -A PREROUTING -p {self.protocol} --dport {self.host_port} -j DNAT --to-destination {self.guest_ip}:{self.guest_port}",
            f"iptables -t nat -A POSTROUTING -p {self.protocol} -d {self.guest_ip} --dport {self.guest_port} -j MASQUERADE",
        ]

    def to_curl_command(self, path: str = "/") -> str:
        """Constructs an executable curl invocation string targeting this forwarded port."""
        normalized_path = "/" + path.lstrip("/")
        return f"curl -s -i http://{self.host_ip}:{self.host_port}{normalized_path}"

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "PortForwardRule":
        return cls(**data)


@dataclass
class HTTPProbeResult:
    """Telemetry report produced by executing an HTTP probe against the emulated web daemon."""

    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    server_banner: Optional[str] = None
    content_length: int = 0
    success: bool = False
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    curl_command: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PortForwardStatus:
    """Global telemetry report for all configured port forwarders in the workspace."""

    active_rules: List[PortForwardRule] = field(default_factory=list)
    is_active: bool = False
    mode: str = "socket-proxy"
    created_at: str = ""

    def to_dict(self) -> Dict:
        return {
            "active_rules": [r.to_dict() for r in self.active_rules],
            "is_active": self.is_active,
            "mode": self.mode,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "PortForwardStatus":
        rules = [PortForwardRule.from_dict(r) for r in data.get("active_rules", [])]
        return cls(
            active_rules=rules,
            is_active=data.get("is_active", False),
            mode=data.get("mode", "socket-proxy"),
            created_at=data.get("created_at", ""),
        )


class _SocketProxyWorker:
    """Internal threaded TCP proxy that forwards traffic between host_port and guest_port."""

    def __init__(self, rule: PortForwardRule) -> None:
        self.rule = rule
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.server_sock: Optional[socket.socket] = None

    def start(self) -> None:
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.rule.host_ip, self.rule.host_port))
        self.server_sock.listen(10)
        self.server_sock.settimeout(0.5)

        self.thread = threading.Thread(target=self._run, daemon=True, name=f"Proxy-{self.rule.rule_id}")
        self.thread.start()
        self.rule.is_active = True

    def stop(self) -> None:
        self.stop_event.set()
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        self.rule.is_active = False

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                client_sock, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock,),
                daemon=True,
            )
            client_thread.start()

    def _handle_client(self, client_sock: socket.socket) -> None:
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(3.0)

        try:
            target_sock.connect((self.rule.guest_ip, self.rule.guest_port))
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            # Emulated guest not responding yet or unreachable
            error_body = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nFirmSight: Target guest {self.rule.guest_ip}:{self.rule.guest_port} unreachable ({exc}).\n"
            try:
                client_sock.sendall(error_body.encode("utf-8"))
            except Exception:
                pass
            finally:
                client_sock.close()
                target_sock.close()
            return

        self.rule.connections_handled += 1
        client_sock.setblocking(False)
        target_sock.setblocking(False)

        sockets = [client_sock, target_sock]
        transferred = 0

        while not self.stop_event.is_set() and sockets:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 0.5)
            except Exception:
                break

            if exceptional:
                break

            for s in readable:
                other = target_sock if s is client_sock else client_sock
                try:
                    data = s.recv(8192)
                    if data:
                        other.sendall(data)
                        transferred += len(data)
                    else:
                        sockets = []
                        break
                except (BlockingIOError, InterruptedError):
                    continue
                except Exception:
                    sockets = []
                    break

        self.rule.bytes_transferred += transferred
        try:
            client_sock.close()
        except Exception:
            pass
        try:
            target_sock.close()
        except Exception:
            pass


class PortForwarder:
    """Manages host-to-guest port forwarders and state tracking."""

    _global_workers: Dict[str, _SocketProxyWorker] = {}

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None) -> None:
        if workspace_dir:
            self.workspace_dir = Path(workspace_dir)
        else:
            self.workspace_dir = Path(__file__).resolve().parent.parent.parent

        self.state_file = self.workspace_dir / "sandbox_workspace" / "network" / "port_forward_state.json"
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._active_workers: Dict[str, _SocketProxyWorker] = PortForwarder._global_workers

    def is_privileged_linux(self) -> bool:
        """Determines if host possesses root capabilities with iptables on Linux."""
        if platform.system() != "Linux":
            return False
        if not shutil.which("iptables"):
            return False
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def add_forward(
        self,
        host_port: int,
        guest_port: int = 80,
        host_ip: str = "127.0.0.1",
        guest_ip: str = "192.168.1.1",
        protocol: str = "tcp",
        mode: str = "auto",
        force_shim: bool = False,
    ) -> PortForwardRule:
        """Configures a port forwarding channel between host_port and guest_port."""
        rule_id = f"pf-{host_port}-{guest_port}"

        # If rule already exists, stop worker before re-binding
        if rule_id in self._active_workers:
            self.remove_forward(rule_id)

        can_use_iptables = (mode == "iptables-nat" or mode == "auto") and self.is_privileged_linux() and not force_shim
        effective_mode = "iptables-nat" if (can_use_iptables and mode == "iptables-nat") else "socket-proxy"

        rule = PortForwardRule(
            rule_id=rule_id,
            host_ip=host_ip,
            host_port=host_port,
            guest_ip=guest_ip,
            guest_port=guest_port,
            protocol=protocol,
            mode=effective_mode,
            is_active=False,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if effective_mode == "iptables-nat":
            logger.info(f"Configuring iptables NAT port forward: {host_ip}:{host_port} -> {guest_ip}:{guest_port}")
            for cmd in rule.to_iptables_commands():
                try:
                    subprocess.run(cmd.split(), check=True, capture_output=True, text=True)
                except subprocess.CalledProcessError as exc:
                    logger.warning(f"iptables command failed: {exc}. Falling back to socket-proxy.")
                    effective_mode = "socket-proxy"
                    rule.mode = "socket-proxy"
                    break

        if effective_mode == "socket-proxy":
            logger.info(f"Spawning socket proxy: {host_ip}:{host_port} -> {guest_ip}:{guest_port}")
            worker = _SocketProxyWorker(rule)
            worker.start()
            self._active_workers[rule_id] = worker

        self._save_state()
        return rule

    def remove_forward(self, rule_id: str) -> bool:
        """Tears down a port forwarding rule and terminates its proxy worker."""
        worker = self._active_workers.pop(rule_id, None)
        if worker:
            worker.stop()

        status = self.get_status()
        if status:
            rule = next((r for r in status.active_rules if r.rule_id == rule_id), None)
            if rule and rule.mode == "iptables-nat" and self.is_privileged_linux():
                for cmd in rule.to_iptables_commands():
                    del_cmd = cmd.replace("-A", "-D").split()
                    try:
                        subprocess.run(del_cmd, capture_output=True)
                    except Exception:
                        pass

        self._save_state()
        return True

    def list_forwards(self) -> List[PortForwardRule]:
        """Returns all currently registered port forwarding rules."""
        if self._active_workers:
            return [w.rule for w in self._active_workers.values()]
        status = self.get_status()
        if not status:
            return []
        return status.active_rules

    def get_status(self) -> Optional[PortForwardStatus]:
        """Loads and returns current port forwarding status from disk or memory."""
        if self._active_workers:
            rules = [w.rule for w in self._active_workers.values()]
            return PortForwardStatus(
                active_rules=rules,
                is_active=len(rules) > 0,
                mode="socket-proxy",
                created_at=datetime.now(timezone.utc).isoformat(),
            )

        if not self.state_file.exists():
            return None
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return PortForwardStatus.from_dict(data)
        except Exception as exc:
            logger.warning(f"Failed to read port forward state: {exc}")
            return None

    def teardown_all(self) -> None:
        """Shuts down all active socket proxies and purges state cache."""
        for worker in list(self._active_workers.values()):
            worker.stop()
        self._active_workers.clear()

        if self.state_file.exists():
            try:
                self.state_file.unlink()
            except OSError:
                pass

    def stop_all(self) -> None:
        """Alias for teardown_all()."""
        self.teardown_all()

    def _save_state(self) -> None:
        """Persists active rules state to disk."""
        rules = [w.rule for w in self._active_workers.values()]
        status = PortForwardStatus(
            active_rules=rules,
            is_active=len(rules) > 0,
            mode="socket-proxy",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        try:
            self.state_file.write_text(json.dumps(status.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning(f"Failed to persist port forward state: {exc}")


class HTTPTriggerHarness:
    """Automated curl / HTTP trigger test harness for emulated IoT web daemons."""

    def __init__(self, forwarder: Optional[PortForwarder] = None) -> None:
        self.forwarder = forwarder or PortForwarder()

    def probe_endpoint(
        self,
        target: Union[str, int],
        path: str = "/",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: float = 3.0,
    ) -> HTTPProbeResult:
        """Executes an HTTP request against a forwarded host port or full URL."""
        if isinstance(target, int):
            normalized_path = "/" + path.lstrip("/")
            url = f"http://127.0.0.1:{target}{normalized_path}"
        else:
            url = target

        headers_dict = headers or {
            "User-Agent": "FirmSight-Harness/1.0",
            "Accept": "*/*",
        }

        curl_cmd = f"curl -s -i -X {method} {url}"
        if headers:
            for k, v in headers.items():
                curl_cmd += f" -H '{k}: {v}'"

        start_time = time.perf_counter()
        req = urllib.request.Request(url, data=data, headers=headers_dict, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                body = resp.read()
                resp_headers = dict(resp.headers.items())
                server_banner = resp_headers.get("Server") or resp_headers.get("server")

                return HTTPProbeResult(
                    url=url,
                    method=method,
                    status_code=resp.status,
                    response_time_ms=round(elapsed_ms, 2),
                    server_banner=server_banner,
                    content_length=len(body),
                    success=True,
                    headers=resp_headers,
                    body_snippet=body[:200].decode("utf-8", errors="replace"),
                    curl_command=curl_cmd,
                )
        except urllib.error.HTTPError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            resp_headers = dict(exc.headers.items()) if exc.headers else {}
            server_banner = resp_headers.get("Server") or resp_headers.get("server")
            body = exc.read() if hasattr(exc, "read") else b""

            return HTTPProbeResult(
                url=url,
                method=method,
                status_code=exc.code,
                response_time_ms=round(elapsed_ms, 2),
                server_banner=server_banner,
                content_length=len(body),
                success=True,  # Daemon is alive and answered with HTTP error code (e.g. 401, 404)
                error=f"HTTP {exc.code}: {exc.reason}",
                headers=resp_headers,
                body_snippet=body[:200].decode("utf-8", errors="replace"),
                curl_command=curl_cmd,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HTTPProbeResult(
                url=url,
                method=method,
                status_code=None,
                response_time_ms=round(elapsed_ms, 2),
                success=False,
                error=str(exc),
                curl_command=curl_cmd,
            )

    def run_diagnostic_scan(
        self,
        host_port: int = 8080,
        endpoints: Optional[List[str]] = None,
    ) -> List[HTTPProbeResult]:
        """Probes a battery of common IoT web daemon endpoints to assess responsiveness."""
        if endpoints is None:
            endpoints = [
                "/",
                "/index.html",
                "/login.cgi",
                "/cgi-bin/status.cgi",
                "/apply.cgi",
                "/admin.html",
            ]

        results = []
        for path in endpoints:
            res = self.probe_endpoint(host_port, path=path)
            results.append(res)
        return results

    def generate_curl_script(
        self,
        host_port: int = 8080,
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        """Generates an executable bash verification script invoking external curl requests."""
        if output_path:
            script_path = Path(output_path)
        else:
            script_path = self.forwarder.workspace_dir / "sandbox_workspace" / "network" / "verify_web_interface.sh"

        script_path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "#!/usr/bin/env bash",
            "# ============================================================================",
            "# FirmSight: Emulated IoT Web Daemon Verification Script",
            f"# Timestamp: {datetime.now(timezone.utc).isoformat()}",
            "# ============================================================================",
            "set -u",
            "",
            f"TARGET=\"http://127.0.0.1:{host_port}\"",
            "echo \"[*] Probing emulated IoT device at: $TARGET\"",
            "",
            "echo \"[+] Probing root index endpoint...\"",
            "curl -s -i \"$TARGET/\" || echo \"[-] Root endpoint unreachable\"",
            "",
            "echo \"[+] Probing router admin cgi endpoint...\"",
            "curl -s -i \"$TARGET/cgi-bin/status.cgi\" || echo \"[-] CGI status endpoint unreachable\"",
            "",
            "echo \"[+] Probing router login page...\"",
            "curl -s -i \"$TARGET/login.cgi\" || echo \"[-] Login endpoint unreachable\"",
            "",
            "echo \"[*] HTTP probe sequence complete.\"",
        ]

        script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            script_path.chmod(0o755)
        except OSError:
            pass
        return script_path
