"""Automated discovery and orchestration of embedded IoT web services."""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger
from firmsight.emulator.chroot_runner import ChrootExecutionResult, ChrootRunner
from firmsight.emulator.nvram import MockNVRAM

logger = get_logger("ServiceLauncher")


@dataclass
class DiscoveredService:
    """Metadata regarding an identified embedded network service."""

    name: str
    binary_path: str        # Path relative to rootfs (e.g., 'usr/sbin/httpd')
    service_type: str       # 'http', 'upnp', 'dns', 'backdoor'
    default_port: int = 80
    suggested_args: List[str] = field(default_factory=list)
    config_file: Optional[str] = None


@dataclass
class ServiceLaunchResult:
    """Outcome of attempting to launch an embedded service."""

    service: DiscoveredService
    execution: ChrootExecutionResult
    is_running: bool
    port: int
    notes: List[str] = field(default_factory=list)


class ServiceLauncher:
    """Scans firmware rootfs for web servers, constructs startup parameters, and launches them in QEMU."""

    # Well-known IoT web server binary signatures and default configurations
    KNOWN_WEB_DAEMONS: Dict[str, Dict] = {
        "httpd": {
            "ports": [80, 8080],
            "args": ["-p", "80"],
            "candidates": ["usr/sbin/httpd", "sbin/httpd", "bin/httpd", "usr/bin/httpd"],
        },
        "uhttpd": {
            "ports": [80, 443],
            "args": ["-p", "0.0.0.0:80", "-h", "/www"],
            "candidates": ["usr/sbin/uhttpd", "sbin/uhttpd"],
        },
        "boa": {
            "ports": [80],
            "args": ["-c", "/etc/boa"],
            "candidates": ["usr/sbin/boa", "bin/boa", "usr/bin/boa"],
        },
        "goahead": {
            "ports": [80, 8080],
            "args": ["--port", "80"],
            "candidates": ["usr/bin/goahead", "sbin/goahead", "bin/goahead"],
        },
        "lighttpd": {
            "ports": [80],
            "args": ["-f", "/etc/lighttpd/lighttpd.conf"],
            "candidates": ["usr/sbin/lighttpd", "usr/bin/lighttpd"],
        },
        "mini_httpd": {
            "ports": [80],
            "args": ["-p", "80"],
            "candidates": ["usr/sbin/mini_httpd", "bin/mini_httpd"],
        },
    }

    def __init__(self, rootfs_dir: Union[str, Path], nvram: Optional[MockNVRAM] = None):
        self.rootfs_dir = Path(rootfs_dir).resolve()
        if not self.rootfs_dir.exists() or not self.rootfs_dir.is_dir():
            raise FileNotFoundError(f"RootFS directory not found: {self.rootfs_dir}")

        self.nvram = nvram or MockNVRAM()
        self.runner = ChrootRunner(self.rootfs_dir, nvram=self.nvram)

    def discover_services(self) -> List[DiscoveredService]:
        """Scans the rootfs for embedded web daemons and startup scripts."""
        discovered: List[DiscoveredService] = []
        found_paths = set()

        # 1. Probe known candidate binary paths
        for daemon_name, config in self.KNOWN_WEB_DAEMONS.items():
            for rel_path in config["candidates"]:
                full_path = self.rootfs_dir / rel_path
                if full_path.exists() and full_path.is_file():
                    if rel_path not in found_paths:
                        found_paths.add(rel_path)
                        discovered.append(
                            DiscoveredService(
                                name=daemon_name,
                                binary_path=rel_path,
                                service_type="http",
                                default_port=config["ports"][0],
                                suggested_args=list(config["args"]),
                            )
                        )
                        logger.info(f"Discovered known web daemon: {daemon_name} at {rel_path}")

        # 2. Inspect init scripts (/etc/init.d/rcS, /etc/rc.local) for invoked services
        rc_scripts = [
            self.rootfs_dir / "etc" / "init.d" / "rcS",
            self.rootfs_dir / "etc" / "rc.local",
            self.rootfs_dir / "etc" / "rc.common",
        ]
        for rc_script in rc_scripts:
            if rc_script.exists():
                try:
                    content = rc_script.read_text(encoding="utf-8", errors="ignore")
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        # Look for execution of httpd, c2_beacon, or web binaries
                        match = re.search(r"(\b(?:usr/sbin|sbin|bin)/[a-zA-Z0-9_\-]+)", line)
                        if match:
                            matched_bin = match.group(1).lstrip("/")
                            if matched_bin not in found_paths:
                                target_file = self.rootfs_dir / matched_bin
                                if target_file.exists() and target_file.is_file():
                                    found_paths.add(matched_bin)
                                    svc_type = "http" if "http" in matched_bin else "custom"
                                    discovered.append(
                                        DiscoveredService(
                                            name=target_file.name,
                                            binary_path=matched_bin,
                                            service_type=svc_type,
                                            default_port=80,
                                        )
                                    )
                                    logger.info(f"Discovered startup service from {rc_script.name}: {matched_bin}")
                except Exception as e:
                    logger.debug(f"Failed to parse {rc_script}: {e}")

        return discovered

    def launch(
        self,
        service: Optional[DiscoveredService] = None,
        port: int = 80,
        timeout: int = 5,
        custom_args: Optional[List[str]] = None,
    ) -> ServiceLaunchResult:
        """Launches the primary web service inside the emulation sandbox."""
        if not service:
            candidates = self.discover_services()
            if not candidates:
                raise RuntimeError(
                    f"No embedded web services discovered in rootfs: {self.rootfs_dir}"
                )
            service = candidates[0]

        args = custom_args or service.suggested_args
        logger.info(f"Launching web service '{service.name}' on port {port} via QEMU...")

        # Update NVRAM http_port parameter before launch
        self.nvram.set("http_port", str(port))
        self.nvram.set("http_enable", "1")

        exec_res = self.runner.run(
            binary_rel_path=service.binary_path,
            args=args,
            timeout=timeout,
        )

        # In IoT emulation, web servers run indefinitely. A timeout means the server stayed up!
        is_running = exec_res.timed_out or exec_res.exit_code == 0
        notes = []
        if exec_res.timed_out:
            notes.append("Web server maintained active execution loop until timeout (SUCCESS).")
        elif exec_res.exit_code == 0:
            notes.append("Web daemon forked successfully into background.")
        else:
            notes.append(f"Web server exited with status {exec_res.exit_code}.")

        return ServiceLaunchResult(
            service=service,
            execution=exec_res,
            is_running=is_running,
            port=port,
            notes=notes,
        )
