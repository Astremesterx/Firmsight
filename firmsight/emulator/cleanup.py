"""Sandbox Teardown & Resource Cleanup Engine.

Provides automated resource reclamation across all sandbox subsystems:
terminating child QEMU and daemon processes, releasing virtual TAP/Bridge
interfaces, flushing netfilter/iptables sandbox rules, unmounting chroot
mountpoints, closing socket proxy workers, and purging transient runtime state.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional, Union

from firmsight.core.config import get_logger
from firmsight.emulator.daemon import DaemonManager
from firmsight.emulator.firewall import FirewallManager
from firmsight.emulator.network_bridge import NetworkBridgeManager
from firmsight.emulator.network_router import NetworkRouter
from firmsight.emulator.pcap_bridge import PCAPBridge
from firmsight.emulator.port_forward import PortForwarder

logger = get_logger("SandboxCleanup")


@dataclass
class CleanupItem:
    """Individual resource release or termination result."""

    category: str      # 'PROXIES', 'PROCESSES', 'NETWORK', 'FIREWALL', 'MOUNTS', 'WORKSPACE'
    resource_id: str   # E.g. PID, interface name, mountpoint, file path
    status: str        # 'SUCCESS', 'SKIPPED', 'FAILED'
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CleanupReport:
    """Consolidated teardown audit report."""

    total_cleaned: int
    total_failed: int
    total_skipped: int
    duration_seconds: float
    items: List[CleanupItem] = field(default_factory=list)
    timestamp: str = ""

    def summary(self) -> str:
        return (
            f"FirmSight Teardown Report: {self.total_cleaned} released, "
            f"{self.total_failed} failed, {self.total_skipped} skipped "
            f"in {self.duration_seconds:.2f}s"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cleaned": self.total_cleaned,
            "total_failed": self.total_failed,
            "total_skipped": self.total_skipped,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
            "items": [i.to_dict() for i in self.items],
        }

    def export_markdown(self) -> str:
        """Renders an executive Markdown summary of teardown actions."""
        lines = [
            "# 🧹 FirmSight Sandbox Teardown & Cleanup Report",
            "",
            f"- **Timestamp:** `{self.timestamp}`",
            f"- **Duration:** `{self.duration_seconds:.2f} seconds`",
            f"- **Resources Released:** `{self.total_cleaned}`",
            f"- **Failures:** `{self.total_failed}`",
            f"- **Skipped:** `{self.total_skipped}`",
            "",
            "## Released Resource Audit",
            "",
            "| Category | Resource Target | Status | Details |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for item in self.items:
            badge = "✅ SUCCESS" if item.status == "SUCCESS" else ("⚠️ SKIP" if item.status == "SKIPPED" else "❌ FAIL")
            lines.append(f"| {item.category} | `{item.resource_id}` | {badge} | {item.details} |")
        return "\n".join(lines) + "\n"


class SandboxCleanupManager:
    """Coordinates graceful and complete teardown of all active emulation artifacts."""

    QEMU_PROCESS_NAMES = [
        "qemu-arm-static",
        "qemu-mips-static",
        "qemu-mipsel-static",
        "qemu-aarch64-static",
        "qemu-system-arm",
        "qemu-system-mips",
        "qemu-system-x86_64",
    ]

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None) -> None:
        if workspace_dir:
            self.workspace_dir = Path(workspace_dir)
        else:
            self.workspace_dir = Path(__file__).resolve().parent.parent.parent

        self.sandbox_workspace = self.workspace_dir / "sandbox_workspace"
        self.cleanup_manifest = self.sandbox_workspace / "cleanup_last_run.json"

    def teardown_port_forwards(self) -> List[CleanupItem]:
        """Terminates active socket proxy forwarder threads and removes state cache."""
        items: List[CleanupItem] = []
        try:
            pf_mgr = PortForwarder(workspace_dir=self.workspace_dir)
            active = pf_mgr.list_forwards()
            count = len(active)
            pf_mgr.teardown_all()
            items.append(
                CleanupItem(
                    category="PROXIES",
                    resource_id="port_forward_workers",
                    status="SUCCESS",
                    details=f"Shut down {count} active socket proxy forwarding rule(s)",
                )
            )
        except Exception as exc:
            items.append(
                CleanupItem(
                    category="PROXIES",
                    resource_id="port_forward_workers",
                    status="FAILED",
                    details=f"Failed to shut down port forwards: {exc}",
                )
            )
        return items

    def teardown_processes(
        self,
        pids: Optional[List[int]] = None,
        process_names: Optional[List[str]] = None,
    ) -> List[CleanupItem]:
        """Terminates registered background daemons and orphan QEMU emulation processes."""
        items: List[CleanupItem] = []

        # 1. Stop daemons tracked by DaemonManager
        try:
            d_mgr = DaemonManager(workspace_dir=self.workspace_dir)
            active_daemons = d_mgr.list_active()
            for daemon in active_daemons:
                success = d_mgr.stop(daemon.name)
                items.append(
                    CleanupItem(
                        category="PROCESSES",
                        resource_id=f"daemon:{daemon.name} (PID {daemon.pid})",
                        status="SUCCESS" if success else "FAILED",
                        details=f"Terminated background daemon process '{daemon.name}'",
                    )
                )
        except Exception as exc:
            items.append(
                CleanupItem(
                    category="PROCESSES",
                    resource_id="daemon_manager",
                    status="FAILED",
                    details=f"Error stopping registered daemons: {exc}",
                )
            )

        # 2. Terminate explicitly supplied PIDs
        if pids:
            for pid in pids:
                res = self._kill_pid(pid)
                items.append(
                    CleanupItem(
                        category="PROCESSES",
                        resource_id=f"PID:{pid}",
                        status="SUCCESS" if res else "SKIPPED",
                        details="Terminated process via signal" if res else "PID already exited",
                    )
                )

        # 3. Kill orphan QEMU user-mode processes if on Linux
        target_names = process_names or self.QEMU_PROCESS_NAMES
        if platform.system() == "Linux":
            for name in target_names:
                try:
                    # Use pkill -f to find and terminate orphan emulator instances
                    ret = subprocess.run(
                        ["pkill", "-f", name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    if ret.returncode == 0:
                        items.append(
                            CleanupItem(
                                category="PROCESSES",
                                resource_id=f"orphan_qemu:{name}",
                                status="SUCCESS",
                                details=f"Sent termination signal to instances of '{name}'",
                            )
                        )
                except Exception:
                    pass

        return items

    def _kill_pid(self, pid: int, timeout: float = 2.0) -> bool:
        """Sends SIGTERM followed by SIGKILL to ensure process termination."""
        if os.name != "nt":
            try:
                os.kill(pid, 0)
            except OSError:
                return False

            try:
                os.kill(pid, signal.SIGTERM)
                deadline = time.time() + timeout
                while time.time() < deadline:
                    time.sleep(0.1)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        return True
                os.kill(pid, signal.SIGKILL)
                return True
            except OSError:
                return False
        else:
            try:
                ret = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return ret.returncode == 0
            except Exception:
                return False

    def teardown_network(
        self,
        bridge_name: str = "fs-br0",
        tap_name: str = "fs-tap0",
        sniffer_name: str = "fs-sniff0",
    ) -> List[CleanupItem]:
        """Stops PCAP capture, removes virtual routing, and releases TAP bridge interfaces."""
        items: List[CleanupItem] = []

        # 1. Stop PCAP capture session
        try:
            pcap_mgr = PCAPBridge(workspace_dir=self.workspace_dir)
            active_cap = pcap_mgr.get_active_session()
            if active_cap:
                stopped = pcap_mgr.stop_capture()
                items.append(
                    CleanupItem(
                        category="NETWORK",
                        resource_id=f"pcap_session:{stopped.session_id if stopped else 'active'}",
                        status="SUCCESS",
                        details=f"Stopped active PCAP capture on {sniffer_name}",
                    )
                )
            else:
                items.append(
                    CleanupItem(
                        category="NETWORK",
                        resource_id="pcap_session",
                        status="SKIPPED",
                        details="No active capture session was running",
                    )
                )
        except Exception as exc:
            items.append(
                CleanupItem(
                    category="NETWORK",
                    resource_id="pcap_session",
                    status="FAILED",
                    details=f"Error stopping capture session: {exc}",
                )
            )

        # 2. Release virtual routing configuration
        try:
            router = NetworkRouter(workspace_dir=self.workspace_dir)
            router.teardown_guest_routing(bridge_name=bridge_name)
            items.append(
                CleanupItem(
                    category="NETWORK",
                    resource_id=f"routing:{bridge_name}",
                    status="SUCCESS",
                    details=f"Released subnet IP binding and routing entries on {bridge_name}",
                )
            )
        except Exception as exc:
            items.append(
                CleanupItem(
                    category="NETWORK",
                    resource_id=f"routing:{bridge_name}",
                    status="FAILED",
                    details=f"Failed to release routing configuration: {exc}",
                )
            )

        # 3. Destroy virtual bridge and TAP interfaces
        try:
            bridge_mgr = NetworkBridgeManager(workspace_dir=self.workspace_dir)
            bridge_mgr.teardown_bridge_network(tap_name=tap_name, bridge_name=bridge_name)
            items.append(
                CleanupItem(
                    category="NETWORK",
                    resource_id=f"interfaces:{bridge_name},{tap_name}",
                    status="SUCCESS",
                    details=f"Released virtual bridge and TAP network interfaces",
                )
            )
        except Exception as exc:
            items.append(
                CleanupItem(
                    category="NETWORK",
                    resource_id=f"interfaces:{bridge_name}",
                    status="FAILED",
                    details=f"Failed to release bridge interfaces: {exc}",
                )
            )

        return items

    def teardown_firewall(self, force_shim: bool = False) -> List[CleanupItem]:
        """Flushes custom iptables netfilter chains and removes state caches."""
        items: List[CleanupItem] = []
        try:
            fw_mgr = FirewallManager(workspace_dir=self.workspace_dir)
            fw_mgr.flush_rules(force_shim=force_shim)
            items.append(
                CleanupItem(
                    category="FIREWALL",
                    resource_id="iptables_rules",
                    status="SUCCESS",
                    details="Flushed sandbox isolation and packet mirroring netfilter rules",
                )
            )
        except Exception as exc:
            items.append(
                CleanupItem(
                    category="FIREWALL",
                    resource_id="iptables_rules",
                    status="FAILED",
                    details=f"Error flushing firewall rules: {exc}",
                )
            )
        return items

    def teardown_mounts(
        self,
        rootfs_dir: Optional[Union[str, Path]] = None,
    ) -> List[CleanupItem]:
        """Safely unmounts chroot-mounted pseudo-filesystems (/proc, /sys, /dev)."""
        items: List[CleanupItem] = []
        if platform.system() != "Linux":
            items.append(
                CleanupItem(
                    category="MOUNTS",
                    resource_id="chroot_mounts",
                    status="SKIPPED",
                    details="Filesystem bind-mounts are only present in native Linux environments",
                )
            )
            return items

        mount_targets = ["proc", "sys", "dev/pts", "dev"]
        target_root = Path(rootfs_dir) if rootfs_dir else self.sandbox_workspace / "extracted"

        # Check /proc/mounts to identify actual mounted paths
        active_mounts: List[str] = []
        try:
            mounts_content = Path("/proc/mounts").read_text(encoding="utf-8", errors="ignore")
            for line in mounts_content.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    active_mounts.append(parts[1])
        except Exception:
            pass

        unmounted_count = 0
        if target_root.exists():
            for m in mount_targets:
                candidate = target_root / m
                # If path is found in active mounts, perform lazy unmount
                candidate_str = str(candidate.resolve()) if candidate.exists() else str(candidate)
                if any(candidate_str in act for act in active_mounts):
                    try:
                        res = subprocess.run(
                            ["umount", "-l", candidate_str],
                            capture_output=True,
                            text=True,
                        )
                        if res.returncode == 0:
                            unmounted_count += 1
                            items.append(
                                CleanupItem(
                                    category="MOUNTS",
                                    resource_id=candidate_str,
                                    status="SUCCESS",
                                    details="Unmounted pseudo-filesystem",
                                )
                            )
                    except Exception as e:
                        items.append(
                            CleanupItem(
                                category="MOUNTS",
                                resource_id=candidate_str,
                                status="FAILED",
                                details=f"Failed to unmount: {e}",
                            )
                        )

        if unmounted_count == 0 and not items:
            items.append(
                CleanupItem(
                    category="MOUNTS",
                    resource_id="chroot_mounts",
                    status="SKIPPED",
                    details="No active chroot pseudo-filesystem mounts detected",
                )
            )

        return items

    def clean_workspace(
        self,
        purge_captures: bool = False,
        purge_traces: bool = False,
        purge_all: bool = False,
    ) -> List[CleanupItem]:
        """Cleans up transient runtime files, PID files, lock files, and optional artifacts."""
        items: List[CleanupItem] = []

        # 1. Clean PID and lock files
        pids_dir = self.sandbox_workspace / "pids"
        if pids_dir.exists():
            for pfile in pids_dir.glob("*.pid"):
                try:
                    pfile.unlink()
                    items.append(
                        CleanupItem(
                            category="WORKSPACE",
                            resource_id=pfile.name,
                            status="SUCCESS",
                            details="Removed orphan PID tracking file",
                        )
                    )
                except OSError:
                    pass

        # 2. Clean temporary state cache files
        state_candidates = [
            self.sandbox_workspace / "orchestration_last_run.json",
            self.sandbox_workspace / "port_forward_state.json",
            self.sandbox_workspace / "bridge_state.json",
            self.sandbox_workspace / "routing_state.json",
            self.sandbox_workspace / "firewall_state.json",
            self.sandbox_workspace / "capture_state.json",
        ]
        for sc in state_candidates:
            if sc.exists() and purge_all:
                try:
                    sc.unlink()
                    items.append(
                        CleanupItem(
                            category="WORKSPACE",
                            resource_id=sc.name,
                            status="SUCCESS",
                            details="Purged state cache file",
                        )
                    )
                except OSError:
                    pass

        # 3. Clean capture files if explicitly requested
        if purge_captures or purge_all:
            caps_dir = self.sandbox_workspace / "captures"
            if caps_dir.exists():
                for cap in caps_dir.glob("*.pcap"):
                    try:
                        cap.unlink()
                        items.append(
                            CleanupItem(
                                category="WORKSPACE",
                                resource_id=cap.name,
                                status="SUCCESS",
                                details="Purged PCAP capture file",
                            )
                        )
                    except OSError:
                        pass

        # 4. Clean trace files if explicitly requested
        if purge_traces or purge_all:
            traces_dir = self.sandbox_workspace / "traces"
            if traces_dir.exists():
                for tr in traces_dir.glob("*"):
                    try:
                        if tr.is_file():
                            tr.unlink()
                            items.append(
                                CleanupItem(
                                    category="WORKSPACE",
                                    resource_id=tr.name,
                                    status="SUCCESS",
                                    details="Purged trace manifest / script file",
                                )
                            )
                    except OSError:
                        pass

        if not items:
            items.append(
                CleanupItem(
                    category="WORKSPACE",
                    resource_id="transient_artifacts",
                    status="SKIPPED",
                    details="No transient workspace locks or stale PID files found",
                )
            )

        return items

    def teardown_all(
        self,
        rootfs_dir: Optional[Union[str, Path]] = None,
        purge_all: bool = False,
        force_shim: bool = False,
    ) -> CleanupReport:
        """Executes full teardown sequence in reverse dependency order."""
        start_time = time.perf_counter()
        all_items: List[CleanupItem] = []

        # 1. Stop external ingress (port forward socket proxies)
        all_items.extend(self.teardown_port_forwards())

        # 2. Terminate running emulation daemons and QEMU instances
        all_items.extend(self.teardown_processes())

        # 3. Remove network firewall isolation and sniffer TEE rules
        all_items.extend(self.teardown_firewall(force_shim=force_shim))

        # 4. Release virtual networking (PCAP tap, routes, bridges)
        all_items.extend(self.teardown_network())

        # 5. Unmount filesystem mounts in chroot
        all_items.extend(self.teardown_mounts(rootfs_dir=rootfs_dir))

        # 6. Clean transient workspace state and locks
        all_items.extend(self.clean_workspace(purge_all=purge_all))

        elapsed = round(time.perf_counter() - start_time, 2)
        total_cleaned = sum(1 for i in all_items if i.status == "SUCCESS")
        total_failed = sum(1 for i in all_items if i.status == "FAILED")
        total_skipped = sum(1 for i in all_items if i.status == "SKIPPED")

        report = CleanupReport(
            total_cleaned=total_cleaned,
            total_failed=total_failed,
            total_skipped=total_skipped,
            duration_seconds=elapsed,
            items=all_items,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            self.cleanup_manifest.parent.mkdir(parents=True, exist_ok=True)
            self.cleanup_manifest.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning(f"Could not persist cleanup manifest: {exc}")

        logger.info(report.summary())
        return report
