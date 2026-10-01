"""Asynchronous background process lifecycle manager and daemon supervisor for IoT firmware emulation."""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Dict, List, Optional, Union

from firmsight.core.config import WORKSPACE_DIR, get_logger
from firmsight.emulator.arch import ArchitectureResolver
from firmsight.emulator.chroot_runner import ChrootRunner
from firmsight.emulator.nvram import MockNVRAM

logger = get_logger("DaemonManager")


@dataclass
class DaemonProcess:
    """Metadata describing a running background sandbox daemon."""

    name: str
    pid: int
    binary_path: str
    start_time: float
    log_file: Path
    pid_file: Path


@dataclass
class DaemonStatus:
    """Live status report of a background daemon."""

    name: str
    pid: int
    is_alive: bool
    exit_code: Optional[int] = None
    uptime_seconds: float = 0.0
    recent_logs: List[str] = field(default_factory=list)


class DaemonManager:
    """Supervises long-running background emulator processes (web servers, beacon daemons) with logging and PID tracking."""

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None):
        self.workspace = Path(workspace_dir) if workspace_dir else WORKSPACE_DIR
        self.pid_dir = self.workspace / "pids"
        self.log_dir = self.workspace / "logs"
        self.pid_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def spawn(
        self,
        rootfs_dir: Union[str, Path],
        binary_rel_path: Union[str, Path],
        name: Optional[str] = None,
        args: Optional[List[str]] = None,
        custom_env: Optional[Dict[str, str]] = None,
    ) -> DaemonProcess:
        """Spawns a target binary in the background inside QEMU and tracks its PID."""
        rootfs = Path(rootfs_dir).resolve()
        bin_path = str(binary_rel_path).lstrip("/\\")
        daemon_name = name or Path(bin_path).name

        pid_file = self.pid_dir / f"{daemon_name}.pid"
        log_file = self.log_dir / f"{daemon_name}.log"

        # Check if already running
        existing = self.poll(daemon_name)
        if existing and existing.is_alive:
            raise RuntimeError(f"Daemon '{daemon_name}' is already running with PID {existing.pid}")

        runner = ChrootRunner(rootfs)
        env = runner.build_environment(custom_env)

        # Build QEMU execution command
        arch_info = runner.arch_info
        qemu_bin = arch_info.qemu_static_bin if arch_info else "qemu-arm-static"
        target_abs = rootfs / bin_path

        # Determine QEMU command
        host_qemu = Path(f"/usr/bin/{qemu_bin}")
        if host_qemu.exists():
            cmd = [str(host_qemu), "-L", str(rootfs), str(target_abs)]
        else:
            shim_path = rootfs / "usr" / "bin" / qemu_bin
            if shim_path.exists() and os.name != "nt":
                cmd = ["/bin/sh", str(shim_path), str(target_abs)]
            else:
                cmd = ["echo", f"[SANDBOX DAEMON] {qemu_bin} {bin_path}"]

        if args:
            cmd.extend(args)

        logger.info(f"Spawning daemon '{daemon_name}' in background: {' '.join(cmd)}")

        # Open log file for stdout and stderr streaming
        log_handle = open(log_file, "a+", encoding="utf-8")
        log_handle.write(f"\n--- [SPAWNED {daemon_name} AT {time.ctime()}] ---\n")
        log_handle.flush()

        proc = subprocess.Popen(
            cmd,
            cwd=str(rootfs),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True if os.name != "nt" else False,
        )

        daemon_info = {
            "name": daemon_name,
            "pid": proc.pid,
            "binary_path": bin_path,
            "start_time": time.time(),
            "log_file": str(log_file),
        }
        pid_file.write_text(json.dumps(daemon_info, indent=2), encoding="utf-8")

        return DaemonProcess(
            name=daemon_name,
            pid=proc.pid,
            binary_path=bin_path,
            start_time=daemon_info["start_time"],
            log_file=log_file,
            pid_file=pid_file,
        )

    def poll(self, name: str) -> Optional[DaemonStatus]:
        """Checks the status, uptime, and recent logs of a background daemon."""
        pid_file = self.pid_dir / f"{name}.pid"
        if not pid_file.exists():
            return None

        try:
            info = json.loads(pid_file.read_text(encoding="utf-8"))
        except Exception:
            return None

        pid = info["pid"]
        start_time = info.get("start_time", time.time())
        log_file = Path(info.get("log_file", ""))

        is_alive = False
        exit_code = None

        if os.name != "nt":
            try:
                # Signal 0 tests if PID is alive without killing it
                os.kill(pid, 0)
                is_alive = True
            except OSError:
                is_alive = False
        else:
            # Windows fallback: test if process exists
            try:
                out = subprocess.check_output(f"tasklist /FI \"PID eq {pid}\"", shell=True, text=True)
                is_alive = str(pid) in out
            except Exception:
                is_alive = False

        uptime = time.time() - start_time if is_alive else 0.0

        # Read recent logs
        recent_logs = []
        if log_file.exists():
            try:
                lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                recent_logs = lines[-10:]  # Last 10 lines
            except Exception:
                pass

        return DaemonStatus(
            name=name,
            pid=pid,
            is_alive=is_alive,
            exit_code=exit_code,
            uptime_seconds=round(uptime, 2),
            recent_logs=recent_logs,
        )

    def stop(self, name: str, timeout: int = 3) -> bool:
        """Gracefully terminates a running daemon, falling back to force-kill if needed."""
        pid_file = self.pid_dir / f"{name}.pid"
        if not pid_file.exists():
            return False

        try:
            info = json.loads(pid_file.read_text(encoding="utf-8"))
            pid = info["pid"]
        except Exception:
            pid_file.unlink(missing_ok=True)
            return False

        logger.info(f"Terminating daemon '{name}' (PID: {pid})...")
        if os.name != "nt":
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait for exit
                for _ in range(timeout * 10):
                    time.sleep(0.1)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                else:
                    # Force kill if still alive
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        else:
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        pid_file.unlink(missing_ok=True)
        return True

    def list_active(self) -> List[DaemonStatus]:
        """Lists all registered daemons and their current live states."""
        results: List[DaemonStatus] = []
        for pfile in self.pid_dir.glob("*.pid"):
            name = pfile.stem
            status = self.poll(name)
            if status:
                results.append(status)
        return results
