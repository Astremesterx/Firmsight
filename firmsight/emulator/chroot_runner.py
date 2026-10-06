"""User-mode QEMU emulation runner and Chroot execution sandbox."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger
from firmsight.emulator.arch import ArchitectureInfo, ArchitectureResolver
from firmsight.emulator.nvram import MockNVRAM

logger = get_logger("ChrootRunner")


@dataclass
class ChrootExecutionResult:
    """Outcome of a sandboxed execution session."""

    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    emulation_mode: str = "qemu-user-direct"
    environment: Dict[str, str] = field(default_factory=dict)


class ChrootRunner:
    """Executes foreign architecture binaries inside a prepared rootfs using QEMU user-mode emulation."""

    def __init__(
        self,
        rootfs_dir: Union[str, Path],
        arch_info: Optional[ArchitectureInfo] = None,
        nvram: Optional[MockNVRAM] = None,
    ):
        self.rootfs_dir = Path(rootfs_dir).resolve()
        if not self.rootfs_dir.exists() or not self.rootfs_dir.is_dir():
            raise FileNotFoundError(f"RootFS directory not found: {self.rootfs_dir}")

        self.arch_info = arch_info or ArchitectureResolver.resolve_rootfs(self.rootfs_dir)
        self.nvram = nvram or MockNVRAM()

    def build_environment(self, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Constructs environment variables including mock NVRAM keys and library search paths."""
        env = dict(os.environ)

        # Standard IoT search paths
        env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
        env["HOME"] = "/root"
        env["USER"] = "root"
        env["TERM"] = "xterm"

        # Inject NVRAM parameters as NVRAM_* environment variables
        for key, value in self.nvram.store.items():
            sanitized = key.upper().replace(".", "_")
            env[f"NVRAM_{sanitized}"] = value

        if custom_env:
            env.update(custom_env)

        return env

    def run(
        self,
        binary_rel_path: Union[str, Path],
        args: Optional[List[str]] = None,
        timeout: int = 5,
        custom_env: Optional[Dict[str, str]] = None,
        use_chroot: bool = False,
    ) -> ChrootExecutionResult:
        """Executes the target binary inside the sandbox using QEMU."""
        binary_path = self.rootfs_dir / str(binary_rel_path).lstrip("/\\")
        if not binary_path.exists():
            raise FileNotFoundError(f"Target binary not found inside rootfs: {binary_path}")

        env = self.build_environment(custom_env)
        cmd: List[str] = []
        mode = "qemu-user-direct"

        qemu_bin = self.arch_info.qemu_static_bin if self.arch_info else "qemu-arm-static"
        host_qemu = shutil.which(qemu_bin) or shutil.which(f"/usr/bin/{qemu_bin}")

        # Choose execution strategy
        if use_chroot and os.name != "nt" and os.geteuid() == 0:
            # Native Linux chroot (requires root)
            mode = "chroot-jail"
            guest_qemu = f"/usr/bin/{qemu_bin}"
            cmd = ["chroot", str(self.rootfs_dir), guest_qemu, f"/{binary_rel_path}"]
            if args:
                cmd.extend(args)
        elif host_qemu:
            # QEMU user space emulation with rootfs library directory (-L)
            mode = "qemu-user-direct"
            cmd = [host_qemu, "-L", str(self.rootfs_dir), str(binary_path)]
            if args:
                cmd.extend(args)
        else:
            # Dry-run / Sandbox shim mode when host qemu-user-static is not yet installed
            mode = "sandbox-shim"
            shim_path = self.rootfs_dir / "usr" / "bin" / qemu_bin
            if shim_path.exists() and os.name != "nt":
                cmd = ["/bin/sh", str(shim_path), str(binary_path)]
            elif os.name == "nt":
                cmd = ["cmd.exe", "/c", "echo", f"[SANDBOX MOCK EXECUTION] {qemu_bin} -L {self.rootfs_dir} {binary_path}"]
            else:
                cmd = ["echo", f"[SANDBOX MOCK EXECUTION] {qemu_bin} -L {self.rootfs_dir} {binary_path}"]
            if args:
                cmd.extend(args)

        logger.info(f"Launching sandbox binary [{mode}]: {' '.join(cmd)}")

        start_time = time.time()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.rootfs_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            exit_code = proc.returncode
            stdout_str = proc.stdout
            stderr_str = proc.stderr
        except subprocess.TimeoutExpired as e:
            timed_out = True
            exit_code = -1
            stdout_str = e.stdout or ""
            stderr_str = (e.stderr or "") + f"\n[!] Process timed out after {timeout} seconds (normal for daemons)."
            logger.info(f"Target process timed out after {timeout}s (service successfully kept running).")
        except Exception as e:
            exit_code = -2
            stdout_str = ""
            stderr_str = f"Execution error: {e}"
            logger.error(stderr_str)

        duration = time.time() - start_time
        return ChrootExecutionResult(
            command=cmd,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_seconds=round(duration, 3),
            timed_out=timed_out,
            emulation_mode=mode,
            environment={k: v for k, v in env.items() if k.startswith("NVRAM_")},
        )
