"""Emulation Health Checker and Dynamic Process Crash Diagnostics."""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import List, Optional, Union

from firmsight.core.config import get_logger
from firmsight.emulator.chroot_runner import ChrootExecutionResult

logger = get_logger("HealthMonitor")


@dataclass
class HealthIssue:
    """Represents a diagnostic issue detected during process emulation."""

    category: str       # 'missing_library', 'crash_signal', 'nvram_error', 'exec_error', 'permission'
    severity: str       # 'CRITICAL', 'WARNING', 'INFO'
    description: str
    remediation: str


@dataclass
class HealthReport:
    """Diagnostic report evaluating the health of an emulated process."""

    binary_path: str
    exit_code: int
    status: str                         # 'HEALTHY', 'CRASHED', 'DEPENDENCY_MISSING', 'DEGRADED', 'TIMED_OUT'
    signal_name: Optional[str] = None
    missing_libraries: List[str] = field(default_factory=list)
    issues: List[HealthIssue] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class HealthMonitor:
    """Analyzes execution traces, output streams, and exit codes to diagnose emulation failures."""

    # Common Unix termination signals (128 + signal_number)
    SIGNAL_MAP = {
        139: ("SIGSEGV", "Segmentation Fault (Invalid memory address dereference or stack overflow)"),
        134: ("SIGABRT", "Abort Signal (Failed assertion, libc abort, or security watchdog trigger)"),
        132: ("SIGILL", "Illegal Instruction (Instruction unsupported by CPU or emulator)"),
        135: ("SIGBUS", "Bus Error (Unaligned memory access)"),
        143: ("SIGTERM", "Terminated Gracefully by external monitor"),
        137: ("SIGKILL", "Killed unconditionally (OOM or force-stopped)"),
    }

    # Regex patterns for dynamic linker and runtime errors
    MISSING_LIB_RE = re.compile(
        r"(?:error while loading shared libraries:\s*|cannot open shared object file:\s*)([a-zA-Z0-9_\.\-\+]+)",
        re.IGNORECASE,
    )
    EXEC_FORMAT_RE = re.compile(r"Exec format error", re.IGNORECASE)
    NVRAM_FAIL_RE = re.compile(r"(?:nvram_get|nvram_set|NVRAM).*?(?:failed|not found|error)", re.IGNORECASE)
    PERMISSION_RE = re.compile(r"Permission denied", re.IGNORECASE)

    @classmethod
    def diagnose(
        cls,
        result: ChrootExecutionResult,
        binary_rel_path: Union[str, Path] = "unknown_binary",
        rootfs_dir: Optional[Union[str, Path]] = None,
    ) -> HealthReport:
        """Diagnoses execution outcomes and identifies failure root causes."""
        binary_str = str(binary_rel_path)
        combined_logs = f"{result.stdout}\n{result.stderr}"

        report = HealthReport(
            binary_path=binary_str,
            exit_code=result.exit_code,
            status="HEALTHY",
        )

        # 1. Check for timeout (healthy indicator for daemon servers)
        if result.timed_out:
            report.status = "TIMED_OUT"
            report.recommendations.append(
                "Process ran continuously until timeout (normal expected behavior for web daemons and network listeners)."
            )
            return report

        # 2. Check for Termination Signals / Crashes
        if result.exit_code in cls.SIGNAL_MAP:
            sig_name, sig_desc = cls.SIGNAL_MAP[result.exit_code]
            report.signal_name = sig_name
            report.status = "CRASHED"
            report.issues.append(
                HealthIssue(
                    category="crash_signal",
                    severity="CRITICAL",
                    description=f"Process crashed with {sig_name} (Code {result.exit_code}): {sig_desc}",
                    remediation="Hook process with Radare2 (r2pipe) to inspect call stack and register state at crash point.",
                )
            )

        # 3. Detect Missing Shared Libraries (.so)
        matched_libs = cls.MISSING_LIB_RE.findall(combined_logs)
        if matched_libs:
            report.status = "DEPENDENCY_MISSING"
            for lib in set(matched_libs):
                report.missing_libraries.append(lib)
                report.issues.append(
                    HealthIssue(
                        category="missing_library",
                        severity="CRITICAL",
                        description=f"Dynamic linker failed to load shared library: '{lib}'",
                        remediation=f"Verify if '{lib}' exists in rootfs /lib or /usr/lib. Copy from firmware rootfs or build mock library.",
                    )
                )

        # 4. Check for Architecture Mismatch / Missing QEMU User Translator
        if cls.EXEC_FORMAT_RE.search(combined_logs) or result.exit_code == 126:
            report.status = "DEGRADED"
            report.issues.append(
                HealthIssue(
                    category="exec_error",
                    severity="CRITICAL",
                    description="Execution failed with 'Exec format error' (CPU architecture mismatch).",
                    remediation="Install host QEMU user emulator via 'sudo apt install qemu-user-static' to translate foreign CPU instructions.",
                )
            )

        # 5. Check for NVRAM Errors
        if cls.NVRAM_FAIL_RE.search(combined_logs):
            report.issues.append(
                HealthIssue(
                    category="nvram_error",
                    severity="WARNING",
                    description="Runtime logs indicate missing or uninitialized NVRAM parameters.",
                    remediation="Run 'firmsight init-nvram <rootfs>' to inject mock router parameters.",
                )
            )

        # 6. Check for Permission Errors
        if cls.PERMISSION_RE.search(combined_logs):
            report.issues.append(
                HealthIssue(
                    category="permission",
                    severity="WARNING",
                    description="Permission denied accessing files or network sockets.",
                    remediation="Ensure target binary and scripts have chmod +x executable permissions.",
                )
            )

        # 7. Compile high-level recommendations
        if report.status == "HEALTHY" and result.exit_code == 0:
            report.recommendations.append("Process executed and exited cleanly without errors.")
        else:
            for issue in report.issues:
                if issue.remediation not in report.recommendations:
                    report.recommendations.append(issue.remediation)

        logger.info(
            f"Diagnostics completed for {binary_str}: Status={report.status}, "
            f"Issues={len(report.issues)}, MissingLibs={len(report.missing_libraries)}"
        )
        return report
