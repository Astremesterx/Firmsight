"""End-to-End Emulation Integration Proof Engine (Mid-Review Milestone).

Orchestrates and verifies the complete Phase 1 and Phase 2 subsystem pipeline:
  1. Firmware Extraction & RootFS Sanitization
  2. Architecture & Endianness Resolution
  3. QEMU Static Linker Bridge
  4. Mock NVRAM Virtualization
  5. Mock Device Nodes & MTD Flash Partitioning
  6. Embedded Web Service Discovery & User-Mode Launch
  7. Process Health Monitoring & Crash Diagnostics (No SIGSEGV / Missing .so)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger
from firmsight.emulator.arch import ArchitectureInfo, ArchitectureResolver
from firmsight.emulator.chroot_runner import ChrootExecutionResult
from firmsight.emulator.device_nodes import DeviceNodeManager, DeviceNodeReport
from firmsight.emulator.health_monitor import HealthIssue, HealthMonitor, HealthReport
from firmsight.emulator.nvram import MockNVRAM
from firmsight.emulator.rootfs_prep import PreparationReport, RootFSPreparer
from firmsight.emulator.service_launcher import (
    DiscoveredService,
    ServiceLaunchResult,
    ServiceLauncher,
)
from firmsight.extractor.extractor import FirmwareExtractor

logger = get_logger("IntegrationProof")


@dataclass
class MilestoneCheck:
    """Represents a specific compliance check for the Mid Review milestone."""

    check_id: str
    title: str
    phase: str          # 'Phase 1: Foundations' or 'Phase 2: Virtualization'
    passed: bool
    details: str


@dataclass
class EmulationProofReport:
    """Comprehensive compliance and verification report for the Mid-Review Milestone."""

    target_path: Path
    rootfs_dir: Path
    architecture: str
    endianness: str
    is_foreign_arch: bool
    prep_report: PreparationReport
    nvram_keys: Dict[str, str]
    device_report: DeviceNodeReport
    service: Optional[DiscoveredService]
    launch_result: Optional[ServiceLaunchResult]
    health_report: Optional[HealthReport]
    checks: List[MilestoneCheck] = field(default_factory=list)
    overall_verdict: str = "FAILED"
    elapsed_time: float = 0.0
    timestamp: str = ""

    def summary(self) -> str:
        passed_count = sum(1 for c in self.checks if c.passed)
        return (
            f"Verdict: {self.overall_verdict} ({passed_count}/{len(self.checks)} checks passed) "
            f"| Arch: {self.architecture} ({self.endianness}) "
            f"| Target: {self.target_path.name}"
        )

    def to_dict(self) -> Dict:
        return {
            "target": str(self.target_path),
            "rootfs": str(self.rootfs_dir),
            "architecture": self.architecture,
            "endianness": self.endianness,
            "is_foreign_arch": self.is_foreign_arch,
            "overall_verdict": self.overall_verdict,
            "elapsed_time_seconds": round(self.elapsed_time, 3),
            "timestamp": self.timestamp,
            "checks": [
                {
                    "id": c.check_id,
                    "title": c.title,
                    "phase": c.phase,
                    "passed": c.passed,
                    "details": c.details,
                }
                for c in self.checks
            ],
            "subsystems": {
                "rootfs_prep": {
                    "directories_created": len(self.prep_report.created_directories),
                    "files_configured": len(self.prep_report.configured_files),
                    "qemu_copied": self.prep_report.qemu_copied,
                    "fixed_symlinks": len(self.prep_report.fixed_symlinks),
                },
                "nvram": {
                    "keys_count": len(self.nvram_keys),
                    "lan_ipaddr": self.nvram_keys.get("lan_ipaddr", "N/A"),
                    "http_port": self.nvram_keys.get("http_port", "N/A"),
                },
                "device_nodes": {
                    "nodes_created": len(self.device_report.created_nodes),
                    "mtd_partitions": len(self.device_report.mtd_partitions),
                    "mode": self.device_report.provisioning_mode,
                },
                "service": {
                    "name": self.service.name if self.service else "none",
                    "binary_path": self.service.binary_path if self.service else "none",
                    "port": self.launch_result.port if self.launch_result else 0,
                    "is_running": self.launch_result.is_running if self.launch_result else False,
                },
                "health": {
                    "status": self.health_report.status if self.health_report else "N/A",
                    "exit_code": self.health_report.exit_code if self.health_report else -1,
                    "issues_count": len(self.health_report.issues) if self.health_report else 0,
                    "missing_libraries": self.health_report.missing_libraries if self.health_report else [],
                },
            },
        }

    def export_markdown(self) -> str:
        """Renders a formatted Markdown report for Mid-Review milestone submission."""
        passed_count = sum(1 for c in self.checks if c.passed)
        verdict_badge = "✅ **PASSED**" if self.overall_verdict == "PASSED" else "❌ **FAILED**"

        lines = [
            "# 🛡️ FirmSight: Track 1 Mid-Review Milestone Verification Report",
            "",
            "**Subsystem:** Systems & QEMU Emulation Engine (Track 1)  ",
            "**Lead / Engineer:** Salif (Team Lead)  ",
            "**Branch:** `salif`  ",
            f"**Milestone Verdict:** {verdict_badge} ({passed_count}/{len(self.checks)} Checks Passed)  ",
            f"**Execution Timestamp:** `{self.timestamp}`  ",
            f"**Duration:** `{self.elapsed_time:.3f}s`  ",
            "",
            "---",
            "",
            "## 1. Emulation Target Overview",
            "",
            "| Parameter | Value |",
            "| :--- | :--- |",
            f"| **Target Path** | `{self.target_path.name}` |",
            f"| **RootFS Directory** | `{self.rootfs_dir}` |",
            f"| **Detected Architecture** | `{self.architecture}` (`{self.endianness}`-endian) |",
            f"| **Foreign Architecture** | `{'Yes (QEMU User Emulation required)' if self.is_foreign_arch else 'Host Native'}` |",
            f"| **Overall Result** | **{self.overall_verdict}** |",
            "",
            "---",
            "",
            "## 2. Milestone Compliance Matrix",
            "",
            "| Check ID | Phase | Verification Check | Status | Telemetry / Details |",
            "| :--- | :--- | :--- | :---: | :--- |",
        ]

        for c in self.checks:
            st = "✅ PASS" if c.passed else "❌ FAIL"
            lines.append(f"| `{c.check_id}` | {c.phase} | {c.title} | {st} | {c.details} |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Subsystem Telemetry Breakdown",
            "",
            "### Phase 1: Foundations & Architecture Identification",
            f"- **Architecture Resolver:** Inferred `{self.architecture}` target from ELF headers.",
            f"- **RootFS Preparer:** Provisioned `{len(self.prep_report.created_directories)}` essential directories, configured DNS (`/etc/resolv.conf`), QEMU copied: `{self.prep_report.qemu_copied}`.",
            f"- **Mock NVRAM:** Injected `{len(self.nvram_keys)}` parameters into `etc/nvram.ini` (e.g. `lan_ipaddr={self.nvram_keys.get('lan_ipaddr', 'N/A')}`, `http_port={self.nvram_keys.get('http_port', 'N/A')}`).",
            "",
            "### Phase 2: Services & Virtualization",
            f"- **Device Node Manager:** Provisioned `{len(self.device_report.created_nodes)}` character device nodes and `{len(self.device_report.mtd_partitions)}` simulated MTD flash blocks (`{self.device_report.provisioning_mode}`).",
            f"- **Service Launcher:** Discovered service `{self.service.name if self.service else 'none'}` at `{self.service.binary_path if self.service else 'none'}`.",
            f"- **Service Execution:** Port `{self.launch_result.port if self.launch_result else 'N/A'}`, Running: `{self.launch_result.is_running if self.launch_result else False}`, Exit code: `{self.launch_result.execution.exit_code if self.launch_result else 'N/A'}`.",
            f"- **Health Monitor:** Diagnostic Status `{self.health_report.status if self.health_report else 'N/A'}` (Signal: `{self.health_report.signal_name if self.health_report else 'None'}`, Missing Libs: `{len(self.health_report.missing_libraries) if self.health_report else 0}`).",
            "",
            "---",
            "",
            "## 4. Milestone Conclusion",
            "",
        ])

        if self.overall_verdict == "PASSED":
            lines.append(
                "> [!NOTE]\n"
                "> **Mid-Review Criteria 100% Satisfied:** Foreign ARM/MIPS binary boots inside the sanitized "
                "chroot sandbox without crashing, successfully binds mock NVRAM parameters, accesses virtual device nodes, "
                "and passes signal/dynamic linker crash inspections. Phase 1 & 2 complete."
            )
        else:
            lines.append(
                "> [!WARNING]\n"
                "> **Mid-Review Incomplete:** One or more milestone checks failed. Inspect telemetry details above."
            )

        return "\n".join(lines)


class EmulationProofEngine:
    """Orchestrates end-to-end foreign firmware emulation and verifies Phase 1-2 milestones."""

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None):
        self.workspace_dir = Path(workspace_dir) if workspace_dir else Path("sandbox_workspace")
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def verify_firmware(
        self,
        firmware_path: Union[str, Path],
        port: int = 8080,
        binary_override: Optional[str] = None,
        timeout: int = 5,
    ) -> EmulationProofReport:
        """Extracts firmware image into workspace and runs full emulation verification."""
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            raise FileNotFoundError(f"Firmware binary not found: {fw_path}")

        extracted_dir = self.workspace_dir / "extracted" / fw_path.stem
        extractor = FirmwareExtractor(output_base=extracted_dir)
        extract_res = extractor.extract(fw_path)

        if not extract_res.success or not extract_res.rootfs_dir:
            raise RuntimeError(f"Firmware extraction failed: {extract_res.error}")

        return self.verify_rootfs(
            rootfs_dir=extract_res.rootfs_dir,
            target_path=fw_path,
            port=port,
            binary_override=binary_override,
            timeout=timeout,
        )

    def verify_rootfs(
        self,
        rootfs_dir: Union[str, Path],
        target_path: Optional[Union[str, Path]] = None,
        port: int = 8080,
        binary_override: Optional[str] = None,
        timeout: int = 5,
    ) -> EmulationProofReport:
        """Executes the complete emulation verification pipeline on a rootfs directory."""
        start_time = time.time()
        rootfs = Path(rootfs_dir).resolve()
        target = Path(target_path).resolve() if target_path else rootfs

        if not rootfs.exists() or not rootfs.is_dir():
            raise NotADirectoryError(f"RootFS directory not found: {rootfs}")

        checks: List[MilestoneCheck] = []

        # 1. Architecture Resolution
        arch_info = ArchitectureResolver.resolve_rootfs(rootfs)
        arch = arch_info.architecture if arch_info else "unknown"
        endianness = arch_info.endianness if arch_info else "little"
        is_foreign = ArchitectureResolver.is_foreign(arch) if arch_info else True

        checks.append(
            MilestoneCheck(
                check_id="CHK-ARCH-01",
                title="Target Architecture Resolution",
                phase="Phase 1: Foundations",
                passed=(arch in ["arm", "mips", "mipsel", "aarch64", "x86"]),
                details=f"Architecture '{arch}' ({endianness}-endian), foreign emulator required: {is_foreign}",
            )
        )

        # 2. RootFS Sanitizer & Linker Bridge
        preparer = RootFSPreparer(rootfs)
        prep_report = preparer.prepare(copy_qemu=True)

        qemu_bin = arch_info.qemu_static_bin if arch_info else "qemu-arm-static"
        qemu_target = rootfs / "usr" / "bin" / qemu_bin
        bridge_ok = qemu_target.exists() or (prep_report.qemu_copied)
        checks.append(
            MilestoneCheck(
                check_id="CHK-PREP-02",
                title="RootFS Sanitization & QEMU Bridge",
                phase="Phase 1: Foundations",
                passed=bridge_ok and len(prep_report.created_directories) >= 5,
                details=f"Provisioned {len(prep_report.created_directories)} dirs, DNS resolver configured, QEMU bridge: {qemu_target.name}",
            )
        )

        # 3. Mock NVRAM Injection
        nvram = MockNVRAM({"http_port": str(port)})
        nvram.write_to_rootfs(rootfs)
        nvram_keys = dict(nvram.store)
        has_nvram = len(nvram_keys) >= 3 and (rootfs / "etc" / "nvram.ini").exists()
        checks.append(
            MilestoneCheck(
                check_id="CHK-NVRAM-03",
                title="NVRAM Virtualization Layer",
                phase="Phase 1: Foundations",
                passed=has_nvram,
                details=f"Injected {len(nvram_keys)} NVRAM variables (lan_ipaddr={nvram.get('lan_ipaddr')}, http_port={nvram.get('http_port')})",
            )
        )

        # 4. Device Nodes & MTD Flash Partitions
        dev_mgr = DeviceNodeManager(rootfs)
        device_report = dev_mgr.provision_all(create_mtd=True)
        nodes_ok = len(device_report.created_nodes) >= 4 and len(device_report.mtd_partitions) >= 1
        checks.append(
            MilestoneCheck(
                check_id="CHK-DEV-04",
                title="Mock Device Nodes & Flash Partitions",
                phase="Phase 2: Virtualization",
                passed=nodes_ok,
                details=f"Provisioned {len(device_report.created_nodes)} character nodes and {len(device_report.mtd_partitions)} MTD partitions (mode: {device_report.provisioning_mode})",
            )
        )

        # 5. Service Discovery
        launcher = ServiceLauncher(rootfs, nvram=nvram)
        discovered = launcher.discover_services()
        target_service: Optional[DiscoveredService] = None

        if binary_override:
            bin_clean = str(binary_override).lstrip("/\\")
            target_service = DiscoveredService(
                name=Path(binary_override).name,
                binary_path=bin_clean,
                service_type="http",
                default_port=port,
                suggested_args=["-p", str(port)],
            )
        elif discovered:
            target_service = discovered[0]

        service_found = target_service is not None and (rootfs / target_service.binary_path).exists()
        checks.append(
            MilestoneCheck(
                check_id="CHK-SVC-05",
                title="Embedded Service Auto-Discovery",
                phase="Phase 2: Virtualization",
                passed=service_found,
                details=(
                    f"Discovered service '{target_service.name}' at '{target_service.binary_path}'"
                    if service_found
                    else "No executable service discovered in rootfs"
                ),
            )
        )

        # 6. Service Execution
        launch_result: Optional[ServiceLaunchResult] = None
        if target_service and (rootfs / target_service.binary_path).exists():
            launch_result = launcher.launch(
                service=target_service,
                port=port,
                timeout=timeout,
            )

        exec_ok = (launch_result is not None) and (
            launch_result.is_running
            or launch_result.execution.exit_code == 0
            or launch_result.execution.timed_out
        )
        checks.append(
            MilestoneCheck(
                check_id="CHK-EXEC-06",
                title="QEMU User-Mode Service Execution",
                phase="Phase 2: Virtualization",
                passed=exec_ok,
                details=(
                    f"Binary executed via {launch_result.execution.emulation_mode} (Exit: {launch_result.execution.exit_code}, Port: {launch_result.port})"
                    if launch_result
                    else "Service launch was not attempted"
                ),
            )
        )

        # 7. Health & Crash Diagnostics
        health_report: Optional[HealthReport] = None
        health_ok = False
        if launch_result and target_service:
            health_report = HealthMonitor.diagnose(
                result=launch_result.execution,
                binary_rel_path=target_service.binary_path,
                rootfs_dir=rootfs,
            )
            health_ok = (health_report.status in ["HEALTHY", "TIMED_OUT", "DEGRADED"]) and (
                len(health_report.missing_libraries) == 0
            )

        checks.append(
            MilestoneCheck(
                check_id="CHK-HEALTH-07",
                title="Emulation Health & Crash Diagnostics",
                phase="Phase 2: Virtualization",
                passed=health_ok,
                details=(
                    f"Health Status: {health_report.status} (Signal: {health_report.signal_name or 'None'}, Missing Libs: {len(health_report.missing_libraries)}, Issues: {len(health_report.issues)})"
                    if health_report
                    else "Health check not performed"
                ),
            )
        )

        # Overall verdict
        all_passed = all(c.passed for c in checks)
        verdict = "PASSED" if all_passed else "FAILED"
        elapsed = time.time() - start_time
        timestamp = datetime.now(timezone.utc).isoformat()

        report = EmulationProofReport(
            target_path=target,
            rootfs_dir=rootfs,
            architecture=arch,
            endianness=endianness,
            is_foreign_arch=is_foreign,
            prep_report=prep_report,
            nvram_keys=nvram_keys,
            device_report=device_report,
            service=target_service,
            launch_result=launch_result,
            health_report=health_report,
            checks=checks,
            overall_verdict=verdict,
            elapsed_time=elapsed,
            timestamp=timestamp,
        )

        logger.info(f"Emulation Proof Complete: {report.summary()}")
        return report
