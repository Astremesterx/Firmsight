"""Unit tests for FirmSight Master Orchestrator and One-Command Runner."""

from pathlib import Path
import shutil
import socket
import tempfile
import unittest

from firmsight.emulator.orchestrator import (
    MasterOrchestrator,
    OrchestrationConfig,
    OrchestrationResult,
    OrchestrationStage,
)
from firmsight.extractor.mock_firmware import MockFirmwareBuilder


def _get_free_port() -> int:
    """Finds an unused ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestMasterOrchestrator(unittest.TestCase):
    """Test suite for MasterOrchestrator 10-stage execution pipeline."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_orch_test_"))
        self.orchestrator = MasterOrchestrator(workspace_dir=self.test_dir)

    def tearDown(self):
        self.orchestrator.cleanup()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_rootfs(self) -> Path:
        """Constructs a minimal test rootfs layout with dummy web daemon."""
        rootfs = self.test_dir / "rootfs"
        (rootfs / "usr" / "sbin").mkdir(parents=True, exist_ok=True)
        (rootfs / "etc").mkdir(parents=True, exist_ok=True)
        (rootfs / "bin").mkdir(parents=True, exist_ok=True)

        # Create dummy httpd binary with ARM ELF header
        elf_header = (
            b"\x7fELF"              # Magic
            b"\x01"                  # 32-bit
            b"\x01"                  # Little-endian
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00"              # EXEC
            b"\x28\x00"              # EM_ARM (40)
        )
        httpd_file = rootfs / "usr" / "sbin" / "httpd"
        httpd_file.write_bytes(elf_header + b"\x00" * 100)

        return rootfs

    def test_run_with_extracted_rootfs(self):
        """Verify executing master pipeline on pre-extracted rootfs passes all 10 stages."""
        rootfs = self._create_mock_rootfs()
        port = _get_free_port()
        config = OrchestrationConfig(
            target_path=rootfs,
            work_dir=self.test_dir,
            host_port=port,
            guest_port=80,
            force_shim=True,
        )

        result = self.orchestrator.run(config)

        self.assertIsInstance(result, OrchestrationResult)
        self.assertEqual(result.target_name, "rootfs")
        self.assertEqual(result.target_type, "EXTRACTED_ROOTFS")
        self.assertEqual(result.architecture, "arm")
        self.assertEqual(result.endianness, "little")
        self.assertIn(result.overall_status, ("SUCCESS", "PARTIAL"))
        self.assertEqual(len(result.stages), 10)

        # Check all critical stages passed
        s1 = next(s for s in result.stages if s.stage_id == 1)
        self.assertEqual(s1.status, "PASSED")
        s2 = next(s for s in result.stages if s.stage_id == 2)
        self.assertEqual(s2.status, "PASSED")
        s5 = next(s for s in result.stages if s.stage_id == 5)
        self.assertEqual(s5.status, "PASSED")
        s9 = next(s for s in result.stages if s.stage_id == 9)
        self.assertEqual(s9.status, "PASSED")

        # Check output formats
        md_text = result.export_markdown()
        self.assertIn("# 🎯 FirmSight Master Emulation Report", md_text)
        self.assertIn("Pipeline Execution Stages", md_text)

        dict_data = result.to_dict()
        self.assertEqual(dict_data["architecture"], "arm")
        self.assertEqual(len(dict_data["stages"]), 10)

        # Check persistence of last run
        last_run = self.orchestrator.get_last_run()
        self.assertIsNotNone(last_run)
        self.assertEqual(last_run.target_name, "rootfs")

    def test_run_with_firmware_binary(self):
        """Verify executing master pipeline from raw firmware .bin image."""
        fw_path = self.test_dir / "sample_router.bin"
        builder = MockFirmwareBuilder(fw_path)
        builder.build()

        port = _get_free_port()
        config = OrchestrationConfig(
            target_path=fw_path,
            work_dir=self.test_dir / "extracted",
            host_port=port,
            guest_port=80,
            force_shim=True,
        )

        result = self.orchestrator.run(config)

        self.assertEqual(result.target_name, "sample_router.bin")
        self.assertEqual(result.target_type, "FIRMWARE_IMAGE")
        self.assertIn(result.overall_status, ("SUCCESS", "PARTIAL"))
        self.assertGreater(result.total_duration_seconds, 0.0)

    def test_run_with_disabled_optional_stages(self):
        """Verify disabling firewall, capture, and probing skips corresponding stages."""
        rootfs = self._create_mock_rootfs()
        port = _get_free_port()
        config = OrchestrationConfig(
            target_path=rootfs,
            work_dir=self.test_dir,
            host_port=port,
            enable_firewall=False,
            enable_capture=False,
            probe_after_launch=False,
            force_shim=True,
        )

        result = self.orchestrator.run(config)

        s6 = next(s for s in result.stages if s.stage_id == 6)
        self.assertEqual(s6.status, "SKIPPED")
        s7 = next(s for s in result.stages if s.stage_id == 7)
        self.assertEqual(s7.status, "SKIPPED")
        s10 = next(s for s in result.stages if s.stage_id == 10)
        self.assertEqual(s10.status, "SKIPPED")


if __name__ == "__main__":
    unittest.main()
