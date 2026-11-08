"""Unit tests for End-to-End Emulation Integration Proof (Mid Review Milestone)."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.integration_proof import (
    EmulationProofEngine,
    EmulationProofReport,
    MilestoneCheck,
)
from firmsight.extractor.mock_firmware import MockFirmwareBuilder


class TestIntegrationProof(unittest.TestCase):
    """Test suite for full Phase 1 & 2 integration verification."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_proof_test_"))
        self.workspace = self.test_dir / "workspace"
        self.workspace.mkdir()

        # Build synthetic ARM rootfs
        self.rootfs = self.test_dir / "rootfs"
        self.rootfs.mkdir()

        # Simulated directories
        (self.rootfs / "etc").mkdir(parents=True)
        (self.rootfs / "usr" / "sbin").mkdir(parents=True)
        (self.rootfs / "bin").mkdir(parents=True)

        # Mock ARM ELF binary for httpd
        httpd_bin = self.rootfs / "usr" / "sbin" / "httpd"
        httpd_bin.write_bytes(MockFirmwareBuilder._create_mock_arm_elf("httpd"))

        # Mock password file
        (self.rootfs / "etc" / "passwd").write_text("admin:x:0:0:Admin:/:/bin/sh\n", encoding="utf-8")

        self.engine = EmulationProofEngine(workspace_dir=self.workspace)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_verify_rootfs_success(self):
        """Verify full emulation pipeline successfully validates all Phase 1-2 criteria."""
        report = self.engine.verify_rootfs(self.rootfs, port=8080)

        self.assertIsInstance(report, EmulationProofReport)
        self.assertEqual(report.overall_verdict, "PASSED")
        self.assertEqual(report.architecture, "arm")
        self.assertEqual(report.endianness, "little")
        self.assertIsInstance(report.is_foreign_arch, bool)

        # Verify all milestone checks passed
        check_ids = [c.check_id for c in report.checks]
        self.assertIn("CHK-ARCH-01", check_ids)
        self.assertIn("CHK-PREP-02", check_ids)
        self.assertIn("CHK-NVRAM-03", check_ids)
        self.assertIn("CHK-DEV-04", check_ids)
        self.assertIn("CHK-SVC-05", check_ids)
        self.assertIn("CHK-EXEC-06", check_ids)
        self.assertIn("CHK-HEALTH-07", check_ids)
        self.assertTrue(all(c.passed for c in report.checks))

        # Check telemetry
        self.assertGreaterEqual(len(report.prep_report.created_directories), 5)
        self.assertIn("http_port", report.nvram_keys)
        self.assertEqual(report.nvram_keys["http_port"], "8080")
        self.assertGreaterEqual(len(report.device_report.created_nodes), 4)
        self.assertIsNotNone(report.service)
        self.assertEqual(report.service.name, "httpd")
        self.assertEqual(report.health_report.status, "HEALTHY")

    def test_export_markdown_report(self):
        """Verify Markdown report generation formats tables, badges, and telemetry."""
        report = self.engine.verify_rootfs(self.rootfs, port=8080)
        md = report.export_markdown()

        self.assertIn("# 🛡️ FirmSight: Track 1 Mid-Review Milestone Verification Report", md)
        self.assertIn("PASSED", md)
        self.assertIn("CHK-ARCH-01", md)
        self.assertIn("CHK-HEALTH-07", md)
        self.assertIn("Telemetry Breakdown", md)

    def test_to_dict_telemetry(self):
        """Verify report serialization to JSON-compatible dictionary."""
        report = self.engine.verify_rootfs(self.rootfs, port=8080)
        data = report.to_dict()

        self.assertEqual(data["overall_verdict"], "PASSED")
        self.assertEqual(data["architecture"], "arm")
        self.assertIn("subsystems", data)
        self.assertIn("nvram", data["subsystems"])
        self.assertIn("health", data["subsystems"])

    def test_verify_firmware_end_to_end(self):
        """Verify full pipeline starting from raw binary firmware carving and extraction."""
        fw_path = self.test_dir / "sample_router.bin"
        builder = MockFirmwareBuilder(output_path=fw_path)
        builder.build()

        report = self.engine.verify_firmware(fw_path, port=9090)
        self.assertEqual(report.overall_verdict, "PASSED")
        self.assertEqual(report.target_path.name, "sample_router.bin")
        self.assertEqual(report.architecture, "arm")

    def test_verify_empty_rootfs_fails_milestone(self):
        """Verify empty rootfs without binaries appropriately fails milestone checks."""
        empty_rootfs = self.test_dir / "empty_rootfs"
        empty_rootfs.mkdir()

        report = self.engine.verify_rootfs(empty_rootfs)
        self.assertEqual(report.overall_verdict, "FAILED")

        # Service discovery check should have failed
        svc_check = next((c for c in report.checks if c.check_id == "CHK-SVC-05"), None)
        self.assertIsNotNone(svc_check)
        self.assertFalse(svc_check.passed)


if __name__ == "__main__":
    unittest.main()
