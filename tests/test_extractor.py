"""Unit tests for binary header parsing and firmware extraction engine."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.extractor.extractor import FirmwareExtractor
from firmsight.extractor.header_parser import HeaderParser
from firmsight.extractor.mock_firmware import MockFirmwareBuilder


class TestFirmwareExtractor(unittest.TestCase):
    """Test suite for firmware carving and extraction."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_test_"))
        self.mock_fw_path = self.test_dir / "test_firmware.bin"
        self.output_dir = self.test_dir / "output"

        # Generate a test firmware binary
        builder = MockFirmwareBuilder(output_path=self.mock_fw_path)
        builder.build()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_mock_firmware_generated(self):
        """Verify the mock firmware generator outputs a non-empty binary."""
        self.assertTrue(self.mock_fw_path.exists())
        self.assertGreater(self.mock_fw_path.stat().st_size, 512)

    def test_header_parser_scan(self):
        """Verify HeaderParser detects U-Boot and compressed signatures."""
        parser = HeaderParser(self.mock_fw_path)
        matches = parser.scan()
        self.assertGreaterEqual(len(matches), 1)

        names = [m.name for m in matches]
        self.assertTrue(any("U-Boot" in n for n in names))
        self.assertTrue(any("Gzip" in n for n in names))

        # Check architecture identification
        uboot_match = next((m for m in matches if "U-Boot" in m.name), None)
        self.assertIsNotNone(uboot_match)
        self.assertEqual(uboot_match.architecture_hint, "arm")

    def test_firmware_extraction(self):
        """Verify full extraction pipeline unrolls rootfs and critical artifacts."""
        extractor = FirmwareExtractor(output_base=self.output_dir)
        res = extractor.extract(self.mock_fw_path)

        self.assertTrue(res.success, f"Extraction failed: {res.error}")
        self.assertEqual(res.architecture, "arm")
        self.assertIsNotNone(res.rootfs_dir)
        self.assertTrue(res.rootfs_dir.exists())

        # Verify extracted files
        expected_files = [
            "etc/passwd",
            "etc/shadow",
            "etc/init.d/rcS",
            "usr/sbin/httpd",
            "bin/c2_beacon",
        ]
        for f in expected_files:
            file_path = res.rootfs_dir / Path(f)
            self.assertTrue(file_path.exists(), f"Missing extracted file: {f}")

        # Check critical artifacts audit
        self.assertIn("passwd", res.critical_artifacts)
        self.assertIn("c2_beacon", res.critical_artifacts)
        self.assertIn("httpd", res.critical_artifacts)


if __name__ == "__main__":
    unittest.main()
