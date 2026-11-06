"""Unit tests for Executive HTML Security Audit Report Generator."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.reports.generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test suite for HTML Report Generator."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_report_test_"))
        self.generator = ReportGenerator(workspace_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_generate_html_report(self):
        """Verify compiling comprehensive HTML report document."""
        out_file = self.generator.generate(
            target_name="test_router.bin",
            architecture="arm (little-endian)",
            emulation_verdict="SUCCESS",
            duration=1.45,
        )

        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")

        self.assertIn("FirmSight Security Audit", content)
        self.assertIn("test_router.bin", content)
        self.assertIn("arm (little-endian)", content)
        self.assertIn("Leaked Credentials", content)
        self.assertIn("Buffer Overflow Exploit Proof-of-Concept", content)
        self.assertIn("C2 Threat Alerts", content)


if __name__ == "__main__":
    unittest.main()
