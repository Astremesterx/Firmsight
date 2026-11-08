"""Unit tests for Track 2 Binary Analyzer, Credential Scanner, and Vulnerability Auditor."""

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.analyzer.credential_scanner import (
    CredentialScanner,
    scan_credentials,
)
from firmsight.analyzer.elf_parser import (
    ELFParser,
    parse_elf,
)
from firmsight.analyzer.vulnerability_scanner import (
    VulnerabilityScanner,
    extract_memory_map,
)
from firmsight.extractor.mock_firmware import MockFirmwareBuilder


class TestTrack2Analyzer(unittest.TestCase):
    """Test suite for Track 2 reverse engineering and security auditing."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_analyzer_test_"))
        self.mock_elf = self.test_dir / "httpd"
        self.mock_elf.write_bytes(MockFirmwareBuilder._create_mock_arm_elf("httpd"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_elf_header_parsing(self):
        """Verifies parsing 32-bit ARM ELF header."""
        parser = ELFParser(self.mock_elf)
        hdr = parser.parse_header()

        self.assertTrue(hdr.is_valid)
        self.assertEqual(hdr.elf_class, "32-bit")
        self.assertEqual(hdr.endianness, "Little Endian")
        self.assertEqual(hdr.machine, "ARM")

        # Test compatibility helper
        compat_dict = parse_elf(self.mock_elf)
        self.assertIsNotNone(compat_dict)
        self.assertEqual(compat_dict["machine"], "ARM")

    def test_elf_segments_and_symbols(self):
        """Verifies extracting program header segments and exported symbols."""
        parser = ELFParser(self.mock_elf)
        segments = parser.extract_segments()
        self.assertGreaterEqual(len(segments), 1)

        # Ensure PT_LOAD segment exists
        load_segs = [s for s in segments if s.segment_type == "PT_LOAD"]
        self.assertGreaterEqual(len(load_segs), 1)

        symbols = parser.extract_symbols()
        self.assertIsInstance(symbols, list)

    def test_credential_scanner(self):
        """Verifies identifying hardcoded credentials and passwords in files and rootfs."""
        secret_file = self.test_dir / "etc" / "passwd"
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(
            "admin:admin\n"
            "root:password123\n"
            "api_key = 'abcdef1234567890abcdef'\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        scanner = CredentialScanner(secret_file)
        findings = scanner.scan()

        self.assertGreaterEqual(len(findings), 3)
        categories = [f.category for f in findings]
        self.assertIn("DEFAULT_LOGIN", categories)
        self.assertIn("API_TOKEN", categories)
        self.assertIn("PRIVATE_KEY", categories)

        # Test compatibility wrapper
        res = scan_credentials(secret_file)
        self.assertGreaterEqual(len(res), 3)

    def test_vulnerability_scanner(self):
        """Verifies static vulnerability detection and memory layout analysis."""
        scanner = VulnerabilityScanner(self.mock_elf)
        report = scanner.audit()

        self.assertEqual(report.architecture, "ARM")
        self.assertIn(report.overall_verdict, ("PASS", "WARNING", "VULNERABLE", "CRITICAL"))

        # Test compatibility helper
        mem_map = extract_memory_map(self.mock_elf)
        self.assertIsInstance(mem_map, list)
        self.assertGreaterEqual(len(mem_map), 1)


if __name__ == "__main__":
    unittest.main()
