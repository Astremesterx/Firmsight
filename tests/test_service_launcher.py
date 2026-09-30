"""Unit tests for automated IoT web service discovery and launcher."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.nvram import MockNVRAM
from firmsight.emulator.service_launcher import DiscoveredService, ServiceLaunchResult, ServiceLauncher


class TestServiceLauncher(unittest.TestCase):
    """Test suite for discovering and launching embedded web services."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_launcher_test_"))
        self.rootfs = self.test_dir / "rootfs"
        self.rootfs.mkdir()

        # Create simulated binary directories
        self.sbin = self.rootfs / "usr" / "sbin"
        self.sbin.mkdir(parents=True)
        self.httpd = self.sbin / "httpd"
        self.httpd.write_text("#!/bin/sh\necho 'Mock HTTPD listening on port 80'\n", encoding="utf-8")

        # Create simulated init script
        etc_init = self.rootfs / "etc" / "init.d"
        etc_init.mkdir(parents=True)
        rcs = etc_init / "rcS"
        rcs.write_text("#!/bin/sh\n/usr/sbin/httpd &\n", encoding="utf-8")

        self.nvram = MockNVRAM()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discover_services_known_binary(self):
        """Verify discover_services finds httpd in standard /usr/sbin path."""
        launcher = ServiceLauncher(self.rootfs, nvram=self.nvram)
        services = launcher.discover_services()

        self.assertGreaterEqual(len(services), 1)
        httpd_svc = next((s for s in services if s.name == "httpd"), None)
        self.assertIsNotNone(httpd_svc)
        self.assertEqual(httpd_svc.binary_path, "usr/sbin/httpd")
        self.assertEqual(httpd_svc.default_port, 80)
        self.assertEqual(httpd_svc.service_type, "http")

    def test_launch_web_service_updates_nvram(self):
        """Verify launching a service updates NVRAM http_port and sets running status."""
        launcher = ServiceLauncher(self.rootfs, nvram=self.nvram)
        result = launcher.launch(port=8080, timeout=2)

        self.assertIsInstance(result, ServiceLaunchResult)
        self.assertEqual(result.port, 8080)
        self.assertEqual(self.nvram.get("http_port"), "8080")
        self.assertEqual(self.nvram.get("http_enable"), "1")
        self.assertTrue(result.is_running)

    def test_launch_no_services_found(self):
        """Verify launching on an empty rootfs raises RuntimeError."""
        empty_rootfs = self.test_dir / "empty_rootfs"
        empty_rootfs.mkdir()

        launcher = ServiceLauncher(empty_rootfs)
        with self.assertRaises(RuntimeError):
            launcher.launch()


if __name__ == "__main__":
    unittest.main()
