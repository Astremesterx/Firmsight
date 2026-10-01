"""Unit tests for Device Node Manager and virtual MTD flash generator."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.device_nodes import DeviceNodeManager, DeviceNodeReport


class TestDeviceNodeManager(unittest.TestCase):
    """Test suite for provisioning Linux character devices and MTD partitions."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_dev_test_"))
        self.rootfs = self.test_dir / "rootfs"
        self.rootfs.mkdir()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_provision_standard_devices(self):
        """Verify standard character devices are created in rootfs/dev."""
        manager = DeviceNodeManager(self.rootfs)
        report = manager.provision_all(create_mtd=False)

        self.assertIsInstance(report, DeviceNodeReport)
        self.assertEqual(report.status, "ready")

        dev_dir = self.rootfs / "dev"
        for dev_name in ["null", "zero", "random", "urandom", "console", "nvram"]:
            node_path = dev_dir / dev_name
            self.assertTrue(node_path.exists(), f"Missing device node: {dev_name}")
            self.assertIn(dev_name, report.created_nodes)

    def test_provision_mtd_flash_partitions(self):
        """Verify MTD flash character and block devices are created."""
        manager = DeviceNodeManager(self.rootfs)
        report = manager.provision_all(create_mtd=True)

        self.assertGreater(len(report.mtd_partitions), 0)
        dev_dir = self.rootfs / "dev"

        # Check mtd0 and mtdblock0
        mtd0 = dev_dir / "mtd0"
        mtdblock0 = dev_dir / "mtdblock0"
        self.assertTrue(mtd0.exists())
        self.assertTrue(mtdblock0.exists())

        # Check header
        content = mtd0.read_bytes()
        self.assertTrue(content.startswith(b"MTD_PARTITION:bootloader"))

    def test_provision_skip_mtd(self):
        """Verify create_mtd=False does not create MTD flash devices."""
        manager = DeviceNodeManager(self.rootfs)
        report = manager.provision_all(create_mtd=False)

        self.assertEqual(len(report.mtd_partitions), 0)
        dev_dir = self.rootfs / "dev"
        self.assertFalse((dev_dir / "mtd0").exists())


if __name__ == "__main__":
    unittest.main()
