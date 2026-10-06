"""Unit tests for RootFS Sanitizer and QEMU Linker Bridge."""

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.arch import ArchitectureInfo
from firmsight.emulator.rootfs_prep import PreparationReport, RootFSPreparer


class TestRootFSPreparer(unittest.TestCase):
    """Test suite for root filesystem sanitization and QEMU bridging."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_prep_test_"))
        self.rootfs = self.test_dir / "rootfs"
        self.rootfs.mkdir()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_ensure_essential_directories(self):
        """Verify all critical Unix mountpoint directories are created."""
        preparer = RootFSPreparer(self.rootfs)
        report = preparer.prepare(copy_qemu=False)

        self.assertEqual(report.status, "ready")
        for expected_dir in [
            "proc",
            "sys",
            "dev",
            "dev/pts",
            "tmp",
            "var/run",
            "var/log",
            "etc",
            "usr/bin",
        ]:
            dir_path = self.rootfs / Path(expected_dir)
            self.assertTrue(dir_path.exists(), f"Missing required directory: {expected_dir}")
            self.assertTrue(dir_path.is_dir())

    def test_configure_network_files(self):
        """Verify /etc/resolv.conf and /etc/hosts are configured for guest networking."""
        preparer = RootFSPreparer(self.rootfs)
        report = preparer.prepare(copy_qemu=False)

        resolv_path = self.rootfs / "etc" / "resolv.conf"
        hosts_path = self.rootfs / "etc" / "hosts"

        self.assertTrue(resolv_path.exists())
        self.assertTrue(hosts_path.exists())

        resolv_content = resolv_path.read_text(encoding="utf-8")
        self.assertIn("nameserver 8.8.8.8", resolv_content)

        hosts_content = hosts_path.read_text(encoding="utf-8")
        self.assertIn("127.0.0.1", hosts_content)

    def test_qemu_static_bridge(self):
        """Verify QEMU static binary is bridged into rootfs /usr/bin/."""
        custom_arch = ArchitectureInfo(
            architecture="arm",
            bitness=32,
            endianness="little",
            machine_code=0x28,
            machine_name="ARM 32-bit",
            qemu_static_bin="qemu-arm-static",
            qemu_system_bin="qemu-system-arm",
        )

        preparer = RootFSPreparer(self.rootfs, arch_info=custom_arch)
        report = preparer.prepare(copy_qemu=True)

        qemu_target = self.rootfs / "usr" / "bin" / "qemu-arm-static"
        self.assertTrue(qemu_target.exists())
        # Verify executable permissions on POSIX
        if os.name != "nt":
            mode = os.stat(qemu_target).st_mode
            self.assertTrue(bool(mode & 0o111), "QEMU binary must be executable")

    def test_dangling_symlink_reporting(self):
        """Verify dangling absolute symlinks inside rootfs are detected and reported."""
        bin_dir = self.rootfs / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        # Create a dangling symlink pointing to nonexistent absolute target
        dangling_link = bin_dir / "nonexistent_cmd"
        try:
            dangling_link.symlink_to("/bin/nonexistent_binary")
            preparer = RootFSPreparer(self.rootfs)
            report = preparer.prepare(copy_qemu=False)
            self.assertTrue(
                any("nonexistent_cmd" in w for w in report.warnings),
                "Should report dangling symlink warning",
            )
        except (OSError, NotImplementedError):
            # On platforms where unprivileged symlink creation is restricted
            pass


if __name__ == "__main__":
    unittest.main()
