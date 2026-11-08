"""Unit tests for user-mode QEMU Chroot execution runner."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.arch import ArchitectureInfo
from firmsight.emulator.chroot_runner import ChrootExecutionResult, ChrootRunner
from firmsight.emulator.nvram import MockNVRAM


class TestChrootRunner(unittest.TestCase):
    """Test suite for ChrootRunner sandboxed execution."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_runner_test_"))
        self.rootfs = self.test_dir / "rootfs"
        self.rootfs.mkdir()

        # Create simulated binary structure
        self.bin_dir = self.rootfs / "usr" / "sbin"
        self.bin_dir.mkdir(parents=True)
        self.dummy_bin = self.bin_dir / "dummy_service"
        self.dummy_bin.write_text("#!/bin/sh\necho 'Service Running'\n", encoding="utf-8")

        self.arch_info = ArchitectureInfo(
            architecture="arm",
            bitness=32,
            endianness="little",
            machine_code=0x28,
            machine_name="ARM 32-bit",
            qemu_static_bin="qemu-arm-static",
            qemu_system_bin="qemu-system-arm",
        )

        self.nvram = MockNVRAM({"lan_ipaddr": "192.168.50.1", "custom_key": "firmware_val"})

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_environment_construction(self):
        """Verify environment variables include NVRAM keys and system paths."""
        runner = ChrootRunner(self.rootfs, arch_info=self.arch_info, nvram=self.nvram)
        env = runner.build_environment()

        self.assertIn("NVRAM_LAN_IPADDR", env)
        self.assertEqual(env["NVRAM_LAN_IPADDR"], "192.168.50.1")
        self.assertIn("NVRAM_CUSTOM_KEY", env)
        self.assertEqual(env["NVRAM_CUSTOM_KEY"], "firmware_val")
        self.assertIn("/usr/sbin", env["PATH"])

    def test_missing_binary_raises_error(self):
        """Verify executing nonexistent binary throws FileNotFoundError."""
        runner = ChrootRunner(self.rootfs, arch_info=self.arch_info, nvram=self.nvram)
        with self.assertRaises(FileNotFoundError):
            runner.run("usr/sbin/nonexistent_binary_xyz")

    def test_execution_sandbox_run(self):
        """Verify sandboxed run produces a valid ChrootExecutionResult."""
        runner = ChrootRunner(self.rootfs, arch_info=self.arch_info, nvram=self.nvram)
        result = runner.run("usr/sbin/dummy_service", timeout=2)

        self.assertIsInstance(result, ChrootExecutionResult)
        self.assertGreaterEqual(result.duration_seconds, 0.0)
        self.assertIn(result.emulation_mode, ["qemu-user-direct", "sandbox-shim", "chroot-jail"])
        self.assertIn("NVRAM_LAN_IPADDR", result.environment)

    def test_custom_env_override(self):
        """Verify user-provided custom environment overrides defaults."""
        runner = ChrootRunner(self.rootfs, arch_info=self.arch_info, nvram=self.nvram)
        env = runner.build_environment({"CUSTOM_PORT": "8080"})
        self.assertEqual(env.get("CUSTOM_PORT"), "8080")


if __name__ == "__main__":
    unittest.main()
