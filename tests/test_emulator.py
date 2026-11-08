"""Unit tests for CPU architecture detection and mock NVRAM handler."""

from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from firmsight.emulator.arch import ArchitectureInfo, ArchitectureResolver
from firmsight.emulator.nvram import MockNVRAM


class TestEmulatorSubsystems(unittest.TestCase):
    """Test suite for emulator architecture resolution and NVRAM simulation."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_emu_test_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_dummy_elf_header(
        self, machine: int = 0x28, bitness: int = 32, endianness: str = "little"
    ) -> bytes:
        """Helper to create dummy 64-byte ELF headers for various architectures."""
        ei_class = 2 if bitness == 64 else 1
        ei_data = 1 if endianness == "little" else 2
        e_ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + (b"\x00" * 8)

        endian_char = "<" if endianness == "little" else ">"
        # struct: 16 bytes ident, uint16 type(2), uint16 machine, uint32 version(1)
        header = struct.pack(f"{endian_char}16sHHI", e_ident, 2, machine, 1)
        return header.ljust(64, b"\x00")

    def test_resolve_arm_architecture(self):
        """Verify ARM 32-bit LE resolution."""
        header = self._make_dummy_elf_header(machine=0x28, bitness=32, endianness="little")
        info = ArchitectureResolver.resolve_bytes(header)

        self.assertEqual(info.architecture, "arm")
        self.assertEqual(info.bitness, 32)
        self.assertEqual(info.endianness, "little")
        self.assertEqual(info.qemu_static_bin, "qemu-arm-static")
        self.assertEqual(info.qemu_system_bin, "qemu-system-arm")

    def test_resolve_mips_architecture(self):
        """Verify MIPS Big-Endian and Little-Endian (mipsel) resolution."""
        # Big Endian
        header_be = self._make_dummy_elf_header(machine=0x08, bitness=32, endianness="big")
        info_be = ArchitectureResolver.resolve_bytes(header_be)
        self.assertEqual(info_be.architecture, "mips")
        self.assertEqual(info_be.endianness, "big")
        self.assertEqual(info_be.qemu_static_bin, "qemu-mips-static")

        # Little Endian (MIPSEL)
        header_le = self._make_dummy_elf_header(machine=0x08, bitness=32, endianness="little")
        info_le = ArchitectureResolver.resolve_bytes(header_le)
        self.assertEqual(info_le.architecture, "mipsel")
        self.assertEqual(info_le.endianness, "little")
        self.assertEqual(info_le.qemu_static_bin, "qemu-mipsel-static")

    def test_resolve_invalid_elf(self):
        """Verify invalid headers raise ValueError."""
        with self.assertRaises(ValueError):
            ArchitectureResolver.resolve_bytes(b"NOT_AN_ELF_FILE_AT_ALL")

    def test_mock_nvram_defaults(self):
        """Verify mock NVRAM default parameters."""
        nvram = MockNVRAM()
        self.assertEqual(nvram.get("lan_ipaddr"), "192.168.1.1")
        self.assertEqual(nvram.get("http_username"), "admin")
        self.assertEqual(nvram.get("router_model"), "RT-AC68U")

    def test_mock_nvram_write_to_rootfs(self):
        """Verify writing NVRAM files directly to rootfs /etc."""
        rootfs = self.test_dir / "rootfs"
        rootfs.mkdir()

        nvram = MockNVRAM({"lan_ipaddr": "10.10.10.1", "router_name": "TestRouter"})
        ini_file = nvram.write_to_rootfs(rootfs)

        self.assertTrue(ini_file.exists())
        self.assertTrue((rootfs / "etc" / "nvram.conf").exists())
        self.assertTrue((rootfs / "etc" / "nvram_env.sh").exists())

        ini_content = ini_file.read_text(encoding="utf-8")
        self.assertIn("lan_ipaddr = 10.10.10.1", ini_content)
        self.assertIn("router_name = TestRouter", ini_content)


if __name__ == "__main__":
    unittest.main()
