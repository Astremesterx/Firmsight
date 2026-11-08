"""Unit tests for advanced SquashFS superblock parsing and partition carving."""

from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from firmsight.extractor.squashfs_handler import (
    SquashFSCarveResult,
    SquashFSHandler,
    SquashFSSuperblock,
)


class TestSquashFSHandler(unittest.TestCase):
    """Test suite for SquashFS superblock scanning and filesystem carving."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_squash_test_"))
        self.blob_path = self.test_dir / "firmware_with_squashfs.bin"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_squashfs_blob(
        self,
        offset: int = 512,
        endianness: str = "little",
        compression_id: int = 1,
        bytes_used: int = 2048,
    ) -> Path:
        """Constructs a test binary containing a synthetic SquashFS 4.0 superblock."""
        magic = b"sqsh" if endianness == "little" else b"hsqs"
        endian_char = "<" if endianness == "little" else ">"

        # Superblock fields (96 bytes)
        header = struct.pack(
            f"{endian_char}IIIIIHHHHHHQQQQQQQQ",
            struct.unpack(f"{endian_char}I", magic)[0],  # s_magic
            150,                                          # inodes
            1710000000,                                   # mkfs_time
            131072,                                       # block_size (128 KB)
            12,                                           # fragments
            compression_id,                               # compression
            17,                                           # block_log
            0,                                            # flags
            1,                                            # no_ids
            4,                                            # s_major (4.0)
            0,                                            # s_minor
            0x1000,                                       # root_inode
            bytes_used,                                   # bytes_used
            0x2000, 0x2100, 0x2200, 0x2300, 0x2400, 0x2500,  # table pointers
        )

        padding_before = b"\xaa" * offset
        payload_data = b"\x55" * (bytes_used - len(header))
        padding_after = b"\xbb" * 1024

        full_blob = padding_before + header + payload_data + padding_after
        self.blob_path.write_bytes(full_blob)
        return self.blob_path

    def test_scan_little_endian_squashfs(self):
        """Verify scanning and parsing a SquashFS 4.0 LE superblock."""
        self._create_mock_squashfs_blob(offset=1024, endianness="little", compression_id=1, bytes_used=4096)
        superblocks = SquashFSHandler.scan_superblocks(self.blob_path)

        self.assertEqual(len(superblocks), 1)
        sb = superblocks[0]
        self.assertEqual(sb.offset, 1024)
        self.assertEqual(sb.version, "4.0")
        self.assertEqual(sb.endianness, "little")
        self.assertEqual(sb.compression_name, "gzip")
        self.assertEqual(sb.block_size, 131072)
        self.assertEqual(sb.inode_count, 150)
        self.assertEqual(sb.bytes_used, 4096)

    def test_scan_big_endian_squashfs(self):
        """Verify scanning and parsing a SquashFS 4.0 BE superblock."""
        self._create_mock_squashfs_blob(offset=256, endianness="big", compression_id=2, bytes_used=2048)
        superblocks = SquashFSHandler.scan_superblocks(self.blob_path)

        self.assertEqual(len(superblocks), 1)
        sb = superblocks[0]
        self.assertEqual(sb.offset, 256)
        self.assertEqual(sb.endianness, "big")
        self.assertEqual(sb.compression_name, "lzma")
        self.assertEqual(sb.bytes_used, 2048)

    def test_carve_partition_slice(self):
        """Verify carving out the exact partition slice to disk."""
        self._create_mock_squashfs_blob(offset=512, endianness="little", compression_id=4, bytes_used=1024)
        superblocks = SquashFSHandler.scan_superblocks(self.blob_path)
        self.assertEqual(len(superblocks), 1)

        out_dir = self.test_dir / "carved_output"
        res = SquashFSHandler.carve_and_unpack(self.blob_path, superblocks[0], out_dir, partition_idx=1)

        self.assertIsInstance(res, SquashFSCarveResult)
        self.assertTrue(res.carved_blob_path.exists())
        self.assertEqual(res.carved_blob_path.stat().st_size, 1024)
        self.assertEqual(res.superblock.compression_name, "xz")

    def test_scan_nonexistent_file_raises(self):
        """Verify scanning nonexistent path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            SquashFSHandler.scan_superblocks(self.test_dir / "nonexistent.bin")


if __name__ == "__main__":
    unittest.main()
