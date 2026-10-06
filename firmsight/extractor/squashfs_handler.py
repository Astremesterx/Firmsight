"""Advanced SquashFS superblock parser, partition boundary validator, and carving engine."""

from dataclasses import dataclass, field
import datetime
import os
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger

logger = get_logger("SquashFSHandler")


@dataclass
class SquashFSSuperblock:
    """Detailed metadata extracted from a SquashFS 4.0/3.0 superblock."""

    offset: int
    magic: bytes
    version: str
    endianness: str           # 'little' or 'big'
    compression_id: int
    compression_name: str
    block_size: int
    inode_count: int
    bytes_used: int
    creation_time: int
    creation_time_str: str
    flags: int


@dataclass
class SquashFSCarveResult:
    """Result of carving and extracting a SquashFS partition from a binary blob."""

    partition_index: int
    superblock: SquashFSSuperblock
    carved_blob_path: Path
    unpacked_dir: Optional[Path] = None
    success: bool = False
    file_count: int = 0
    error: Optional[str] = None


class SquashFSHandler:
    """Parses SquashFS headers, validates partition boundaries, and carves filesystems."""

    COMPRESSION_MAP = {
        1: "gzip",
        2: "lzma",
        3: "lzo",
        4: "xz",
        5: "lz4",
        6: "zstd",
    }

    # SquashFS 4.0 header format:
    # uint32 s_magic, inodes, mkfs_time, block_size, fragments
    # uint16 compression, block_log, flags, no_ids, s_major, s_minor
    # uint64 root_inode, bytes_used, id_table_start, xattr_table_start,
    #        inode_table_start, dir_table_start, frag_table_start, lookup_table_start
    HEADER_STRUCT_FMT = "IIIIIHHHHHHQQQQQQQQ"
    HEADER_SIZE = 96

    @classmethod
    def scan_superblocks(cls, firmware_path: Union[str, Path]) -> List[SquashFSSuperblock]:
        """Scans a firmware binary and parses every SquashFS superblock found."""
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            raise FileNotFoundError(f"Firmware binary not found: {fw_path}")

        data = fw_path.read_bytes()
        superblocks: List[SquashFSSuperblock] = []

        magics = [
            (b"sqsh", "little", "<"),
            (b"hsqs", "big", ">"),
        ]

        for magic_bytes, endianness, endian_char in magics:
            pos = 0
            while True:
                idx = data.find(magic_bytes, pos)
                if idx == -1:
                    break

                if idx + cls.HEADER_SIZE <= len(data):
                    header_bytes = data[idx : idx + cls.HEADER_SIZE]
                    parsed = cls._parse_header(header_bytes, idx, endianness, endian_char)
                    if parsed:
                        superblocks.append(parsed)

                pos = idx + len(magic_bytes)

        superblocks.sort(key=lambda sb: sb.offset)
        logger.info(f"Identified {len(superblocks)} valid SquashFS partition(s) in {fw_path.name}")
        return superblocks

    @classmethod
    def _parse_header(
        cls, header_bytes: bytes, offset: int, endianness: str, endian_char: str
    ) -> Optional[SquashFSSuperblock]:
        """Unpacks and validates a 96-byte SquashFS superblock."""
        try:
            fields = struct.unpack(f"{endian_char}{cls.HEADER_STRUCT_FMT}", header_bytes)
            (
                s_magic,
                inodes,
                mkfs_time,
                block_size,
                fragments,
                compression_id,
                block_log,
                flags,
                no_ids,
                s_major,
                s_minor,
                root_inode,
                bytes_used,
                id_table_start,
                xattr_table_start,
                inode_table_start,
                dir_table_start,
                frag_table_start,
                lookup_table_start,
            ) = fields

            # Sanity checks for valid SquashFS 4.x/3.x filesystem
            if s_major not in (3, 4) or block_size not in (4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576):
                return None

            if bytes_used <= 0:
                return None

            comp_name = cls.COMPRESSION_MAP.get(compression_id, f"custom_{compression_id}")
            time_str = datetime.datetime.fromtimestamp(mkfs_time, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if mkfs_time > 0 else "Unknown"

            return SquashFSSuperblock(
                offset=offset,
                magic=header_bytes[:4],
                version=f"{s_major}.{s_minor}",
                endianness=endianness,
                compression_id=compression_id,
                compression_name=comp_name,
                block_size=block_size,
                inode_count=inodes,
                bytes_used=bytes_used,
                creation_time=mkfs_time,
                creation_time_str=time_str,
                flags=flags,
            )
        except Exception:
            return None

    @classmethod
    def carve_and_unpack(
        cls,
        firmware_path: Union[str, Path],
        superblock: SquashFSSuperblock,
        output_dir: Union[str, Path],
        partition_idx: int = 1,
    ) -> SquashFSCarveResult:
        """Carves the exact SquashFS byte slice from the firmware and extracts files using unsquashfs."""
        fw_path = Path(firmware_path)
        out_base = Path(output_dir).resolve()
        out_base.mkdir(parents=True, exist_ok=True)

        blob_path = out_base / f"partition_{partition_idx}.squashfs"
        unpacked_target = out_base / f"rootfs_partition_{partition_idx}"

        data = fw_path.read_bytes()
        end_offset = superblock.offset + superblock.bytes_used

        if end_offset > len(data):
            # If header claims more bytes than file size, carve to end of file
            end_offset = len(data)

        # 1. Carve exact partition slice
        partition_data = data[superblock.offset : end_offset]
        blob_path.write_bytes(partition_data)
        logger.info(
            f"Carved partition {partition_idx}: offset 0x{superblock.offset:x}..0x{end_offset:x} "
            f"({len(partition_data)} bytes) -> {blob_path.name}"
        )

        result = SquashFSCarveResult(
            partition_index=partition_idx,
            superblock=superblock,
            carved_blob_path=blob_path,
            unpacked_dir=unpacked_target,
        )

        # 2. Extract using host unsquashfs if available
        unsquashfs_bin = shutil.which("unsquashfs")
        if unsquashfs_bin:
            try:
                cmd = [unsquashfs_bin, "-d", str(unpacked_target), "-f", str(blob_path)]
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                result.success = True
                result.file_count = sum(1 for _ in unpacked_target.rglob("*") if _.is_file())
                logger.info(f"unsquashfs extracted {result.file_count} files into {unpacked_target}")
            except Exception as e:
                result.error = f"unsquashfs extraction failed: {e}"
                logger.warning(result.error)
        else:
            result.error = "Host tool 'unsquashfs' not found. Partition carved successfully for manual inspection."
            result.success = True  # Carving succeeded
            logger.info(result.error)

        return result
