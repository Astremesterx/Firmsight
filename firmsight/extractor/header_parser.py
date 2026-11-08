"""Binary header parser and filesystem magic signature scanner."""

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Dict, List, Optional, Union


@dataclass
class SignatureMatch:
    """Represents a signature match found within a firmware binary."""

    name: str
    offset: int
    magic: bytes
    description: str
    architecture_hint: Optional[str] = None
    payload_size: Optional[int] = None


class HeaderParser:
    """Scans binary blobs for known firmware headers, filesystems, and compressed containers."""

    # Well-known signatures mapped to identifier, description, and byte sequence
    SIGNATURES = {
        "squashfs_le": {
            "magic": b"sqsh",
            "name": "SquashFS (Little Endian)",
            "description": "SquashFS compressed read-only filesystem (little-endian)",
        },
        "squashfs_be": {
            "magic": b"hsqs",
            "name": "SquashFS (Big Endian)",
            "description": "SquashFS compressed read-only filesystem (big-endian)",
        },
        "cramfs_le": {
            "magic": b"\x45\x3d\xcd\x28",
            "name": "CramFS (Little Endian)",
            "description": "CramFS compressed ROM filesystem (little-endian)",
        },
        "cramfs_be": {
            "magic": b"\x28\xcd\x3d\x45",
            "name": "CramFS (Big Endian)",
            "description": "CramFS compressed ROM filesystem (big-endian)",
        },
        "uboot_image": {
            "magic": b"\x27\x05\x19\x56",
            "name": "U-Boot Legacy Image",
            "description": "Das U-Boot firmware header with checksum and load address",
        },
        "gzip": {
            "magic": b"\x1f\x8b\x08",
            "name": "Gzip Compressed Archive",
            "description": "Gzip compressed container/payload",
        },
        "elf": {
            "magic": b"\x7fELF",
            "name": "ELF Executable",
            "description": "Executable and Linkable Format binary/kernel",
        },
        "jffs2_be": {
            "magic": b"\x19\x85",
            "name": "JFFS2 Filesystem (Big Endian)",
            "description": "JFFS2 flash filesystem (big-endian)",
        },
        "jffs2_le": {
            "magic": b"\x85\x19",
            "name": "JFFS2 Filesystem (Little Endian)",
            "description": "JFFS2 flash filesystem (little-endian)",
        },
    }

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)

    def scan(self, chunk_size: int = 1024 * 1024) -> List[SignatureMatch]:
        """Scans the entire firmware file in chunks and identifies magic signatures."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Firmware binary not found: {self.file_path}")

        matches: List[SignatureMatch] = []

        with open(self.file_path, "rb") as f:
            data = f.read()

        for key, sig_info in self.SIGNATURES.items():
            magic = sig_info["magic"]
            pos = 0
            while True:
                idx = data.find(magic, pos)
                if idx == -1:
                    break

                # Parse specific metadata if available
                match = self._analyze_match(key, data, idx, sig_info)
                if match:
                    matches.append(match)

                pos = idx + len(magic)

        # Sort matches chronologically by offset
        matches.sort(key=lambda m: m.offset)
        return matches

    def _analyze_match(
        self, key: str, data: bytes, offset: int, sig_info: Dict[str, Union[str, bytes]]
    ) -> Optional[SignatureMatch]:
        """Performs deep inspection of matched offset to extract headers and sizes."""
        arch_hint: Optional[str] = None
        payload_size: Optional[int] = None

        if key == "uboot_image" and len(data) >= offset + 64:
            # U-Boot header is 64 bytes
            # struct image_header: uint32 magic, hcrc, time, size, load, ep, dcrc, uint8 os, arch, type, comp, name[32]
            try:
                header = data[offset : offset + 64]
                _, _, _, data_size, _, _, _, _, arch_code, _, _ = struct.unpack(
                    ">IIIIIII4B", header[:32]
                )
                payload_size = data_size
                # U-Boot architecture codes (IH_ARCH_ARM = 2, IH_ARCH_MIPS = 5, IH_ARCH_X86 = 3)
                arch_map = {2: "arm", 5: "mips", 3: "x86", 7: "ppc"}
                arch_hint = arch_map.get(arch_code, "unknown")
            except Exception:
                pass

        elif key == "elf" and len(data) >= offset + 52:
            # Check 32-bit vs 64-bit and e_machine
            try:
                ei_class = data[offset + 4]  # 1 = 32-bit, 2 = 64-bit
                ei_data = data[offset + 5]   # 1 = LE, 2 = BE
                endian = "<" if ei_data == 1 else ">"
                e_machine = struct.unpack(f"{endian}H", data[offset + 18 : offset + 20])[0]
                # 0x28 = ARM, 0x08 = MIPS, 0x3E = x86_64, 0x03 = 386, 0xB7 = AArch64
                machine_map = {
                    0x28: "arm",
                    0x08: "mips",
                    0x3E: "x86_64",
                    0x03: "i386",
                    0xB7: "aarch64",
                }
                arch_hint = machine_map.get(e_machine, "unknown")
            except Exception:
                pass

        elif "squashfs" in key and len(data) >= offset + 36:
            try:
                # SquashFS header checks
                is_le = "le" in key
                endian = "<" if is_le else ">"
                bytes_used = struct.unpack(
                    f"{endian}Q", data[offset + 24 : offset + 32]
                )[0]
                if bytes_used > 0 and bytes_used < len(data):
                    payload_size = bytes_used
            except Exception:
                pass

        return SignatureMatch(
            name=str(sig_info["name"]),
            offset=offset,
            magic=sig_info["magic"],
            description=str(sig_info["description"]),
            architecture_hint=arch_hint,
            payload_size=payload_size,
        )
