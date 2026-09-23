"""CPU architecture detection and QEMU emulator resolution for embedded binaries."""

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Optional, Union

from firmsight.core.config import get_logger

logger = get_logger("ArchitectureResolver")


@dataclass
class ArchitectureInfo:
    """Detailed architecture profile of an ELF binary or rootfs."""

    architecture: str          # e.g., 'arm', 'mips', 'mipsel', 'aarch64', 'x86_64'
    bitness: int               # 32 or 64
    endianness: str            # 'little' or 'big'
    machine_code: int          # raw e_machine integer
    machine_name: str          # human-readable machine name
    qemu_static_bin: str       # e.g. 'qemu-arm-static'
    qemu_system_bin: str       # e.g. 'qemu-system-arm'
    binary_path: Optional[Path] = None


class ArchitectureResolver:
    """Resolves target CPU architecture and matches it to the required QEMU virtualization binary."""

    # Standard ELF Machine mappings
    EM_MAP = {
        0x03: ("x86", "Intel 80386"),
        0x08: ("mips", "MIPS RS3000"),
        0x14: ("ppc", "PowerPC"),
        0x28: ("arm", "ARM 32-bit"),
        0x3E: ("x86_64", "AMD x86-64"),
        0xB7: ("aarch64", "ARM 64-bit (AArch64)"),
    }

    @classmethod
    def resolve_binary(cls, binary_path: Union[str, Path]) -> ArchitectureInfo:
        """Inspects an ELF binary and resolves its exact architecture specifications."""
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary file not found: {path}")

        with open(path, "rb") as f:
            header = f.read(64)

        return cls.resolve_bytes(header, binary_path=path)

    @classmethod
    def resolve_bytes(
        cls, header_bytes: bytes, binary_path: Optional[Path] = None
    ) -> ArchitectureInfo:
        """Parses ELF header bytes directly."""
        if len(header_bytes) < 20 or not header_bytes.startswith(b"\x7fELF"):
            raise ValueError("Invalid ELF binary: missing '\\x7fELF' magic bytes.")

        ei_class = header_bytes[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = header_bytes[5]   # 1 = Little Endian, 2 = Big Endian

        bitness = 64 if ei_class == 2 else 32
        endianness = "little" if ei_data == 1 else "big"
        endian_char = "<" if endianness == "little" else ">"

        # e_machine is at offset 18-20 (uint16)
        e_machine = struct.unpack(f"{endian_char}H", header_bytes[18:20])[0]
        arch_id, machine_name = cls.EM_MAP.get(
            e_machine, (f"unknown_{e_machine}", f"Unknown (0x{e_machine:x})")
        )

        # Distinguish MIPS big vs little endian
        if arch_id == "mips":
            arch_id = "mipsel" if endianness == "little" else "mips"

        # Map to QEMU binaries
        qemu_static = f"qemu-{arch_id}-static"
        qemu_system = f"qemu-system-{arch_id}"
        if arch_id == "mipsel":
            qemu_system = "qemu-system-mipsel"
        elif arch_id == "x86":
            qemu_static = "qemu-i386-static"
            qemu_system = "qemu-system-i386"

        return ArchitectureInfo(
            architecture=arch_id,
            bitness=bitness,
            endianness=endianness,
            machine_code=e_machine,
            machine_name=machine_name,
            qemu_static_bin=qemu_static,
            qemu_system_bin=qemu_system,
            binary_path=binary_path,
        )

    @classmethod
    def resolve_rootfs(cls, rootfs_dir: Union[str, Path]) -> Optional[ArchitectureInfo]:
        """Scans well-known binary locations in an extracted rootfs to infer overall system architecture."""
        rootfs = Path(rootfs_dir)
        candidate_binaries = [
            rootfs / "bin" / "busybox",
            rootfs / "bin" / "sh",
            rootfs / "usr" / "bin" / "busybox",
            rootfs / "usr" / "sbin" / "httpd",
            rootfs / "bin" / "echo",
        ]

        for candidate in candidate_binaries:
            if candidate.exists() and candidate.is_file():
                try:
                    info = cls.resolve_binary(candidate)
                    logger.info(
                        f"Resolved system architecture '{info.architecture}' from: {candidate.name}"
                    )
                    return info
                except Exception as e:
                    logger.debug(f"Candidate {candidate} could not be resolved: {e}")

        # Fallback: scan any ELF file in /bin or /usr/bin
        for bin_dir in (rootfs / "bin", rootfs / "usr" / "bin", rootfs / "sbin"):
            if bin_dir.exists() and bin_dir.is_dir():
                for item in bin_dir.iterdir():
                    if item.is_file():
                        try:
                            return cls.resolve_binary(item)
                        except Exception:
                            continue

        return None
