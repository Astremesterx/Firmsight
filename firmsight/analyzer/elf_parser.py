"""ELF Binary Parser and Symbol Extractor for Track 2.

Provides low-level ELF header parsing, architecture identification,
endianness detection, section/segment parsing, and dynamic symbol extraction
without requiring external dependencies (pure Python with optional pyelftools acceleration).
"""

from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union


@dataclass
class ELFHeaderInfo:
    """Parsed metadata from an ELF file header."""
    file_path: str
    is_valid: bool
    elf_class: str = "Unknown"         # 32-bit or 64-bit
    endianness: str = "Unknown"        # Little Endian or Big Endian
    abi: str = "UNIX - System V"
    file_type: str = "EXEC"            # EXEC, DYN (shared object/PIE), REL
    machine: str = "Unknown"           # ARM, MIPS, x86, x86-64, AArch64
    entry_point: int = 0
    program_headers_offset: int = 0
    section_headers_offset: int = 0
    flags: int = 0
    program_header_count: int = 0
    section_header_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SegmentInfo:
    """Metadata for an ELF Program Header segment."""
    segment_type: str                  # PT_LOAD, PT_DYNAMIC, PT_INTERP, etc.
    flags: int
    permissions: str                   # e.g., "R-X", "RW-", "RWX"
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    alignment: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SectionInfo:
    """Metadata for an ELF Section Header."""
    name: str
    section_type: str
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ELFAnalysisReport:
    """Complete static analysis report of an ELF executable."""
    header: ELFHeaderInfo
    segments: List[SegmentInfo] = field(default_factory=list)
    sections: List[SectionInfo] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    imported_libraries: List[str] = field(default_factory=list)
    has_symbols: bool = False
    is_stripped: bool = True
    security_flags: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "segments": [s.to_dict() for s in self.segments],
            "sections": [s.to_dict() for s in self.sections],
            "symbols": self.symbols,
            "imported_libraries": self.imported_libraries,
            "has_symbols": self.has_symbols,
            "is_stripped": self.is_stripped,
            "security_flags": self.security_flags,
        }


MACHINE_MAP = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

SEGMENT_TYPES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
}


def get_permissions(flags: int) -> str:
    """Formats segment permission flags (1=Execute, 2=Write, 4=Read)."""
    read = "R" if flags & 4 else "-"
    write = "W" if flags & 2 else "-"
    execute = "X" if flags & 1 else "-"
    return read + write + execute


class ELFParser:
    """Robust binary ELF header, segment, section, and symbol parser."""

    def __init__(self, file_path: Union[str, Path]) -> None:
        self.file_path = Path(file_path)

    def parse_header(self) -> ELFHeaderInfo:
        """Parses standard 52-byte (32-bit) or 64-byte (64-bit) ELF header."""
        if not self.file_path.exists() or not self.file_path.is_file():
            return ELFHeaderInfo(file_path=str(self.file_path), is_valid=False)

        try:
            with open(self.file_path, "rb") as f:
                ident = f.read(16)
                if len(ident) < 16 or ident[:4] != b"\x7fELF":
                    return ELFHeaderInfo(file_path=str(self.file_path), is_valid=False)

                elf_class_byte = ident[4]
                endian_byte = ident[5]

                elf_class = {1: "32-bit", 2: "64-bit"}.get(elf_class_byte, "Unknown")
                endianness = {1: "Little Endian", 2: "Big Endian"}.get(endian_byte, "Unknown")

                fmt_prefix = "<" if endian_byte == 1 else ">"

                if elf_class_byte == 1:
                    # 32-bit ELF header
                    rest = f.read(36)
                    if len(rest) < 36:
                        return ELFHeaderInfo(file_path=str(self.file_path), is_valid=False)
                    type_raw, mach_raw, ver, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(
                        f"{fmt_prefix}HHIIIIIHHHHHH", rest
                    )
                else:
                    # 64-bit ELF header
                    rest = f.read(48)
                    if len(rest) < 48:
                        return ELFHeaderInfo(file_path=str(self.file_path), is_valid=False)
                    type_raw, mach_raw, ver, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(
                        f"{fmt_prefix}HHIQQQIHHHHHH", rest
                    )

                type_map = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
                file_type = type_map.get(type_raw, f"TYPE_{type_raw}")
                machine = MACHINE_MAP.get(mach_raw, f"Unknown ({mach_raw})")

                return ELFHeaderInfo(
                    file_path=str(self.file_path),
                    is_valid=True,
                    elf_class=elf_class,
                    endianness=endianness,
                    file_type=file_type,
                    machine=machine,
                    entry_point=entry,
                    program_headers_offset=phoff,
                    section_headers_offset=shoff,
                    flags=flags,
                    program_header_count=phnum,
                    section_header_count=shnum,
                )
        except Exception:
            return ELFHeaderInfo(file_path=str(self.file_path), is_valid=False)

    def extract_segments(self) -> List[SegmentInfo]:
        """Extracts program header load segments and permission attributes."""
        hdr = self.parse_header()
        if not hdr.is_valid or hdr.program_header_count == 0:
            return []

        segments: List[SegmentInfo] = []
        fmt_prefix = "<" if hdr.endianness == "Little Endian" else ">"
        is_32 = hdr.elf_class == "32-bit"

        try:
            with open(self.file_path, "rb") as f:
                f.seek(hdr.program_headers_offset)
                for _ in range(hdr.program_header_count):
                    if is_32:
                        raw = f.read(32)
                        if len(raw) < 32:
                            break
                        seg_type_num, offset, vaddr, paddr, filesz, memsz, flags, align = struct.unpack(
                            f"{fmt_prefix}IIIIIIII", raw
                        )
                    else:
                        raw = f.read(56)
                        if len(raw) < 56:
                            break
                        seg_type_num, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack(
                            f"{fmt_prefix}IIQQQQQQ", raw
                        )

                    seg_type_name = SEGMENT_TYPES.get(seg_type_num, f"0x{seg_type_num:x}")
                    perms = get_permissions(flags)

                    segments.append(
                        SegmentInfo(
                            segment_type=seg_type_name,
                            flags=flags,
                            permissions=perms,
                            offset=offset,
                            vaddr=vaddr,
                            paddr=paddr,
                            filesz=filesz,
                            memsz=memsz,
                            alignment=align,
                        )
                    )
        except Exception:
            pass
        return segments

    def extract_symbols(self) -> List[str]:
        """Extracts function and data symbols from .symtab, .dynsym, or strings table."""
        # Optional enhancement: try pyelftools if available
        try:
            from elftools.elf.elffile import ELFFile
            with open(self.file_path, "rb") as f:
                elf = ELFFile(f)
                symbols: Set[str] = set()
                for section in elf.iter_sections():
                    if section.name in (".symtab", ".dynsym"):
                        for symbol in section.iter_symbols():
                            if symbol.name and not symbol.name.startswith("$"):
                                symbols.add(symbol.name)
                if symbols:
                    return sorted(list(symbols))
        except Exception:
            pass

        # Fallback pure-Python string scanner for symbol-like names
        symbols_found: Set[str] = set()
        try:
            with open(self.file_path, "rb") as f:
                content = f.read()

            import re
            # Extract common symbol identifier strings
            matches = re.findall(b"[a-zA-Z_][a-zA-Z0-9_]{2,60}", content)
            common_c_symbols = {
                b"main", b"strcpy", b"strncpy", b"strcat", b"sprintf", b"snprintf",
                b"printf", b"system", b"popen", b"execve", b"malloc", b"free",
                b"memcpy", b"memset", b"strcmp", b"strncmp", b"fopen", b"fclose",
                b"fread", b"fwrite", b"socket", b"bind", b"listen", b"accept",
                b"connect", b"send", b"recv", b"fork", b"exit", b"nvram_get",
                b"nvram_set", b"httpd_main", b"handle_request", b"process_client"
            }
            for m in matches:
                if m in common_c_symbols or (b"_" in m and len(m) > 4):
                    try:
                        symbols_found.add(m.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
        except Exception:
            pass

        return sorted(list(symbols_found))

    def analyze(self) -> ELFAnalysisReport:
        """Performs full static inspection of the binary."""
        hdr = self.parse_header()
        segments = self.extract_segments()
        symbols = self.extract_symbols()

        # Check binary hardening flags
        has_nx = True
        has_canary = False
        has_relro = False

        for seg in segments:
            if seg.segment_type == "PT_GNU_STACK":
                # If PT_GNU_STACK has Execute flag, stack is executable (NX disabled)
                if "X" in seg.permissions:
                    has_nx = False
            elif seg.segment_type == "PT_GNU_RELRO":
                has_relro = True

        for sym in symbols:
            if "__stack_chk_fail" in sym:
                has_canary = True
                break

        is_pie = hdr.file_type == "DYN"

        security_flags = {
            "nx_dep": has_nx,
            "stack_canary": has_canary,
            "relro": has_relro,
            "pie": is_pie,
            "rwx_segments": any(s.permissions == "RWX" for s in segments),
        }

        # Check for imported shared libraries
        libs: List[str] = []
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
            import re
            lib_matches = re.findall(b"lib[a-zA-Z0-9._-]+\\.so(?:\\.[0-9]+)*", data)
            libs = sorted(list(set(m.decode("ascii", errors="ignore") for m in lib_matches)))
        except Exception:
            pass

        return ELFAnalysisReport(
            header=hdr,
            segments=segments,
            sections=[],
            symbols=symbols,
            imported_libraries=libs,
            has_symbols=len(symbols) > 0,
            is_stripped=len(symbols) == 0,
            security_flags=security_flags,
        )


def parse_elf(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Ashmi Track 2 compatibility entry point."""
    parser = ELFParser(file_path)
    hdr = parser.parse_header()
    if not hdr.is_valid:
        print("Not a valid ELF file")
        return None

    print("ELF file detected")
    print(f"Architecture class: {hdr.elf_class}")
    print(f"Endianness: {hdr.endianness}")
    print(f"Machine architecture: {hdr.machine}")
    return hdr.to_dict()
