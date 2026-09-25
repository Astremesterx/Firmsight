"""Command-line interface for FirmSight."""

import argparse
import sys
from pathlib import Path

from firmsight.core.config import SAMPLES_DIR, ensure_directories
from firmsight.emulator.arch import ArchitectureResolver
from firmsight.emulator.nvram import MockNVRAM
from firmsight.emulator.rootfs_prep import RootFSPreparer
from firmsight.extractor.extractor import FirmwareExtractor
from firmsight.extractor.header_parser import HeaderParser
from firmsight.extractor.mock_firmware import MockFirmwareBuilder


def main() -> None:
    """FirmSight main CLI router."""
    ensure_directories()
    parser = argparse.ArgumentParser(
        prog="firmsight",
        description="FirmSight: IoT Firmware Emulation & Dynamic Analysis Sandbox",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: generate-mock
    mock_parser = subparsers.add_parser(
        "generate-mock", help="Generate synthetic vulnerable IoT firmware for testing"
    )
    mock_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(SAMPLES_DIR / "vulnerable_router_arm.bin"),
        help="Path to save synthetic firmware image",
    )

    # Command: scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan firmware binary for magic headers and partitions"
    )
    scan_parser.add_argument("file", type=str, help="Firmware binary path")

    # Command: extract
    extract_parser = subparsers.add_parser(
        "extract", help="Carve and unpack Linux root filesystem from firmware"
    )
    extract_parser.add_argument("file", type=str, help="Firmware binary path")
    extract_parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default=None,
        help="Custom output directory for extracted filesystem",
    )

    # Command: identify-arch
    arch_parser = subparsers.add_parser(
        "identify-arch", help="Detect CPU architecture and QEMU emulator for a binary or rootfs"
    )
    arch_parser.add_argument("target", type=str, help="Path to ELF binary or rootfs directory")

    # Command: init-nvram
    nvram_parser = subparsers.add_parser(
        "init-nvram", help="Initialize mock NVRAM configuration for a rootfs"
    )
    nvram_parser.add_argument(
        "rootfs", type=str, help="Path to extracted rootfs directory"
    )

    # Command: prep-rootfs
    prep_parser = subparsers.add_parser(
        "prep-rootfs", help="Sanitize rootfs and bridge QEMU static binaries for chroot execution"
    )
    prep_parser.add_argument(
        "rootfs", type=str, help="Path to extracted rootfs directory"
    )

    args = parser.parse_args()

    if args.command == "generate-mock":
        builder = MockFirmwareBuilder(args.output)
        output_file = builder.build()
        print(f"[+] Successfully generated mock firmware: {output_file}")
        print(f"[+] File size: {output_file.stat().st_size} bytes")

    elif args.command == "scan":
        target = Path(args.file)
        if not target.exists():
            print(f"[-] Error: File not found: {target}", file=sys.stderr)
            sys.exit(1)
        header_parser = HeaderParser(target)
        matches = header_parser.scan()
        print(f"[*] Signature scan results for: {target.name}")
        print("-" * 70)
        print(f"{'Offset (Hex)':<15} {'Name':<30} {'Arch':<10}")
        print("-" * 70)
        for m in matches:
            arch = m.architecture_hint or "N/A"
            print(f"0x{m.offset:08X}     {m.name:<30} {arch:<10}")
        print("-" * 70)

    elif args.command == "extract":
        target = Path(args.file)
        if not target.exists():
            print(f"[-] Error: File not found: {target}", file=sys.stderr)
            sys.exit(1)
        extractor = FirmwareExtractor(output_base=args.output_dir)
        res = extractor.extract(target)
        if res.success:
            print(f"[+] Extraction SUCCESSFUL!")
            print(f"[+] Architecture detected: {res.architecture}")
            print(f"[+] RootFS Location: {res.rootfs_dir}")
            print(f"[+] Total files extracted: {len(res.extracted_files)}")
            if res.critical_artifacts:
                print("\n[+] Critical Artifacts Found:")
                for k, v in res.critical_artifacts.items():
                    print(f"    - {k}: {v[:60]}...")
        else:
            print(f"[-] Extraction failed: {res.error}", file=sys.stderr)
    elif args.command == "identify-arch":
        target = Path(args.target)
        if not target.exists():
            print(f"[-] Error: Target not found: {target}", file=sys.stderr)
            sys.exit(1)

        info = None
        if target.is_dir():
            info = ArchitectureResolver.resolve_rootfs(target)
            if not info:
                print(f"[-] Could not infer architecture from binaries in {target}", file=sys.stderr)
                sys.exit(1)
        else:
            info = ArchitectureResolver.resolve_binary(target)

        print(f"[+] Architecture Resolved: {info.architecture.upper()} ({info.bitness}-bit, {info.endianness}-endian)")
        print(f"    - Machine: {info.machine_name} (code: 0x{info.machine_code:02x})")
        print(f"    - Required QEMU User Emulator:   {info.qemu_static_bin}")
        print(f"    - Matching QEMU System Target:  {info.qemu_system_bin}")

    elif args.command == "init-nvram":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        nvram = MockNVRAM()
        ini_file = nvram.write_to_rootfs(rootfs)
        print(f"[+] Mock NVRAM successfully initialized in: {ini_file.parent}")
        print(f"[+] Generated: nvram.ini, nvram.conf, nvram_env.sh")
    elif args.command == "prep-rootfs":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        preparer = RootFSPreparer(rootfs)
        report = preparer.prepare()
        print(f"[+] RootFS Preparation: {report.status.upper()}")
        print(f"[+] Target Architecture: {report.architecture}")
        print(f"[+] QEMU Static Binary: {report.qemu_static_bin} (copied: {report.qemu_copied})")
        print(f"[+] Created Directories: {len(report.created_directories)}")
        print(f"[+] Configured Files: {', '.join(report.configured_files) or 'None'}")
        if report.warnings:
            print("[!] Notices / Warnings:")
            for w in report.warnings:
                print(f"    - {w}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
