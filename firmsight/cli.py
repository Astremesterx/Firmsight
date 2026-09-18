"""Command-line interface for FirmSight."""

import argparse
import sys
from pathlib import Path

from firmsight.core.config import SAMPLES_DIR, ensure_directories
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
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
