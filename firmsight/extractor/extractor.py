"""Firmware extraction and root filesystem carving engine."""

from dataclasses import dataclass, field
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from typing import Dict, List, Optional, Union

from firmsight.core.config import EXTRACTED_DIR, ensure_directories, get_logger
from firmsight.extractor.header_parser import HeaderParser, SignatureMatch

logger = get_logger("FirmwareExtractor")


@dataclass
class ExtractionResult:
    """Summary of extraction results and parsed filesystem metadata."""

    firmware_file: Path
    output_dir: Path
    rootfs_dir: Optional[Path] = None
    architecture: str = "unknown"
    signatures: List[SignatureMatch] = field(default_factory=list)
    extracted_files: List[str] = field(default_factory=list)
    critical_artifacts: Dict[str, str] = field(default_factory=dict)
    success: bool = False
    error: Optional[str] = None


class FirmwareExtractor:
    """Automates firmware carving, partition analysis, and rootfs extraction."""

    def __init__(self, output_base: Optional[Union[str, Path]] = None):
        ensure_directories()
        self.output_base = Path(output_base) if output_base else EXTRACTED_DIR

    def extract(self, firmware_path: Union[str, Path]) -> ExtractionResult:
        """Extracts filesystems from a raw binary firmware blob."""
        firmware_path = Path(firmware_path)
        if not firmware_path.exists():
            raise FileNotFoundError(f"Firmware binary not found: {firmware_path}")

        session_name = firmware_path.stem
        target_dir = self.output_base / session_name
        rootfs_target = target_dir / "rootfs"

        if target_dir.exists():
            shutil.rmtree(target_dir)
        rootfs_target.mkdir(parents=True, exist_ok=True)

        result = ExtractionResult(
            firmware_file=firmware_path,
            output_dir=target_dir,
            rootfs_dir=rootfs_target,
        )

        logger.info(f"Analyzing firmware headers for: {firmware_path.name}")
        parser = HeaderParser(firmware_path)
        signatures = parser.scan()
        result.signatures = signatures

        # Infer architecture from signatures
        for sig in signatures:
            if sig.architecture_hint and sig.architecture_hint != "unknown":
                result.architecture = sig.architecture_hint
                break

        logger.info(f"Found {len(signatures)} potential headers/partitions. Inferred Arch: {result.architecture}")

        # Attempt extraction using native carvers or binwalk
        extracted = self._carve_and_extract(firmware_path, signatures, rootfs_target)
        if not extracted:
            # Try binwalk subprocess if installed
            extracted = self._try_binwalk_subprocess(firmware_path, target_dir)

        if extracted and rootfs_target.exists():
            result.success = True
            result.extracted_files = [
                str(p.relative_to(rootfs_target))
                for p in rootfs_target.rglob("*")
                if p.is_file()
            ]
            self._audit_critical_artifacts(result)
            logger.info(f"Extracted {len(result.extracted_files)} files successfully.")
        else:
            result.error = "No supported compressed filesystem could be extracted."
            logger.warning(result.error)

        return result

    def _carve_and_extract(
        self, firmware_path: Path, signatures: List[SignatureMatch], target_rootfs: Path
    ) -> bool:
        """Carves matching payload streams (gzip, tar, squashfs) from offsets."""
        with open(firmware_path, "rb") as f:
            data = f.read()

        for sig in signatures:
            offset = sig.offset
            # If gzip payload signature detected
            if b"\x1f\x8b" in sig.magic or sig.name == "Gzip Compressed Archive":
                logger.info(f"Attempting Gzip/Tar extraction at offset 0x{offset:x}")
                payload_slice = data[offset:]
                try:
                    with tarfile.open(fileobj=io.BytesIO(payload_slice), mode="r:gz") as tar:
                        try:
                            tar.extractall(path=target_rootfs, filter="data")
                        except TypeError:
                            tar.extractall(path=target_rootfs)
                    return True
                except Exception as e:
                    logger.debug(f"Direct tar.gz extraction failed at offset {offset}: {e}")

            # If SquashFS detected
            elif "SquashFS" in sig.name:
                logger.info(f"SquashFS partition detected at offset 0x{offset:x}")
                # Save carved squashfs blob
                blob_path = target_rootfs.parent / "partition.squashfs"
                size = sig.payload_size if sig.payload_size else (len(data) - offset)
                blob_path.write_bytes(data[offset : offset + size])

                # Check if unsquashfs is available
                if shutil.which("unsquashfs"):
                    try:
                        subprocess.run(
                            ["unsquashfs", "-d", str(target_rootfs), "-f", str(blob_path)],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        return True
                    except Exception as e:
                        logger.debug(f"unsquashfs execution failed: {e}")

        return False

    def _try_binwalk_subprocess(self, firmware_path: Path, target_dir: Path) -> bool:
        """Falls back to binwalk command-line tool if available."""
        if not shutil.which("binwalk"):
            return False

        logger.info("Running system 'binwalk' extraction fallback...")
        try:
            cmd = ["binwalk", "--extract", "--matryoshka", "--directory", str(target_dir), str(firmware_path)]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Check if an extracted directory was created
            extracted_subdirs = [d for d in target_dir.iterdir() if d.is_dir() and d.name != "rootfs"]
            if extracted_subdirs:
                # Copy or link contents to rootfs
                source_root = extracted_subdirs[0]
                for item in source_root.iterdir():
                    dest = target_dir / "rootfs" / item.name
                    if item.is_dir():
                        shutil.copytree(item, dest, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, dest)
                return True
        except Exception as e:
            logger.warning(f"Binwalk execution encountered error: {e}")
        return False

    def _audit_critical_artifacts(self, result: ExtractionResult) -> None:
        """Audits the extracted rootfs for sensitive configurations and binaries."""
        if not result.rootfs_dir or not result.rootfs_dir.exists():
            return

        checks = {
            "passwd": result.rootfs_dir / "etc" / "passwd",
            "shadow": result.rootfs_dir / "etc" / "shadow",
            "rcS": result.rootfs_dir / "etc" / "init.d" / "rcS",
            "httpd": result.rootfs_dir / "usr" / "sbin" / "httpd",
            "c2_beacon": result.rootfs_dir / "bin" / "c2_beacon",
        }

        for key, path in checks.items():
            if path.exists():
                try:
                    preview = path.read_text(errors="ignore")[:200].strip()
                    result.critical_artifacts[key] = preview
                except Exception:
                    result.critical_artifacts[key] = f"Binary artifact present ({path.stat().st_size} bytes)"
