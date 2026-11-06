"""Firmware extraction and binary carving pipeline for FirmSight."""

from firmsight.extractor.extractor import FirmwareExtractor
from firmsight.extractor.header_parser import HeaderParser, SignatureMatch
from firmsight.extractor.mock_firmware import MockFirmwareBuilder
from firmsight.extractor.squashfs_handler import (
    SquashFSCarveResult,
    SquashFSHandler,
    SquashFSSuperblock,
)

__all__ = [
    "FirmwareExtractor",
    "HeaderParser",
    "MockFirmwareBuilder",
    "SignatureMatch",
    "SquashFSCarveResult",
    "SquashFSHandler",
    "SquashFSSuperblock",
]
