"""Global configuration and directory constants for FirmSight."""

from enum import Enum
import logging
from pathlib import Path
import sys


class Architecture(str, Enum):
    """Supported CPU architectures for IoT firmware."""

    ARM = "arm"
    AARCH64 = "aarch64"
    MIPS = "mips"
    MIPSEL = "mipsel"
    X86_64 = "x86_64"
    UNKNOWN = "unknown"


# Base directory locations
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_DIR = PROJECT_ROOT / "sandbox_workspace"
EXTRACTED_DIR = WORKSPACE_DIR / "extracted"
CAPTURES_DIR = WORKSPACE_DIR / "captures"
SAMPLES_DIR = PROJECT_ROOT / "firmware_samples"


def ensure_directories() -> None:
    """Ensure all runtime directories exist."""
    for directory in (WORKSPACE_DIR, EXTRACTED_DIR, CAPTURES_DIR, SAMPLES_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def get_logger(name: str = "FirmSight") -> logging.Logger:
    """Configures and returns a structured logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
