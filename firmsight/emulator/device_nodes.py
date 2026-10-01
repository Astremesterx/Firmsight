"""Simulated device nodes and virtual flash memory (MTD) generator for IoT firmware emulation."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import subprocess
from typing import Dict, List, Optional, Tuple, Union

from firmsight.core.config import get_logger

logger = get_logger("DeviceNodeManager")


@dataclass
class DeviceNodeReport:
    """Summary of created or provisioned device nodes."""

    rootfs_dir: Path
    created_nodes: List[str] = field(default_factory=list)
    mtd_partitions: List[str] = field(default_factory=list)
    provisioning_mode: str = "shim-unprivileged"   # 'mknod-privileged' or 'shim-unprivileged'
    warnings: List[str] = field(default_factory=list)
    status: str = "ready"


class DeviceNodeManager:
    """Provisions required Linux character devices and mock MTD flash blocks inside rootfs/dev."""

    # Standard character device specifications: (type, major, minor, permissions)
    STANDARD_DEVICES: Dict[str, Tuple[int, int, int, int]] = {
        "null": (stat.S_IFCHR, 1, 3, 0o666),
        "zero": (stat.S_IFCHR, 1, 5, 0o666),
        "random": (stat.S_IFCHR, 1, 8, 0o666),
        "urandom": (stat.S_IFCHR, 1, 9, 0o666),
        "console": (stat.S_IFCHR, 5, 1, 0o600),
        "tty": (stat.S_IFCHR, 5, 0, 0o666),
    }

    # Standard IoT flash partition layout (MTD)
    MTD_LAYOUT = [
        ("mtd0", "mtdblock0", "bootloader", 256 * 1024),       # 256 KB U-Boot
        ("mtd1", "mtdblock1", "kernel", 2 * 1024 * 1024),      # 2 MB Kernel
        ("mtd2", "mtdblock2", "rootfs", 8 * 1024 * 1024),      # 8 MB SquashFS
        ("mtd3", "mtdblock3", "nvram", 128 * 1024),            # 128 KB NVRAM
        ("mtd4", "mtdblock4", "config", 64 * 1024),            # 64 KB Calibration
    ]

    def __init__(self, rootfs_dir: Union[str, Path]):
        self.rootfs_dir = Path(rootfs_dir).resolve()
        if not self.rootfs_dir.exists() or not self.rootfs_dir.is_dir():
            raise FileNotFoundError(f"RootFS directory not found: {self.rootfs_dir}")

        self.dev_dir = self.rootfs_dir / "dev"

    def provision_all(self, create_mtd: bool = True) -> DeviceNodeReport:
        """Provisions character devices and virtual flash partitions."""
        self.dev_dir.mkdir(parents=True, exist_ok=True)
        report = DeviceNodeReport(rootfs_dir=self.rootfs_dir)

        is_root = (os.name != "nt" and os.geteuid() == 0)

        # 1. Provision standard system character devices
        for dev_name, (dev_type, major, minor, perms) in self.STANDARD_DEVICES.items():
            node_path = self.dev_dir / dev_name
            if node_path.exists():
                report.created_nodes.append(dev_name)
                continue

            created = False
            if is_root:
                try:
                    os.mknod(node_path, mode=dev_type | perms, device=os.makedev(major, minor))
                    report.provisioning_mode = "mknod-privileged"
                    created = True
                except OSError as e:
                    logger.debug(f"mknod failed for {dev_name}: {e}")

            # Fallback for unprivileged / user-mode execution
            if not created:
                self._create_unprivileged_shim(node_path, dev_name)
                report.provisioning_mode = "shim-unprivileged"

            report.created_nodes.append(dev_name)

        # 2. Provision mock NVRAM device node (/dev/nvram)
        nvram_node = self.dev_dir / "nvram"
        if not nvram_node.exists():
            # Create a regular file /dev/nvram containing mock binary or text header
            nvram_node.write_bytes(b"FLSH_NVRAM_V1\x00\x00" + (b"\xff" * 512))
            try:
                nvram_node.chmod(0o666)
            except OSError:
                pass
            report.created_nodes.append("nvram")

        # 3. Provision virtual flash partitions (MTD blocks)
        if create_mtd:
            self._provision_mtd_partitions(report)

        logger.info(
            f"Device nodes provisioned ({len(report.created_nodes)} nodes, "
            f"{len(report.mtd_partitions)} MTD partitions, Mode: {report.provisioning_mode})."
        )
        return report

    def _create_unprivileged_shim(self, node_path: Path, dev_name: str) -> None:
        """Creates an unprivileged file or symlink shim when mknod permissions are unavailable."""
        # On Linux, try symlinking to host device if allowed
        host_dev = Path(f"/dev/{dev_name}")
        if os.name != "nt" and host_dev.exists():
            try:
                node_path.symlink_to(host_dev)
                return
            except OSError:
                pass

        # Otherwise create a regular placeholder file
        if dev_name in ("null", "zero"):
            node_path.write_bytes(b"")
        elif dev_name in ("random", "urandom"):
            node_path.write_bytes(os.urandom(256))
        else:
            node_path.write_text(f"[MOCK_DEV_{dev_name.upper()}]\n", encoding="utf-8")

        try:
            node_path.chmod(0o666)
        except OSError:
            pass

    def _provision_mtd_partitions(self, report: DeviceNodeReport) -> None:
        """Generates mock MTD character and block partitions inside /dev/."""
        for mtd_char, mtd_block, label, size_bytes in self.MTD_LAYOUT:
            char_path = self.dev_dir / mtd_char
            block_path = self.dev_dir / mtd_block

            # Create minimal partition image file (header + padding)
            if not char_path.exists():
                header = f"MTD_PARTITION:{label}\x00".encode("ascii")
                # Pad up to 1024 bytes (or full size if small)
                sample_data = header + (b"\xff" * max(0, min(1024, size_bytes) - len(header)))
                char_path.write_bytes(sample_data)
                try:
                    char_path.chmod(0o666)
                except OSError:
                    pass
                report.mtd_partitions.append(f"{mtd_char} ({label})")

            if not block_path.exists():
                try:
                    # Link block device to character device or create mirror
                    block_path.write_bytes(char_path.read_bytes())
                    block_path.chmod(0o666)
                except OSError:
                    pass
                report.mtd_partitions.append(f"{mtd_block} ({label})")
