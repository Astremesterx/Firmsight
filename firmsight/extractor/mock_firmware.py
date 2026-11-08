"""Mock vulnerable IoT firmware generator for offline sandbox testing and CI/CD."""

import io
from pathlib import Path
import struct
import tarfile
import time
from typing import Optional, Union

from firmsight.core.config import SAMPLES_DIR, ensure_directories


class MockFirmwareBuilder:
    """Builds realistic synthetic IoT firmware images containing filesystems, ELF binaries, and mock backdoors."""

    def __init__(self, output_path: Optional[Union[str, Path]] = None):
        ensure_directories()
        self.output_path = (
            Path(output_path)
            if output_path
            else SAMPLES_DIR / "vulnerable_router_arm.bin"
        )

    @staticmethod
    def _create_mock_arm_elf(name: str = "httpd") -> bytes:
        """Creates a synthetic ELF header for an ARM 32-bit little-endian executable."""
        # 16-byte e_ident: \x7fELF, 1=32bit, 1=LE, 1=current version, 0=SysV
        e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
        e_type = 2  # ET_EXEC
        e_machine = 0x28  # EM_ARM (40)
        e_version = 1
        e_entry = 0x00010400
        e_phoff = 52
        e_shoff = 0
        e_flags = 0x05000000  # EF_ARM_EABI_VER5
        e_ehsize = 52
        e_phentsize = 32
        e_phnum = 1
        e_shentsize = 40
        e_shnum = 0
        e_shstrndx = 0

        elf_header = struct.pack(
            "<16sHHIIIIIHHHHHH",
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        )

        # Mock program header + dummy ARM payload strings
        p_header = struct.pack("<IIIIIIII", 1, 0, 0x00010000, 0x00010000, 512, 512, 7, 0x1000)
        embedded_strings = (
            f"FirmSight Mock Server ({name})\x00".encode("ascii")
            + b"GET /login.cgi HTTP/1.1\x00"
            + b"admin:backdoor123\x00"
            + b"DEBUG: vulnerable buffer overflow in handle_request()\x00"
            + b"system(/bin/sh)\x00"
        )
        payload = elf_header + p_header + (b"\x90" * 64) + embedded_strings
        # Pad to 512 bytes
        return payload.ljust(512, b"\x00")

    def build(self) -> Path:
        """Constructs the mock firmware image and writes it to disk."""
        # 1. Build an in-memory tar.gz representing the Linux rootfs
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            files = {
                "etc/banner": "===========================================\n"
                " FirmSight Vulnerable Router v1.0.0 (ARM) \n"
                " WARNING: FOR RESEARCH & AUDIT PURPOSES ONLY\n"
                "===========================================\n",
                "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n"
                "guest:x:1000:1000:guest:/home/guest:/bin/sh\n"
                "backdoor_user:x:0:0:Hidden Admin:/root:/bin/sh\n",
                "etc/shadow": "root:$1$admin$hAcKB0oT.uY7l/x7G9Gq7.:19000:0:99999:7:::\n"
                "backdoor_user:$1$secret$xP3lK9gqM0l7Z.y6L3.:19000:0:99999:7:::\n",
                "etc/init.d/rcS": "#!/bin/sh\n"
                "echo 'Starting FirmSight IoT Services...'\n"
                "/usr/sbin/httpd &\n"
                "/bin/c2_beacon &\n",
                "bin/c2_beacon": "#!/bin/sh\n"
                "# Simulated Botnet C2 Callback\n"
                "C2_HOST='198.51.100.42'\n"
                "C2_PORT=4444\n"
                "echo \"[!] Initiating heartbeat to C2: $C2_HOST:$C2_PORT\"\n",
            }

            for path, content in files.items():
                data = content.encode("utf-8")
                info = tarfile.TarInfo(name=path)
                info.size = len(data)
                info.mtime = int(time.time())
                info.mode = 0o755 if "bin/" in path else 0o644
                tar.addfile(info, io.BytesIO(data))

            # Add mock ARM binary: /usr/sbin/httpd
            httpd_bin = self._create_mock_arm_elf("httpd")
            httpd_info = tarfile.TarInfo(name="usr/sbin/httpd")
            httpd_info.size = len(httpd_bin)
            httpd_info.mtime = int(time.time())
            httpd_info.mode = 0o755
            tar.addfile(httpd_info, io.BytesIO(httpd_bin))

        rootfs_data = tar_buffer.getvalue()

        # 2. Build synthetic U-Boot Header (64 bytes)
        # Magic: 0x27051956, IH_ARCH_ARM = 2, IH_TYPE_KERNEL = 2, IH_COMP_GZIP = 1
        uboot_magic = 0x27051956
        hcrc = 0xCAFEBABE
        timestamp = int(time.time())
        data_size = len(rootfs_data)
        load_addr = 0x80008000
        entry_point = 0x80008000
        dcrc = 0xDEADBEEF
        ih_os = 5       # Linux
        ih_arch = 2     # ARM
        ih_type = 5     # Filesystem / Multi
        ih_comp = 2     # Gzip
        image_name = b"FirmSight-ARM-RootFS".ljust(32, b"\x00")

        uboot_header = struct.pack(
            ">IIIIIII4B32s",
            uboot_magic,
            hcrc,
            timestamp,
            data_size,
            load_addr,
            entry_point,
            dcrc,
            ih_os,
            ih_arch,
            ih_type,
            ih_comp,
            image_name,
        )

        # 3. Prepend mock bootloader / vendor metadata and combine
        vendor_header = (
            b"VENDOR=FIRMSIGHT\n"
            b"HW_VERSION=RT-ARM-V2\n"
            b"BOOTLOADER=U-Boot 2024.04\n"
        ).ljust(256, b"\x00")

        full_firmware = vendor_header + uboot_header + rootfs_data

        # Ensure directory exists and write
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(full_firmware)

        return self.output_path
