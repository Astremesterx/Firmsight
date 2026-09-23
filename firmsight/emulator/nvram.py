"""Mock NVRAM handler and environment variable injector for IoT daemon emulation."""

from pathlib import Path
from typing import Dict, Optional, Union

from firmsight.core.config import get_logger

logger = get_logger("MockNVRAM")


class MockNVRAM:
    """Simulates non-volatile RAM (NVRAM) parameters commonly required by IoT router daemons."""

    DEFAULT_PARAMETERS = {
        "lan_ipaddr": "192.168.1.1",
        "lan_netmask": "255.255.255.0",
        "lan_gateway": "192.168.1.1",
        "lan_hwaddr": "00:AA:BB:CC:DD:EE",
        "lan_ifname": "br0",
        "wan_ipaddr": "10.0.2.15",
        "wan_netmask": "255.255.255.0",
        "wan_gateway": "10.0.2.2",
        "router_name": "FirmSight-Gateway",
        "router_model": "RT-AC68U",
        "productid": "RT-AC68U",
        "firmware_version": "3.0.0.4.386",
        "http_username": "admin",
        "http_passwd": "admin",
        "http_port": "80",
        "http_enable": "1",
        "http_client_ip": "192.168.1.100",
        "wl0_ssid": "FirmSight-Secure-IoT",
        "wl0_wpa_psk": "firmsight2026",
    }

    def __init__(self, custom_params: Optional[Dict[str, str]] = None):
        self.store: Dict[str, str] = dict(self.DEFAULT_PARAMETERS)
        if custom_params:
            self.store.update(custom_params)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a configuration parameter."""
        return self.store.get(key, default)

    def set(self, key: str, value: str) -> None:
        """Sets or overrides a configuration parameter."""
        self.store[key] = str(value)

    def dump_ini(self) -> str:
        """Generates an INI-formatted representation for libnvram wrappers."""
        lines = ["[nvram]"]
        for k, v in sorted(self.store.items()):
            lines.append(f"{k} = {v}")
        return "\n".join(lines) + "\n"

    def dump_flat(self) -> str:
        """Generates a key=value representation suitable for /etc/nvram.conf."""
        lines = [f"{k}={v}" for k, v in sorted(self.store.items())]
        return "\n".join(lines) + "\n"

    def dump_shell_exports(self) -> str:
        """Generates shell export statements for direct environment injection."""
        lines = ["#!/bin/sh", "# FirmSight NVRAM Environment Overrides"]
        for k, v in sorted(self.store.items()):
            sanitized_key = k.upper().replace(".", "_")
            lines.append(f'export NVRAM_{sanitized_key}="{v}"')
        return "\n".join(lines) + "\n"

    def write_to_rootfs(self, rootfs_dir: Union[str, Path]) -> Path:
        """Writes mock NVRAM configurations directly into the extracted root filesystem."""
        rootfs = Path(rootfs_dir)
        etc_dir = rootfs / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)

        ini_path = etc_dir / "nvram.ini"
        conf_path = etc_dir / "nvram.conf"
        env_path = etc_dir / "nvram_env.sh"

        ini_path.write_text(self.dump_ini(), encoding="utf-8")
        conf_path.write_text(self.dump_flat(), encoding="utf-8")
        env_path.write_text(self.dump_shell_exports(), encoding="utf-8")

        logger.info(f"Injected mock NVRAM parameters into {etc_dir}")
        return ini_path
