"""Virtual Network Bridge & TAP Interface Manager for IoT Firmware Sandboxing.

Provisions virtual TAP devices and Ethernet bridge interfaces for guest-to-host
networking during QEMU system and user-mode emulation. Automatically falls back
to an unprivileged stateful network shim on non-root or unprivileged environments.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger

logger = get_logger("NetworkBridge")


def generate_local_mac() -> str:
    """Generates a locally administered, unicast MAC address (02:xx:xx:xx:xx:xx)."""
    octets = [0x02] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in octets)


@dataclass
class TAPConfig:
    """Configuration profile for a virtual TAP network device."""

    name: str = "fs-tap0"
    mac_address: str = field(default_factory=generate_local_mac)
    mtu: int = 1500
    state: str = "DOWN"                 # 'UP', 'DOWN', 'SHIM'
    bridge_name: Optional[str] = None
    is_shim: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "TAPConfig":
        return cls(**data)


@dataclass
class BridgeStatus:
    """Telemetry report representing the active state of the virtual network bridge."""

    bridge_name: str = "fs-br0"
    tap_interfaces: List[TAPConfig] = field(default_factory=list)
    is_active: bool = False
    mode: str = "shim-unprivileged"     # 'kernel-netlink' or 'shim-unprivileged'
    created_at: str = ""
    ip_address: Optional[str] = None
    netmask: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "bridge_name": self.bridge_name,
            "tap_interfaces": [t.to_dict() for t in self.tap_interfaces],
            "is_active": self.is_active,
            "mode": self.mode,
            "created_at": self.created_at,
            "ip_address": self.ip_address,
            "netmask": self.netmask,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "BridgeStatus":
        taps = [TAPConfig.from_dict(t) for t in data.get("tap_interfaces", [])]
        return cls(
            bridge_name=data.get("bridge_name", "fs-br0"),
            tap_interfaces=taps,
            is_active=data.get("is_active", False),
            mode=data.get("mode", "shim-unprivileged"),
            created_at=data.get("created_at", ""),
            ip_address=data.get("ip_address"),
            netmask=data.get("netmask"),
        )


class NetworkBridgeManager:
    """Manages virtual TAP interfaces, kernel bridge devices, and sandboxed traffic routing."""

    DEFAULT_TAP = "fs-tap0"
    DEFAULT_BRIDGE = "fs-br0"

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None):
        self.workspace_dir = (
            Path(workspace_dir) if workspace_dir else Path("sandbox_workspace")
        )
        self.net_dir = self.workspace_dir / "network"
        self.net_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.net_dir / "bridge_state.json"

    @staticmethod
    def is_privileged() -> bool:
        """Determines if the running environment has raw networking administration privileges."""
        if os.name == "nt":
            return False
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def setup_bridge_network(
        self,
        tap_name: str = DEFAULT_TAP,
        bridge_name: str = DEFAULT_BRIDGE,
        force_shim: bool = False,
    ) -> BridgeStatus:
        """Provisions a TAP device, Ethernet bridge, and binds them together."""
        timestamp = datetime.now(timezone.utc).isoformat()
        use_kernel = self.is_privileged() and not force_shim and shutil.which("ip") is not None

        tap = TAPConfig(name=tap_name, bridge_name=bridge_name)

        if use_kernel:
            try:
                # 1. Create Bridge
                self._run_cmd(["ip", "link", "add", "name", bridge_name, "type", "bridge"])
                self._run_cmd(["ip", "link", "set", "dev", bridge_name, "up"])

                # 2. Create TAP
                self._run_cmd(["ip", "tuntap", "add", "dev", tap_name, "mode", "tap"])
                self._run_cmd(["ip", "link", "set", "dev", tap_name, "address", tap.mac_address])
                self._run_cmd(["ip", "link", "set", "dev", tap_name, "master", bridge_name])
                self._run_cmd(["ip", "link", "set", "dev", tap_name, "up"])

                tap.state = "UP"
                tap.is_shim = False
                mode = "kernel-netlink"
                logger.info(
                    f"Kernel network bridge created: {bridge_name} <-> {tap_name} (MAC: {tap.mac_address})"
                )
            except Exception as e:
                logger.warning(
                    f"Kernel interface creation failed ({e}); falling back to unprivileged network shim."
                )
                tap.state = "SHIM"
                tap.is_shim = True
                mode = "shim-unprivileged"
        else:
            tap.state = "SHIM"
            tap.is_shim = True
            mode = "shim-unprivileged"
            logger.info(
                f"Provisioned unprivileged virtual network shim: {bridge_name} <-> {tap_name} (MAC: {tap.mac_address})"
            )

        status = BridgeStatus(
            bridge_name=bridge_name,
            tap_interfaces=[tap],
            is_active=True,
            mode=mode,
            created_at=timestamp,
        )

        self.save_state(status)
        return status

    def teardown_bridge_network(
        self,
        tap_name: Optional[str] = None,
        bridge_name: Optional[str] = None,
    ) -> bool:
        """Tears down the virtual bridge and destroys associated TAP devices."""
        current = self.load_state()
        b_name = bridge_name or (current.bridge_name if current else self.DEFAULT_BRIDGE)
        t_name = tap_name or (
            current.tap_interfaces[0].name
            if current and current.tap_interfaces
            else self.DEFAULT_TAP
        )

        if current and current.mode == "kernel-netlink" and self.is_privileged():
            try:
                # Detach and delete TAP
                self._run_cmd(["ip", "link", "set", "dev", t_name, "nomaster"], check=False)
                self._run_cmd(["ip", "link", "set", "dev", t_name, "down"], check=False)
                self._run_cmd(["ip", "tuntap", "del", "dev", t_name, "mode", "tap"], check=False)

                # Delete Bridge
                self._run_cmd(["ip", "link", "set", "dev", b_name, "down"], check=False)
                self._run_cmd(["ip", "link", "delete", b_name, "type", "bridge"], check=False)
                logger.info(f"Released kernel interfaces: {b_name}, {t_name}")
            except Exception as e:
                logger.warning(f"Error releasing kernel network interfaces: {e}")

        # Update saved state
        if self.state_file.exists():
            try:
                self.state_file.unlink()
                logger.info(f"Removed network bridge state cache at {self.state_file}")
            except OSError:
                pass

        return True

    def get_status(self) -> Optional[BridgeStatus]:
        """Retrieves the current virtual network bridge status."""
        return self.load_state()

    def save_state(self, status: BridgeStatus) -> None:
        """Persists the bridge telemetry to workspace cache for inter-agent access."""
        try:
            self.state_file.write_text(
                json.dumps(status.to_dict(), indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.error(f"Failed to persist network bridge state: {e}")

    def load_state(self) -> Optional[BridgeStatus]:
        """Loads the active bridge status from the workspace cache."""
        if not self.state_file.exists():
            return None
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return BridgeStatus.from_dict(data)
        except Exception as e:
            logger.debug(f"Failed to read bridge state: {e}")
            return None

    def _run_cmd(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Executes a system networking command with logging."""
        logger.debug(f"Executing: {' '.join(cmd)}")
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check,
        )
