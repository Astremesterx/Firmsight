"""Guest-to-Host Virtual IP Routing and Subnet Manager for IoT Firmware Sandboxing.

Provisions IPv4 subnets, host bridge IP bindings, and guest-to-host virtual routing rules
required for communication between the host sandbox and the emulated IoT device.
Automatically aligns subnets with extracted NVRAM configurations (e.g. lan_ipaddr).
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger
from firmsight.emulator.network_bridge import NetworkBridgeManager

logger = get_logger("NetworkRouter")


@dataclass
class SubnetConfig:
    """IPv4 network allocation profile for an emulated IoT device and sandbox bridge."""

    cidr: str = "192.168.1.0/24"
    gateway_ip: str = "192.168.1.1"       # Emulated IoT router IP (Guest)
    host_ip: str = "192.168.1.254"        # Host sandbox bridge interface IP
    netmask: str = "255.255.255.0"
    broadcast_ip: str = "192.168.1.255"
    dhcp_start: str = "192.168.1.100"
    dhcp_end: str = "192.168.1.200"

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "SubnetConfig":
        return cls(**data)


@dataclass
class RouteRule:
    """Represents a virtual routing rule between host and guest environments."""

    destination: str                      # e.g., '192.168.1.0/24' or '192.168.1.1/32'
    gateway: str                          # e.g., '192.168.1.254' or '0.0.0.0'
    interface: str                        # e.g., 'fs-br0'
    metric: int = 100

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "RouteRule":
        return cls(**data)


@dataclass
class RoutingStatus:
    """Telemetry report representing active virtual routing and subnet configurations."""

    bridge_name: str = "fs-br0"
    subnet: SubnetConfig = field(default_factory=SubnetConfig)
    routes: List[RouteRule] = field(default_factory=list)
    forwarding_enabled: bool = False
    mode: str = "shim-unprivileged"       # 'kernel-routing' or 'shim-unprivileged'
    is_active: bool = False
    created_at: str = ""

    def to_dict(self) -> Dict:
        return {
            "bridge_name": self.bridge_name,
            "subnet": self.subnet.to_dict(),
            "routes": [r.to_dict() for r in self.routes],
            "forwarding_enabled": self.forwarding_enabled,
            "mode": self.mode,
            "is_active": self.is_active,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "RoutingStatus":
        sub = SubnetConfig.from_dict(data.get("subnet", {}))
        routes = [RouteRule.from_dict(r) for r in data.get("routes", [])]
        return cls(
            bridge_name=data.get("bridge_name", "fs-br0"),
            subnet=sub,
            routes=routes,
            forwarding_enabled=data.get("forwarding_enabled", False),
            mode=data.get("mode", "shim-unprivileged"),
            is_active=data.get("is_active", False),
            created_at=data.get("created_at", ""),
        )


class NetworkRouter:
    """Calculates subnets, configures host IP interfaces, and manages guest-to-host virtual routing."""

    DEFAULT_BRIDGE = "fs-br0"

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None):
        self.workspace_dir = (
            Path(workspace_dir) if workspace_dir else Path("sandbox_workspace")
        )
        self.net_dir = self.workspace_dir / "network"
        self.net_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.net_dir / "routing_state.json"
        self.bridge_mgr = NetworkBridgeManager(workspace_dir=self.workspace_dir)

    @staticmethod
    def calculate_subnet(gateway_ip: str = "192.168.1.1", netmask: str = "255.255.255.0") -> SubnetConfig:
        """Derives a complete SubnetConfig given a gateway IP and subnet mask."""
        try:
            network = ipaddress.IPv4Network(f"{gateway_ip}/{netmask}", strict=False)
        except ValueError:
            # Fallback to standard /24 if invalid
            network = ipaddress.IPv4Network("192.168.1.0/24")
            gateway_ip = "192.168.1.1"

        hosts = list(network.hosts())
        # Pick last usable IP for host side of the bridge (e.g. 192.168.1.254)
        host_ip = str(hosts[-1]) if len(hosts) > 1 else str(network.network_address + 2)
        dhcp_start = str(hosts[min(99, len(hosts) - 1)]) if len(hosts) >= 100 else str(hosts[0])
        dhcp_end = str(hosts[min(199, len(hosts) - 1)]) if len(hosts) >= 200 else str(hosts[-1])

        return SubnetConfig(
            cidr=str(network),
            gateway_ip=gateway_ip,
            host_ip=host_ip,
            netmask=str(network.netmask),
            broadcast_ip=str(network.broadcast_address),
            dhcp_start=dhcp_start,
            dhcp_end=dhcp_end,
        )

    @classmethod
    def derive_from_nvram(cls, nvram_params: Dict[str, str]) -> SubnetConfig:
        """Derives subnet and routing configurations directly from extracted NVRAM parameters."""
        gw_ip = nvram_params.get("lan_ipaddr", "192.168.1.1")
        netmask = nvram_params.get("lan_netmask", "255.255.255.0")
        return cls.calculate_subnet(gateway_ip=gw_ip, netmask=netmask)

    def setup_guest_routing(
        self,
        bridge_name: str = DEFAULT_BRIDGE,
        subnet: Optional[SubnetConfig] = None,
        force_shim: bool = False,
    ) -> RoutingStatus:
        """Assigns host IP to the bridge, adds routing table rules, and enables IP forwarding."""
        sub = subnet or self.calculate_subnet()
        timestamp = datetime.now(timezone.utc).isoformat()
        use_kernel = (
            self.bridge_mgr.is_privileged()
            and not force_shim
            and shutil.which("ip") is not None
        )

        routes: List[RouteRule] = [
            # Direct subnet route on bridge interface
            RouteRule(
                destination=sub.cidr,
                gateway="0.0.0.0",
                interface=bridge_name,
                metric=10,
            ),
            # Host-to-guest gateway route
            RouteRule(
                destination=f"{sub.gateway_ip}/32",
                gateway=sub.host_ip,
                interface=bridge_name,
                metric=5,
            ),
        ]

        forwarding_enabled = False

        if use_kernel:
            try:
                # 1. Assign Host IP and Netmask to bridge interface
                ip_with_prefix = f"{sub.host_ip}/{sub.cidr.split('/')[-1]}"
                self._run_cmd(["ip", "addr", "add", ip_with_prefix, "dev", bridge_name])
                self._run_cmd(["ip", "link", "set", "dev", bridge_name, "up"])

                # 2. Add route to guest target
                self._run_cmd(
                    ["ip", "route", "replace", f"{sub.gateway_ip}/32", "dev", bridge_name]
                )

                # 3. Enable IPv4 forwarding
                forwarding_enabled = self._enable_ip_forwarding()
                mode = "kernel-routing"
                logger.info(
                    f"Configured kernel routing on {bridge_name}: Host IP {sub.host_ip}, Guest IP {sub.gateway_ip} ({sub.cidr})"
                )
            except Exception as e:
                logger.warning(
                    f"Kernel IP routing setup failed ({e}); falling back to unprivileged routing shim."
                )
                mode = "shim-unprivileged"
        else:
            mode = "shim-unprivileged"
            logger.info(
                f"Configured unprivileged virtual routing shim on {bridge_name}: Host IP {sub.host_ip}, Guest IP {sub.gateway_ip} ({sub.cidr})"
            )

        status = RoutingStatus(
            bridge_name=bridge_name,
            subnet=sub,
            routes=routes,
            forwarding_enabled=forwarding_enabled,
            mode=mode,
            is_active=True,
            created_at=timestamp,
        )

        # Update bridge status cache with assigned IP
        bridge_status = self.bridge_mgr.get_status()
        if bridge_status:
            bridge_status.ip_address = sub.host_ip
            bridge_status.netmask = sub.netmask
            self.bridge_mgr.save_state(bridge_status)

        self.save_state(status)
        return status

    def teardown_guest_routing(self, bridge_name: Optional[str] = None) -> bool:
        """Removes assigned IP addresses and deletes host-to-guest virtual routes."""
        current = self.load_state()
        b_name = bridge_name or (current.bridge_name if current else self.DEFAULT_BRIDGE)

        if current and current.mode == "kernel-routing" and self.bridge_mgr.is_privileged():
            try:
                ip_with_prefix = f"{current.subnet.host_ip}/{current.subnet.cidr.split('/')[-1]}"
                self._run_cmd(
                    ["ip", "addr", "del", ip_with_prefix, "dev", b_name], check=False
                )
                self._run_cmd(
                    ["ip", "route", "del", f"{current.subnet.gateway_ip}/32", "dev", b_name],
                    check=False,
                )
                logger.info(f"Released IP configuration on {b_name}")
            except Exception as e:
                logger.warning(f"Error releasing IP route configuration on {b_name}: {e}")

        if self.state_file.exists():
            try:
                self.state_file.unlink()
                logger.info(f"Removed virtual routing state cache at {self.state_file}")
            except OSError:
                pass

        return True

    def get_routing_status(self) -> Optional[RoutingStatus]:
        """Retrieves active virtual routing and subnet configurations."""
        return self.load_state()

    def save_state(self, status: RoutingStatus) -> None:
        """Persists the routing status to workspace cache."""
        try:
            self.state_file.write_text(
                json.dumps(status.to_dict(), indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.error(f"Failed to persist routing state: {e}")

    def load_state(self) -> Optional[RoutingStatus]:
        """Loads routing status from the workspace cache."""
        if not self.state_file.exists():
            return None
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return RoutingStatus.from_dict(data)
        except Exception as e:
            logger.debug(f"Failed to read routing state: {e}")
            return None

    def _enable_ip_forwarding(self) -> bool:
        """Enables Linux IPv4 packet forwarding via procfs or sysctl."""
        proc_path = Path("/proc/sys/net/ipv4/ip_forward")
        if proc_path.exists():
            try:
                proc_path.write_text("1\n", encoding="utf-8")
                return True
            except OSError:
                pass
        try:
            res = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            return res.returncode == 0
        except Exception:
            return False

    def _run_cmd(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Runs a system command with logging."""
        logger.debug(f"Executing: {' '.join(cmd)}")
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check,
        )
