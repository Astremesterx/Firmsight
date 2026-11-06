"""IPTables Sandbox Security Rules and Packet Mirroring Engine.

Enforces network isolation for emulated IoT firmware sandboxes:
- Blocks unauthorized guest outbound WAN egress (preventing real-world malware beaconing/DDoS).
- Clones / forwards all guest network packets to Track 3's PCAP sniffer interface (fs-sniff0).
- Provides controlled, bidirectional host-to-guest management channels (HTTP/DNS/ICMP).
- Provides a software policy evaluator for unprivileged CI/CD, Windows, and testing environments.
- Automatically persists active firewall state and exports deployment shell scripts.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Dict, List, Optional, Union

from firmsight.core.config import get_logger

logger = get_logger("FirewallManager")


@dataclass
class FirewallRule:
    """Represents a discrete netfilter / iptables rule for the sandbox environment."""

    table: str = "filter"                  # 'filter', 'nat', 'mangle'
    chain: str = "FORWARD"                 # 'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING'
    protocol: str = "all"                  # 'tcp', 'udp', 'icmp', 'all'
    source: Optional[str] = None           # e.g., '192.168.1.0/24'
    destination: Optional[str] = None      # e.g., '192.168.1.1/32' or '! 192.168.1.0/24'
    sport: Optional[Union[int, str]] = None
    dport: Optional[Union[int, str]] = None
    in_interface: Optional[str] = None     # e.g., 'fs-br0'
    out_interface: Optional[str] = None    # e.g., '! fs-br0'
    action: str = "ACCEPT"                 # 'ACCEPT', 'DROP', 'REJECT', 'TEE', 'MIRROR'
    target_options: Optional[str] = None   # e.g., '--gateway 192.168.1.250'
    state_match: Optional[str] = None      # e.g., 'ESTABLISHED,RELATED'
    comment: str = ""

    def to_iptables_command(self) -> str:
        """Constructs an executable iptables command string."""
        parts = ["iptables"]
        if self.table != "filter":
            parts.extend(["-t", self.table])

        parts.extend(["-A", self.chain])

        if self.in_interface:
            if self.in_interface.startswith("!"):
                parts.extend(["!", "-i", self.in_interface.replace("!", "").strip()])
            else:
                parts.extend(["-i", self.in_interface])

        if self.out_interface:
            if self.out_interface.startswith("!"):
                parts.extend(["!", "-o", self.out_interface.replace("!", "").strip()])
            else:
                parts.extend(["-o", self.out_interface])

        if self.protocol and self.protocol.lower() != "all":
            parts.extend(["-p", self.protocol.lower()])

        if self.source:
            if self.source.startswith("!"):
                parts.extend(["!", "-s", self.source.replace("!", "").strip()])
            else:
                parts.extend(["-s", self.source])

        if self.destination:
            if self.destination.startswith("!"):
                parts.extend(["!", "-d", self.destination.replace("!", "").strip()])
            else:
                parts.extend(["-d", self.destination])

        if self.sport is not None and self.protocol.lower() in ("tcp", "udp"):
            parts.extend(["--sport", str(self.sport)])

        if self.dport is not None and self.protocol.lower() in ("tcp", "udp"):
            parts.extend(["--dport", str(self.dport)])

        if self.state_match:
            parts.extend(["-m", "state", "--state", self.state_match])

        if self.comment:
            parts.extend(["-m", "comment", "--comment", f'"{self.comment}"'])

        parts.extend(["-j", self.action])

        if self.target_options:
            parts.append(self.target_options)

        return " ".join(parts)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "FirewallRule":
        return cls(**data)


@dataclass
class PacketEvaluation:
    """Telemetry report describing the evaluation decision of a packet against sandbox rules."""

    source_ip: str
    dest_ip: str
    protocol: str
    dest_port: Optional[int]
    in_interface: str
    out_interface: Optional[str]
    verdict: str                          # 'ACCEPT', 'DROP', 'REJECT'
    matched_rule: Optional[str] = None
    mirrored_to_sniffer: bool = False
    sniffer_interface: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class FirewallStatus:
    """Active firewall state, security posture, and rules telemetry."""

    bridge_name: str = "fs-br0"
    sniffer_interface: str = "fs-sniff0"
    guest_ip: str = "192.168.1.1"
    host_ip: str = "192.168.1.254"
    subnet_cidr: str = "192.168.1.0/24"
    policy: str = "SANDBOX_MONITORED"     # 'SANDBOX_MONITORED', 'ISOLATE_ALL', 'PERMISSIVE'
    wan_isolation: bool = True
    packet_mirroring: bool = True
    mode: str = "shim-unprivileged"       # 'kernel-iptables' or 'shim-unprivileged'
    is_active: bool = False
    rules: List[FirewallRule] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> Dict:
        return {
            "bridge_name": self.bridge_name,
            "sniffer_interface": self.sniffer_interface,
            "guest_ip": self.guest_ip,
            "host_ip": self.host_ip,
            "subnet_cidr": self.subnet_cidr,
            "policy": self.policy,
            "wan_isolation": self.wan_isolation,
            "packet_mirroring": self.packet_mirroring,
            "mode": self.mode,
            "is_active": self.is_active,
            "rules": [r.to_dict() for r in self.rules],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "FirewallStatus":
        rules = [FirewallRule.from_dict(r) for r in data.get("rules", [])]
        return cls(
            bridge_name=data.get("bridge_name", "fs-br0"),
            sniffer_interface=data.get("sniffer_interface", "fs-sniff0"),
            guest_ip=data.get("guest_ip", "192.168.1.1"),
            host_ip=data.get("host_ip", "192.168.1.254"),
            subnet_cidr=data.get("subnet_cidr", "192.168.1.0/24"),
            policy=data.get("policy", "SANDBOX_MONITORED"),
            wan_isolation=data.get("wan_isolation", True),
            packet_mirroring=data.get("packet_mirroring", True),
            mode=data.get("mode", "shim-unprivileged"),
            is_active=data.get("is_active", False),
            rules=rules,
            created_at=data.get("created_at", ""),
        )


class FirewallManager:
    """Configures sandbox security policies, WAN egress isolation, and Track 3 sniffer packet forwarding."""

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None) -> None:
        if workspace_dir:
            self.workspace_dir = Path(workspace_dir)
        else:
            self.workspace_dir = Path(__file__).resolve().parent.parent.parent

        self.state_file = self.workspace_dir / "sandbox_workspace" / "network" / "firewall_state.json"
        self.script_file = self.workspace_dir / "sandbox_workspace" / "network" / "firmsight_firewall.sh"
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    def is_privileged_linux(self) -> bool:
        """Determines if the runtime environment possesses root/sudo capabilities with iptables."""
        if platform.system() != "Linux":
            return False
        if not shutil.which("iptables"):
            return False
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def build_sandbox_rules(
        self,
        bridge_name: str = "fs-br0",
        sniffer_iface: str = "fs-sniff0",
        guest_ip: str = "192.168.1.1",
        host_ip: str = "192.168.1.254",
        subnet_cidr: str = "192.168.1.0/24",
        block_wan: bool = True,
        mirror_sniffer: bool = True,
        allowed_ports: Optional[List[int]] = None,
    ) -> List[FirewallRule]:
        """Constructs an ordered list of security and forwarding rules for the sandbox."""
        if allowed_ports is None:
            allowed_ports = [80, 8080, 443, 53]

        rules: List[FirewallRule] = []

        # 1. Track 3 Packet Sniffer Forwarding / Mirroring Rules (TEE Ingress & Egress)
        if mirror_sniffer:
            rules.append(
                FirewallRule(
                    table="mangle",
                    chain="PREROUTING",
                    in_interface=bridge_name,
                    action="TEE",
                    target_options=f"--gateway {host_ip}",
                    comment=f"Track 3 Sniffer: Clone sandbox ingress traffic to {sniffer_iface}",
                )
            )
            rules.append(
                FirewallRule(
                    table="mangle",
                    chain="POSTROUTING",
                    out_interface=bridge_name,
                    action="TEE",
                    target_options=f"--gateway {host_ip}",
                    comment=f"Track 3 Sniffer: Clone sandbox egress traffic to {sniffer_iface}",
                )
            )

        # 2. Connection Tracking: Allow Established & Related sessions
        rules.append(
            FirewallRule(
                table="filter",
                chain="FORWARD",
                state_match="ESTABLISHED,RELATED",
                action="ACCEPT",
                comment="Allow established and related sandbox connections",
            )
        )

        # 3. Host-to-Guest Controlled Management Channel (Allowed Ports)
        for port in allowed_ports:
            rules.append(
                FirewallRule(
                    table="filter",
                    chain="FORWARD",
                    protocol="tcp",
                    source=host_ip,
                    destination=guest_ip,
                    dport=port,
                    in_interface=bridge_name,
                    out_interface=bridge_name,
                    action="ACCEPT",
                    comment=f"Allow Host management access to guest port {port} (TCP)",
                )
            )

        # Allow ICMP ping between sandbox host and guest
        rules.append(
            FirewallRule(
                table="filter",
                chain="FORWARD",
                protocol="icmp",
                source=host_ip,
                destination=guest_ip,
                in_interface=bridge_name,
                out_interface=bridge_name,
                action="ACCEPT",
                comment="Allow ICMP health check pings between sandbox host and guest",
            )
        )

        # 4. Strict WAN Isolation Rules (Drop Rogue Guest Outbound Egress)
        if block_wan:
            # Rule: Drop any traffic exiting sandbox bridge destined to external interfaces
            rules.append(
                FirewallRule(
                    table="filter",
                    chain="FORWARD",
                    in_interface=bridge_name,
                    out_interface=f"! {bridge_name}",
                    action="DROP",
                    comment="WAN Isolation: Drop outbound forwarding from sandbox bridge to external networks",
                )
            )

            # Rule: Drop guest subnet traffic destined for foreign/WAN IP ranges
            rules.append(
                FirewallRule(
                    table="filter",
                    chain="FORWARD",
                    source=subnet_cidr,
                    destination=f"! {subnet_cidr}",
                    action="DROP",
                    comment="WAN Isolation: Prevent guest IP leakages to outside subnets",
                )
            )

            # Rule: Ingress Protection: Drop unsolicited external traffic attempting to reach sandbox bridge
            rules.append(
                FirewallRule(
                    table="filter",
                    chain="FORWARD",
                    in_interface=f"! {bridge_name}",
                    out_interface=bridge_name,
                    action="DROP",
                    comment="Ingress Protection: Drop external unauthorized traffic to sandbox bridge",
                )
            )

        # 5. Default Catch-All Sandbox Isolation Rule
        rules.append(
            FirewallRule(
                table="filter",
                chain="FORWARD",
                in_interface=bridge_name,
                action="DROP",
                comment="Default Sandbox Rule: Drop any unauthorized sandbox bridge traffic",
            )
        )

        return rules

    def apply_rules(
        self,
        bridge_name: str = "fs-br0",
        sniffer_iface: str = "fs-sniff0",
        guest_ip: str = "192.168.1.1",
        host_ip: str = "192.168.1.254",
        subnet_cidr: str = "192.168.1.0/24",
        block_wan: bool = True,
        mirror_sniffer: bool = True,
        allowed_ports: Optional[List[int]] = None,
        force_shim: bool = False,
    ) -> FirewallStatus:
        """Generates, applies, and caches sandbox firewall rules."""
        if allowed_ports is None:
            allowed_ports = [80, 8080, 443, 53]

        rules = self.build_sandbox_rules(
            bridge_name=bridge_name,
            sniffer_iface=sniffer_iface,
            guest_ip=guest_ip,
            host_ip=host_ip,
            subnet_cidr=subnet_cidr,
            block_wan=block_wan,
            mirror_sniffer=mirror_sniffer,
            allowed_ports=allowed_ports,
        )

        can_use_kernel = self.is_privileged_linux() and not force_shim
        mode = "kernel-iptables" if can_use_kernel else "shim-unprivileged"

        if can_use_kernel:
            logger.info("Applying iptables sandbox rules in kernel mode...")
            for rule in rules:
                cmd = rule.to_iptables_command().split()
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                except subprocess.CalledProcessError as exc:
                    logger.warning(f"Failed to execute '{rule.to_iptables_command()}': {exc.stderr.strip()}")
        else:
            logger.info(f"Running firewall manager in '{mode}' mode. Generated {len(rules)} simulated rules.")

        status = FirewallStatus(
            bridge_name=bridge_name,
            sniffer_interface=sniffer_iface,
            guest_ip=guest_ip,
            host_ip=host_ip,
            subnet_cidr=subnet_cidr,
            policy="SANDBOX_MONITORED",
            wan_isolation=block_wan,
            packet_mirroring=mirror_sniffer,
            mode=mode,
            is_active=True,
            rules=rules,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        self._save_state(status)
        self.export_shell_script(self.script_file)
        return status

    def evaluate_packet(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str = "tcp",
        dest_port: Optional[int] = None,
        in_interface: str = "fs-br0",
        out_interface: Optional[str] = None,
    ) -> PacketEvaluation:
        """Simulates software evaluation of an incoming/outgoing packet against active sandbox rules."""
        status = self.get_status()
        if not status or not status.is_active:
            return PacketEvaluation(
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                dest_port=dest_port,
                in_interface=in_interface,
                out_interface=out_interface,
                verdict="ACCEPT",
                reason="No active firewall rules in workspace (Permissive default)",
            )

        bridge = status.bridge_name
        sniffer = status.sniffer_interface
        subnet = ipaddress.ip_network(status.subnet_cidr)
        src_addr = ipaddress.ip_address(source_ip)
        dst_addr = ipaddress.ip_address(dest_ip)

        # Sniffer mirroring check: packets passing through the sandbox bridge are mirrored
        is_mirrored = False
        if status.packet_mirroring and (in_interface == bridge or out_interface == bridge):
            is_mirrored = True

        # Check WAN egress isolation: guest inside sandbox trying to contact external WAN
        if status.wan_isolation:
            # Egress attempt from sandbox to non-bridge interface
            if in_interface == bridge and out_interface and out_interface != bridge:
                return PacketEvaluation(
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    protocol=protocol,
                    dest_port=dest_port,
                    in_interface=in_interface,
                    out_interface=out_interface,
                    verdict="DROP",
                    matched_rule="WAN Isolation: Drop outbound forwarding from sandbox bridge to external networks",
                    mirrored_to_sniffer=is_mirrored,
                    sniffer_interface=sniffer if is_mirrored else None,
                    reason="Blocked: Guest outbound WAN packet dropped by sandbox firewall",
                )

            # Egress attempt destined outside the sandbox subnet CIDR
            if src_addr in subnet and dst_addr not in subnet:
                return PacketEvaluation(
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    protocol=protocol,
                    dest_port=dest_port,
                    in_interface=in_interface,
                    out_interface=out_interface,
                    verdict="DROP",
                    matched_rule="WAN Isolation: Prevent guest IP leakages to outside subnets",
                    mirrored_to_sniffer=is_mirrored,
                    sniffer_interface=sniffer if is_mirrored else None,
                    reason=f"Blocked: Subnet leakage attempt to external IP {dest_ip}",
                )

            # External unsolicited ingress to sandbox bridge
            if in_interface != bridge and out_interface == bridge:
                return PacketEvaluation(
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    protocol=protocol,
                    dest_port=dest_port,
                    in_interface=in_interface,
                    out_interface=out_interface,
                    verdict="DROP",
                    matched_rule="Ingress Protection: Drop external unauthorized traffic to sandbox bridge",
                    mirrored_to_sniffer=is_mirrored,
                    sniffer_interface=sniffer if is_mirrored else None,
                    reason="Blocked: Unsolicited WAN ingress into sandbox",
                )

        # Host-to-guest allowed channel
        if source_ip == status.host_ip and dest_ip == status.guest_ip:
            if protocol.lower() == "icmp":
                return PacketEvaluation(
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    protocol=protocol,
                    dest_port=dest_port,
                    in_interface=in_interface,
                    out_interface=out_interface,
                    verdict="ACCEPT",
                    matched_rule="Allow ICMP health check pings between sandbox host and guest",
                    mirrored_to_sniffer=is_mirrored,
                    sniffer_interface=sniffer if is_mirrored else None,
                    reason="Permitted: Host-to-guest diagnostic ICMP ping",
                )

            # Check allowed port rules
            for rule in status.rules:
                if (
                    rule.action == "ACCEPT"
                    and rule.protocol.lower() == protocol.lower()
                    and rule.dport == dest_port
                ):
                    return PacketEvaluation(
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        protocol=protocol,
                        dest_port=dest_port,
                        in_interface=in_interface,
                        out_interface=out_interface,
                        verdict="ACCEPT",
                        matched_rule=rule.comment,
                        mirrored_to_sniffer=is_mirrored,
                        sniffer_interface=sniffer if is_mirrored else None,
                        reason=f"Permitted: Host management access to port {dest_port}",
                    )

        # Established/Related return responses from guest to host
        if source_ip == status.guest_ip and dest_ip == status.host_ip:
            return PacketEvaluation(
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                dest_port=dest_port,
                in_interface=in_interface,
                out_interface=out_interface,
                verdict="ACCEPT",
                matched_rule="Allow established and related sandbox connections",
                mirrored_to_sniffer=is_mirrored,
                sniffer_interface=sniffer if is_mirrored else None,
                reason="Permitted: Guest return traffic to host sandbox interface",
            )

        # Default fallback: DROP unauthorized intra-bridge or unclassified traffic
        return PacketEvaluation(
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            dest_port=dest_port,
            in_interface=in_interface,
            out_interface=out_interface,
            verdict="DROP",
            matched_rule="Default Sandbox Rule: Drop any unauthorized sandbox bridge traffic",
            mirrored_to_sniffer=is_mirrored,
            sniffer_interface=sniffer if is_mirrored else None,
            reason="Blocked: Unauthorized traffic pattern caught by default drop policy",
        )

    def flush_rules(self, force_shim: bool = False) -> bool:
        """Flushes active sandbox rules and purges state cache."""
        status = self.get_status()
        can_use_kernel = self.is_privileged_linux() and not force_shim

        if can_use_kernel and status:
            logger.info("Flushing kernel iptables sandbox rules...")
            # Flushes can be targeted or command-based
            for rule in status.rules:
                # Replace -A with -D to safely remove the rule
                cmd = rule.to_iptables_command().replace("-A", "-D").split()
                try:
                    subprocess.run(cmd, capture_output=True)
                except Exception:
                    pass

        if self.state_file.exists():
            try:
                self.state_file.unlink()
            except OSError:
                pass

        return True

    def export_shell_script(self, output_path: Optional[Union[str, Path]] = None) -> Path:
        """Generates a standalone, executable bash deployment script for system administrators."""
        target_path = Path(output_path) if output_path else self.script_file
        target_path.parent.mkdir(parents=True, exist_ok=True)

        status = self.get_status()
        rules = status.rules if status else self.build_sandbox_rules()

        lines = [
            "#!/usr/bin/env bash",
            "# ============================================================================",
            "# FirmSight Sandbox Security Firewall Script (Track 1 - Systems & Emulation)",
            "# Generated automatically by FirmSight FirewallManager",
            f"# Timestamp: {datetime.now(timezone.utc).isoformat()}",
            "# ============================================================================",
            "set -euo pipefail",
            "",
            "if [ \"$(id -u)\" -ne 0 ]; then",
            "    echo \"[-] Error: This script must be run as root (or with sudo).\" >&2",
            "    exit 1",
            "fi",
            "",
            "echo \"[*] Configuring FirmSight Sandbox Firewall Rules...\"",
            "",
        ]

        for rule in rules:
            if rule.comment:
                lines.append(f"# {rule.comment}")
            lines.append(f"{rule.to_iptables_command()}")
            lines.append("")

        lines.extend([
            "echo \"[+] FirmSight sandbox firewall rules successfully applied.\"",
            "echo \"[+] Sniffer mirroring active for Track 3 capture engine.\"",
            "echo \"[+] WAN egress isolation active.\"",
        ])

        target_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            target_path.chmod(0o755)
        except OSError:
            pass

        return target_path

    def get_status(self) -> Optional[FirewallStatus]:
        """Loads and parses cached firewall state from disk."""
        if not self.state_file.exists():
            return None
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return FirewallStatus.from_dict(data)
        except (json.JSONDecodeError, KeyError, OSError) as exc:
            logger.warning(f"Failed to read firewall state file: {exc}")
            return None

    def _save_state(self, status: FirewallStatus) -> None:
        """Persists firewall state to disk."""
        try:
            self.state_file.write_text(json.dumps(status.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning(f"Could not persist firewall state: {exc}")


# Alias for explicit SOP terminology
IPTablesManager = FirewallManager
