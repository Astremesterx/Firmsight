"""Track 3 PCAP Packet Capture and Sniffer Integration Bridge.

Integrates the Track 1 emulation & virtual network sandbox with Track 3's
Network Interception, PCAP Sniffer & C2 Heuristics Engine (Poornima).

Capabilities:
- Manages live packet capture sessions on the dedicated sniffer tap (fs-sniff0) or bridge (fs-br0).
- Spawns background system capture processes (tcpdump/tshark) when privileged tools are available.
- Features a zero-dependency, pure-Python binary PCAP synthesizer (PCAP v2.4 specification)
  for unprivileged CI/CD, Windows native, and simulated IoT traffic flows.
- Synthesizes realistic IoT traffic: DNS resolutions, HTTP administration traffic,
  ICMP ping health checks, and simulated suspicious C2 beacons for Track 3 heuristics.
- Exports structured session manifests (capture_manifest.json) enabling automated Track 3
  PCAP ingestion, live flow telemetry, and protocol statistics.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import subprocess
import time
from typing import Dict, List, Optional, Tuple, Union

from firmsight.core.config import get_logger

logger = get_logger("PCAPBridge")

# PCAP 2.4 Magic numbers & Link types
PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1


def compute_internet_checksum(data: bytes) -> int:
    """Computes standard Internet Checksum (RFC 1071) for IPv4/UDP/TCP/ICMP headers."""
    if len(data) % 2 != 0:
        data += b"\x00"
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass
class CaptureSessionInfo:
    """Telemetry report representing an active or completed PCAP packet capture session."""

    session_id: str
    interface: str = "fs-sniff0"
    bridge_name: str = "fs-br0"
    pcap_file: str = ""
    manifest_file: str = ""
    is_active: bool = False
    mode: str = "synthesizer-shim"         # 'system-tcpdump' or 'synthesizer-shim'
    packet_count: int = 0
    byte_count: int = 0
    filter_expr: Optional[str] = None
    protocols: Dict[str, int] = field(default_factory=dict)
    guest_ip: str = "192.168.1.1"
    host_ip: str = "192.168.1.254"
    pid: Optional[int] = None
    start_time: str = ""
    end_time: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "CaptureSessionInfo":
        return cls(**data)


class PCAPBridge:
    """Orchestrates network packet capture on virtual interfaces and bridges with Track 3."""

    _global_session: Optional[CaptureSessionInfo] = None

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None) -> None:
        if workspace_dir:
            self.workspace_dir = Path(workspace_dir)
        else:
            self.workspace_dir = Path(__file__).resolve().parent.parent.parent

        self.captures_dir = self.workspace_dir / "sandbox_workspace" / "captures"
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file = self.captures_dir / "capture_manifest.json"
        self._current_session: Optional[CaptureSessionInfo] = PCAPBridge._global_session
        self._tcpdump_proc: Optional[subprocess.Popen] = None

    def is_privileged_linux(self) -> bool:
        """Determines if host has root capabilities with tcpdump on Linux."""
        if platform.system() != "Linux":
            return False
        if not shutil.which("tcpdump"):
            return False
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def create_pcap_header(self, snaplen: int = 65535) -> bytes:
        """Generates standard 24-byte PCAP v2.4 Global Header (Microsecond, Ethernet)."""
        return struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_MICROSECONDS,  # magic_number (little endian)
            PCAP_VERSION_MAJOR,       # version_major (2)
            PCAP_VERSION_MINOR,       # version_minor (4)
            0,                        # thiszone (GMT to local correction)
            0,                        # sigfigs (accuracy of timestamps)
            snaplen,                  # snaplen (max packet length captured)
            LINKTYPE_ETHERNET,        # network (1 = LINKTYPE_ETHERNET)
        )

    def build_ethernet_frame(
        self,
        src_mac: str = "02:5a:3c:2f:2f:28",
        dst_mac: str = "02:fe:00:19:68:01",
        payload: bytes = b"",
    ) -> bytes:
        """Encapsulates payload inside a 14-byte IEEE 802.3 Ethernet frame."""
        src_bytes = bytes.fromhex(src_mac.replace(":", "").replace("-", ""))
        dst_bytes = bytes.fromhex(dst_mac.replace(":", "").replace("-", ""))
        ethertype = struct.pack("!H", 0x0800)  # IPv4
        return dst_bytes + src_bytes + ethertype + payload

    def build_ipv4_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        payload: bytes,
    ) -> bytes:
        """Builds standard 20-byte IPv4 packet header and appends protocol payload."""
        total_len = 20 + len(payload)
        version_ihl = 0x45
        dscp_ecn = 0x00
        ident = 0x1234
        flags_frag = 0x4000  # DF (Don't Fragment)
        ttl = 64
        checksum = 0

        header_pre = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            dscp_ecn,
            total_len,
            ident,
            flags_frag,
            ttl,
            protocol,
            checksum,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        checksum = compute_internet_checksum(header_pre)

        header_real = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            dscp_ecn,
            total_len,
            ident,
            flags_frag,
            ttl,
            protocol,
            checksum,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        return header_real + payload

    def build_udp_datagram(
        self,
        src_port: int,
        dst_port: int,
        payload: bytes,
    ) -> bytes:
        """Builds standard 8-byte UDP header with payload."""
        length = 8 + len(payload)
        checksum = 0
        header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
        return header + payload

    def build_tcp_segment(
        self,
        src_port: int,
        dst_port: int,
        payload: bytes = b"",
        flags: int = 0x18,  # ACK + PSH
        seq: int = 1000,
        ack: int = 1,
    ) -> bytes:
        """Builds standard 20-byte TCP header with payload."""
        data_offset_res = (5 << 4)  # 5 32-bit words (20 bytes)
        window = 64240
        checksum = 0
        urg_ptr = 0

        header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            data_offset_res,
            flags,
            window,
            checksum,
            urg_ptr,
        )
        return header + payload

    def build_icmp_echo(
        self,
        icmp_type: int = 8,  # 8 = Echo Request, 0 = Echo Reply
        code: int = 0,
        ident: int = 0x1122,
        seq: int = 1,
        payload: bytes = b"FirmSight-Health-Ping",
    ) -> bytes:
        """Builds standard ICMP Echo Request/Reply packet."""
        checksum = 0
        header_pre = struct.pack("!BBHHH", icmp_type, code, checksum, ident, seq) + payload
        checksum = compute_internet_checksum(header_pre)
        header_real = struct.pack("!BBHHH", icmp_type, code, checksum, ident, seq)
        return header_real + payload

    def wrap_pcap_record(self, raw_frame: bytes, timestamp_float: Optional[float] = None) -> bytes:
        """Encloses raw layer-2 Ethernet frame within a 16-byte PCAP packet record."""
        t = timestamp_float if timestamp_float is not None else time.time()
        ts_sec = int(t)
        ts_usec = int((t - ts_sec) * 1_000_000)
        incl_len = len(raw_frame)
        orig_len = len(raw_frame)

        record_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        return record_header + raw_frame

    def start_capture(
        self,
        interface: str = "fs-sniff0",
        bridge_name: str = "fs-br0",
        output_pcap: Optional[Union[str, Path]] = None,
        filter_expr: Optional[str] = None,
        guest_ip: str = "192.168.1.1",
        host_ip: str = "192.168.1.254",
        force_shim: bool = False,
    ) -> CaptureSessionInfo:
        """Initializes a packet capture session and registers it for Track 3."""
        if not output_pcap:
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            pcap_path = self.captures_dir / f"firmware_emulation_{timestamp_str}.pcap"
        else:
            pcap_path = Path(output_pcap)
            pcap_path.parent.mkdir(parents=True, exist_ok=True)

        session_id = f"cap-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        can_use_system = self.is_privileged_linux() and not force_shim
        mode = "system-tcpdump" if can_use_system else "synthesizer-shim"

        pid: Optional[int] = None
        if can_use_system:
            logger.info(f"Spawning native tcpdump capture on '{interface}' -> {pcap_path.name}")
            cmd = ["tcpdump", "-i", interface, "-w", str(pcap_path), "-U", "-s", "65535"]
            if filter_expr:
                cmd.extend(filter_expr.split())
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                pid = proc.pid
                self._tcpdump_proc = proc
            except Exception as exc:
                logger.warning(f"Failed to spawn tcpdump: {exc}. Falling back to synthesizer-shim.")
                mode = "synthesizer-shim"

        if mode == "synthesizer-shim":
            # Initialize binary PCAP with 24-byte global header
            pcap_path.write_bytes(self.create_pcap_header())

        session = CaptureSessionInfo(
            session_id=session_id,
            interface=interface,
            bridge_name=bridge_name,
            pcap_file=str(pcap_path.resolve()),
            manifest_file=str(self.manifest_file.resolve()),
            is_active=True,
            mode=mode,
            packet_count=0,
            byte_count=24 if mode == "synthesizer-shim" else 0,
            filter_expr=filter_expr,
            protocols={},
            guest_ip=guest_ip,
            host_ip=host_ip,
            pid=pid,
            start_time=datetime.now(timezone.utc).isoformat(),
        )

        self._current_session = session
        PCAPBridge._global_session = session
        self._save_manifest(session)
        return session

    def inject_packet(
        self,
        packet_type: str = "http_request",
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: int = 54321,
        dst_port: int = 80,
        custom_payload: Optional[bytes] = None,
    ) -> bool:
        """Injects a synthetically generated protocol frame into the active PCAP file."""
        session = self.get_active_session()
        if not session or not session.is_active:
            logger.warning("No active capture session to inject packet into.")
            return False

        pcap_file = Path(session.pcap_file)
        if not pcap_file.exists():
            pcap_file.write_bytes(self.create_pcap_header())

        src_ip = src_ip or session.host_ip
        dst_ip = dst_ip or session.guest_ip
        proto_tag = "tcp"

        if packet_type == "http_request":
            proto_tag = "http"
            http_body = custom_payload or b"GET / HTTP/1.1\r\nHost: 192.168.1.1\r\nUser-Agent: FirmSight-Sandbox/1.0\r\nAccept: */*\r\n\r\n"
            tcp_seg = self.build_tcp_segment(src_port=src_port, dst_port=dst_port, payload=http_body)
            ip_pkt = self.build_ipv4_packet(src_ip=src_ip, dst_ip=dst_ip, protocol=6, payload=tcp_seg)
            frame = self.build_ethernet_frame(payload=ip_pkt)

        elif packet_type == "http_response":
            proto_tag = "http"
            http_resp = custom_payload or b"HTTP/1.1 200 OK\r\nServer: Boa/0.94.14rc21\r\nContent-Type: text/html\r\nContent-Length: 42\r\n\r\n<html><body>FirmSight Ready</body></html>"
            tcp_seg = self.build_tcp_segment(src_port=dst_port, dst_port=src_port, payload=http_resp)
            ip_pkt = self.build_ipv4_packet(src_ip=dst_ip, dst_ip=src_ip, protocol=6, payload=tcp_seg)
            frame = self.build_ethernet_frame(payload=ip_pkt)

        elif packet_type == "dns_query":
            proto_tag = "dns"
            # Standard DNS query for pool.ntp.org (UDP 53)
            dns_payload = custom_payload or (
                b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x04pool\x03ntp\x03org\x00\x00\x01\x00\x01"
            )
            udp_datagram = self.build_udp_datagram(src_port=src_port, dst_port=53, payload=dns_payload)
            ip_pkt = self.build_ipv4_packet(src_ip=src_ip, dst_ip="8.8.8.8", protocol=17, payload=udp_datagram)
            frame = self.build_ethernet_frame(payload=ip_pkt)

        elif packet_type == "icmp_ping":
            proto_tag = "icmp"
            icmp_body = self.build_icmp_echo(icmp_type=8, payload=custom_payload or b"FirmSight-Probe")
            ip_pkt = self.build_ipv4_packet(src_ip=src_ip, dst_ip=dst_ip, protocol=1, payload=icmp_body)
            frame = self.build_ethernet_frame(payload=ip_pkt)

        elif packet_type == "c2_beacon":
            proto_tag = "c2_beacon"
            # Suspicious C2 beacon string simulating Mirai/IoT malware check-in
            beacon_data = custom_payload or (
                b"POST /api/v1/beacon HTTP/1.1\r\nHost: 198.51.100.42:4444\r\n"
                b"X-Bot-ID: 746f6f6c\r\nContent-Type: application/octet-stream\r\n\r\n"
                b"MIRAI_HEARTBEAT_ARM32_ONLINE\n"
            )
            tcp_seg = self.build_tcp_segment(src_port=src_port, dst_port=4444, payload=beacon_data)
            ip_pkt = self.build_ipv4_packet(src_ip=session.guest_ip, dst_ip="198.51.100.42", protocol=6, payload=tcp_seg)
            frame = self.build_ethernet_frame(payload=ip_pkt)

        else:
            # Generic TCP frame
            payload = custom_payload or b"GENERIC_DATA\n"
            tcp_seg = self.build_tcp_segment(src_port=src_port, dst_port=dst_port, payload=payload)
            ip_pkt = self.build_ipv4_packet(src_ip=src_ip, dst_ip=dst_ip, protocol=6, payload=tcp_seg)
            frame = self.build_ethernet_frame(payload=ip_pkt)

        record_bytes = self.wrap_pcap_record(frame)

        with open(pcap_file, "ab") as f:
            f.write(record_bytes)

        session.packet_count += 1
        session.byte_count += len(record_bytes)
        session.protocols[proto_tag] = session.protocols.get(proto_tag, 0) + 1
        self._save_manifest(session)
        return True

    def inject_traffic_flow(
        self,
        flow_type: str = "iot_baseline",
        count: int = 5,
        inject_c2: bool = False,
    ) -> int:
        """Injects a full realistic sequence of IoT network traffic packets."""
        session = self.get_active_session()
        if not session or not session.is_active:
            self.start_capture()
            session = self.get_active_session()

        injected = 0

        # Baseline: ICMP ping probe
        self.inject_packet("icmp_ping")
        injected += 1

        # Baseline: Router DNS time sync lookup
        self.inject_packet("dns_query", src_ip=session.guest_ip)
        injected += 1

        # Baseline: Web management GUI access
        self.inject_packet("http_request", src_ip=session.host_ip, dst_ip=session.guest_ip, dst_port=80)
        self.inject_packet("http_response", src_ip=session.guest_ip, dst_ip=session.host_ip, src_port=80)
        injected += 2

        # Additional queries up to count
        while injected < count:
            self.inject_packet("http_request", dst_port=8080)
            injected += 1

        # Optional simulated malicious C2 beacon for Track 3 heuristics detection
        if inject_c2:
            self.inject_packet("c2_beacon")
            injected += 1

        return injected

    def stop_capture(self, session_id: Optional[str] = None) -> Optional[CaptureSessionInfo]:
        """Finalizes active capture session, terminates processes, and locks manifest."""
        session = self.get_active_session()
        if not session:
            logger.info("No active capture session found to stop.")
            return None

        if self._tcpdump_proc:
            try:
                self._tcpdump_proc.terminate()
                self._tcpdump_proc.wait(timeout=2)
            except Exception:
                pass
            self._tcpdump_proc = None

        session.is_active = False
        session.end_time = datetime.now(timezone.utc).isoformat()
        if PCAPBridge._global_session:
            PCAPBridge._global_session.is_active = False

        # Update stats from disk if pcap file exists
        pcap_path = Path(session.pcap_file)
        if pcap_path.exists():
            headers = self.parse_pcap_headers(pcap_path)
            if headers["is_valid"]:
                session.packet_count = headers["packet_count"]
                session.byte_count = pcap_path.stat().st_size

        self._save_manifest(session)
        self._current_session = None
        PCAPBridge._global_session = None
        return session

    def stop_capture_session(self, session_id: Optional[str] = None) -> Optional[CaptureSessionInfo]:
        """Alias for stop_capture()."""
        return self.stop_capture(session_id=session_id)

    def parse_pcap_headers(self, pcap_path: Union[str, Path]) -> Dict:
        """Parses and validates standard binary PCAP headers and counts packet records."""
        path = Path(pcap_path)
        if not path.exists() or path.stat().st_size < 24:
            return {"is_valid": False, "packet_count": 0, "error": "File too small or nonexistent"}

        with open(path, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return {"is_valid": False, "packet_count": 0, "error": "Invalid global header"}

            magic, v_maj, v_min, tz, sigfigs, snaplen, linktype = struct.unpack("<IHHiIII", global_hdr)
            if magic != PCAP_MAGIC_MICROSECONDS:
                return {"is_valid": False, "packet_count": 0, "error": f"Invalid PCAP magic: 0x{magic:08x}"}

            pkt_count = 0
            total_payload = 0
            while True:
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", rec_hdr)
                f.seek(incl_len, 1)  # skip packet body
                pkt_count += 1
                total_payload += incl_len

        return {
            "is_valid": True,
            "magic": hex(magic),
            "version": f"{v_maj}.{v_min}",
            "snaplen": snaplen,
            "linktype": linktype,
            "packet_count": pkt_count,
            "file_size": path.stat().st_size,
        }

    def get_active_session(self) -> Optional[CaptureSessionInfo]:
        """Retrieves active capture session from memory or manifest cache."""
        if self.manifest_file.exists():
            try:
                data = json.loads(self.manifest_file.read_text(encoding="utf-8"))
                if not data.get("is_active", False):
                    if self._current_session:
                        self._current_session.is_active = False
                        self._current_session = None
                    if PCAPBridge._global_session:
                        PCAPBridge._global_session.is_active = False
                        PCAPBridge._global_session = None
                    return None
            except (json.JSONDecodeError, KeyError, OSError):
                pass

        if self._current_session and self._current_session.is_active:
            return self._current_session

        if PCAPBridge._global_session and PCAPBridge._global_session.is_active:
            self._current_session = PCAPBridge._global_session
            return self._current_session

        if self.manifest_file.exists():
            try:
                data = json.loads(self.manifest_file.read_text(encoding="utf-8"))
                if data.get("is_active", False):
                    session = CaptureSessionInfo.from_dict(data)
                    self._current_session = session
                    PCAPBridge._global_session = session
                    return session
            except (json.JSONDecodeError, KeyError, OSError):
                pass

        return None

    def export_track3_manifest(self) -> Dict:
        """Returns the contract dictionary required by Poornima's Track 3 PCAP analyzer."""
        session = self.get_active_session()
        if not session and self.manifest_file.exists():
            try:
                return json.loads(self.manifest_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return session.to_dict() if session else {}

    def _save_manifest(self, session: CaptureSessionInfo) -> None:
        """Persists session manifest to disk."""
        try:
            self.manifest_file.write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning(f"Could not persist capture manifest: {exc}")


# Alias for explicit SOP nomenclature
SnifferBridge = PCAPBridge
