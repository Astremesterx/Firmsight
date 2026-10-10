"""Unit tests for Track 3 PCAP Packet Capture and Sniffer Integration Bridge."""

from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from firmsight.emulator.pcap_bridge import (
    CaptureSessionInfo,
    PCAPBridge,
    SnifferBridge,
    compute_internet_checksum,
)


class TestPCAPBridge(unittest.TestCase):
    """Test suite for binary PCAP synthesis, packet capture sessions, and Track 3 integration."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_pcap_test_"))
        self.bridge = PCAPBridge(workspace_dir=self.test_dir)

    def tearDown(self):
        self.bridge.stop_capture()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_alias_equivalence(self):
        """Verify SnifferBridge is an alias for PCAPBridge."""
        self.assertIs(SnifferBridge, PCAPBridge)

    def test_pcap_global_header_structure(self):
        """Verify 24-byte PCAP v2.4 global header format and byte packing."""
        hdr = self.bridge.create_pcap_header(snaplen=65535)
        self.assertEqual(len(hdr), 24)

        magic, v_maj, v_min, tz, sigfigs, snaplen, linktype = struct.unpack("<IHHiIII", hdr)
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual(v_maj, 2)
        self.assertEqual(v_min, 4)
        self.assertEqual(snaplen, 65535)
        self.assertEqual(linktype, 1)  # Ethernet

    def test_checksum_computation(self):
        """Verify RFC 1071 internet checksum calculation."""
        # Known IPv4 test header
        test_bytes = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\xfe\xc0\xa8\x01\x01"
        chk = compute_internet_checksum(test_bytes)
        self.assertIsInstance(chk, int)
        self.assertGreater(chk, 0)
        self.assertLessEqual(chk, 0xFFFF)

    def test_frame_builders(self):
        """Verify Ethernet, IPv4, TCP, UDP, and ICMP frame generators."""
        eth = self.bridge.build_ethernet_frame(payload=b"HELLO")
        self.assertEqual(len(eth), 14 + 5)
        self.assertEqual(eth[12:14], b"\x08\x00")  # IPv4 EtherType

        udp = self.bridge.build_udp_datagram(src_port=1234, dst_port=53, payload=b"DNS")
        self.assertEqual(len(udp), 8 + 3)

        tcp = self.bridge.build_tcp_segment(src_port=54321, dst_port=80, payload=b"HTTP")
        self.assertEqual(len(tcp), 20 + 4)

        icmp = self.bridge.build_icmp_echo(icmp_type=8, payload=b"PING")
        self.assertEqual(len(icmp), 8 + 4)

        ip = self.bridge.build_ipv4_packet(src_ip="192.168.1.254", dst_ip="192.168.1.1", protocol=6, payload=tcp)
        self.assertEqual(len(ip), 20 + len(tcp))

    def test_start_capture_session(self):
        """Verify starting an unprivileged capture session creates PCAP file and manifest."""
        session = self.bridge.start_capture(
            interface="fs-sniff0",
            bridge_name="fs-br0",
            force_shim=True,
        )

        self.assertIsInstance(session, CaptureSessionInfo)
        self.assertTrue(session.is_active)
        self.assertEqual(session.mode, "synthesizer-shim")
        self.assertEqual(session.interface, "fs-sniff0")
        self.assertEqual(session.bridge_name, "fs-br0")

        # Check PCAP file created with global header
        pcap_path = Path(session.pcap_file)
        self.assertTrue(pcap_path.exists())
        self.assertEqual(pcap_path.stat().st_size, 24)

        # Check manifest written
        self.assertTrue(self.bridge.manifest_file.exists())
        manifest = self.bridge.export_track3_manifest()
        self.assertEqual(manifest["session_id"], session.session_id)
        self.assertTrue(manifest["is_active"])

    def test_inject_packets_and_parse(self):
        """Verify injecting different protocol frames and validating standard PCAP records."""
        session = self.bridge.start_capture(force_shim=True)

        # Inject various protocol frames
        self.bridge.inject_packet("http_request")
        self.bridge.inject_packet("http_response")
        self.bridge.inject_packet("dns_query")
        self.bridge.inject_packet("icmp_ping")
        self.bridge.inject_packet("c2_beacon")

        self.assertEqual(session.packet_count, 5)
        self.assertIn("http", session.protocols)
        self.assertIn("dns", session.protocols)
        self.assertIn("icmp", session.protocols)
        self.assertIn("c2_beacon", session.protocols)

        # Parse written PCAP headers directly
        parsed = self.bridge.parse_pcap_headers(session.pcap_file)
        self.assertTrue(parsed["is_valid"])
        self.assertEqual(parsed["packet_count"], 5)
        self.assertEqual(parsed["version"], "2.4")
        self.assertEqual(parsed["linktype"], 1)
        self.assertGreater(parsed["file_size"], 24)

    def test_inject_traffic_flow(self):
        """Verify synthesizing complete IoT baseline traffic and C2 beacon flows."""
        session = self.bridge.start_capture(force_shim=True)
        count = self.bridge.inject_traffic_flow(count=5, inject_c2=True)

        self.assertGreaterEqual(count, 5)
        self.assertEqual(session.packet_count, count)
        self.assertIn("c2_beacon", session.protocols)

        parsed = self.bridge.parse_pcap_headers(session.pcap_file)
        self.assertTrue(parsed["is_valid"])
        self.assertEqual(parsed["packet_count"], count)

    def test_stop_capture(self):
        """Verify stopping capture session updates manifest and marks session inactive."""
        session = self.bridge.start_capture(force_shim=True)
        self.bridge.inject_packet("http_request")

        stopped = self.bridge.stop_capture()
        self.assertIsNotNone(stopped)
        self.assertFalse(stopped.is_active)
        self.assertIsNotNone(stopped.end_time)
        self.assertEqual(stopped.packet_count, 1)

        # Session should no longer be active
        self.assertIsNone(self.bridge.get_active_session())

        # Manifest should reflect inactive status
        manifest = self.bridge.export_track3_manifest()
        self.assertFalse(manifest["is_active"])
        self.assertEqual(manifest["packet_count"], 1)

    def test_parse_corrupt_or_missing_pcap(self):
        """Verify error handling on non-existent or truncated files."""
        res_missing = self.bridge.parse_pcap_headers(self.test_dir / "nonexistent.pcap")
        self.assertFalse(res_missing["is_valid"])

        corrupt_file = self.test_dir / "corrupt.pcap"
        corrupt_file.write_bytes(b"\x00" * 24)
        res_corrupt = self.bridge.parse_pcap_headers(corrupt_file)
        self.assertFalse(res_corrupt["is_valid"])
        self.assertIn("Invalid PCAP magic", res_corrupt["error"])


if __name__ == "__main__":
    unittest.main()
