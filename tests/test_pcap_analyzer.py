"""Unit tests for Track 3 PCAP Deep Packet Inspection and C2 Threat Heuristic Engine."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.pcap_bridge import PCAPBridge
from firmsight.network.pcap_analyzer import (
    PCAPAnalysisReport,
    PCAPAnalyzer,
    PacketRecord,
    SecurityThreatAlert,
)


class TestPCAPAnalyzer(unittest.TestCase):
    """Test suite for PCAP Forensic Analyzer and C2 Botnet Threat Engine."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_pcap_test_"))
        # Generate a valid binary PCAP file with synthesised flows and C2 beacon
        bridge = PCAPBridge(workspace_dir=self.test_dir)
        session = bridge.start_capture(force_shim=True)
        bridge.inject_traffic_flow(count=5, inject_c2=True)
        bridge.stop_capture()
        self.pcap_file = Path(session.pcap_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pcap_parsing_and_protocols(self):
        """Verify deep packet inspection on generated PCAP file."""
        analyzer = PCAPAnalyzer(self.pcap_file)
        report = analyzer.analyze()

        self.assertTrue(report.is_valid)
        self.assertGreaterEqual(report.total_packets, 5)
        self.assertGreater(report.total_bytes, 100)

        # Check protocol breakdown
        self.assertIn("HTTP", report.protocols_breakdown)
        self.assertIn("DNS", report.protocols_breakdown)
        self.assertIn("ICMP_ECHO", report.protocols_breakdown)

    def test_c2_threat_heuristic_detection(self):
        """Verify detection of Mirai/IoT botnet C2 heartbeat beacon."""
        analyzer = PCAPAnalyzer(self.pcap_file)
        report = analyzer.analyze()

        self.assertGreaterEqual(len(report.threat_alerts), 1)
        self.assertEqual(report.threat_level, "CRITICAL")
        self.assertGreaterEqual(report.threat_score, 40)

        threat_names = [a.threat_name for a in report.threat_alerts]
        self.assertTrue(any("Botnet" in name or "C2" in name for name in threat_names))

        r_dict = report.to_dict()
        self.assertEqual(r_dict["threat_level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
