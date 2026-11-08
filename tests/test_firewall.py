"""Unit tests for IPTables Sandbox Firewall and Packet Mirroring Engine."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.firewall import (
    FirewallManager,
    FirewallRule,
    FirewallStatus,
    IPTablesManager,
    PacketEvaluation,
)


class TestFirewallManager(unittest.TestCase):
    """Test suite for sandbox firewall rules, WAN egress isolation, and sniffer mirroring."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_fw_test_"))
        self.fw_mgr = FirewallManager(workspace_dir=self.test_dir)

    def tearDown(self):
        self.fw_mgr.flush_rules()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_alias_equivalence(self):
        """Verify IPTablesManager is an alias for FirewallManager."""
        self.assertIs(IPTablesManager, FirewallManager)

    def test_firewall_rule_command_generation(self):
        """Verify FirewallRule correctly compiles into standard iptables shell commands."""
        # Standard drop rule
        rule1 = FirewallRule(
            table="filter",
            chain="FORWARD",
            in_interface="fs-br0",
            out_interface="! fs-br0",
            action="DROP",
            comment="WAN Isolation",
        )
        cmd1 = rule1.to_iptables_command()
        self.assertIn("iptables -A FORWARD -i fs-br0 ! -o fs-br0", cmd1)
        self.assertIn("-j DROP", cmd1)
        self.assertIn('WAN Isolation', cmd1)

        # Mangle TEE mirroring rule for Track 3 sniffer
        rule2 = FirewallRule(
            table="mangle",
            chain="PREROUTING",
            in_interface="fs-br0",
            action="TEE",
            target_options="--gateway 192.168.1.254",
            comment="Sniffer mirror",
        )
        cmd2 = rule2.to_iptables_command()
        self.assertIn("iptables -t mangle -A PREROUTING -i fs-br0", cmd2)
        self.assertIn("-j TEE --gateway 192.168.1.254", cmd2)

        # Port-specific TCP allow rule
        rule3 = FirewallRule(
            table="filter",
            chain="FORWARD",
            protocol="tcp",
            source="192.168.1.254",
            destination="192.168.1.1",
            dport=8080,
            action="ACCEPT",
        )
        cmd3 = rule3.to_iptables_command()
        self.assertIn("-p tcp -s 192.168.1.254 -d 192.168.1.1 --dport 8080 -j ACCEPT", cmd3)

    def test_build_sandbox_rules_structure(self):
        """Verify build_sandbox_rules produces the complete defense-in-depth ruleset."""
        rules = self.fw_mgr.build_sandbox_rules(
            bridge_name="fs-br0",
            sniffer_iface="fs-sniff0",
            guest_ip="192.168.1.1",
            host_ip="192.168.1.254",
            subnet_cidr="192.168.1.0/24",
            block_wan=True,
            mirror_sniffer=True,
            allowed_ports=[80, 8080],
        )

        # Must have sniffer TEE rules
        tee_rules = [r for r in rules if r.action == "TEE"]
        self.assertGreaterEqual(len(tee_rules), 2)
        self.assertEqual(tee_rules[0].table, "mangle")

        # Must have WAN isolation DROP rules
        wan_drops = [r for r in rules if r.action == "DROP" and "WAN Isolation" in r.comment]
        self.assertGreaterEqual(len(wan_drops), 2)

        # Must have HTTP management rules
        http_allows = [r for r in rules if r.action == "ACCEPT" and r.dport in (80, 8080)]
        self.assertEqual(len(http_allows), 2)

        # Must have connection tracking rule
        conntrack = [r for r in rules if r.state_match == "ESTABLISHED,RELATED"]
        self.assertEqual(len(conntrack), 1)

    def test_apply_rules_shim_mode(self):
        """Verify apply_rules initializes status, caches JSON state, and writes shell script."""
        status = self.fw_mgr.apply_rules(
            bridge_name="fs-br0",
            sniffer_iface="fs-sniff0",
            guest_ip="192.168.1.1",
            host_ip="192.168.1.254",
            subnet_cidr="192.168.1.0/24",
            force_shim=True,
        )

        self.assertIsInstance(status, FirewallStatus)
        self.assertTrue(status.is_active)
        self.assertEqual(status.mode, "shim-unprivileged")
        self.assertEqual(status.bridge_name, "fs-br0")
        self.assertEqual(status.sniffer_interface, "fs-sniff0")
        self.assertTrue(status.wan_isolation)
        self.assertTrue(status.packet_mirroring)
        self.assertGreater(len(status.rules), 5)

        # Check state file exists on disk
        self.assertTrue(self.fw_mgr.state_file.exists())
        self.assertTrue(self.fw_mgr.script_file.exists())

        # Check script content
        script_text = self.fw_mgr.script_file.read_text(encoding="utf-8")
        self.assertIn("#!/usr/bin/env bash", script_text)
        self.assertIn("iptables", script_text)
        self.assertIn("fs-br0", script_text)

    def test_get_status_persistence(self):
        """Verify get_status restores cached state correctly."""
        self.assertIsNone(self.fw_mgr.get_status())

        self.fw_mgr.apply_rules(force_shim=True)
        cached = self.fw_mgr.get_status()

        self.assertIsNotNone(cached)
        self.assertTrue(cached.is_active)
        self.assertEqual(cached.guest_ip, "192.168.1.1")
        self.assertEqual(cached.host_ip, "192.168.1.254")

    def test_evaluate_packet_allowed_host_to_guest(self):
        """Verify host management packets to allowed guest ports are accepted and mirrored."""
        self.fw_mgr.apply_rules(allowed_ports=[80, 8080], force_shim=True)

        res = self.fw_mgr.evaluate_packet(
            source_ip="192.168.1.254",
            dest_ip="192.168.1.1",
            dest_port=80,
            protocol="tcp",
            in_interface="fs-br0",
            out_interface="fs-br0",
        )

        self.assertEqual(res.verdict, "ACCEPT")
        self.assertTrue(res.mirrored_to_sniffer)
        self.assertEqual(res.sniffer_interface, "fs-sniff0")
        self.assertIn("Permitted", res.reason)

    def test_evaluate_packet_allowed_icmp(self):
        """Verify host ICMP ping checks to guest are accepted and mirrored."""
        self.fw_mgr.apply_rules(force_shim=True)

        res = self.fw_mgr.evaluate_packet(
            source_ip="192.168.1.254",
            dest_ip="192.168.1.1",
            protocol="icmp",
            in_interface="fs-br0",
            out_interface="fs-br0",
        )

        self.assertEqual(res.verdict, "ACCEPT")
        self.assertTrue(res.mirrored_to_sniffer)
        self.assertIn("ICMP", res.reason)

    def test_evaluate_packet_guest_return_traffic(self):
        """Verify guest return traffic to host is accepted and mirrored."""
        self.fw_mgr.apply_rules(force_shim=True)

        res = self.fw_mgr.evaluate_packet(
            source_ip="192.168.1.1",
            dest_ip="192.168.1.254",
            protocol="tcp",
            dest_port=54321,
            in_interface="fs-br0",
            out_interface="fs-br0",
        )

        self.assertEqual(res.verdict, "ACCEPT")
        self.assertTrue(res.mirrored_to_sniffer)
        self.assertIn("return traffic", res.reason)

    def test_evaluate_packet_blocked_wan_egress(self):
        """Verify rogue guest malware outbound traffic to public internet is strictly dropped."""
        self.fw_mgr.apply_rules(force_shim=True)

        # Emulated malware attempting to contact external C2 server (e.g. 198.51.100.42)
        res = self.fw_mgr.evaluate_packet(
            source_ip="192.168.1.1",
            dest_ip="198.51.100.42",
            dest_port=4444,
            protocol="tcp",
            in_interface="fs-br0",
            out_interface="eth0",
        )

        self.assertEqual(res.verdict, "DROP")
        self.assertTrue(res.mirrored_to_sniffer)  # Sniffer still captures the drop attempt!
        self.assertIn("Blocked", res.reason)

    def test_evaluate_packet_blocked_wan_leakage(self):
        """Verify subnet leakage outside 192.168.1.0/24 is dropped even on bridge."""
        self.fw_mgr.apply_rules(force_shim=True)

        res = self.fw_mgr.evaluate_packet(
            source_ip="192.168.1.1",
            dest_ip="8.8.8.8",
            dest_port=53,
            protocol="udp",
            in_interface="fs-br0",
            out_interface="fs-br0",
        )

        self.assertEqual(res.verdict, "DROP")
        self.assertTrue(res.mirrored_to_sniffer)
        self.assertIn("leakage", res.reason)

    def test_evaluate_packet_blocked_unsolicited_wan_ingress(self):
        """Verify unsolicited external incoming traffic into the sandbox bridge is dropped."""
        self.fw_mgr.apply_rules(force_shim=True)

        res = self.fw_mgr.evaluate_packet(
            source_ip="203.0.113.5",
            dest_ip="192.168.1.1",
            dest_port=80,
            protocol="tcp",
            in_interface="eth0",
            out_interface="fs-br0",
        )

        self.assertEqual(res.verdict, "DROP")
        self.assertIn("Blocked", res.reason)

    def test_flush_rules(self):
        """Verify flush_rules purges cached state file cleanly."""
        self.fw_mgr.apply_rules(force_shim=True)
        self.assertTrue(self.fw_mgr.state_file.exists())

        res = self.fw_mgr.flush_rules(force_shim=True)
        self.assertTrue(res)
        self.assertFalse(self.fw_mgr.state_file.exists())
        self.assertIsNone(self.fw_mgr.get_status())


if __name__ == "__main__":
    unittest.main()
