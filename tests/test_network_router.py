"""Unit tests for Guest-to-Host Virtual IP Routing and Subnet Manager."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.network_router import (
    NetworkRouter,
    RouteRule,
    RoutingStatus,
    SubnetConfig,
)


class TestNetworkRouter(unittest.TestCase):
    """Test suite for subnet calculation, host IP binding, and guest-to-host virtual routing."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_router_test_"))
        self.router = NetworkRouter(workspace_dir=self.test_dir)

    def tearDown(self):
        self.router.teardown_guest_routing()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_calculate_subnet_default(self):
        """Verify default /24 subnet calculation yields correct CIDR, host IP, and broadcast."""
        sub = self.router.calculate_subnet("192.168.1.1", "255.255.255.0")

        self.assertEqual(sub.cidr, "192.168.1.0/24")
        self.assertEqual(sub.gateway_ip, "192.168.1.1")
        self.assertEqual(sub.host_ip, "192.168.1.254")
        self.assertEqual(sub.broadcast_ip, "192.168.1.255")
        self.assertEqual(sub.netmask, "255.255.255.0")

    def test_calculate_subnet_class_b(self):
        """Verify custom Class B /16 subnet calculation."""
        sub = self.router.calculate_subnet("10.0.0.1", "255.255.0.0")

        self.assertEqual(sub.cidr, "10.0.0.0/16")
        self.assertEqual(sub.gateway_ip, "10.0.0.1")
        self.assertEqual(sub.host_ip, "10.0.255.254")
        self.assertEqual(sub.broadcast_ip, "10.0.255.255")

    def test_derive_from_nvram(self):
        """Verify deriving subnet profile from extracted NVRAM parameters."""
        nvram = {
            "lan_ipaddr": "192.168.50.1",
            "lan_netmask": "255.255.255.0",
        }
        sub = self.router.derive_from_nvram(nvram)

        self.assertEqual(sub.cidr, "192.168.50.0/24")
        self.assertEqual(sub.gateway_ip, "192.168.50.1")
        self.assertEqual(sub.host_ip, "192.168.50.254")

    def test_setup_guest_routing_shim(self):
        """Verify unprivileged / shim routing setup creates route rules and state cache."""
        sub = self.router.calculate_subnet("192.168.1.1")
        status = self.router.setup_guest_routing(
            bridge_name="fs-br0",
            subnet=sub,
            force_shim=True,
        )

        self.assertIsInstance(status, RoutingStatus)
        self.assertTrue(status.is_active)
        self.assertEqual(status.bridge_name, "fs-br0")
        self.assertEqual(status.mode, "shim-unprivileged")
        self.assertGreaterEqual(len(status.routes), 2)

        # Check route to subnet
        subnet_route = next((r for r in status.routes if r.destination == "192.168.1.0/24"), None)
        self.assertIsNotNone(subnet_route)
        self.assertEqual(subnet_route.interface, "fs-br0")

        # Check route to guest gateway
        gw_route = next((r for r in status.routes if r.destination == "192.168.1.1/32"), None)
        self.assertIsNotNone(gw_route)

        self.assertTrue(self.router.state_file.exists())

    def test_get_routing_status(self):
        """Verify get_routing_status returns cached telemetry accurately."""
        self.assertIsNone(self.router.get_routing_status())

        self.router.setup_guest_routing(force_shim=True)
        cached = self.router.get_routing_status()

        self.assertIsNotNone(cached)
        self.assertTrue(cached.is_active)
        self.assertEqual(cached.subnet.gateway_ip, "192.168.1.1")

    def test_teardown_guest_routing(self):
        """Verify teardown deletes state cache cleanly."""
        self.router.setup_guest_routing(force_shim=True)
        self.assertTrue(self.router.state_file.exists())

        res = self.router.teardown_guest_routing()
        self.assertTrue(res)
        self.assertFalse(self.router.state_file.exists())
        self.assertIsNone(self.router.get_routing_status())

    def test_route_rule_and_status_serialization(self):
        """Verify RouteRule and RoutingStatus serialization roundtrip."""
        rule = RouteRule(destination="192.168.1.0/24", gateway="0.0.0.0", interface="br0")
        rule_dict = rule.to_dict()
        restored_rule = RouteRule.from_dict(rule_dict)
        self.assertEqual(restored_rule.destination, rule.destination)

        sub = SubnetConfig(cidr="192.168.1.0/24", gateway_ip="192.168.1.1", host_ip="192.168.1.254")
        status = RoutingStatus(bridge_name="br0", subnet=sub, routes=[rule], is_active=True)
        status_dict = status.to_dict()
        restored_status = RoutingStatus.from_dict(status_dict)

        self.assertEqual(restored_status.bridge_name, "br0")
        self.assertEqual(restored_status.subnet.cidr, "192.168.1.0/24")
        self.assertEqual(len(restored_status.routes), 1)


if __name__ == "__main__":
    unittest.main()
