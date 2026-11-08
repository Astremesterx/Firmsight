"""Unit tests for Virtual Network Bridge and TAP Interface Manager."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.emulator.network_bridge import (
    BridgeStatus,
    NetworkBridgeManager,
    TAPConfig,
    generate_local_mac,
)


class TestNetworkBridge(unittest.TestCase):
    """Test suite for virtual TAP interface and network bridge provisioning."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_net_test_"))
        self.mgr = NetworkBridgeManager(workspace_dir=self.test_dir)

    def tearDown(self):
        self.mgr.teardown_bridge_network()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_generate_local_mac(self):
        """Verify generated MAC addresses are valid locally-administered unicast addresses."""
        mac1 = generate_local_mac()
        mac2 = generate_local_mac()

        self.assertNotEqual(mac1, mac2)
        octets = mac1.split(":")
        self.assertEqual(len(octets), 6)
        # Check locally-administered bit (second bit of first byte is 1 -> 0x02)
        self.assertEqual(octets[0], "02")

    def test_tap_config_serialization(self):
        """Verify TAPConfig dataclass to_dict and from_dict roundtrip."""
        tap = TAPConfig(name="test-tap1", bridge_name="test-br1")
        data = tap.to_dict()

        self.assertEqual(data["name"], "test-tap1")
        self.assertEqual(data["bridge_name"], "test-br1")
        self.assertEqual(data["mtu"], 1500)

        restored = TAPConfig.from_dict(data)
        self.assertEqual(restored.name, tap.name)
        self.assertEqual(restored.mac_address, tap.mac_address)
        self.assertEqual(restored.bridge_name, tap.bridge_name)

    def test_setup_bridge_network_shim(self):
        """Verify unprivileged / shim network provisioning creates state file and interface profiles."""
        status = self.mgr.setup_bridge_network(
            tap_name="test-tap0",
            bridge_name="test-br0",
            force_shim=True,
        )

        self.assertIsInstance(status, BridgeStatus)
        self.assertTrue(status.is_active)
        self.assertEqual(status.bridge_name, "test-br0")
        self.assertEqual(status.mode, "shim-unprivileged")
        self.assertEqual(len(status.tap_interfaces), 1)

        tap = status.tap_interfaces[0]
        self.assertEqual(tap.name, "test-tap0")
        self.assertEqual(tap.state, "SHIM")
        self.assertTrue(tap.is_shim)
        self.assertTrue(self.mgr.state_file.exists())

    def test_get_status(self):
        """Verify get_status retrieves persisted state accurately."""
        # Initial status is None
        self.assertIsNone(self.mgr.get_status())

        # After setup
        self.mgr.setup_bridge_network(tap_name="tap-demo", bridge_name="br-demo", force_shim=True)
        cached = self.mgr.get_status()

        self.assertIsNotNone(cached)
        self.assertTrue(cached.is_active)
        self.assertEqual(cached.bridge_name, "br-demo")
        self.assertEqual(cached.tap_interfaces[0].name, "tap-demo")

    def test_teardown_cleans_state_file(self):
        """Verify teardown removes the cached state file."""
        self.mgr.setup_bridge_network(force_shim=True)
        self.assertTrue(self.mgr.state_file.exists())

        res = self.mgr.teardown_bridge_network()
        self.assertTrue(res)
        self.assertFalse(self.mgr.state_file.exists())
        self.assertIsNone(self.mgr.get_status())

    def test_custom_interfaces(self):
        """Verify provisioning with custom interface parameters."""
        status = self.mgr.setup_bridge_network(
            tap_name="iot-tap99",
            bridge_name="iot-br99",
            force_shim=True,
        )

        self.assertEqual(status.bridge_name, "iot-br99")
        self.assertEqual(status.tap_interfaces[0].name, "iot-tap99")
        self.assertEqual(status.tap_interfaces[0].bridge_name, "iot-br99")


if __name__ == "__main__":
    unittest.main()
