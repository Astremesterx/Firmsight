"""Unit tests for Sandbox Teardown & Resource Cleanup Engine."""

import json
from pathlib import Path
import shutil
import socket
import tempfile
import unittest

from firmsight.emulator.cleanup import (
    CleanupItem,
    CleanupReport,
    SandboxCleanupManager,
)
from firmsight.emulator.daemon import DaemonManager
from firmsight.emulator.firewall import FirewallManager
from firmsight.emulator.network_bridge import NetworkBridgeManager
from firmsight.emulator.network_router import NetworkRouter
from firmsight.emulator.orchestrator import MasterOrchestrator, OrchestrationConfig
from firmsight.emulator.pcap_bridge import PCAPBridge
from firmsight.emulator.port_forward import PortForwarder


def _get_free_port() -> int:
    """Finds an unused ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestSandboxCleanup(unittest.TestCase):
    """Test suite for SandboxCleanupManager and resource reclamation."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_clean_test_"))
        self.cleaner = SandboxCleanupManager(workspace_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cleanup_item_and_report_dataclasses(self):
        item = CleanupItem(
            category="PROXIES",
            resource_id="port_forward_workers",
            status="SUCCESS",
            details="Released 2 proxies",
        )
        self.assertEqual(item.category, "PROXIES")
        self.assertEqual(item.status, "SUCCESS")
        item_dict = item.to_dict()
        self.assertEqual(item_dict["category"], "PROXIES")

        report = CleanupReport(
            total_cleaned=1,
            total_failed=0,
            total_skipped=1,
            duration_seconds=0.15,
            items=[item],
            timestamp="2026-10-27T12:00:00Z",
        )
        self.assertIn("1 released", report.summary())
        self.assertEqual(report.total_cleaned, 1)

        md = report.export_markdown()
        self.assertIn("# 🧹 FirmSight Sandbox Teardown & Cleanup Report", md)
        self.assertIn("Released 2 proxies", md)
        self.assertIn("✅ SUCCESS", md)

    def test_teardown_port_forwards(self):
        pf_mgr = PortForwarder(workspace_dir=self.test_dir)
        port = _get_free_port()
        pf_mgr.add_forward(host_port=port, guest_port=80, force_shim=True)
        self.assertTrue(len(pf_mgr.list_forwards()) > 0)

        items = self.cleaner.teardown_port_forwards()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].category, "PROXIES")
        self.assertEqual(items[0].status, "SUCCESS")
        self.assertEqual(len(pf_mgr.list_forwards()), 0)

    def test_teardown_processes(self):
        # Register a mock PID file in DaemonManager
        d_mgr = DaemonManager(workspace_dir=self.test_dir)
        d_mgr.pid_dir.mkdir(parents=True, exist_ok=True)
        mock_pid_file = d_mgr.pid_dir / "test_httpd.pid"
        mock_pid_file.write_text(
            json.dumps({"name": "test_httpd", "pid": 999999, "start_time": 0}),
            encoding="utf-8",
        )

        items = self.cleaner.teardown_processes(pids=[999998])
        categories = [i.category for i in items]
        self.assertIn("PROCESSES", categories)
        # Verify the mock pid file was cleaned
        self.assertFalse(mock_pid_file.exists())

    def test_teardown_network(self):
        # Provision simulated bridge, router, and capture
        br_mgr = NetworkBridgeManager(workspace_dir=self.test_dir)
        br_mgr.setup_bridge_network(force_shim=True)

        router = NetworkRouter(workspace_dir=self.test_dir)
        router.setup_guest_routing(force_shim=True)

        pcap = PCAPBridge(workspace_dir=self.test_dir)
        pcap.start_capture(force_shim=True)

        # Run network teardown
        items = self.cleaner.teardown_network()
        self.assertEqual(len(items), 3)
        for item in items:
            self.assertEqual(item.category, "NETWORK")
            self.assertIn(item.status, ("SUCCESS", "SKIPPED"))

        # Verify active capture session was stopped
        self.assertIsNone(pcap.get_active_session())

    def test_teardown_firewall(self):
        fw_mgr = FirewallManager(workspace_dir=self.test_dir)
        fw_mgr.apply_rules(force_shim=True)
        self.assertTrue(fw_mgr.state_file.exists())

        items = self.cleaner.teardown_firewall(force_shim=True)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].category, "FIREWALL")
        self.assertEqual(items[0].status, "SUCCESS")
        self.assertFalse(fw_mgr.state_file.exists())

    def test_teardown_mounts(self):
        items = self.cleaner.teardown_mounts(rootfs_dir=self.test_dir)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].category, "MOUNTS")
        self.assertIn(items[0].status, ("SUCCESS", "SKIPPED"))

    def test_clean_workspace(self):
        ws = self.test_dir / "sandbox_workspace"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "pids").mkdir(parents=True, exist_ok=True)
        (ws / "pids" / "stale.pid").write_text("{}", encoding="utf-8")
        (ws / "orchestration_last_run.json").write_text("{}", encoding="utf-8")
        (ws / "captures").mkdir(parents=True, exist_ok=True)
        (ws / "captures" / "old.pcap").write_bytes(b"dummy")

        items = self.cleaner.clean_workspace(purge_all=True)
        self.assertGreater(len(items), 0)
        self.assertFalse((ws / "pids" / "stale.pid").exists())
        self.assertFalse((ws / "orchestration_last_run.json").exists())
        self.assertFalse((ws / "captures" / "old.pcap").exists())

    def test_teardown_all_master_sequence(self):
        report = self.cleaner.teardown_all(purge_all=False, force_shim=True)
        self.assertIsInstance(report, CleanupReport)
        self.assertGreaterEqual(report.total_cleaned + report.total_skipped, 4)
        self.assertEqual(report.total_failed, 0)
        self.assertTrue(self.cleaner.cleanup_manifest.exists())

        saved = json.loads(self.cleaner.cleanup_manifest.read_text(encoding="utf-8"))
        self.assertIn("items", saved)
        self.assertEqual(saved["total_failed"], 0)

    def test_master_orchestrator_cleanup_integration(self):
        orchestrator = MasterOrchestrator(workspace_dir=self.test_dir)
        # MasterOrchestrator.cleanup() should invoke SandboxCleanupManager
        orchestrator.cleanup()
        manifest = self.test_dir / "sandbox_workspace" / "cleanup_last_run.json"
        self.assertTrue(manifest.exists())


if __name__ == "__main__":
    unittest.main()
