"""Unit tests for Track 3 Terminal User Interface Dashboard."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.tui.app import (
    FirmSightTUI,
    launch_tui,
)


class TestFirmSightTUI(unittest.TestCase):
    """Test suite for Terminal User Interface dashboard."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_tui_test_"))
        self.tui = FirmSightTUI(workspace_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dashboard_state_harvesting(self):
        """Verify harvesting telemetry from sandbox files."""
        state = self.tui.get_dashboard_state()

        self.assertIn("target", state)
        self.assertIn("architecture", state)
        self.assertIn("verdict", state)
        self.assertIn("rootfs_tree", state)
        self.assertIn("dynamic_hooks", state)

    def test_dashboard_snapshot_render(self):
        """Verify generating ANSI formatted dashboard snapshot string."""
        snapshot = self.tui.render_snapshot()

        self.assertIn("FIRMSIGHT", snapshot)
        self.assertIn("Extracted RootFS Tree", snapshot)
        self.assertIn("Dynamic Memory & API Hooks", snapshot)
        self.assertIn("Network PCAP Forensics", snapshot)


if __name__ == "__main__":
    unittest.main()
