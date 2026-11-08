"""Unit tests for Process Lifecycle Daemon Manager."""

from pathlib import Path
import shutil
import tempfile
import time
import unittest

from firmsight.emulator.daemon import DaemonManager, DaemonProcess, DaemonStatus


class TestDaemonManager(unittest.TestCase):
    """Test suite for supervising background emulator processes."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_daemon_test_"))
        self.rootfs = self.test_dir / "rootfs"
        self.rootfs.mkdir()

        # Dummy script that sleeps or loops
        self.bin_dir = self.rootfs / "usr" / "sbin"
        self.bin_dir.mkdir(parents=True)
        self.dummy = self.bin_dir / "loop_daemon"
        self.dummy.write_text("#!/bin/sh\nwhile true; do echo 'alive'; sleep 1; done\n", encoding="utf-8")

        self.mgr = DaemonManager(workspace_dir=self.test_dir / "workspace")

    def tearDown(self):
        # Stop any left over processes
        for d in self.mgr.list_active():
            self.mgr.stop(d.name)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_spawn_and_poll_daemon(self):
        """Verify spawning a daemon creates PID/log files and reports is_alive."""
        d_proc = self.mgr.spawn(self.rootfs, "usr/sbin/loop_daemon", name="test_loop")
        self.assertIsInstance(d_proc, DaemonProcess)
        self.assertEqual(d_proc.name, "test_loop")
        self.assertTrue(d_proc.pid_file.exists())
        self.assertTrue(d_proc.log_file.exists())

        # Poll status
        status = self.mgr.poll("test_loop")
        self.assertIsNotNone(status)
        self.assertEqual(status.name, "test_loop")
        self.assertTrue(status.is_alive)
        self.assertGreaterEqual(status.uptime_seconds, 0.0)

        # Stop daemon
        stopped = self.mgr.stop("test_loop")
        self.assertTrue(stopped)
        self.assertFalse(d_proc.pid_file.exists())

    def test_spawn_already_running_raises(self):
        """Verify attempting to spawn an already running daemon raises RuntimeError."""
        self.mgr.spawn(self.rootfs, "usr/sbin/loop_daemon", name="dup_daemon")
        with self.assertRaises(RuntimeError):
            self.mgr.spawn(self.rootfs, "usr/sbin/loop_daemon", name="dup_daemon")

        self.mgr.stop("dup_daemon")

    def test_list_active_daemons(self):
        """Verify list_active enumerates all active daemons."""
        self.mgr.spawn(self.rootfs, "usr/sbin/loop_daemon", name="daemon_1")
        self.mgr.spawn(self.rootfs, "usr/sbin/loop_daemon", name="daemon_2")

        active = self.mgr.list_active()
        names = [d.name for d in active]
        self.assertIn("daemon_1", names)
        self.assertIn("daemon_2", names)

        self.mgr.stop("daemon_1")
        self.mgr.stop("daemon_2")


if __name__ == "__main__":
    unittest.main()
