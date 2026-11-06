"""Unit tests for Emulation Health Monitor and Crash Diagnostics."""

import unittest

from firmsight.emulator.chroot_runner import ChrootExecutionResult
from firmsight.emulator.health_monitor import HealthMonitor


class TestHealthMonitor(unittest.TestCase):
    """Test suite for process health diagnostics and crash analysis."""

    def test_diagnose_healthy_exit(self):
        """Verify normal exit 0 is diagnosed as HEALTHY."""
        res = ChrootExecutionResult(
            command=["test_cmd"],
            exit_code=0,
            stdout="Service started successfully\n",
            stderr="",
            duration_seconds=0.5,
        )
        report = HealthMonitor.diagnose(res, "usr/sbin/httpd")
        self.assertEqual(report.status, "HEALTHY")
        self.assertEqual(len(report.issues), 0)
        self.assertIn("cleanly", report.recommendations[0])

    def test_diagnose_timeout_daemon(self):
        """Verify timed out process is recognized as long-running daemon."""
        res = ChrootExecutionResult(
            command=["httpd"],
            exit_code=-1,
            stdout="Listening on port 80...\n",
            stderr="",
            duration_seconds=5.0,
            timed_out=True,
        )
        report = HealthMonitor.diagnose(res, "usr/sbin/httpd")
        self.assertEqual(report.status, "TIMED_OUT")
        self.assertTrue(any("normal expected behavior" in r for r in report.recommendations))

    def test_diagnose_sigsegv_crash(self):
        """Verify exit code 139 is correctly diagnosed as SIGSEGV crash."""
        res = ChrootExecutionResult(
            command=["httpd"],
            exit_code=139,
            stdout="",
            stderr="Segmentation fault (core dumped)\n",
            duration_seconds=0.1,
        )
        report = HealthMonitor.diagnose(res, "usr/sbin/httpd")
        self.assertEqual(report.status, "CRASHED")
        self.assertEqual(report.signal_name, "SIGSEGV")
        self.assertTrue(any("Radare2" in issue.remediation for issue in report.issues))

    def test_diagnose_missing_library(self):
        """Verify missing shared libraries are extracted and reported."""
        res = ChrootExecutionResult(
            command=["httpd"],
            exit_code=127,
            stdout="",
            stderr="httpd: error while loading shared libraries: libnvram.so: cannot open shared object file: No such file or directory\n",
            duration_seconds=0.05,
        )
        report = HealthMonitor.diagnose(res, "usr/sbin/httpd")
        self.assertEqual(report.status, "DEPENDENCY_MISSING")
        self.assertIn("libnvram.so", report.missing_libraries)
        self.assertTrue(any("libnvram.so" in i.description for i in report.issues))

    def test_diagnose_exec_format_error(self):
        """Verify Exec format error diagnoses foreign CPU mismatch."""
        res = ChrootExecutionResult(
            command=["httpd"],
            exit_code=126,
            stdout="",
            stderr="exec: /usr/sbin/httpd: Exec format error\n",
            duration_seconds=0.01,
        )
        report = HealthMonitor.diagnose(res, "usr/sbin/httpd")
        self.assertEqual(report.status, "DEGRADED")
        self.assertTrue(any("qemu-user-static" in issue.remediation for issue in report.issues))


if __name__ == "__main__":
    unittest.main()
