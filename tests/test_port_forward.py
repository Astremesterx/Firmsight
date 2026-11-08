"""Unit tests for Port Forwarding and External HTTP Trigger Harness."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import shutil
import socket
import tempfile
import threading
import unittest

from firmsight.emulator.port_forward import (
    HTTPProbeResult,
    HTTPTriggerHarness,
    PortForwardRule,
    PortForwardStatus,
    PortForwarder,
)


def _get_free_port() -> int:
    """Finds an unused ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _MockRouterHTTPHandler(BaseHTTPRequestHandler):
    """Minimal mock HTTP server simulating an IoT router web management daemon."""

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Boa/0.94.14rc21")
            self.end_headers()
            self.wfile.write(b"<html><head><title>FirmSight Router</title></head><body>Welcome</body></html>")
        elif self.path == "/cgi-bin/status.cgi":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "Boa/0.94.14rc21")
            self.end_headers()
            self.wfile.write(b'{"device": "arm_router", "uptime": 1234, "status": "online"}')
        elif self.path == "/login.cgi":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Router Admin"')
            self.send_header("Server", "Boa/0.94.14rc21")
            self.end_headers()
            self.wfile.write(b"Unauthorized Access")
        else:
            self.send_response(404)
            self.send_header("Server", "Boa/0.94.14rc21")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Suppress standard logging in test suite
        pass


class TestPortForwarder(unittest.TestCase):
    """Test suite for port forwarding rules, socket proxying, and HTTP trigger harnesses."""

    @classmethod
    def setUpClass(cls):
        # Start a local mock HTTP server simulating the emulated IoT device on an ephemeral port
        cls.mock_server = HTTPServer(("127.0.0.1", 0), _MockRouterHTTPHandler)
        cls.mock_port = cls.mock_server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.mock_server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_server.shutdown()
        cls.mock_server.server_close()

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_pf_test_"))
        self.forwarder = PortForwarder(workspace_dir=self.test_dir)
        self.harness = HTTPTriggerHarness(self.forwarder)

    def tearDown(self):
        self.forwarder.teardown_all()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rule_command_generation(self):
        """Verify PortForwardRule generates correct netfilter commands and curl strings."""
        rule = PortForwardRule(
            rule_id="pf-8080-80",
            host_ip="127.0.0.1",
            host_port=8080,
            guest_ip="192.168.1.1",
            guest_port=80,
        )

        cmds = rule.to_iptables_commands()
        self.assertEqual(len(cmds), 2)
        self.assertIn("DNAT --to-destination 192.168.1.1:80", cmds[0])
        self.assertIn("MASQUERADE", cmds[1])

        curl_cmd = rule.to_curl_command("/status.cgi")
        self.assertEqual(curl_cmd, "curl -s -i http://127.0.0.1:8080/status.cgi")

    def test_add_and_list_forwards(self):
        """Verify adding port forward creates active rule and persists state."""
        host_port = _get_free_port()
        rule = self.forwarder.add_forward(
            host_port=host_port,
            guest_port=self.mock_port,
            host_ip="127.0.0.1",
            guest_ip="127.0.0.1",
            mode="socket-proxy",
        )

        self.assertIsInstance(rule, PortForwardRule)
        self.assertTrue(rule.is_active)
        self.assertEqual(rule.host_port, host_port)
        self.assertEqual(rule.guest_port, self.mock_port)

        forwards = self.forwarder.list_forwards()
        self.assertEqual(len(forwards), 1)
        self.assertEqual(forwards[0].rule_id, f"pf-{host_port}-{self.mock_port}")

        # Check state file exists
        self.assertTrue(self.forwarder.state_file.exists())

    def test_socket_proxy_end_to_end_traffic(self):
        """Verify socket proxy forwards HTTP traffic to mock server and receives responses."""
        host_port = _get_free_port()
        self.forwarder.add_forward(
            host_port=host_port,
            guest_port=self.mock_port,
            host_ip="127.0.0.1",
            guest_ip="127.0.0.1",
            mode="socket-proxy",
        )

        # Probe root endpoint through forwarded host port
        res_root = self.harness.probe_endpoint(target=host_port, path="/")
        self.assertTrue(res_root.success)
        self.assertEqual(res_root.status_code, 200)
        self.assertEqual(res_root.server_banner, "Boa/0.94.14rc21")
        self.assertIn("FirmSight Router", res_root.body_snippet)
        self.assertGreater(res_root.response_time_ms, 0.0)

        # Probe cgi endpoint
        res_cgi = self.harness.probe_endpoint(target=host_port, path="/cgi-bin/status.cgi")
        self.assertTrue(res_cgi.success)
        self.assertEqual(res_cgi.status_code, 200)
        self.assertIn("arm_router", res_cgi.body_snippet)

        # Probe login endpoint (returns 401 Unauthorized, still success=True since daemon answered)
        res_login = self.harness.probe_endpoint(target=host_port, path="/login.cgi")
        self.assertTrue(res_login.success)
        self.assertEqual(res_login.status_code, 401)
        self.assertIn("Unauthorized", res_login.body_snippet)

        # Check proxy rule statistics updated
        rule = self.forwarder.list_forwards()[0]
        self.assertGreaterEqual(rule.connections_handled, 3)
        self.assertGreater(rule.bytes_transferred, 100)

    def test_probe_unreachable_endpoint(self):
        """Verify probing an unreachable port returns clean failure report without throwing."""
        unreachable_port = _get_free_port()
        res = self.harness.probe_endpoint(target=unreachable_port, path="/test")
        self.assertFalse(res.success)
        self.assertIsNone(res.status_code)
        self.assertIsNotNone(res.error)

    def test_run_diagnostic_scan(self):
        """Verify diagnostic scan probes battery of standard router endpoints."""
        host_port = _get_free_port()
        self.forwarder.add_forward(
            host_port=host_port,
            guest_port=self.mock_port,
            host_ip="127.0.0.1",
            guest_ip="127.0.0.1",
        )

        results = self.harness.run_diagnostic_scan(host_port=host_port)
        self.assertEqual(len(results), 6)

        # First result is '/'
        self.assertEqual(results[0].status_code, 200)
        # Login is 401
        login_res = next((r for r in results if "login.cgi" in r.url), None)
        self.assertIsNotNone(login_res)
        self.assertEqual(login_res.status_code, 401)

    def test_generate_curl_script(self):
        """Verify curl reproduction script is generated and contains target port."""
        host_port = _get_free_port()
        script_path = self.harness.generate_curl_script(host_port=host_port)
        self.assertTrue(script_path.exists())

        content = script_path.read_text(encoding="utf-8")
        self.assertIn("#!/usr/bin/env bash", content)
        self.assertIn(f"http://127.0.0.1:{host_port}", content)
        self.assertIn("curl -s -i", content)

    def test_remove_forward(self):
        """Verify remove_forward terminates proxy and clears state."""
        host_port = _get_free_port()
        rule = self.forwarder.add_forward(
            host_port=host_port,
            guest_port=self.mock_port,
            host_ip="127.0.0.1",
            guest_ip="127.0.0.1",
        )
        self.assertEqual(len(self.forwarder.list_forwards()), 1)

        success = self.forwarder.remove_forward(rule.rule_id)
        self.assertTrue(success)
        self.assertEqual(len(self.forwarder.list_forwards()), 0)


if __name__ == "__main__":
    unittest.main()
