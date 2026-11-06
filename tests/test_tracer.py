"""Unit tests for Track 2 Radare2 Dynamic Tracer and Memory Auditor."""

from pathlib import Path
import shutil
import tempfile
import unittest

from firmsight.tracer.r2_hook import (
    MemoryRegion,
    R2TraceManifest,
    Radare2Tracer,
)


class TestRadare2Tracer(unittest.TestCase):
    """Test suite for Radare2 dynamic memory hooking."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="firmsight_r2_test_"))
        self.mock_bin = self.test_dir / "httpd"
        self.mock_bin.write_bytes(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 40)
        self.tracer = Radare2Tracer(self.mock_bin, gdb_port=1234, workspace_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_memory_regions_dump(self):
        """Verify memory mapping extraction."""
        regions = self.tracer.dump_memory_maps()
        self.assertGreaterEqual(len(regions), 4)

        paths = [r.pathname for r in regions]
        self.assertIn("[stack]", paths)
        self.assertIn("[heap]", paths)

    def test_trace_execution_and_manifest(self):
        """Verify dynamic tracing and manifest export."""
        manifest = self.tracer.trace_execution(force_shim=True)

        self.assertIsInstance(manifest, R2TraceManifest)
        self.assertGreaterEqual(len(manifest.intercepted_calls), 2)
        self.assertTrue(self.tracer.manifest_path.exists())

        m_dict = manifest.to_dict()
        self.assertEqual(m_dict["architecture"], "ARM")


if __name__ == "__main__":
    unittest.main()
