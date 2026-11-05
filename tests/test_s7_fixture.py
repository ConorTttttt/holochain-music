"""S7 local fixture tests; the complete live integration runs in Rust Sweettest."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from holochain_storage.package import manifest_digest, sha256, verify_package

SCRIPT = Path(__file__).resolve().parents[1] / "music-e2e/tests/helpers/s7_live_package.py"


class S7FixtureTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="holochain-music-s7-fixture-")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name) / "fixture"

    def prepare(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--root", str(self.root)],
            capture_output=True, text=True, check=True, env={**os.environ, "PYTHONPATH": str(SCRIPT.parents[3])},
        )
        return json.loads(result.stdout)

    def test_preparation_creates_signed_encrypted_chunks_and_public_references(self):
        fixture = self.prepare()
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.assertEqual(manifest_digest(manifest), fixture["manifest_sha256"])
        self.assertEqual(manifest["body"]["file_id"], fixture["file_id"])
        self.assertEqual(sha256((self.root / "sample.flac").read_bytes()), fixture["sample_sha256"])
        self.assertEqual(verify_package(manifest, self.root / "alice-store",
                                        bytes.fromhex(fixture["artist_public_hex"]))["file_id"],
                         fixture["file_id"])
        self.assertNotIn("artist_private", fixture)
        self.assertNotIn("content_key", fixture)
        self.assertEqual(len((self.root / "content.key").read_bytes()), 32)
        self.assertGreater(len(manifest["body"]["chunks"]), 1)

    def test_fails_closed_without_running_storage_node(self):
        self.prepare()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "upload", "--root", str(self.root),
             "--node-url", "http://127.0.0.1:1", "--node-root", str(self.root / "missing-node")],
            capture_output=True, text=True, check=False, env={**os.environ, "PYTHONPATH": str(SCRIPT.parents[3])},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "receipt.json").exists())

    def test_recovery_stage_refuses_wrong_track_before_network(self):
        fixture = self.prepare()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "download", "--root", str(self.root),
             "--node-url", "http://127.0.0.1:1", "--bridge-binary", "/nonexistent/bridge",
             "--admin-port", "1", "--app-id", "test", "--catalogue-dna", "music-dna",
             "--storage-dna", "storage-dna", "--reader-agent", "bob",
             "--artist-agent", "alice", "--node-agent", "bob", "--track-id", "f" * 32,
             "--catalogue-role", "music", "--storage-role", "storage"],
            capture_output=True, text=True, check=False, env={**os.environ, "PYTHONPATH": str(SCRIPT.parents[3])},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "bob-store").exists())
        self.assertNotEqual(fixture["track_id"], "f" * 32)


if __name__ == "__main__":
    unittest.main()
