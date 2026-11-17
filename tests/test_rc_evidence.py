"""Safety regression checks for the private RC provenance helper."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "rc-evidence.py"
spec = importlib.util.spec_from_file_location("rc_evidence", SCRIPT)
rc_evidence = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(rc_evidence)


class ReleaseEvidenceTests(unittest.TestCase):
    def test_python_version_metadata_agrees(self):
        self.assertRegex(rc_evidence.versions(), r"^\d+\.\d+\.\d+rc\d+$")

    def test_sha256_is_the_hash_of_file_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "sample.bin"
            sample.write_bytes(b"test candidate\x00")
            self.assertEqual(rc_evidence.sha(sample),
                             hashlib.sha256(sample.read_bytes()).hexdigest())

    def test_checksum_manifest_refuses_duplicates_and_bad_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "contents.sha256"
            good = hashlib.sha256(b"content").hexdigest()
            manifest.write_text(f"{good}  bin/holochain.exe\n", encoding="utf-8")
            self.assertEqual(rc_evidence.read_manifest(manifest)["bin/holochain.exe"], good)
            manifest.write_text(f"{good}  x\n{good}  x\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                rc_evidence.read_manifest(manifest)
            manifest.write_text("unverified hash  x\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                rc_evidence.read_manifest(manifest)

    def test_wrong_or_abbreviated_git_commit_is_refused(self):
        with self.assertRaises(ValueError):
            rc_evidence.verify_source("bd7aabc", clean=False)
        with self.assertRaises(ValueError):
            rc_evidence.verify_source("0" * 40, clean=False)

    def test_cli_requires_commit_and_does_not_create_public_release(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "preflight", "--commit", "not-a-sha"],
            capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("40-character", result.stderr)

    def test_key_binaries_included_in_manifest_requirements(self):
        self.assertIn("usr/lib/holochain-music/holochain_music.happ", rc_evidence.LINUX_PATHS)
        self.assertIn("bin/music_app_bridge.exe", rc_evidence.WINDOWS_PATHS)
        self.assertIn("docs/SOURCE_COMMIT.txt", rc_evidence.WINDOWS_PATHS)


if __name__ == "__main__":
    unittest.main()
