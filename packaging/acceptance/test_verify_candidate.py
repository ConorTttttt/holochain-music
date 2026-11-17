"""Stdlib-only, ephemeral fixtures. No release packages or physical hardware."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name("verify_candidate.py")
SHA = "a" * 40


class PackageVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pkg = self.root / "fixture.deb"
        self.pkg.write_bytes(b"synthetic package only")
        self.data = {"schema_version": 1, "approval_id": "test-only",
                     "source_sha": SHA, "artifacts": [{"platform": "test-only",
                     "filename": self.pkg.name, "size_bytes": self.pkg.stat().st_size,
                     "sha256": self.sha(self.pkg)}]}
        self.manifest = self.root / "manifest.json"
        self.save()

    @staticmethod
    def sha(file):
        return hashlib.sha256(file.read_bytes()).hexdigest()

    def save(self):
        self.manifest.write_text(json.dumps(self.data), encoding="utf-8")

    def invoke(self, *, approved_sha=None, expected_sha=SHA):
        cmd = [sys.executable, str(TOOL), "--manifest", str(self.manifest),
               "--approved-manifest-sha256", approved_sha or self.sha(self.manifest),
               "--expected-source-sha", expected_sha, "--artifact", str(self.pkg)]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_valid_fixture_is_hash_only_not_hardware_pass(self):
        p = self.invoke()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(json.loads(p.stdout)["status"], "HASH_VERIFIED_NOT_HARDWARE_ACCEPTANCE")

    def test_external_manifest_digest_mismatch_blocks(self):
        p = self.invoke(approved_sha="0" * 64)
        self.assertEqual(p.returncode, 2)
        self.assertIn("BLOCKED_HASH_OR_PROVENANCE", p.stdout)

    def test_wrong_candidate_commit_blocks(self):
        p = self.invoke(expected_sha="b" * 40)
        self.assertEqual(p.returncode, 2)

    def test_artifact_content_tampering_blocks(self):
        self.pkg.write_bytes(b"synthetic package only " )
        self.assertEqual(self.invoke().returncode, 2)

    def test_artifact_digest_tampering_same_length_blocks(self):
        self.pkg.write_bytes(b"synthetic package onlf")
        self.assertEqual(self.invoke().returncode, 2)

    def test_manifest_with_duplicate_entry_blocks(self):
        self.data["artifacts"].append(dict(self.data["artifacts"][0]))
        self.save()
        self.assertEqual(self.invoke().returncode, 2)

    def test_unapproved_filename_blocks(self):
        self.data["artifacts"][0]["filename"] = "different.deb"
        self.save()
        self.assertEqual(self.invoke().returncode, 2)

    def test_placeholder_approval_blocks(self):
        self.data["approval_id"] = "PLACEHOLDER"
        self.save()
        self.assertEqual(self.invoke().returncode, 2)

    def test_missing_artifact_blocks(self):
        self.pkg.unlink()
        self.assertEqual(self.invoke().returncode, 2)


if __name__ == "__main__":
    unittest.main()
