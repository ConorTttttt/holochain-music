"""Opt-in CORE-004 resilience comparisons on Music-issued ciphertext.

These use the real CLI, but never Music's production read/write path.
Network partition is represented by an unavailable/incomplete local source;
a separate real-conductor suite covers MoQ transport failures.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage import media_core_adapter as core, portable
from holochain_storage.package import (
    StorageError, canonical, create_package, object_path, public_key_bytes,
    replicate_package, verify_package, verify_receipt,
)

ENABLED = bool(os.environ.get(core.ENV_BINARY))


@unittest.skipUnless(ENABLED, f"set {core.ENV_BINARY} to run the real Media Core CLI")
class MediaCoreRecoveryComparisonTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="media-core-resilience-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.artist_public = public_key_bytes(self.artist)
        self.host_a = Ed25519PrivateKey.generate()
        self.host_b = Ed25519PrivateKey.generate()
        (self.root / "original.bin").write_bytes(os.urandom(8193))
        self.a = self.root / "host-a"
        self.b = self.root / "host-b"
        self.cas = self.root / "listener-cas"
        self.manifest, self.content_key = create_package(
            self.root / "original.bin", self.a, self.artist, chunk_size=1024)
        self.receipt_a = replicate_package(
            self.manifest, self.a, self.a, self.artist_public, self.host_a)
        self.receipt_b = replicate_package(
            self.manifest, self.a, self.b, self.artist_public, self.host_b)
        self.chunks = self.manifest["body"]["chunks"]
        self.n = len(self.chunks)

    def assert_parity(self, ready):
        report = core.audit_cas(self.manifest, self.artist_public, self.cas)["store"]
        self.assertEqual(report["offline_ready"], ready)
        try:
            verify_package(self.manifest, self.cas, self.artist_public)
        except StorageError:
            python_ready = False
        else:
            python_ready = True
        self.assertEqual(python_ready, ready)
        self.assertEqual(report["verified"] + report["missing"] + report["corrupt"], self.n)
        return report

    def test_partial_transfer_then_host_switch_then_process_restart(self):
        # Host A vanishes after the first three valid objects. The import
        # must leave only authenticated progress, not mark the file ready.
        missing = object_path(self.a, self.chunks[3]["sha256"])
        missing.unlink()
        with self.assertRaises(core.MediaCoreRejected) as cm:
            core.import_into_cas(self.manifest, self.artist_public, self.a, self.cas)
        self.assertEqual(cm.exception.boundary, "ciphertext-integrity")
        self.assertEqual(cm.exception.result["failed_index"], 3)
        state = self.assert_parity(False)
        self.assertEqual((state["verified"], state["missing"]), (3, self.n - 3))

        # A new CLI subprocess fetches remaining objects from B; it must
        # reuse the first three rather than restarting or trusting bad bytes.
        result = core.import_into_cas(self.manifest, self.artist_public, self.b, self.cas)
        self.assertEqual(result["already_verified"], 3)
        self.assertEqual(result["imported"], self.n - 3)
        self.assert_parity(True)
        self.assertEqual(
            verify_package(self.manifest, self.cas, self.artist_public)["file_id"],
            self.manifest["body"]["file_id"])
        self.assert_parity(True)  # another subprocess/restart

    def test_corrupt_source_never_published_and_verified_repair(self):
        chunk = self.chunks[2]
        p = object_path(self.a, chunk["sha256"])
        raw = bytearray(p.read_bytes())
        raw[0] ^= 1
        p.write_bytes(raw)  # same-length, invalid SHA-256
        with self.assertRaises(core.MediaCoreRejected) as cm:
            core.import_into_cas(self.manifest, self.artist_public, self.a, self.cas)
        self.assertEqual(cm.exception.result["failed_index"], 2)
        self.assertFalse(object_path(self.cas, chunk["sha256"]).exists())
        self.assert_parity(False)

        core.import_into_cas(self.manifest, self.artist_public, self.b, self.cas)
        self.assert_parity(True)
        local = object_path(self.cas, chunk["sha256"])
        local.write_bytes(local.read_bytes()[:-1])  # truncation in cached object
        report = self.assert_parity(False)
        self.assertEqual(report["corrupt"], 1)

        # An incomplete on-disk temporary file from a terminated writer is
        # NOT a committed object and must not satisfy offline readiness.
        staged = local.parent / ".incoming-interrupted-test"
        staged.write_bytes(b"unverified-ciphertext")
        repaired = core.import_into_cas(self.manifest, self.artist_public, self.b, self.cas)
        self.assertEqual(repaired["repaired"], 1)
        self.assert_parity(True)
        self.assertTrue(staged.exists())  # ignored; later temp GC is separate

    def test_receipt_identity_changes_with_host(self):
        host_a_key = public_key_bytes(self.host_a)
        host_b_key = public_key_bytes(self.host_b)
        py_a = verify_receipt(self.receipt_a, self.manifest, host_a_key, self.artist_public)
        py_b = verify_receipt(self.receipt_b, self.manifest, host_b_key, self.artist_public)
        self.assertEqual(
            core.verify_receipt(self.receipt_a, self.manifest, host_a_key, self.artist_public)["chunk_count"],
            py_a["chunk_count"])
        self.assertEqual(
            core.verify_receipt(self.receipt_b, self.manifest, host_b_key, self.artist_public)["chunk_count"],
            py_b["chunk_count"])
        for receipt, wrong in ((self.receipt_a, host_b_key), (self.receipt_b, host_a_key)):
            with self.assertRaises(StorageError):
                verify_receipt(receipt, self.manifest, wrong, self.artist_public)
            with self.assertRaises(core.MediaCoreRejected) as cm:
                core.verify_receipt(receipt, self.manifest, wrong, self.artist_public)
            self.assertEqual(cm.exception.boundary, "s1-receipt")

    def test_killed_import_process_cannot_bypass_restart_audit(self):
        """Terminate a disposable CLI process and retry via a fresh process.

        A fast machine may kill it before its first write; this proves restart
        handling, not a guaranteed mid-write crash (see adoption blockers).
        """
        self.cas.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="core-crash-command-") as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_bytes(canonical(self.manifest))
            proc = subprocess.Popen(
                [str(core.binary()), "import", "--manifest", str(manifest),
                 "--trusted-artist-hex", self.artist_public.hex(),
                 "--source-store", str(self.a), "--cas", str(self.cas)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, **portable.popen_kwargs())
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=20)
        # No partial data may appear ready; if the import finished before the
        # kill, every committed chunk must still be authentic.
        audit = core.audit_cas(self.manifest, self.artist_public, self.cas)["store"]
        self.assertEqual(audit["corrupt"], 0)
        core.import_into_cas(self.manifest, self.artist_public, self.b, self.cas)
        self.assert_parity(True)


if __name__ == "__main__":
    unittest.main()
