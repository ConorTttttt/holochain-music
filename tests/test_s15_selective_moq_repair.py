"""S15 one-index MoQ repair security contract (fake subprocess, no QUIC here)."""
from __future__ import annotations

import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import wave
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from holochain_storage.package import (
    StorageError, _read_verified_chunk, _store_chunk, create_package,
    manifest_digest, object_path, public_key_bytes, verify_package,
)
from music_catalogue.moq_repair import repair_missing_ciphertext_over_moq


class S15SelectiveMoqRepairTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="s15-moq-unit-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        artist = Ed25519PrivateKey.generate()
        self.key = public_key_bytes(artist)
        pcm = b"".join(struct.pack("<h", i % 26000 - 13000) for i in range(5000))
        wav = io.BytesIO()
        with wave.open(wav, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(16000)
            w.writeframes(pcm)
        (self.root / "source.wav").write_bytes(wav.getvalue())
        self.host, self.local = self.root / "host", self.root / "bob"
        self.manifest, _ = create_package(self.root / "source.wav", self.host, artist, chunk_size=512)
        self.chunks = self.manifest["body"]["chunks"]
        self.missing = self.chunks[3]
        for i, chunk in enumerate(self.chunks):
            if i != 3:
                _store_chunk(self.local, _read_verified_chunk(self.host, chunk))
        self.binary = self.root / "trusted-moq"
        self.binary.touch()
        self.calls: list[list[str]] = []

    def args(self):
        return dict(signed_manifest=self.manifest, ciphertext_store=self.local,
                    trusted_artist=self.key,
                    expected_manifest_sha256=manifest_digest(self.manifest),
                    moq_binary=self.binary, moq_url="https://127.0.0.1:43213",
                    moq_cert_fingerprint_hex="a" * 64)

    def successful_report(self, chunk=None):
        chunk = chunk or self.missing
        return {"repair_verified": True, "repair_index": chunk["index"],
                "cipher_bytes": chunk["cipher_bytes"],
                "manifest_sha256": manifest_digest(self.manifest),
                "file_id": self.manifest["body"]["file_id"],
                "repair_transport": "pinned-moq-quic-v1"}

    def fake_receiver(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertEqual(argv[1], "repair-receive")
        self.assertEqual(argv[-2:], ["--index", "3"])
        self.assertNotIn("content.key", " ".join(argv))
        self.assertNotIn("artist.ed25519", " ".join(argv))
        self.assertIn("--cert-fingerprint-hex", argv)
        self.assertIn("--expected-manifest-sha256", argv)
        _store_chunk(self.local, _read_verified_chunk(self.host, self.missing))
        return subprocess.CompletedProcess(argv, 0, json.dumps(self.successful_report()), "")

    def test_missing_one_object_is_repaired_only_via_pinned_moq(self):
        with patch("music_catalogue.moq_repair.subprocess.run", side_effect=self.fake_receiver):
            result = repair_missing_ciphertext_over_moq(**self.args())
        self.assertTrue(result["repair_complete"])
        self.assertEqual(result["recovered_objects"], 1)
        self.assertEqual(result["repair_index"], 3)
        self.assertEqual(result["repair_transport"], "pinned-moq-quic-v1")
        self.assertEqual(len(self.calls), 1)
        verify_package(self.manifest, self.local, self.key)

    def test_idempotent_reuse_no_network(self):
        with patch("music_catalogue.moq_repair.subprocess.run", side_effect=self.fake_receiver):
            repair_missing_ciphertext_over_moq(**self.args())
        with patch("music_catalogue.moq_repair.subprocess.run", side_effect=AssertionError("network unexpectedly used")):
            report = repair_missing_ciphertext_over_moq(**self.args())
        self.assertEqual(report["recovered_objects"], 0)

    def test_forged_holochain_manifest_digest_rejected_before_network(self):
        with patch("music_catalogue.moq_repair.subprocess.run") as process:
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**{**self.args(), "expected_manifest_sha256":"0"*64})
        process.assert_not_called()

    def test_wrong_artist_signer_rejected_before_network(self):
        with patch("music_catalogue.moq_repair.subprocess.run") as process:
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**{**self.args(), "trusted_artist":public_key_bytes(Ed25519PrivateKey.generate())})
        process.assert_not_called()

    def test_bad_endpoint_or_tls_pin_rejected_before_network(self):
        for changed in ({"moq_url":"https://example.org:3000"},
                        {"moq_cert_fingerprint_hex":"0"*63},
                        {"moq_url":"http://127.0.0.1:4000"},
                        {"moq_url":"https://127.0.0.1:4000/evil"}):
            with self.subTest(changed=changed):
                with patch("music_catalogue.moq_repair.subprocess.run") as process:
                    with self.assertRaises(StorageError):
                        repair_missing_ciphertext_over_moq(**{**self.args(), **changed})
                process.assert_not_called()

    def test_missing_two_objects_aborts_before_network(self):
        second = self.chunks[4]
        object_path(self.local, second["sha256"]).unlink()
        with patch("music_catalogue.moq_repair.subprocess.run") as process:
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())
        process.assert_not_called()

    def test_corrupt_local_object_not_replaced(self):
        c = self.chunks[4]
        object_path(self.local, c["sha256"]).write_bytes(b"bad")
        with patch("music_catalogue.moq_repair.subprocess.run") as process:
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())
        process.assert_not_called()

    def test_existing_symlink_rejected_before_network(self):
        c = self.chunks[4]
        obj = object_path(self.local, c["sha256"])
        obj.unlink()
        obj.symlink_to(self.root / "missing")
        with patch("music_catalogue.moq_repair.subprocess.run") as process:
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())
        process.assert_not_called()

    def test_forged_success_json_rejected(self):
        report = self.successful_report()
        report["repair_index"] = 4
        with patch("music_catalogue.moq_repair.subprocess.run", return_value=subprocess.CompletedProcess([],0,json.dumps(report),"")):
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())

    def test_bogus_success_without_cas_object_rejected(self):
        with patch("music_catalogue.moq_repair.subprocess.run", return_value=subprocess.CompletedProcess([],0,json.dumps(self.successful_report()),"")):
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())

    def test_corrupt_repaired_cas_ciphertext_rejected(self):
        def corrupt(argv, **kwargs):
            dest=object_path(self.local,self.missing["sha256"])
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(b"x"*self.missing["cipher_bytes"])
            return subprocess.CompletedProcess(argv,0,json.dumps(self.successful_report()),"")
        with patch("music_catalogue.moq_repair.subprocess.run",side_effect=corrupt):
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())

    def test_timeout_and_invalid_report_are_fail_closed(self):
        with patch("music_catalogue.moq_repair.subprocess.run",side_effect=subprocess.TimeoutExpired("moq", 4)):
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())
        with patch("music_catalogue.moq_repair.subprocess.run",return_value=subprocess.CompletedProcess([],0,"not-json", "")):
            with self.assertRaises(StorageError):
                repair_missing_ciphertext_over_moq(**self.args())


if __name__ == "__main__": unittest.main()
