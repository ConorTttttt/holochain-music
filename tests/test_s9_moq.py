"""S9 local-IPC fail-closed contracts; Sweettest separately uses real QUIC/DHT.

These fast Python tests MOCK bridge and MoQ subprocesses. A successful local
mock says nothing about live conductor/QUIC correctness: that is covered by
music-e2e/tests/s9_holochain_moq_sweettest.rs.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from holochain_storage.package import object_path
from music_catalogue.live_conductor import ConductorBridgeError
from music_catalogue.moq_conductor import (
    MOQ_BRIDGE_SCHEMA, MOQ_ENDPOINT_SCHEMA, receive_moq_from_live_conductor,
)
import test_verified_catalogue_download as fixtures


class S9BridgeContractTests(unittest.TestCase):
    def setUp(self):
        fixtures.VerifiedTrackContractTests.setUp(self)
        self._original_receipt = self.receipt
        self.bridge = self.root / "bridge"
        self.bridge.write_text("placeholder binary")
        self.moq = self.root / "moq"
        self.moq.write_text("placeholder binary")
        self.catalogue = "music-DNA-from-known-app"
        self.storage = "storage-DNA-from-known-app"
        self.reader_agent = "listener-agent"
        self.endpoint = fixtures.record(self.host, {
            "schema": MOQ_ENDPOINT_SCHEMA,
            "node_agent": self.host,
            "owner_agent": self.alice,
            "file_id": self.manifest_body["file_id"],
            "manifest_sha256": self.digest,
            "url": "https://127.0.0.1:4443",
            "cert_fingerprint_hex": "5" * 64,
        })
        self.envelope = {
            "schema": MOQ_BRIDGE_SCHEMA, "app_id": "s9-music",
            "reader_agent": self.reader_agent,
            "catalogue_dna": self.catalogue, "storage_dna": self.storage,
            "track": asdict(self.track), "owner_key_binding": asdict(self.artist_key_record),
            "owner_commitment": asdict(self.owner_commitment),
            "node_key_binding": asdict(self.node_key_record),
            "replica_claim": asdict(self.claim), "moq_endpoint": asdict(self.endpoint),
        }
        self.kwargs = dict(
            bridge_binary=self.bridge, moq_binary=self.moq, admin_port=9020,
            app_id="s9-music", catalogue_dna=self.catalogue,
            storage_dna=self.storage, reader_agent=self.reader_agent,
            artist_agent=self.alice, node_agent=self.host, track_id="a" * 32,
            storage_url="http://127.0.0.1:9999", target_store=self.root / "listener",
            reader=self._reader(),
        )
        self.moq_calls = 0
        self.manifest_calls = 0
        self.receipt_calls = 0

    def _reader(self):
        class Adapter:
            def manifest(_self, file_id):
                return self.read_manifest(file_id)
            def receipt(_self, signed_manifest):
                return self.read_receipt(signed_manifest)
        return Adapter()

    def read_manifest(self, file_id):
        self.manifest_calls += 1
        self.assertEqual(file_id, self.manifest_body["file_id"])
        return self.manifest

    def read_receipt(self, signed_manifest):
        self.receipt_calls += 1
        self.assertEqual(signed_manifest, self.manifest)
        return self._original_receipt

    def _run(self, argv, **kwargs):
        if "--include-moq-endpoint" in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.envelope), "")
        self.moq_calls += 1
        self.assertEqual(argv[0], str(self.moq))
        self.assertEqual(argv[1], "receive")
        self.assertEqual(argv[argv.index("--url") + 1], self.endpoint.body["url"])
        self.assertEqual(argv[argv.index("--cert-fingerprint-hex") + 1], self.endpoint.body["cert_fingerprint_hex"])
        self.assertEqual(argv[argv.index("--trusted-artist-hex") + 1], self.artist_pub.hex())
        self.assertEqual(argv[argv.index("--expected-manifest-sha256") + 1], self.digest)
        target = Path(argv[argv.index("--store") + 1])
        for chunk in self.manifest_body["chunks"]:
            source = object_path(self.root / "artist", chunk["sha256"])
            destination = object_path(target, chunk["sha256"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        return subprocess.CompletedProcess(argv, 0, json.dumps({
            "verified": True, "received_chunks": len(self.manifest_body["chunks"]),
            "cipher_bytes": sum(c["cipher_bytes"] for c in self.manifest_body["chunks"]),
            "manifest_sha256": self.digest, "file_id": self.manifest_body["file_id"],
        }), "")

    def call(self):
        with patch("music_catalogue.moq_conductor.subprocess.run", side_effect=self._run):
            return receive_moq_from_live_conductor(**self.kwargs)

    def _bad(self, key, value):
        self.envelope["moq_endpoint"]["body"][key] = value
        with self.assertRaises(ConductorBridgeError):
            self.call()
        self.assertEqual(self.moq_calls, 0)

    def test_verified_metadata_pins_real_receiver_arguments(self):
        self._original_receipt = self.receipt
        got = self.call()
        self.assertTrue(got["verified"])
        self.assertEqual(self.moq_calls, 1)
        self.assertEqual(self.receipt_calls, 1)
        self.assertEqual(self.manifest_calls, 1)

    def test_forbidden_wrong_host_authorship(self):
        self._original_receipt = self.receipt
        self.envelope["moq_endpoint"]["author"] = self.alice
        with self.assertRaises(ConductorBridgeError):
            self.call()
        self.assertEqual(self.manifest_calls, 0)
        self.assertEqual(self.moq_calls, 0)

    def test_wrong_endpoint_manifest_and_file_bindings(self):
        self._original_receipt = self.receipt
        for key, value in (("file_id", "a" * 64), ("manifest_sha256", "0" * 64),
                           ("owner_agent", "impostor"), ("node_agent", "impostor")):
            with self.subTest(key=key):
                old = self.endpoint.body[key]
                self._bad(key, value)
                self.endpoint.body[key] = old
        self.assertEqual(self.manifest_calls, 0)

    def test_wrong_tls_fingerprint_and_external_urls(self):
        self._original_receipt = self.receipt
        for key, value in (("cert_fingerprint_hex", "bogus"),
                           ("url", "https://attacker.example:443"),
                           ("url", "https://127.0.0.1:0"),
                           ("url", "https://127.0.0.1:443/path")):
            with self.subTest(key=key, value=value):
                old = self.endpoint.body[key]
                self._bad(key, value)
                self.endpoint.body[key] = old
        self.assertEqual(self.moq_calls, 0)

    def test_wrong_reader_and_dna_pins_rejected_before_s4(self):
        self._original_receipt = self.receipt
        for key in ("reader_agent", "catalogue_dna", "storage_dna", "app_id"):
            with self.subTest(key=key):
                old = self.envelope[key]
                self.envelope[key] = "untrusted"
                with self.assertRaises(ConductorBridgeError):
                    self.call()
                self.envelope[key] = old
        self.assertEqual(self.manifest_calls, 0)

    def test_unknown_json_field_and_bad_signed_receipt_fail_closed(self):
        self._original_receipt = self.receipt
        self.envelope["surprise"] = "not a bridge response"
        with self.assertRaises(ConductorBridgeError):
            self.call()
        del self.envelope["surprise"]
        self._original_receipt = {"untrusted": True}
        with self.assertRaises(Exception):
            self.call()
        self.assertEqual(self.moq_calls, 0)

    def test_bad_digest_in_catalogue_and_missing_trusted_bridge(self):
        self._original_receipt = self.receipt
        self.envelope["track"]["body"]["manifest_sha256"] = "f" * 64
        with self.assertRaises(Exception):
            self.call()
        self.assertEqual(self.moq_calls, 0)
        self.kwargs["bridge_binary"] = self.root / "does-not-exist"
        with self.assertRaises(ConductorBridgeError):
            self.call()


if __name__ == "__main__":
    unittest.main()
