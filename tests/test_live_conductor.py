"""Fail-closed local IPC contract for the real Holochain conductor bridge.

The subprocess is mocked in these tests; the complementary Sweettest exercises
an actual Holochain 0.7 WebSocket connection, app/DNA pins and signed calls.
"""
from __future__ import annotations

import json
import subprocess
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import test_verified_catalogue_download as fixtures
from music_catalogue.live_conductor import ConductorBridgeError, BRIDGE_SCHEMA, fetch_from_live_conductor
from music_catalogue.contract import CatalogueError
from holochain_storage.package import StorageError


class LocalConductorBridgeTests(unittest.TestCase):
    def setUp(self):
        fixtures.VerifiedTrackContractTests.setUp(self)
        self.binary = self.root / "trusted-listener-bridge"
        self.binary.write_text("binary fixture")
        self.catalogue_dna = "catalogue-dna-pinned-hash"
        self.storage_dna = "storage-dna-pinned-hash"
        self.reader_agent = "bob-listener-agent"
        self.envelope = {
            "schema": BRIDGE_SCHEMA,
            "app_id": "holochain_music",
            "reader_agent": self.reader_agent,
            "catalogue_dna": self.catalogue_dna,
            "storage_dna": self.storage_dna,
            "track": asdict(self.track),
            "owner_key_binding": asdict(self.artist_key_record),
            "owner_commitment": asdict(self.owner_commitment),
            "node_key_binding": asdict(self.node_key_record),
            "replica_claim": asdict(self.claim),
        }
        self.kwargs = {
            "bridge_binary": self.binary,
            "admin_port": 9000,
            "app_id": "holochain_music",
            "catalogue_dna": self.catalogue_dna,
            "storage_dna": self.storage_dna,
            "reader_agent": self.reader_agent,
            "artist_agent": self.alice,
            "node_agent": self.host,
            "track_id": "a" * 32,
            "signed_manifest": self.manifest,
            "storage_url": "http://127.0.0.1:12345",
            "target_store": self.root / "download",
            "reader": self.reader,
        }

    def invoke(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0,
                                                stdout=json.dumps(self.envelope), stderr="")
        with patch("music_catalogue.live_conductor.subprocess.run", return_value=completed) as run:
            result = fetch_from_live_conductor(**self.kwargs)
        return result, run.call_args

    def test_happy_path_pins_app_agent_dnas_and_verifies_manifest_before_download(self):
        got, args = self.invoke()
        self.assertEqual(got["file_id"], self.manifest_body["file_id"])
        self.assertEqual(self.reader.receipt_calls, 1)
        self.assertEqual(self.reader.fetch_calls, 1)
        argv = args.args[0]
        self.assertEqual(argv[0], str(self.binary))
        self.assertIn("--expect-catalogue-dna", argv)
        self.assertIn(self.catalogue_dna, argv)
        self.assertIn("--expect-storage-dna", argv)
        self.assertIn("127.0.0.1:9000", argv)
        self.assertFalse(args.kwargs.get("shell", False))

    def test_downloads_manifest_from_node_when_not_supplied(self):
        class ReaderWithManifest:
            def __init__(self, inner, package):
                self.inner = inner
                self.package = package
                self.calls = []

            def manifest(self, file_id):
                self.calls.append(file_id)
                return self.package

            def receipt(self, package):
                return self.inner.receipt(package)

            def fetch(self, package, target, *, trusted_artist, trusted_node):
                return self.inner.fetch(package, target,
                                        trusted_artist=trusted_artist, trusted_node=trusted_node)

        wrapped = ReaderWithManifest(self.reader, self.manifest)
        self.kwargs.pop("signed_manifest")
        self.kwargs["reader"] = wrapped
        got, _ = self.invoke()
        self.assertEqual(got["file_id"], self.manifest_body["file_id"])
        self.assertEqual(wrapped.calls, [self.manifest_body["file_id"]])
        self.assertEqual(self.reader.fetch_calls, 1)

    def test_wrong_remote_manifest_is_rejected_before_ciphertext(self):
        class BadManifestReader:
            def manifest(self, file_id):
                return {"body": {"file_id": file_id}}
            def receipt(self, manifest):
                raise AssertionError("receipt request must not be made")
            def fetch(self, *args, **kwargs):
                raise AssertionError("ciphertext must not be downloaded")

        self.kwargs.pop("signed_manifest")
        self.kwargs["reader"] = BadManifestReader()
        with self.assertRaises((CatalogueError, StorageError)):
            self.invoke()

    def test_wrong_reader_or_dna_pin_stops_before_network(self):
        for key, wrong in (("reader_agent", "impostor"), ("catalogue_dna", "wrong"),
                           ("storage_dna", "wrong"), ("app_id", "wrong")):
            with self.subTest(key=key):
                old = self.envelope[key]
                self.envelope[key] = wrong
                with self.assertRaises(ConductorBridgeError):
                    self.invoke()
                self.envelope[key] = old
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_wrong_action_authors_and_track_id_stop_before_network(self):
        for record_type in ("track", "owner_key_binding", "owner_commitment",
                            "node_key_binding", "replica_claim"):
            with self.subTest(record=record_type):
                old = self.envelope[record_type]["author"]
                self.envelope[record_type]["author"] = "forged-agent"
                with self.assertRaises(ConductorBridgeError):
                    self.invoke()
                self.envelope[record_type]["author"] = old
        self.envelope["track"]["body"]["track_id"] = "f" * 32
        with self.assertRaises(ConductorBridgeError):
            self.invoke()
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_wrong_manifest_digest_fails_crypto_verification(self):
        self.envelope["track"]["body"]["manifest_sha256"] = "f" * 64
        with self.assertRaises((CatalogueError, StorageError)):
            self.invoke()
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_rejects_non_json_or_unknown_fields(self):
        self.envelope["surprise"] = "untrusted"
        with self.assertRaises(ConductorBridgeError):
            self.invoke()
        self.assertEqual(self.reader.fetch_calls, 0)

    def test_rejects_nonlocal_or_missing_binary(self):
        self.kwargs["bridge_binary"] = Path("relative/path")
        with self.assertRaises(ConductorBridgeError):
            self.invoke()
        self.kwargs["bridge_binary"] = self.binary
        self.kwargs["admin_port"] = 0
        with self.assertRaises(ConductorBridgeError):
            self.invoke()
        self.assertEqual(self.reader.fetch_calls, 0)

    def test_subprocess_failure_is_closed_not_a_mocked_success(self):
        with patch("music_catalogue.live_conductor.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "error")):
            with self.assertRaises(ConductorBridgeError):
                fetch_from_live_conductor(**self.kwargs)
        with patch("music_catalogue.live_conductor.subprocess.run", side_effect=subprocess.TimeoutExpired("bridge", 10)):
            with self.assertRaises(ConductorBridgeError):
                fetch_from_live_conductor(**self.kwargs)
        self.assertEqual(self.reader.fetch_calls, 0)


if __name__ == "__main__":
    unittest.main()
