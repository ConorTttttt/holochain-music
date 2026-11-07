"""S1/S2/S4/S5 verification contracts; optional real Rust HTTP node integration."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.request import urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.holochain_identity import AuthoredRecord, FILE_SCHEMA, HOST_PURPOSE, KEY_SCHEMA, OWNER_PURPOSE, REPLICA_SCHEMA
from holochain_storage.network_client import ReadOnlyStorageNodeClient, StorageNodeClient
from holochain_storage.package import StorageError, canonical, create_package, decrypt_package, manifest_digest, public_key_bytes, sha256, verify_package
from music_catalogue.contract import CatalogueError
from music_catalogue.verified_retrieval import fetch_verified_track


class FakeReader:
    def __init__(self, receipt):
        self.signed_receipt = receipt
        self.receipt_calls = 0
        self.fetch_calls = 0

    def receipt(self, manifest):
        self.receipt_calls += 1
        return self.signed_receipt

    def fetch(self, manifest, target_store, *, trusted_artist, trusted_node):
        self.fetch_calls += 1


def record(agent, body):
    # Test-only stand-in for a Holochain-conductor-authenticated action.
    return AuthoredRecord(author=agent, action_hash="mock-action-hash", body=body)


class VerifiedTrackContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="s5-s2-s4-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.artist_pub = public_key_bytes(self.artist)
        self.node = Ed25519PrivateKey.generate()
        self.node_pub = public_key_bytes(self.node)
        self.alice, self.host = "alice-agent", "host-agent"
        source = self.root / "sample.flac"
        source.write_bytes(b"example opaque audio bytes" * 100)
        self.manifest, self.secret = create_package(source, self.root / "artist", self.artist, chunk_size=1024)
        self.manifest_body = self.manifest["body"]
        self.digest = manifest_digest(self.manifest)
        self.track = record(self.alice, {
            "schema": "holochain-music/track/v1", "artist_agent": self.alice,
            "track_id": "a" * 32, "album_id": None, "title": "My Song",
            "duration_ms": 10000, "disc_number": 1, "track_number": 1,
            "audio_format": "audio/flac", "file_id": self.manifest_body["file_id"],
            "manifest_sha256": self.digest, "rights_basis": "original_owner",
        })
        self.artist_key_record = record(self.alice, {
            "schema": KEY_SCHEMA, "agent": self.alice, "purpose": OWNER_PURPOSE,
            "signing_key_hex": self.artist_pub.hex(),
        })
        self.node_key_record = record(self.host, {
            "schema": KEY_SCHEMA, "agent": self.host, "purpose": HOST_PURPOSE,
            "signing_key_hex": self.node_pub.hex(),
        })
        self.owner_commitment = record(self.alice, {
            "schema": FILE_SCHEMA, "owner_agent": self.alice,
            "file_id": self.manifest_body["file_id"], "manifest_sha256": self.digest,
        })
        import datetime
        receipt_body = {
            "schema": "holochain-storage/replica-receipt/v1",
            "file_id": self.manifest_body["file_id"],
            "manifest_sha256": self.digest,
            "chunk_count": len(self.manifest_body["chunks"]),
            "received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.receipt = {"body": receipt_body,
                        "signer": base64.b64encode(self.node_pub).decode(),
                        "signature": base64.b64encode(self.node.sign(canonical(receipt_body))).decode()}
        self.claim = record(self.host, {
            "schema": REPLICA_SCHEMA, "node_agent": self.host, "owner_agent": self.alice,
            "file_id": self.manifest_body["file_id"], "manifest_sha256": self.digest,
            "receipt_sha256": sha256(canonical(self.receipt)),
        })
        self.reader = FakeReader(self.receipt)

    def call(self):
        return fetch_verified_track(
            track_record=self.track, signed_manifest=self.manifest,
            owner_key_binding=self.artist_key_record, owner_commitment=self.owner_commitment,
            node_agent=self.host, node_key_binding=self.node_key_record,
            replica_claim=self.claim, reader=self.reader,
            target_store=self.root / "download",
        )

    def test_valid_contract_accepts_pinned_identity_and_receipt(self):
        self.assertEqual(self.call()["file_id"], self.manifest_body["file_id"])
        self.assertEqual(self.reader.receipt_calls, 1)
        self.assertEqual(self.reader.fetch_calls, 1)

    def test_forged_artist_record_rejected_before_network(self):
        self.track = record("bob-agent", self.track.body)
        with self.assertRaises(StorageError):
            self.call()
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_wrong_signing_key_rejected_before_network(self):
        self.artist_key_record.body["signing_key_hex"] = public_key_bytes(Ed25519PrivateKey.generate()).hex()
        with self.assertRaises(CatalogueError):
            self.call()
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_wrong_manifest_digest_rejected_before_network(self):
        self.track.body["manifest_sha256"] = "f" * 64
        with self.assertRaises(CatalogueError):
            self.call()
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_wrong_owner_commitment_rejected_before_network(self):
        self.owner_commitment.body["manifest_sha256"] = "0" * 64
        with self.assertRaises(StorageError):
            self.call()
        self.assertEqual(self.reader.receipt_calls, 0)

    def test_wrong_node_claim_rejected_before_payload_transfer(self):
        self.claim.body["receipt_sha256"] = "0" * 64
        with self.assertRaises(StorageError):
            self.call()
        self.assertEqual(self.reader.fetch_calls, 0)

    def test_wrong_node_key_rejected_before_payload_transfer(self):
        self.node_key_record.body["signing_key_hex"] = public_key_bytes(Ed25519PrivateKey.generate()).hex()
        with self.assertRaises(StorageError):
            self.call()
        self.assertEqual(self.reader.fetch_calls, 0)

    def test_receipt_mismatch_rejected_before_payload_transfer(self):
        self.receipt["body"]["manifest_sha256"] = "f" * 64
        with self.assertRaises(StorageError):
            self.call()
        self.assertEqual(self.reader.fetch_calls, 0)


class RealNodeVerifiedTrackTests(unittest.TestCase):
    """Optional Rust HTTP process: full ciphertext download without artist secret."""

    def setUp(self):
        VerifiedTrackContractTests.setUp(self)
        binary = os.environ.get("HOLOCHAIN_STORAGE_NODE_BIN")
        if not binary:
            self.skipTest("set HOLOCHAIN_STORAGE_NODE_BIN for actual S4 Rust-node tests")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.proc = subprocess.Popen(
            [binary, "--root", str(self.root / "node"), "--listen", f"127.0.0.1:{port}",
             "--artist-key", base64.b64encode(self.artist_pub).decode()],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop_node)
        for _ in range(100):
            if self.proc.poll() is not None:
                self.fail("Rust storage node exited before ready")
            try:
                with urlopen(self.url + "/health", timeout=0.2) as result:
                    if result.read() == b"ok":
                        break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail("Rust storage node not ready")
        self.node = Ed25519PrivateKey.from_private_bytes((self.root / "node" / "node.ed25519").read_bytes())
        self.node_pub = public_key_bytes(self.node)
        self.node_key_record.body["signing_key_hex"] = self.node_pub.hex()
        client = StorageNodeClient(self.url, self.artist)
        client.upload(self.manifest, self.root / "artist")
        self.receipt = client.commit(self.manifest, self.node_pub)
        self.claim.body["receipt_sha256"] = sha256(canonical(self.receipt))
        self.reader = ReadOnlyStorageNodeClient(self.url)

    def call(self):
        return VerifiedTrackContractTests.call(self)

    def stop_node(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def test_listener_can_download_with_public_keys_only(self):
        self.assertFalse(hasattr(self.reader, "owner_key"))
        # S6: the read-only listener can obtain the public signed manifest
        # itself, before verifying its exact hash against Holochain data.
        remote_manifest = self.reader.manifest(self.manifest_body["file_id"])
        self.assertEqual(manifest_digest(remote_manifest), self.digest)
        self.assertEqual(self.call()["file_id"], self.manifest_body["file_id"])
        verify_package(self.manifest, self.root / "download", self.artist_pub)
        recovered = decrypt_package(self.manifest, self.root / "download", self.root / "recovered.flac", self.secret, self.artist_pub)
        self.assertEqual(recovered.read_bytes(), (self.root / "sample.flac").read_bytes())


if __name__ == "__main__":
    unittest.main()
