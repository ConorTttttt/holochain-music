"""Protocol-level tests of generic Model A full-replica encrypted files."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import (
    StorageError, create_package, verify_package, replicate_package, decrypt_package,
    verify_receipt, create_perpetual_grant, open_perpetual_grant,
)
from holochain_storage.package import object_path


class EncryptedStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.host = Ed25519PrivateKey.generate()
        self.attacker = Ed25519PrivateKey.generate()
        self.buyer = X25519PrivateKey.generate()
        self.artist_pub = self.artist.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.host_pub = self.host.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.source = self.root / "source.bin"
        self.plaintext = b"audio or any arbitrary file format \x00\xff" * 500
        self.source.write_bytes(self.plaintext)
        self.original_store = self.root / "artist-store"
        self.replica_store = self.root / "node-store"
        self.package, self.key = create_package(self.source, self.original_store, self.artist, chunk_size=127)

    def test_full_replica_matches_without_key(self):
        self.assertEqual(verify_package(self.package, self.original_store, self.artist_pub)["total_plain_bytes"], len(self.plaintext))
        receipt = replicate_package(self.package, self.original_store, self.replica_store, self.artist_pub, self.host)
        self.assertEqual(verify_receipt(receipt, self.package, self.host_pub, self.artist_pub)["chunk_count"], len(self.package["body"]["chunks"]))
        self.assertEqual(verify_package(self.package, self.replica_store, self.artist_pub)["file_id"], self.package["body"]["file_id"])

    def test_encrypted_chunks_are_not_plaintext(self):
        c = self.package["body"]["chunks"][0]
        self.assertNotEqual(object_path(self.original_store, c["sha256"]).read_bytes(), self.plaintext[:127])
        self.assertNotIn(self.key.hex(), json.dumps(self.package))

    def test_offline_buyer_export_after_artist_store_deleted(self):
        receipt = replicate_package(self.package, self.original_store, self.replica_store, self.artist_pub, self.host)
        self.assertEqual(verify_receipt(receipt, self.package, self.host_pub, self.artist_pub)["file_id"], self.package["body"]["file_id"])
        buyer_pub = self.buyer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        grant = create_perpetual_grant(self.package, self.artist_pub, self.artist, self.key, buyer_pub)
        buyer_key = open_perpetual_grant(grant, self.package, self.artist_pub, self.buyer)
        self.assertEqual(buyer_key, self.key)
        for p in self.original_store.rglob("*"):
            if p.is_file():
                p.unlink()
        target = decrypt_package(self.package, self.replica_store, self.root / "buyers-personal-copy.flac", buyer_key, self.artist_pub)
        self.assertEqual(target.read_bytes(), self.plaintext)

    def test_cannot_decrypt_without_correct_key(self):
        with self.assertRaises(StorageError):
            decrypt_package(self.package, self.original_store, self.root / "bad.bin", b"x" * 32, self.artist_pub)
        self.assertFalse((self.root / "bad.bin").exists())

    def test_tampered_stored_chunk_fails(self):
        c = self.package["body"]["chunks"][0]
        p = object_path(self.original_store, c["sha256"])
        p.write_bytes(b"attack")
        with self.assertRaises(StorageError):
            verify_package(self.package, self.original_store, self.artist_pub)

    def test_tampered_manifest_fails(self):
        altered = copy.deepcopy(self.package)
        altered["body"]["total_plain_bytes"] += 1
        with self.assertRaises(StorageError):
            verify_package(altered, self.original_store, self.artist_pub)

    def test_untrusted_manifest_signer_fails(self):
        attacker_pub = self.attacker.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with self.assertRaises(StorageError):
            verify_package(self.package, self.original_store, attacker_pub)

    def test_receipt_is_bound_to_one_signed_manifest(self):
        receipt = replicate_package(self.package, self.original_store, self.replica_store, self.artist_pub, self.host)
        other = self.root / "other.bin"
        other.write_bytes(b"different")
        other_package, _ = create_package(other, self.original_store, self.artist)
        with self.assertRaises(StorageError):
            verify_receipt(receipt, other_package, self.host_pub, self.artist_pub)

    def test_wrong_node_identity_rejected(self):
        receipt = replicate_package(self.package, self.original_store, self.replica_store, self.artist_pub, self.host)
        bad_host = self.attacker.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with self.assertRaises(StorageError):
            verify_receipt(receipt, self.package, bad_host, self.artist_pub)

    def test_grant_cannot_be_used_by_other_buyer(self):
        buyer_pub = self.buyer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        grant = create_perpetual_grant(self.package, self.artist_pub, self.artist, self.key, buyer_pub)
        with self.assertRaises(StorageError):
            open_perpetual_grant(grant, self.package, self.artist_pub, X25519PrivateKey.generate())

    def test_grant_tampering_fails(self):
        buyer_pub = self.buyer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        grant = create_perpetual_grant(self.package, self.artist_pub, self.artist, self.key, buyer_pub)
        altered = copy.deepcopy(grant)
        altered["body"]["license"] = "expired"
        with self.assertRaises(StorageError):
            open_perpetual_grant(altered, self.package, self.artist_pub, self.buyer)

    def test_randomisation_prevents_cross_package_equality(self):
        other, other_key = create_package(self.source, self.root / "another-store", self.artist, chunk_size=127)
        self.assertNotEqual(other["body"]["file_id"], self.package["body"]["file_id"])
        self.assertNotEqual(other["body"]["chunks"][0]["sha256"], self.package["body"]["chunks"][0]["sha256"])
        self.assertNotEqual(other_key, self.key)

    def test_missing_chunk_rejects_full_replica(self):
        c = self.package["body"]["chunks"][2]
        object_path(self.original_store, c["sha256"]).unlink()
        with self.assertRaises(StorageError):
            replicate_package(self.package, self.original_store, self.replica_store, self.artist_pub, self.host)


if __name__ == "__main__":
    unittest.main()
