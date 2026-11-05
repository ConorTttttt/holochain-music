"""Adversarial tests for bounded/parsing-safe generic encrypted storage v1."""

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import (
    StorageError, create_package, verify_package, replicate_package,
    verify_receipt, decrypt_package, create_perpetual_grant, open_perpetual_grant,
)
from holochain_storage.package import (
    MAX_CHUNKS, MAX_FILE_BYTES, _assert_manifest, _sign, object_path,
)


class StorageValidationTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.base = Path(scratch.name)
        self.artist = Ed25519PrivateKey.generate()
        self.node = Ed25519PrivateKey.generate()
        self.artist_pub = self.artist.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.node_pub = self.node.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.source = self.base / "any-file.dat"
        self.source.write_bytes(bytes(range(256)) * 10)
        self.store = self.base / "artist-store"
        self.package, self.key = create_package(self.source, self.store, self.artist, chunk_size=128)

    def test_empty_generic_file_is_supported(self):
        empty = self.base / "empty.file"
        empty.write_bytes(b"")
        package, key = create_package(empty, self.base / "empty-store", self.artist)
        self.assertEqual(verify_package(package, self.base / "empty-store", self.artist_pub)["chunks"], [])
        receipt = replicate_package(package, self.base / "empty-store", self.base / "empty-node", self.artist_pub, self.node)
        self.assertEqual(verify_receipt(receipt, package, self.node_pub, self.artist_pub)["chunk_count"], 0)
        output = decrypt_package(package, self.base / "empty-node", self.base / "restored-empty", key, self.artist_pub)
        self.assertEqual(output.read_bytes(), b"")

    def test_rejects_duplicate_nonce_even_if_artist_signed(self):
        forged = copy.deepcopy(self.package["body"])
        forged["chunks"][1]["nonce"] = forged["chunks"][0]["nonce"]
        with self.assertRaisesRegex(StorageError, "nonce reused"):
            verify_package(_sign(forged, self.artist), self.store, self.artist_pub)

    def test_rejects_noncontiguous_chunk_index(self):
        forged = copy.deepcopy(self.package["body"])
        forged["chunks"][1]["index"] = 999
        with self.assertRaisesRegex(StorageError, "index"):
            verify_package(_sign(forged, self.artist), self.store, self.artist_pub)

    def test_rejects_out_of_bounds_manifest(self):
        malformed = copy.deepcopy(self.package["body"])
        malformed["total_plain_bytes"] = MAX_FILE_BYTES + 1
        with self.assertRaisesRegex(StorageError, "length"):
            _assert_manifest(malformed)
        malformed = copy.deepcopy(self.package["body"])
        malformed["chunks"] = [malformed["chunks"][0]] * (MAX_CHUNKS + 1)
        with self.assertRaisesRegex(StorageError, "number of package chunks"):
            _assert_manifest(malformed)

    def test_rejects_wrong_manifest_shape_and_non_json_values(self):
        malformed = _sign({"schema": "irrelevant", "file_id": "safe"}, self.artist)
        malformed["body"]["file_id"] = float("nan")
        with self.assertRaisesRegex(StorageError, "signature"):
            verify_package(malformed, self.store, self.artist_pub)
        for kind in (None, 17, b"raw", []):
            with self.subTest(kind=kind):
                with self.assertRaises(StorageError):
                    verify_package(kind, self.store, self.artist_pub)

    def test_invalid_trusted_key_types_fail_closed(self):
        with self.assertRaises(StorageError):
            verify_package(self.package, self.store, None)
        with self.assertRaises(StorageError):
            verify_package(self.package, self.store, "not raw public key")

    def test_rejects_oversized_manifest_before_verification(self):
        forged = _sign({"schema": "bad", "padding": "x" * (8 * 1024 * 1024)}, self.artist)
        with self.assertRaisesRegex(StorageError, "size limit"):
            verify_package(forged, self.store, self.artist_pub)

    def test_rejects_symlinked_chunk(self):
        chunk = self.package["body"]["chunks"][0]
        real = object_path(self.store, chunk["sha256"])
        relocated = self.base / "relocated"
        real.rename(relocated)
        real.symlink_to(relocated)
        with self.assertRaisesRegex(StorageError, "symlink"):
            verify_package(self.package, self.store, self.artist_pub)

    def test_rejects_corrupt_existing_replica(self):
        first = self.package["body"]["chunks"][0]
        dest = object_path(self.base / "node", first["sha256"])
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"corrupted object")
        with self.assertRaisesRegex(StorageError, "corrupt existing object"):
            replicate_package(self.package, self.store, self.base / "node", self.artist_pub, self.node)

    def test_cannot_replace_existing_output_when_wrong_key(self):
        output = self.base / "user-file"
        output.write_bytes(b"keep this")
        with self.assertRaises(StorageError):
            decrypt_package(self.package, self.store, output, b"\xff" * 32, self.artist_pub)
        self.assertEqual(output.read_bytes(), b"keep this")

    def test_rejects_malformed_node_receipt_timestamp(self):
        receipt = replicate_package(self.package, self.store, self.base / "node", self.artist_pub, self.node)
        malformed = copy.deepcopy(receipt["body"])
        malformed["received_at"] = "2026-11-05"  # lacks timezone
        with self.assertRaisesRegex(StorageError, "timestamp"):
            verify_receipt(_sign(malformed, self.node), self.package, self.node_pub, self.artist_pub)

    def test_rejects_low_order_recipient_public_key(self):
        with self.assertRaises(StorageError):
            create_perpetual_grant(self.package, self.artist_pub, self.artist, self.key, b"\0" * 32)

    def test_replicas_are_independent(self):
        replica_a, replica_b = self.base / "node-a", self.base / "node-b"
        receipt_a = replicate_package(self.package, self.store, replica_a, self.artist_pub, self.node)
        receipt_b = replicate_package(self.package, self.store, replica_b, self.artist_pub, self.node)
        verify_receipt(receipt_a, self.package, self.node_pub, self.artist_pub)
        verify_receipt(receipt_b, self.package, self.node_pub, self.artist_pub)
        for encrypted in self.store.rglob("*"):
            if encrypted.is_file():
                encrypted.unlink()
        recovered = decrypt_package(self.package, replica_b, self.base / "offline.dat", self.key, self.artist_pub)
        self.assertEqual(recovered.read_bytes(), self.source.read_bytes())


if __name__ == "__main__":
    unittest.main()
