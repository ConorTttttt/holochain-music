"""Cross-module contract between S5 track metadata and S1 encrypted files."""

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from holochain_storage.package import create_package, manifest_digest
from music_catalogue import CatalogueError, validate_track, verify_track_manifest


class CatalogueContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source.flac"
        self.source.write_bytes(b"sample audio data" * 50)
        self.artist_key = Ed25519PrivateKey.generate()
        self.signer = self.artist_key.public_key().public_bytes_raw()
        self.manifest, _key = create_package(self.source, self.base / "objects", self.artist_key)
        self.track = {
            "schema": "holochain-music/track/v1",
            "artist_agent": "alice",
            "track_id": "a" * 32,
            "album_id": None,
            "title": "First Song",
            "duration_ms": 120_000,
            "disc_number": 1,
            "track_number": 1,
            "audio_format": "audio/flac",
            "file_id": self.manifest["body"]["file_id"],
            "manifest_sha256": manifest_digest(self.manifest),
            "rights_basis": "original_owner",
        }

    def test_valid_track_pins_exact_signed_manifest(self):
        body = verify_track_manifest(self.track, self.manifest, author="alice", trusted_signer=self.signer)
        self.assertEqual(body["file_id"], self.track["file_id"])

    def test_track_cannot_claim_another_author(self):
        with self.assertRaisesRegex(CatalogueError, "publisher"):
            validate_track(self.track, author="bob")

    def test_wrong_file_id_rejected(self):
        self.track["file_id"] = "0" * 64
        with self.assertRaisesRegex(CatalogueError, "different"):
            verify_track_manifest(self.track, self.manifest, author="alice", trusted_signer=self.signer)

    def test_swapped_manifest_digest_rejected(self):
        self.track["manifest_sha256"] = "1" * 64
        with self.assertRaisesRegex(CatalogueError, "different"):
            verify_track_manifest(self.track, self.manifest, author="alice", trusted_signer=self.signer)

    def test_wrong_signing_key_rejected(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with self.assertRaisesRegex(CatalogueError, "verification failed"):
            verify_track_manifest(self.track, self.manifest, author="alice", trusted_signer=other)

    def test_tampered_manifest_rejected(self):
        modified = copy.deepcopy(self.manifest)
        modified["body"]["chunks"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(CatalogueError, "verification failed"):
            verify_track_manifest(self.track, modified, author="alice", trusted_signer=self.signer)

    def test_does_not_publish_content_key_or_chunk_data(self):
        self.assertNotIn("key", self.track)
        self.assertNotIn("chunks", self.track)
        self.assertNotIn("nonce", self.track)
        self.assertNotIn("signed_manifest", self.track)

    def test_rejects_public_payload_or_unknown_fields(self):
        bad = {**self.track, "audio_bytes": "plaintext"}
        with self.assertRaisesRegex(CatalogueError, "fields"):
            validate_track(bad, author="alice")

    def test_unsupported_format_rejected(self):
        self.track["audio_format"] = "application/zip"
        with self.assertRaisesRegex(CatalogueError, "format"):
            validate_track(self.track, author="alice")

    def test_bad_album_id_rejected(self):
        self.track["album_id"] = "not-a-uuid"
        with self.assertRaisesRegex(CatalogueError, "album"):
            validate_track(self.track, author="alice")

    def test_boolean_duration_rejected(self):
        self.track["duration_ms"] = True
        with self.assertRaisesRegex(CatalogueError, "duration_ms"):
            validate_track(self.track, author="alice")

    def test_long_title_rejected(self):
        self.track["title"] = "🎵" * 100
        with self.assertRaisesRegex(CatalogueError, "title"):
            validate_track(self.track, author="alice")


if __name__ == "__main__":
    unittest.main()
