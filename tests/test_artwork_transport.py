"""Signed MoQ public-artwork manifest and offline cache — no live network.

Run: python3 -m unittest discover -s tests -p 'test_artwork_transport.py' -v
Remote MoQ/QUIC and two-node Holochain end-to-end tests are still required.
"""
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.package import (_read_verified_chunk, _store_chunk,
                                        manifest_digest, StorageError)
from holochain_music.artwork import ArtworkError, SIG
from holochain_music.artwork_transport import (
    VerifiedArtworkCache, public_artwork_file_id, public_artwork_key,
    publish_public_artwork, recover_public_artwork, verify_public_artwork_manifest,
)

ARTIST = "uhCAktestArtist_1"
ALBUM = "a" * 32


def _chunk(name, payload):
    return (struct.pack(">I", len(payload)) + name + payload
            + struct.pack(">I", zlib.crc32(name + payload) & 0xFFFFFFFF))


def sample_png(width=3, height=2):
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = (b"\x00" + b"\x33" * (width * 4)) * height
    return SIG + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")


class PublicArtworkTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.alice_store = self.root / "alice" / "cas"
        self.bob_store = self.root / "bob" / "cas"
        self.key = Ed25519PrivateKey.generate()
        self.trusted = self.key.public_key().public_bytes_raw()
        self.png = sample_png()
        self.manifest = publish_public_artwork(
            self.png, artist_agent=ARTIST, album_id=ALBUM,
            signer=self.key, store=self.alice_store)
        self.pin = manifest_digest(self.manifest)

    def verify(self, **overrides):
        values = dict(manifest=self.manifest, artist_agent=ARTIST, album_id=ALBUM,
                      trusted_artist=self.trusted, expected_digest=self.pin)
        values.update(overrides)
        return verify_public_artwork_manifest(**values)

    def copy_chunks(self):
        for chunk in self.manifest["body"]["chunks"]:
            data = _read_verified_chunk(self.alice_store, chunk)
            self.assertEqual(_store_chunk(self.bob_store, data), chunk["sha256"])

    def test_artist_signed_manifest_pinned_to_album_and_public_identity(self):
        body = self.verify()
        self.assertEqual(body["file_id"], public_artwork_file_id(ARTIST, ALBUM))
        self.assertEqual(body["total_plain_bytes"], len(self.png))
        self.assertNotIn("content_key", json.dumps(self.manifest))
        self.assertEqual(public_artwork_key(ARTIST, ALBUM), public_artwork_key(ARTIST, ALBUM))
        self.assertNotEqual(public_artwork_key(ARTIST, ALBUM), public_artwork_key(ARTIST, "b" * 32))

    def test_alice_to_bob_chunks_and_offline_cache(self):
        self.copy_chunks()  # Simulated verified MoQ objects, not a real network
        received = recover_public_artwork(
            self.manifest, store=self.bob_store, artist_agent=ARTIST, album_id=ALBUM,
            trusted_artist=self.trusted, expected_digest=self.pin)
        self.assertEqual(received, self.png)
        cache = VerifiedArtworkCache(self.root / "bob" / "artwork", cas=self.bob_store)
        cache.save(artist_agent=ARTIST, album_id=ALBUM, manifest=self.manifest,
                   trusted_artist=self.trusted, expected_digest=self.pin,
                   image=received, store=self.bob_store)
        self.assertEqual(cache.read(ARTIST, ALBUM), self.png)
        self.assertIsNone(cache.read("otherArtist", ALBUM))
        del cache
        self.assertEqual(VerifiedArtworkCache(self.root / "bob" / "artwork", cas=self.bob_store).read(ARTIST, ALBUM), self.png)

    def test_swapped_album_or_artist_is_rejected(self):
        for identity in ({"album_id": "b" * 32}, {"artist_agent": "anotherArtist"}):
            with self.subTest(identity=identity), self.assertRaises(ArtworkError):
                self.verify(**identity)

    def test_wrong_album_digest_and_wrong_trusted_signer_are_rejected(self):
        with self.assertRaises(ArtworkError):
            self.verify(expected_digest="0" * 64)
        forged = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with self.assertRaises(StorageError):
            self.verify(trusted_artist=forged)

    def test_manifest_signature_mutation_cannot_change_payload(self):
        tampered = copy.deepcopy(self.manifest)
        tampered["body"]["total_plain_bytes"] += 1
        with self.assertRaises(ArtworkError):
            self.verify(manifest=tampered, expected_digest=self.pin)

    def test_tampered_chunks_do_not_recover(self):
        self.copy_chunks()
        chunk = self.manifest["body"]["chunks"][0]
        from holochain_storage.package import object_path
        obj = object_path(self.bob_store, chunk["sha256"])
        data = bytearray(obj.read_bytes())
        data[-1] ^= 1
        obj.write_bytes(bytes(data))
        with self.assertRaises(StorageError):
            recover_public_artwork(self.manifest, store=self.bob_store,
                                   artist_agent=ARTIST, album_id=ALBUM,
                                   trusted_artist=self.trusted, expected_digest=self.pin)

    def test_cache_rejects_unrelated_clean_png(self):
        self.copy_chunks()
        cache = VerifiedArtworkCache(self.root / "cache", cas=self.bob_store)
        other = sample_png(width=5)
        with self.assertRaises(ArtworkError):
            cache.save(artist_agent=ARTIST, album_id=ALBUM, manifest=self.manifest,
                       trusted_artist=self.trusted, expected_digest=self.pin,
                       image=other, store=self.bob_store)
        self.assertIsNone(cache.read(ARTIST, ALBUM))

    def test_cache_rejects_disk_tampering(self):
        self.copy_chunks()
        cache = VerifiedArtworkCache(self.root / "cache", cas=self.bob_store)
        cache.save(artist_agent=ARTIST, album_id=ALBUM, manifest=self.manifest,
                   trusted_artist=self.trusted, expected_digest=self.pin,
                   image=self.png, store=self.bob_store)
        owner_dir = next((self.root / "cache").iterdir())
        (owner_dir / (ALBUM + ".png")).write_bytes(sample_png(width=7))
        self.assertIsNone(cache.read(ARTIST, ALBUM))

    def test_invalid_identity_cannot_traverse_cache_or_create_key(self):
        for identity in ("../no", "%2e", "bad/agent", "\\bad", ""):
            with self.subTest(identity=identity), self.assertRaises(ArtworkError):
                public_artwork_file_id(identity, ALBUM)
        with self.assertRaises(ArtworkError):
            public_artwork_key(ARTIST, "../bad")

    def test_cache_manifest_replacement_detected_offline(self):
        self.copy_chunks()
        cache = VerifiedArtworkCache(self.root / "cache", cas=self.bob_store)
        cache.save(artist_agent=ARTIST, album_id=ALBUM, manifest=self.manifest,
                   trusted_artist=self.trusted, expected_digest=self.pin,
                   image=self.png, store=self.bob_store)
        owner_dir = next((self.root / "cache").iterdir())
        meta = owner_dir / (ALBUM + ".json")
        row = json.loads(meta.read_text())
        row["manifest_sha256"] = "f" * 64
        meta.write_text(json.dumps(row))
        self.assertIsNone(cache.read(ARTIST, ALBUM))


if __name__ == "__main__":
    unittest.main()
