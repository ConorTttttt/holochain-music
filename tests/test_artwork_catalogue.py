"""Authenticated artwork discovery via fake *validated* conductor records.

Exercises Holochain author/key/receipt pins while mocking only the MoQ
document transport; not a live two-computer Holochain/QUIC integration test.
"""
import copy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from holochain_storage.holochain_identity import (
    AuthoredRecord, FILE_SCHEMA, HOST_PURPOSE, KEY_SCHEMA, OWNER_PURPOSE, REPLICA_SCHEMA)
from holochain_storage.package import (
    RECEIPT_SCHEMA, _sign, canonical, manifest_digest, public_key_bytes, sha256)
from music_catalogue.moq_conductor import MOQ_ENDPOINT_SCHEMA
from holochain_music.artwork import SIG
from holochain_music.artwork_transport import publish_public_artwork
from holochain_music.catalogue import Catalogue, ResolveError

ARTIST = "uhCAkAliceArtist"
HOST = "uhCAkCarolHost"
ALBUM_ID = "a" * 32


def record(author, body):
    return AuthoredRecord(author=author, action_hash="action-" + author, body=body)


class Bridge:
    def __init__(self, values):
        self.values = values

    def records(self, operation, **kwargs):
        return self.values.get(operation, [])


class ArtworkCatalogueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.artist_key = Ed25519PrivateKey.generate()
        self.host_key = Ed25519PrivateKey.generate()
        self.owner_pub = public_key_bytes(self.artist_key)
        self.node_pub = public_key_bytes(self.host_key)
        # Build a correct PNG stream, 2 rows of RGBA with no metadata.
        png_bytes = (SIG + self._chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 6, 0, 0, 0))
                     + self._chunk(b"IDAT", zlib.compress((b"\x00" + b"\x00" * 8) * 2))
                     + self._chunk(b"IEND", b""))
        self.manifest = publish_public_artwork(
            png_bytes, artist_agent=ARTIST, album_id=ALBUM_ID,
            signer=self.artist_key, store=Path(self.tmp.name))
        self.digest = manifest_digest(self.manifest)
        file_id = self.manifest["body"]["file_id"]
        receipt_body = {"schema": RECEIPT_SCHEMA, "file_id": file_id,
                        "manifest_sha256": self.digest, "chunk_count": len(self.manifest["body"]["chunks"]),
                        "received_at": "2026-01-01T00:00:00+00:00"}
        self.receipt = _sign(receipt_body, self.host_key)
        self.values = {
            "list_albums": [record(ARTIST, {"schema": "holochain-music/album/v1",
                "artist_agent": ARTIST, "album_id": ALBUM_ID, "title": "Demo",
                "release_date": None, "artwork_manifest_sha256": self.digest})],
            "get_signing_keys": [],
            "get_file_commitments": [record(ARTIST, {
                "schema": FILE_SCHEMA, "owner_agent": ARTIST, "file_id": file_id,
                "manifest_sha256": self.digest})],
            "get_replica_claims": [record(HOST, {
                "schema": REPLICA_SCHEMA, "node_agent": HOST, "owner_agent": ARTIST,
                "file_id": file_id, "manifest_sha256": self.digest,
                "receipt_sha256": sha256(canonical(self.receipt))})],
            "get_moq_endpoints": [record(HOST, {
                "schema": MOQ_ENDPOINT_SCHEMA, "node_agent": HOST, "owner_agent": ARTIST,
                "file_id": file_id, "manifest_sha256": self.digest,
                "url": "https://127.0.0.1:49999", "cert_fingerprint_hex": "b" * 64})]
        }
        self.artist_binding = record(ARTIST, {"schema": KEY_SCHEMA, "agent": ARTIST,
                                             "purpose": OWNER_PURPOSE, "signing_key_hex": self.owner_pub.hex()})
        self.host_binding = record(HOST, {"schema": KEY_SCHEMA, "agent": HOST,
                                         "purpose": HOST_PURPOSE, "signing_key_hex": self.node_pub.hex()})
        self.bridge = Bridge(self.values)
        # Per-agent key lookups must preserve authenticated authorship.
        def records(operation, **kwargs):
            if operation == "get_signing_keys":
                agent = kwargs["agent"]
                return [self.artist_binding] if agent == ARTIST else [self.host_binding] if agent == HOST else []
            return self.values.get(operation, [])
        self.bridge.records = records
        self.catalogue = Catalogue(self.bridge, moq_binary="/does/not/matter")

    @staticmethod
    def _chunk(tag, content):
        return struct.pack(">I", len(content)) + tag + content + struct.pack(
            ">I", zlib.crc32(tag + content) & 0xFFFFFFFF)

    def resolve(self):
        with patch("holochain_music.catalogue.fetch_document",
                   side_effect=lambda **kw: self.manifest if kw["document"] == "manifest" else self.receipt):
            return self.catalogue.resolve_artwork(ARTIST, ALBUM_ID)

    def test_album_pin_reveals_valid_signed_hosted_art(self):
        result = self.resolve()
        self.assertEqual(result.artist_agent, ARTIST)
        self.assertEqual(result.album_id, ALBUM_ID)
        self.assertEqual(result.digest, self.digest)
        self.assertEqual(result.artist_key, self.owner_pub)
        self.assertEqual(result.hosts[0].url, "https://127.0.0.1:49999")

    def test_forged_album_author_is_ignored(self):
        row = self.values["list_albums"][0]
        self.values["list_albums"] = [record(HOST, row.body)]
        with self.assertRaises(ResolveError):
            self.resolve()

    def test_pin_mutation_rejects_manifest(self):
        self.values["list_albums"][0].body["artwork_manifest_sha256"] = "f" * 64
        with self.assertRaises(ResolveError):
            self.resolve()

    def test_unbound_artist_public_key_rejected(self):
        forged = Ed25519PrivateKey.generate()
        self.artist_binding = record(ARTIST, {"schema": KEY_SCHEMA, "agent": ARTIST,
            "purpose": OWNER_PURPOSE, "signing_key_hex": public_key_bytes(forged).hex()})
        with self.assertRaises(ResolveError):
            self.resolve()

    def test_forged_replica_claim_rejected(self):
        claim = self.values["get_replica_claims"][0]
        self.values["get_replica_claims"] = [record(ARTIST, claim.body)]
        with self.assertRaises(ResolveError):
            self.resolve()

    def test_mismatching_signed_receipt_rejected(self):
        self.receipt["body"]["file_id"] = "0" * 64
        with self.assertRaises(ResolveError):
            self.resolve()

    def test_non_private_hostname_endpoint_is_rejected(self):
        self.values["get_moq_endpoints"][0].body["url"] = "https://example.com:443"
        with self.assertRaises(ResolveError):
            self.resolve()

    def test_without_artwork_pin_existing_album_is_not_advertised(self):
        self.values["list_albums"][0].body["artwork_manifest_sha256"] = None
        with self.assertRaisesRegex(ResolveError, "does not reference"):
            self.resolve()


if __name__ == "__main__":
    unittest.main()
