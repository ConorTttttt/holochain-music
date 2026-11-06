"""Album, artwork, genre and metadata-only revision regression tests."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from holochain_storage.holochain_identity import AuthoredRecord
from holochain_music.artist import ArtistError, ArtistService
from holochain_music.catalogue import Catalogue
from holochain_music.metadata import artwork_bytes, genres_list, validate_artwork_record
from music_catalogue.contract import CatalogueError, validate_track

ARTIST = "uhCAkArtist"
FILE = "a" * 64
DIGEST = "b" * 64
TRACK = "c" * 32
ART = b"RIFF1234WEBPdemo-image"


class FakeBridge:
    whoami = {"agent": ARTIST}

    def __init__(self):
        self.art = {}
        self.albums = {}
        self.tracks = {}

    def call(self, op, **kw):
        entry = kw.get("entry")
        if op == "publish_artwork":
            self.art[entry["sha256"]] = dict(entry)
        elif op == "publish_album":
            self.albums[entry["album_id"]] = dict(entry)
        elif op == "publish_track":
            self.tracks[entry["track_id"]] = dict(entry)
        else:
            raise AssertionError(op)
        return {"action_hash": "x"}

    def record(self, op, **kw):
        if op == "get_artwork":
            d = self.art.get(kw["sha256"])
        elif op == "get_track":
            d = self.tracks.get(kw["track_id"])
        else:
            raise AssertionError(op)
        return AuthoredRecord(author=ARTIST, action_hash="hash", body=d) if d else None

    def records(self, op, **kw):
        if op == "list_albums":
            return [AuthoredRecord(author=ARTIST, action_hash="hash", body=a)
                    for a in self.albums.values()]
        raise AssertionError(op)


class AlbumArtworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bridge = FakeBridge()
        self.artist = ArtistService.__new__(ArtistService)
        self.artist.root = self.root
        self.artist.files = self.root / "files"
        self.artist.files.mkdir()
        self.artist.bridge = self.bridge
        self.track_dir = self.artist.files / FILE
        self.track_dir.mkdir()
        (self.track_dir / "track.json").write_text(json.dumps({
            "track_id": TRACK, "file_id": FILE, "manifest_sha256": DIGEST,
            "title": "My Song", "duration_ms": 1000,
        }))
        self.original = {
            "schema": "holochain-music/track/v1", "artist_agent": ARTIST,
            "track_id": TRACK, "album_id": None, "title": "My Song",
            "duration_ms": 1000, "disc_number": 1, "track_number": 1,
            "audio_format": "audio/wav", "file_id": FILE, "manifest_sha256": DIGEST,
            "rights_basis": "original_owner",
        }
        self.bridge.tracks[TRACK] = dict(self.original)

    def tearDown(self):
        self.tmp.cleanup()

    def test_old_tracks_remain_valid_and_new_metadata_is_checked(self):
        validate_track(self.original, author=ARTIST)
        new = {**self.original, "genres": ["Ambient", "Electronic"],
               "artwork_sha256": "0" * 64}
        validate_track(new, author=ARTIST)
        with self.assertRaises(CatalogueError):
            validate_track({**new, "genres": ["Ambient", "ambient"]}, author=ARTIST)
        with self.assertRaises(CatalogueError):
            validate_track({**new, "artwork_sha256": "invalid"}, author=ARTIST)
        self.assertEqual(genres_list(["R&B", "Lo-Fi"]), ["R&B", "Lo-Fi"])
        for bad in (["Rock", "rock"], ["x" * 40], [1], ["x"] * 7):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                genres_list(bad)

    def test_public_cover_authorship_mime_hash_and_tamper(self):
        value = base64.b64encode(ART).decode()
        response = self.artist.publish_artwork(mime_type="image/webp", data_base64=value)
        digest = hashlib.sha256(ART).hexdigest()
        self.assertEqual(response["artwork_sha256"], digest)
        published = self.bridge.art[digest]
        self.assertEqual(validate_artwork_record(published, author=ARTIST, digest=digest), ART)
        self.assertEqual(Catalogue(self.bridge, moq_binary=None).artwork(ARTIST, digest)["data_base64"], value)
        for bad in ({"artist_agent": "forged"}, {"data_base64": base64.b64encode(b"RIFF1234WEBPwrong").decode()}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_artwork_record({**published, **bad}, author=ARTIST, digest=digest)
        for mime, raw in (("image/svg+xml", ART), ("image/webp", b"not-webp"),
                          ("image/webp", b"RIFF1234WEBP" + b"x" * 32769)):
            with self.subTest(mime=mime), self.assertRaises(ValueError):
                artwork_bytes(mime_type=mime, data_base64=base64.b64encode(raw).decode())

    def test_create_album_then_move_existing_track_without_replacing_audio(self):
        digest = self.artist.publish_artwork(
            mime_type="image/webp", data_base64=base64.b64encode(ART).decode())["artwork_sha256"]
        album = self.artist.create_album("First Album", None, ["Ambient"], digest)
        self.assertEqual(self.bridge.albums[album["album_id"]]["genres"], ["Ambient"])
        self.assertEqual(self.bridge.albums[album["album_id"]]["artwork_sha256"], digest)
        result = self.artist.update_track(
            file_id=FILE, album_id=album["album_id"], track_number=3,
            genres=["Jazz", "Soul"], artwork_sha256=digest)
        self.assertEqual(result["album_id"], album["album_id"])
        updated = self.bridge.tracks[TRACK]
        for field in ("file_id", "manifest_sha256", "duration_ms", "audio_format", "rights_basis"):
            self.assertEqual(updated[field], self.original[field], field)
        self.assertEqual(updated["track_number"], 3)
        self.assertEqual(updated["genres"], ["Jazz", "Soul"])
        saved = json.loads((self.track_dir / "track.json").read_text())
        self.assertEqual(saved["album_id"], album["album_id"])
        self.artist.update_album(album_id=album["album_id"], title="Renamed",
                                 release_date="2026-11-06", genres=["Jazz"], artwork_sha256=digest)
        self.assertEqual(self.bridge.albums[album["album_id"]]["title"], "Renamed")
        self.artist.update_track(file_id=FILE, album_id=None, track_number=1,
                                 genres=["Jazz"], artwork_sha256=None)
        self.assertIsNone(self.bridge.tracks[TRACK]["album_id"])
        self.assertEqual(self.bridge.tracks[TRACK]["file_id"], FILE)

    def test_cross_artist_unknown_track_and_unpublished_cover_are_rejected(self):
        with self.assertRaises(ArtistError):
            self.artist.update_track(file_id="f" * 64, album_id=None, track_number=1,
                                     genres=[], artwork_sha256=None)
        self.bridge.tracks[TRACK]["file_id"] = "9" * 64
        with self.assertRaises(ArtistError):
            self.artist.update_track(file_id=FILE, album_id=None, track_number=1,
                                     genres=[], artwork_sha256=None)
        with self.assertRaises(ArtistError):
            self.artist.create_album("Wrong cover", None, ["Rock"], "f" * 64)
        with self.assertRaises(ArtistError):
            self.artist.update_album(album_id="f" * 32, title="Unknown", release_date=None,
                                     genres=[], artwork_sha256=None)


if __name__ == "__main__":
    unittest.main()
