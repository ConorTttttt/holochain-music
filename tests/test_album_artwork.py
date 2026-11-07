"""Phase 1 album artwork regression tests. No network or third-party packages.

Run: python3 -m unittest discover -s tests -p 'test_album_artwork.py' -v
These tests do not prove peer-to-peer artwork availability (not implemented).
"""
from pathlib import Path
import os
import struct
import tempfile
import unittest
import zlib

from holochain_music.artwork import (ALBUM_ID, SIG, AlbumArtworkStore,
                                    ArtworkError, clean_png_bytes, load_cover)
from holochain_music.artist import ArtistService

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "holochain_music" / "ui" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "holochain_music" / "ui" / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "holochain_music" / "ui" / "app.css").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
PREVIEW = (ROOT / "holochain_music" / "ui" / "player-preview.js").read_text(encoding="utf-8")


def chunk(name: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + name + data + struct.pack(
        ">I", zlib.crc32(name + data) & 0xFFFFFFFF)


def png(width=2, height=2, *, mode=6, metadata=b"") -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, mode, 0, 0, 0)
    raw = (b"\x00" + b"\x00" * width * (4 if mode == 6 else 3)) * height
    return SIG + chunk(b"IHDR", header) + metadata + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


class FakeBridge:
    def __init__(self):
        self.whoami = {"agent": "artist-agent"}
        self.entries = []
        self.fail = False

    def call(self, operation, *, entry):
        if self.fail:
            raise RuntimeError("simulated Holochain publish failure")
        self.entries.append((operation, entry))
        return {"ok": True}

    def records(self, operation, *, artist):
        if operation != "list_albums" or artist != "artist-agent":
            return []
        from types import SimpleNamespace
        return [SimpleNamespace(author="artist-agent", body=entry) for op, entry in self.entries
                if op == "publish_album"]


class AlbumArtworkTests(unittest.TestCase):
    def test_png_rgb_and_rgba_are_accepted(self):
        for mode in (2, 6):
            with self.subTest(mode=mode):
                raw = png(mode=mode)
                self.assertEqual(clean_png_bytes(raw), raw)

    def test_metadata_is_removed_before_storage(self):
        original = png(metadata=chunk(b"tEXt", b"GPS location\x00private"))
        cleaned = clean_png_bytes(original)
        self.assertNotIn(b"GPS location", cleaned)
        self.assertNotIn(b"private", cleaned)
        self.assertEqual(clean_png_bytes(cleaned), cleaned)

    def test_corrupt_and_oversized_files_are_rejected(self):
        corrupted = bytearray(png())
        corrupted[-1] ^= 1
        bad = [b"not a png", bytes(corrupted), png(width=1201), png(mode=0),
               png() + b"extra bytes"]
        for value in bad:
            with self.subTest(value=len(value)):
                with self.assertRaises(ArtworkError):
                    clean_png_bytes(value)

    def test_bad_zlib_image_data_is_rejected(self):
        header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
        too_many_pixels = SIG + chunk(b"IHDR", header) + chunk(
            b"IDAT", zlib.compress(b"\x00" + b"\x00" * 15000)) + chunk(b"IEND", b"")
        with self.assertRaises(ArtworkError):
            clean_png_bytes(too_many_pixels)

    def test_input_must_be_absolute_png_path_not_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "cover.png"
            target.write_bytes(png())
            self.assertEqual(load_cover(target), png())
            with self.assertRaises(ArtworkError):
                load_cover(root / "missing.png")
            link = root / "link.png"
            try:
                link.symlink_to(target)
            except OSError:
                pass
            else:
                with self.assertRaises(ArtworkError):
                    load_cover(link)
            wrong_extension = root / "cover.svg"
            wrong_extension.write_bytes(png())
            with self.assertRaises(ArtworkError):
                load_cover(wrong_extension)

    def test_content_addressed_sanitised_storage_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            store = AlbumArtworkStore(Path(temp) / "artwork")
            album_id = "a" * 32
            original = png(metadata=chunk(b"tEXt", b"Artist contact\x00do not distribute"))
            with self.assertRaises(ArtworkError):
                store.save(album_id, original)
            store.save(album_id, clean_png_bytes(original))
            self.assertTrue(store.has(album_id))
            saved = store.read(album_id)
            self.assertNotIn(b"Artist contact", saved)
            if os.name == "posix":
                self.assertEqual((store.root / (album_id + ".png")).stat().st_mode & 0o777, 0o600)
            (store.root / (album_id + ".png")).write_bytes(b"broken")
            self.assertIsNone(store.read(album_id))
            store.delete(album_id)
            self.assertFalse(store.has(album_id))

    def test_album_ids_are_strict_and_do_not_traverse(self):
        store = AlbumArtworkStore(Path("dummy"))
        for value in ("../x", "A" * 32, "b" * 31, "c" * 33, "%2e", ""):
            with self.subTest(value=value):
                self.assertFalse(ALBUM_ID.fullmatch(value))
                with self.assertRaises(ArtworkError):
                    store.read(value)

    def test_published_album_keeps_artwork_manifest_unset(self):
        with tempfile.TemporaryDirectory() as temp:
            bridge = FakeBridge()
            cover = Path(temp) / "cover.png"
            cover.write_bytes(png(metadata=chunk(b"tEXt", b"author\x00private")))
            artist = ArtistService(bridge=bridge, keys=object(), host_root=Path(temp) / "host")
            result = artist.create_album("Example album", None, artwork_path=cover)
            self.assertTrue(result["local_artwork"])
            self.assertTrue(artist.album_art.has(result["album_id"]))
            self.assertEqual(bridge.entries[0][0], "publish_album")
            self.assertIsNone(bridge.entries[0][1]["artwork_manifest_sha256"])
            self.assertEqual(artist.my_albums()[0]["local_artwork"], True)

    def test_failed_album_publish_rolls_back_local_cover(self):
        with tempfile.TemporaryDirectory() as temp:
            bridge = FakeBridge()
            bridge.fail = True
            cover = Path(temp) / "cover.png"
            cover.write_bytes(png())
            artist = ArtistService(bridge=bridge, keys=object(), host_root=Path(temp) / "host")
            with self.assertRaisesRegex(RuntimeError, "publish failure"):
                artist.create_album("Failed release", None, artwork_path=cover)
            self.assertEqual(list((artist.root / "artwork").glob("*.png")), [])

    def test_server_authenticates_png_bytes_and_rejects_bad_ids(self):
        token_check = SERVER.index('secrets.compare_digest(self.headers.get("Authorization"')
        artwork_route = SERVER.index('path.path.startswith("/api/artwork/")')
        self.assertLess(token_check, artwork_route)
        self.assertIn("ALBUM_ID.fullmatch(album_id)", SERVER)
        self.assertIn('self._headers(200, "image/png", len(image))', SERVER)
        self.assertIn("img-src 'self' blob:", SERVER)
        self.assertIn('"/api/artist/albums"', SERVER)

    def test_player_uses_blob_urls_without_token_query_or_external_image(self):
        self.assertIn('id="now-art-image" alt="" hidden', HTML)
        self.assertIn("URL.createObjectURL(image)", JS)
        self.assertIn("URL.revokeObjectURL(url)", JS)
        self.assertIn("headers: { Authorization:", JS)
        self.assertIn("showPlayerArtwork(item);", JS)
        self.assertIn("function albumCoverThumb(albumId)", JS)
        self.assertIn("document.createElementNS(", JS)
        self.assertIn(".player .art img[hidden] { display: none; }", CSS)
        self.assertNotIn("img.src = item.cover_url", JS)

    def test_album_creator_lets_artist_assign_tracks_without_audio_changes(self):
        self.assertIn("'/api/artist/album'", JS)
        self.assertIn("'/api/artist/albums'", JS)
        self.assertIn("album_id: albumSelect.value || null", JS)
        self.assertIn("create_album(", (ROOT / "holochain_music" / "artist.py").read_text())
        self.assertIn("artwork_path=Path(", SERVER)
        self.assertIn("rights_basis: rights.value", JS)

    def test_own_tracks_keep_album_identity_for_offline_artwork(self):
        artist_source = (ROOT / "holochain_music" / "artist.py").read_text(encoding="utf-8")
        app_source = (ROOT / "holochain_music" / "app.py").read_text(encoding="utf-8")
        self.assertIn('"album_id": album_id or None, "track_number": track_number,', artist_source)
        self.assertIn('album_id = track.get("album_id")', app_source)
        self.assertIn('"album_id": album_id, "album_title": album_title,', app_source)
        self.assertIn('"track_number": track.get("track_number", 1)', app_source)
        self.assertIn('"album_id", "duration_ms"', app_source)

    def test_static_preview_never_sends_artwork_to_a_server(self):
        self.assertIn("preview-artwork-file", PREVIEW)
        self.assertIn("URL.createObjectURL(file)", PREVIEW)
        self.assertNotIn("fetch(", PREVIEW)
        self.assertNotIn("/api/", PREVIEW)
        self.assertNotIn("localStorage", PREVIEW)


if __name__ == "__main__":
    unittest.main()
