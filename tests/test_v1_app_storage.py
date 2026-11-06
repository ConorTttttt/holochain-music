"""v1 app: data paths, key store, encrypted backups, library, WAV import."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from holochain_music.artist import ArtistError, normalise_wav
from holochain_music.keys import KeyStore, KeyStoreError, export_backup, import_backup
from holochain_music.library import Library, LibraryError
from holochain_music.paths import AppPaths, PathError

from v1_fixtures import Track, assert_private, write_tone


class Temp(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-v1-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)


class PathTests(Temp):
    def test_home_override_and_private_permissions(self):
        with mock.patch.dict(os.environ, {"HOLOCHAIN_MUSIC_HOME": str(self.root / "h")}):
            paths = AppPaths.default()
        paths.ensure()
        self.assertEqual(paths.data, (self.root / "h" / "data").resolve())
        for d in (paths.keys, paths.conductor, paths.library):
            assert_private(self, d, 0o700)

    @unittest.skipIf(os.name == "nt", "Unix-socket path limit; Windows lair uses a named pipe")
    def test_too_long_for_keystore_socket_is_refused(self):
        deep = self.root / ("x" * 90)
        with self.assertRaises(PathError):
            AppPaths(data=deep / "data", config=deep / "config").ensure()


class KeyStoreTests(Temp):
    def test_keys_are_created_once_0600_and_stable(self):
        ks = KeyStore(self.root / "keys")
        a = ks.listener_public_hex()
        self.assertEqual(KeyStore(self.root / "keys").listener_public_hex(), a)
        for name in ("listener.x25519",):
            assert_private(self, self.root / "keys" / name, 0o600)
        self.assertEqual(len(ks.conductor_passphrase()), 43)

    def test_refuses_group_readable_symlinked_or_truncated_keys(self):
        ks = KeyStore(self.root / "keys")
        ks.artist_ed25519()
        path = self.root / "keys" / "artist.ed25519"
        if os.name != "nt":  # Windows DACL refusal: test_windows_port.WindowsOnlyTests
            path.chmod(0o644)
            with self.assertRaises(KeyStoreError):
                ks.artist_ed25519()
            path.chmod(0o600)
        path.write_bytes(b"short")
        with self.assertRaises(KeyStoreError):
            ks.artist_ed25519()
        path.unlink()
        target = self.root / "elsewhere"
        target.write_bytes(os.urandom(32))
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(KeyStoreError):
            ks.artist_ed25519()

    def test_content_keys_are_per_file_and_validated(self):
        ks = KeyStore(self.root / "keys")
        fid = "a" * 64
        ks.save_content_key(fid, b"k" * 32)
        self.assertEqual(ks.content_key(fid), b"k" * 32)
        with self.assertRaises(KeyStoreError):
            ks.content_key("b" * 64)
        with self.assertRaises(KeyStoreError):
            ks.content_key("../../etc")
        with self.assertRaises(FileExistsError):
            ks.save_content_key(fid, b"z" * 32)


class BackupTests(Temp):
    def make_sources(self):
        keys = self.root / "keys"
        ks = KeyStore(keys)
        ks.listener_x25519()
        lib = self.root / "library"
        (lib / "tracks").mkdir(parents=True)
        (lib / "tracks" / "x.json").write_text('{"a":1}')
        return ks, keys, lib

    def test_round_trip_restores_identical_keys_into_empty_targets(self):
        ks, keys, lib = self.make_sources()
        out = export_backup(sources={"keys": keys, "library": lib}, destination=self.root / "b.hmbackup",
                            passphrase="correct horse battery")
        assert_private(self, out, 0o600)
        self.assertNotIn((keys / "listener.x25519").read_bytes(), out.read_bytes())
        restored = import_backup(source=out, passphrase="correct horse battery",
                                 targets={"keys": self.root / "r" / "keys", "library": self.root / "r" / "library"})
        self.assertEqual(sorted(restored), ["keys", "library"])
        self.assertEqual(KeyStore(self.root / "r" / "keys").listener_public_hex(), ks.listener_public_hex())
        self.assertEqual((self.root / "r" / "library" / "tracks" / "x.json").read_text(), '{"a":1}')

    def test_wrong_passphrase_short_passphrase_and_overwrite_are_refused(self):
        _, keys, lib = self.make_sources()
        with self.assertRaises(KeyStoreError):
            export_backup(sources={"keys": keys}, destination=self.root / "b", passphrase="short")
        out = export_backup(sources={"keys": keys}, destination=self.root / "b", passphrase="a long passphrase")
        with self.assertRaises(KeyStoreError):
            import_backup(source=out, passphrase="wrong passphrase!", targets={"keys": self.root / "r"})
        with self.assertRaises(KeyStoreError):
            import_backup(source=out, passphrase="a long passphrase", targets={"keys": keys})

    def test_path_traversal_in_backup_container_is_rejected(self):
        evil = self.root / "evil.hmbackup"
        with tarfile.open(evil, "w") as tar:
            data = b"{}"
            info = tarfile.TarInfo("../../escape.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        with self.assertRaises(KeyStoreError):
            import_backup(source=evil, passphrase="a long passphrase", targets={"keys": self.root / "r"})
        self.assertFalse((self.root.parent / "escape.json").exists())


class LibraryTests(Temp):
    def setUp(self):
        super().setUp()
        self.track = Track(self.root / "t")
        self.lib = Library(self.root / "library")
        self.meta = {"manifest_sha256": self.track.digest, "artist_key_hex": self.track.artist_key.hex(),
                     "track_key": "uhCAkArtistAgent:" + "c" * 32, "title": "Tone"}

    def test_add_grant_never_downgrades_a_licence(self):
        self.lib.add(manifest=self.track.manifest, meta=self.meta)
        fid = self.track.file_id
        self.lib.set_grant(fid, self.track.licence(), "perpetual-personal")
        self.lib.set_grant(fid, self.track.stream_grant(), "stream")
        self.assertEqual(self.lib.meta(fid)["grant_kind"], "perpetual-personal")
        self.assertEqual(self.lib.grant(fid)["body"]["schema"], "holochain-music/personal-licence/v1")

    def test_rejects_mismatched_or_replaced_manifest(self):
        with self.assertRaises(LibraryError):
            self.lib.add(manifest=self.track.manifest, meta={**self.meta, "manifest_sha256": "0" * 64})
        other = Track(self.root / "o")
        self.lib.add(manifest=self.track.manifest, meta=self.meta)
        forged = json.loads(json.dumps(other.manifest))
        forged["body"]["file_id"] = self.track.file_id
        from holochain_storage.package import manifest_digest
        with self.assertRaises(LibraryError):
            self.lib.add(manifest=forged, meta={**self.meta, "manifest_sha256": manifest_digest(forged)})

    def test_completeness_tracks_real_ciphertext(self):
        self.lib.add(manifest=self.track.manifest, meta=self.meta)
        fid = self.track.file_id
        self.assertFalse(self.lib.verify_complete(fid))
        from holochain_storage.package import replicate_package
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        replicate_package(self.track.manifest, self.track.store, self.lib.cas, self.track.artist_key,
                          Ed25519PrivateKey.generate())
        self.assertTrue(self.lib.verify_complete(fid))
        self.assertEqual(self.lib.present_chunks(self.track.manifest),
                         set(range(len(self.track.manifest["body"]["chunks"]))))

    def test_playlists_and_history_are_validated_and_bounded(self):
        good = [{"id": "0123456789abcdef", "name": "Mix", "tracks": [self.track.file_id]}]
        self.lib.save_playlists(good)
        self.assertEqual(self.lib.playlists(), good)
        for bad in ([{"id": "x", "name": "Mix", "tracks": []}],
                    [{"id": "0123456789abcdef", "name": "", "tracks": []}],
                    [{"id": "0123456789abcdef", "name": "a", "tracks": ["../x"]}],
                    [{"id": "0123456789abcdef", "name": "a", "tracks": [], "extra": 1}]):
            with self.assertRaises(LibraryError):
                self.lib.save_playlists(bad)
        for i in range(250):
            self.lib.record_play({"key": f"{i:064x}", "title": "t"})
        self.assertEqual(len(self.lib.history()), 200)


class WavImportTests(Temp):
    def test_extra_chunks_are_normalised_and_unsupported_formats_refused(self):
        src = self.root / "in.wav"
        frames = write_tone(src, seconds=0.25, rate=16000, channels=2, extra_chunk=True)
        info = normalise_wav(src, self.root / "out.wav")
        self.assertEqual((info["frames"], info["channels"], info["sample_rate"]), (frames, 2, 16000))
        data = (self.root / "out.wav").read_bytes()
        self.assertEqual(data[36:40], b"data")
        self.assertEqual(len(data), 44 + frames * 4)
        assert_private(self, self.root / "out.wav", 0o600)
        import wave
        with wave.open(str(self.root / "w24.wav"), "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(3)
            w.setframerate(8000)
            w.writeframes(b"\0" * 300)
        with self.assertRaises(ArtistError):
            normalise_wav(self.root / "w24.wav", self.root / "o2.wav")
        (self.root / "junk.wav").write_bytes(b"not a wav")
        with self.assertRaises(ArtistError):
            normalise_wav(self.root / "junk.wav", self.root / "o3.wav")


if __name__ == "__main__":
    unittest.main()
