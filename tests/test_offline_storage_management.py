"""Guarded offline download removal, shared CAS retention and on-demand usage.

Run: python3 -m unittest discover -s tests -p 'test_offline_storage_management.py' -v
These are local-unit/structural tests; real playback, filesystem quota and
exported WAV testing are still required before merging.
"""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from holochain_storage.package import create_package, manifest_digest, object_path, public_key_bytes
from holochain_music.app import MusicApp, AppError
from holochain_music.library import Library, LibraryError, _atomic_json

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "holochain_music/ui/app.js").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music/server.py").read_text(encoding="utf-8")
CSS = (ROOT / "holochain_music/ui/app.css").read_text(encoding="utf-8")


class OfflineStorageManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.library = Library(self.root / "library")
        self.signer = Ed25519PrivateKey.generate()
        self.artist_key = public_key_bytes(self.signer).hex()

    def add_track(self, label: str):
        source = self.root / (label + ".wav")
        source.write_bytes(bytes(label, "utf-8") * 16)
        manifest, _ = create_package(source, self.library.cas, self.signer, chunk_size=16)
        fid = manifest["body"]["file_id"]
        self.library.add(manifest=manifest, meta={
            "file_id": fid, "title": label, "manifest_sha256": manifest_digest(manifest),
            "artist_key_hex": self.artist_key, "complete": True,
        })
        return fid, manifest

    def test_storage_usage_counts_only_cas_and_library_metadata(self):
        fid, manifest = self.add_track("A")
        (self.root / "exported.wav").write_bytes(b"EXTERNAL EXPORT")
        result = self.library.storage_usage()
        self.assertGreater(result["encrypted_bytes"], 0)
        self.assertEqual(result["encrypted_objects"], len(manifest["body"]["chunks"]))
        self.assertGreater(result["library_metadata_bytes"], 0)
        self.assertEqual(result["accounted_bytes"],
                         result["encrypted_bytes"] + result["library_metadata_bytes"])
        self.assertLess(result["accounted_bytes"], (self.root / "exported.wav").stat().st_size +
                        4096 * 10)
        self.assertNotIn("export", str(result).lower())

    def test_removal_retains_licences_and_unrelated_track_and_playlist(self):
        first, m1 = self.add_track("FIRST")
        second, m2 = self.add_track("SECOND")
        ids = [first, second]
        playlist = [{"id": "1" * 16, "name": "Keep these", "tracks": ids}]
        self.library.save_playlists(playlist)
        grant = {"body": {"schema": "local-test", "track": first}}
        _atomic_json(self.library._dir(first) / "grant.json", grant)
        result = self.library.remove_offline_copy(first)
        self.assertGreater(result["removed_bytes"], 0)
        self.assertEqual(result["removed_objects"], len(m1["body"]["chunks"]))
        self.assertFalse(self.library.meta(first)["complete"])
        self.assertEqual(self.library.grant(first), grant)
        self.assertEqual(self.library.playlists(), playlist)
        self.assertTrue(self.library.verify_complete(second))
        self.assertFalse(self.library.verify_complete(first))
        for chunk in m2["body"]["chunks"]:
            self.assertTrue(object_path(self.library.cas, chunk["sha256"]).is_file())

    def test_shared_chunk_references_are_preserved_even_if_another_track_is_unavailable(self):
        first, m1 = self.add_track("SHARED")
        # Separate authenticated manifest points at a shared object. The
        # remover must preserve it, even without a decryptable other track.
        other_source, _ = self.add_track("OTHER")
        old = self.library.manifest(other_source)
        body = dict(old["body"])
        body["chunks"] = list(m1["body"]["chunks"])
        body["chunk_size"] = m1["body"]["chunk_size"]
        body["total_plain_bytes"] = m1["body"]["total_plain_bytes"]
        from holochain_storage.package import _sign
        replaced = _sign(body, self.signer)
        _atomic_json(self.library._dir(other_source) / "manifest.json", replaced)
        self.library.update_meta(other_source, manifest_sha256=manifest_digest(replaced))
        result = self.library.remove_offline_copy(first)
        self.assertEqual(result["shared_objects_preserved"], len(m1["body"]["chunks"]))
        for chunk in m1["body"]["chunks"]:
            self.assertTrue(object_path(self.library.cas, chunk["sha256"]).is_file())
        self.assertFalse(self.library.meta(first)["complete"])

    def test_corrupt_other_manifest_prevents_all_deletion(self):
        first, manifest = self.add_track("FIRST")
        second, _ = self.add_track("SECOND")
        (self.library._dir(second) / "manifest.json").write_text('{"body":{},"signer":"broken"}')
        first_object = object_path(self.library.cas, manifest["body"]["chunks"][0]["sha256"])
        with self.assertRaises(LibraryError):
            self.library.remove_offline_copy(first)
        self.assertTrue(first_object.is_file())
        self.assertTrue(self.library.meta(first)["complete"])

    def test_symlinked_chunk_is_refused_without_deleting_external_file(self):
        first, manifest = self.add_track("FIRST")
        link = object_path(self.library.cas, manifest["body"]["chunks"][0]["sha256"])
        outside = self.root / "external-file"
        outside.write_bytes(b"DO NOT TOUCH")
        link.unlink()
        link.symlink_to(outside)
        with self.assertRaisesRegex(LibraryError, "unsafe encrypted-object link"):
            self.library.remove_offline_copy(first)
        self.assertEqual(outside.read_bytes(), b"DO NOT TOUCH")
        self.assertTrue(self.library.meta(first)["complete"])

    def test_unknown_track_and_invalid_id_never_remove_anything(self):
        first, manifest = self.add_track("FIRST")
        for invalid in ("../escape", "f" * 64):
            with self.assertRaises(LibraryError):
                self.library.remove_offline_copy(invalid)
        path = object_path(self.library.cas, manifest["body"]["chunks"][0]["sha256"])
        self.assertTrue(path.is_file())

    def fake_app(self, state="stopped", running=False):
        app = MusicApp.__new__(MusicApp)
        app._storage_lock = threading.RLock()
        app.library = self.library
        app.player = MagicMock()
        app.player.status.return_value = {"state": state, "track_key": None}
        worker = MagicMock()
        worker.is_running.return_value = running
        app.downloads = {"example": worker}
        return app

    def test_remove_refuses_live_playback(self):
        first, manifest = self.add_track("FIRST")
        app = self.fake_app(state="playing")
        with self.assertRaisesRegex(AppError, "Stop playback"):
            app.remove_download(first)
        self.assertTrue(self.library.meta(first)["complete"])
        app.player.shutdown.assert_not_called()

    def test_remove_refuses_active_downloader_worker(self):
        first, _ = self.add_track("FIRST")
        app = self.fake_app(running=True)
        with self.assertRaisesRegex(AppError, "download is still active"):
            app.remove_download(first)
        self.assertTrue(self.library.meta(first)["complete"])
        app.downloads["example"].stop.assert_not_called()

    def test_successful_app_remove_invalidates_downloader_cache_without_stopping_audio(self):
        first, manifest = self.add_track("FIRST")
        app = self.fake_app()
        result = app.remove_download(first)
        self.assertGreater(result["removed_bytes"], 0)
        self.assertEqual(app.downloads, {})
        app.player.shutdown.assert_not_called()
        self.assertFalse(self.library.meta(first)["complete"])

    def test_routes_are_local_authenticated_and_no_generic_clear_all(self):
        self.assertIn('("GET", "/api/offline/storage")', SERVER)
        self.assertIn('("POST", "/api/offline/remove")', SERVER)
        self.assertIn("app.remove_download(_keys(d, {", SERVER)
        self.assertNotIn('"/api/offline/clear-all"', SERVER)
        self.assertIn("self._storage_lock = threading.RLock()", (ROOT / "holochain_music" / "app.py").read_text())
        self.assertIn("if any(download.is_running()", (ROOT / "holochain_music" / "app.py").read_text())

    def test_ui_requires_confirmation_displays_accounted_totals(self):
        self.assertIn("function removeLocalDownload(item)", JS)
        self.assertIn("if (!confirm('Remove only the local app-managed encrypted copy", JS)
        self.assertIn("'/api/offline/remove', { file_id: item.file_id }", JS)
        self.assertIn("'/api/offline/storage'", JS)
        self.assertIn("offlineChecks.delete(item.file_id)", JS)
        self.assertIn("Shared audio chunks are retained", JS)
        self.assertIn("Check local storage usage", JS)
        self.assertIn("readableBytes(storageReport.data.accounted_bytes)", JS)
        self.assertIn("Sizes count file bytes, not filesystem quota", JS)
        self.assertIn(".offline-storage-metrics", CSS)
        self.assertIn("pendingSeek", JS)


if __name__ == "__main__":
    unittest.main()
