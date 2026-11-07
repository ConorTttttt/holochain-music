"""Offline P1: deterministic pause/resume/retry regression coverage.

Uses encrypted fixture chunks and a fake authenticated MoQ receiver; it does
NOT claim to validate real host connectivity, transfer rate or native audio.
"""
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_music.app import AppError, MusicApp
from holochain_music.catalogue import HostCandidate, TrustedTrack
from holochain_music.streaming import Download, TrackUnavailable
from holochain_storage.package import create_package, manifest_digest, object_path, public_key_bytes
from music_catalogue.content_grants import LICENCE_SCHEMA, GRANT_SCHEMA
from music_catalogue.moq_host import MoqFetchCancelled, MoqFetchError

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "holochain_music/ui/app.js").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music/server.py").read_text(encoding="utf-8")
APP = (ROOT / "holochain_music/app.py").read_text(encoding="utf-8")
FILE_ID = "a" * 64


def wait_until(predicate, timeout=4):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("timed out waiting for download worker")


class OfflineDownloadControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        wav = self.root / "fixture.pcm"
        wav.write_bytes(b"verified encrypted chunk fixture" * 100)
        self.artist = Ed25519PrivateKey.generate()
        self.source = self.root / "source"
        self.destination = self.root / "listener"
        self.manifest, _ = create_package(wav, self.source, self.artist, chunk_size=128)
        self.chunks = self.manifest["body"]["chunks"]
        self.trusted = TrustedTrack(
            artist_agent="test_artist", track={},
            artist_key=public_key_bytes(self.artist),
            manifest=self.manifest, digest=manifest_digest(self.manifest),
            hosts=[HostCandidate(node_agent="test_host", node_key=b"key",
                url="https://fake.test/stream", fingerprint="00" * 32)],
        )

    def make_download(self, *, present=None, on_complete=None):
        return Download(trusted=self.trusted, store=self.destination,
            moq_binary="fake-receiver", present=present, on_complete=on_complete,
            stall_timeout=0.1)

    def receiver(self, *, first_chunk_pause=False):
        first_sent = threading.Event()
        calls = []
        def fetch(**kw):
            indexes = kw["objects"] if kw["objects"] is not None else list(range(kw["start_index"], len(self.chunks)))
            calls.append(list(indexes))
            for i in indexes:
                if kw["cancel"].is_set():
                    raise MoqFetchCancelled("cancelled")
                original = object_path(self.source, self.chunks[i]["sha256"])
                target = object_path(self.destination, self.chunks[i]["sha256"])
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, target)
                kw["on_chunk"](self.chunks[i]["index"])
                if first_chunk_pause and len(calls) == 1 and i == 0:
                    first_sent.set()
                    if not kw["cancel"].wait(4):
                        raise AssertionError("pause did not cancel blocked transfer")
                    raise MoqFetchCancelled("pause")
        return fetch, first_sent, calls

    def test_pause_keeps_authenticated_chunks_and_resume_finishes_missing_only(self):
        fetch, first_sent, calls = self.receiver(first_chunk_pause=True)
        completed = []
        d = self.make_download(on_complete=lambda: completed.append("done"))
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=fetch):
            d.start()
            self.assertTrue(first_sent.wait(2), "first authenticated chunk never arrived")
            result = d.pause()
            self.assertEqual(result["state"], "paused")
            self.assertFalse(d.is_running())
            self.assertEqual(result["available_chunks"], 1)
            self.assertTrue(object_path(self.destination, self.chunks[0]["sha256"]).is_file())
            resumed = d.resume()
            self.assertEqual(resumed["state"], "downloading")
            wait_until(lambda: d.progress()["state"] == "complete")
        self.assertEqual(d.progress()["available_chunks"], len(self.chunks))
        self.assertEqual(calls[0][0], 0)
        self.assertEqual(calls[1][0], 1)
        self.assertEqual(completed, ["done"])

    def test_pause_during_retry_backoff_reaches_paused_not_stuck_pausing(self):
        d = self.make_download()
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=MoqFetchError("unreachable")):
            d.start()
            wait_until(lambda: d.progress()["state"] == "retrying")
            result = d.pause()
            self.assertEqual(result["state"], "paused")
            self.assertFalse(d.is_running())
            self.assertEqual(result["available_chunks"], 0)

    def test_retry_is_explicit_and_cached_chunks_survive_restart(self):
        fetch, _, _ = self.receiver()
        d = self.make_download()
        # A restored process discovers already present authenticated chunks.
        first = self.chunks[0]
        cached = object_path(self.destination, first["sha256"])
        cached.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(object_path(self.source, first["sha256"]), cached)
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=fetch):
            restored = self.make_download(present={0})
            restored.start()
            wait_until(lambda: restored.progress()["state"] == "complete")
        self.assertEqual(restored.progress()["available_chunks"], len(self.chunks))
        self.assertTrue(cached.exists())

    def test_resume_rejects_nonpaused_worker_without_changing_progress(self):
        d = self.make_download()
        with self.assertRaisesRegex(TrackUnavailable, "not finished pausing"):
            d.resume()
        self.assertEqual(d.progress()["state"], "idle")

    def fake_app(self, grant_schema=LICENCE_SCHEMA):
        app = MusicApp.__new__(MusicApp)
        app._storage_lock = threading.RLock()
        app.library = MagicMock()
        app.library.meta.return_value = {"file_id": FILE_ID}
        app.library.grant.return_value = {"body": {"schema": grant_schema}}
        app.downloads = {}
        app.online = True
        app.catalogue = MagicMock()
        app.player = MagicMock()
        app.player.status.return_value = {"state": "stopped", "track_key": None}
        return app

    def test_pause_refuses_when_same_track_playing(self):
        app = self.fake_app()
        app.player.status.return_value = {"state": "playing", "track_key": FILE_ID}
        d = MagicMock()
        d.state = "downloading"
        app.downloads[FILE_ID] = d
        with self.assertRaisesRegex(AppError, "Stop playback"):
            app.pause_download(FILE_ID)
        d.pause.assert_not_called()

    def test_temporary_streaming_grant_cannot_control_offline_download(self):
        app = self.fake_app(GRANT_SCHEMA)
        app.downloads[FILE_ID] = MagicMock()
        for command in (app.pause_download, app.resume_download, app.retry_download):
            with self.assertRaisesRegex(AppError, "permanent personal-use licence"):
                command(FILE_ID)

    def test_resume_refuses_offline_and_missing_session_worker(self):
        app = self.fake_app()
        app.online = False
        app.catalogue = None
        with self.assertRaisesRegex(AppError, "offline"):
            app.resume_download(FILE_ID)
        app.online = True
        app.catalogue = MagicMock()
        with self.assertRaisesRegex(AppError, "No paused transfer"):
            app.resume_download(FILE_ID)

    def test_resume_requires_paused_state_and_reuses_existing_worker(self):
        app = self.fake_app()
        d = MagicMock()
        d.state = "paused"
        d.resume.return_value = {"state": "downloading", "available_chunks": 2}
        app.downloads[FILE_ID] = d
        result = app.resume_download(FILE_ID)
        self.assertEqual(result["available_chunks"], 2)
        d.resume.assert_called_once_with()

    def test_retry_only_allows_unavailable_and_re_resolves(self):
        app = self.fake_app()
        d = MagicMock()
        d.state = "unavailable"
        app.downloads[FILE_ID] = d
        app._ensure_download = MagicMock(return_value=d)
        result = app.retry_download(FILE_ID)
        self.assertIs(result, d.progress.return_value)
        app._ensure_download.assert_called_once_with(FILE_ID)
        d.state = "downloading"
        with self.assertRaisesRegex(AppError, "No failed download"):
            app.retry_download(FILE_ID)

    def test_api_and_offline_ui_use_per_track_command_routes(self):
        for route, handler in (
            ('("POST", "/api/offline/download/pause")', "app.pause_download"),
            ('("POST", "/api/offline/download/resume")', "app.resume_download"),
            ('("POST", "/api/offline/download/retry")', "app.retry_download"),
        ):
            self.assertIn(route, SERVER)
            self.assertIn(handler, SERVER)
        self.assertIn("function controlOfflineDownload(fileId, action)", JS)
        self.assertIn("downloadActionsBusy.add(fileId)", JS)
        self.assertIn("text: 'Pause download'", JS)
        self.assertIn("text: 'Resume download'", JS)
        self.assertIn("text: 'Retry download'", JS)
        self.assertIn("['downloading', 'retrying', 'pausing']", JS)
        self.assertIn("result.state === 'paused'", JS)
        self.assertIn("Shared audio chunks are retained", JS)
        self.assertIn("pendingSeek", JS)
        self.assertIn("p.seq < lastSeq", JS)

    def test_paused_download_stays_protected_from_removal_until_worker_exits(self):
        d = self.make_download()
        app = self.fake_app()
        app._storage_readers = 0
        app.downloads[FILE_ID] = d
        app.library.remove_offline_copy.return_value = {"removed_bytes": 0}
        fetch, first, _ = self.receiver(first_chunk_pause=True)
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=fetch):
            d.start()
            self.assertTrue(first.wait(2))
            with self.assertRaisesRegex(AppError, "download is still active"):
                app.remove_download(FILE_ID)
            d.pause()
            app.remove_download(FILE_ID)
        app.library.remove_offline_copy.assert_called_once_with(FILE_ID)


if __name__ == "__main__":
    unittest.main()
