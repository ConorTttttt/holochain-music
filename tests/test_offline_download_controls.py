"""Offline P1: deterministic pause/resume/retry regression coverage.

Uses encrypted fixture chunks and a fake authenticated MoQ receiver; it does
NOT claim to validate real host connectivity, transfer rate or native audio.
"""
from pathlib import Path
import shutil
import copy
import json
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_music.app import AppError, MusicApp
from holochain_music.library import Library
from holochain_music.catalogue import HostCandidate, TrustedTrack
from holochain_music.streaming import Download, TrackUnavailable
from holochain_storage.package import create_package, manifest_digest, object_path, public_key_bytes
from music_catalogue.content_grants import (LICENCE_SCHEMA, GRANT_SCHEMA,
    issue_content_grant, issue_personal_licence)
from music_catalogue.moq_host import MoqFetchCancelled, MoqFetchError, fetch_ciphertext

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "holochain_music/ui/app.js").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music/server.py").read_text(encoding="utf-8")
APP = (ROOT / "holochain_music/app.py").read_text(encoding="utf-8")


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
        self.file_id = self.manifest["body"]["file_id"]
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
            self.assertIn(resumed["state"], ("downloading", "complete"))
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
        app.library.meta.return_value = {
            "file_id": self.file_id, "artist_key_hex": public_key_bytes(self.artist).hex(),
            "artist_agent": "test_artist", "listener_agent": "test_listener"}
        app.library.manifest.return_value = self.manifest
        recipient = X25519PrivateKey.generate()
        app.keys = MagicMock()
        app.keys.listener_x25519.return_value = recipient
        recipient_public = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        licence_args = dict(owner_signer=self.artist, owner_agent="test_artist",
            listener_agent="test_listener", recipient_public=recipient_public,
            signed_manifest=self.manifest, content_key=b"K" * 32)
        app.library.grant.return_value = (issue_personal_licence(**licence_args)
            if grant_schema == LICENCE_SCHEMA else issue_content_grant(**licence_args))
        app.downloads = {}
        app.online = True
        app.catalogue = MagicMock()
        app.player = MagicMock()
        app.player.status.return_value = {"state": "stopped", "track_key": None}
        return app

    def test_pause_refuses_when_same_track_playing(self):
        app = self.fake_app()
        app.player.status.return_value = {"state": "playing", "track_key": self.file_id}
        d = MagicMock()
        d.state = "downloading"
        app.downloads[self.file_id] = d
        with self.assertRaisesRegex(AppError, "Stop playback"):
            app.pause_download(self.file_id)
        d.pause.assert_not_called()

    def test_temporary_streaming_grant_cannot_control_offline_download(self):
        app = self.fake_app(GRANT_SCHEMA)
        app.downloads[self.file_id] = MagicMock()
        for command in (app.pause_download, app.resume_download, app.retry_download):
            with self.assertRaisesRegex(AppError, "permanent personal-use licence"):
                command(self.file_id)

    def test_resume_refuses_offline_and_missing_session_worker(self):
        app = self.fake_app()
        app.online = False
        app.catalogue = None
        with self.assertRaisesRegex(AppError, "offline"):
            app.resume_download(self.file_id)
        app.online = True
        app.catalogue = MagicMock()
        with self.assertRaisesRegex(AppError, "No paused transfer"):
            app.resume_download(self.file_id)

    def test_resume_requires_paused_state_and_reuses_existing_worker(self):
        app = self.fake_app()
        d = MagicMock()
        d.state = "paused"
        d.resume.return_value = {"state": "downloading", "available_chunks": 2}
        app.downloads[self.file_id] = d
        result = app.resume_download(self.file_id)
        self.assertEqual(result["available_chunks"], 2)
        d.resume.assert_called_once_with()

    def test_retry_only_allows_unavailable_and_re_resolves(self):
        app = self.fake_app()
        d = MagicMock()
        d.state = "unavailable"
        app.downloads[self.file_id] = d
        app._ensure_download = MagicMock(return_value=d)
        result = app.retry_download(self.file_id)
        self.assertIs(result, d.progress.return_value)
        app._ensure_download.assert_called_once_with(self.file_id)
        d.state = "downloading"
        with self.assertRaisesRegex(AppError, "No failed download"):
            app.retry_download(self.file_id)

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
        self.assertIn("'aria-label': 'Pause download of '", JS)
        self.assertIn("'aria-live': 'polite'", JS)
        self.assertIn("text: 'Resume download'", JS)
        self.assertIn("text: 'Retry download'", JS)
        self.assertIn("['downloading', 'retrying', 'pausing']", JS)
        self.assertIn("result.state === 'paused'", JS)
        self.assertIn("Shared audio chunks are retained", JS)
        self.assertIn("pendingSeek", JS)
        self.assertIn("p.seq < lastSeq", JS)


    def test_same_size_corrupt_saved_chunk_is_not_counted_as_authenticated(self):
        library = Library(self.root / "cached-library")
        first = self.chunks[0]
        dest = object_path(library.cas, first["sha256"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        original = object_path(self.source, first["sha256"]).read_bytes()
        dest.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        self.assertEqual(dest.stat().st_size, first["cipher_bytes"])
        self.assertNotIn(0, library.present_chunks(self.manifest))
        self.assertTrue(dest.exists(), "read-only cache discovery must not delete objects")

    def test_resume_repairs_corrupt_same_size_chunk_without_refetching_valid_ones(self):
        for chunk in self.chunks:
            path = object_path(self.destination, chunk["sha256"])
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(object_path(self.source, chunk["sha256"]), path)
        corrupt = self.chunks[1]
        path = object_path(self.destination, corrupt["sha256"])
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        fetched, _, calls = self.receiver()
        def native_behaviour(**kw):
            # The Rust CAS refuses to overwrite an invalid existing object.
            indexes = kw["objects"] if kw["objects"] is not None else list(
                range(kw["start_index"], len(self.chunks)))
            for i in indexes:
                if object_path(self.destination, self.chunks[i]["sha256"]).exists():
                    raise MoqFetchError("corrupt existing object")
            return fetched(**kw)
        d = self.make_download(present=set(range(len(self.chunks))))
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=native_behaviour):
            d.start()
            wait_until(lambda: d.progress()["state"] in ("complete", "unavailable"))
        self.assertEqual(d.progress()["state"], "complete", d.progress())
        self.assertEqual(calls, [[1]])
        self.assertEqual(path.read_bytes(), original)

    def test_verification_rechecks_damage_after_transport_and_repairs_gap(self):
        fetched, _, calls = self.receiver()
        count = 0
        target = object_path(self.destination, self.chunks[2]["sha256"])
        def corrupt_after_receive(**kw):
            nonlocal count
            count += 1
            fetched(**kw)
            if count == 1:
                original = target.read_bytes()
                target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        d = self.make_download()
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=corrupt_after_receive):
            d.start()
            wait_until(lambda: d.progress()["state"] in ("complete", "unavailable"))
        self.assertEqual(d.progress()["state"], "complete", d.progress())
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], [2])

    def test_completion_callback_failure_never_announces_complete(self):
        fetched, _, _ = self.receiver()
        d = self.make_download(on_complete=lambda: False)
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=fetched):
            d.start()
            wait_until(lambda: d.progress()["state"] in ("complete", "unavailable"))
        self.assertEqual(d.progress()["state"], "unavailable")
        self.assertIn("completion failed", d.progress()["error"])

    def test_host_interruption_rotates_to_alternate_with_saved_authenticated_chunk(self):
        alternate = HostCandidate(node_agent="second_host", node_key=b"key",
            url="https://alternate.test/stream", fingerprint="11" * 32)
        self.trusted.hosts.append(alternate)
        fetched, _, calls = self.receiver()
        urls = []
        def failover(**kw):
            urls.append(kw["url"])
            if kw["url"] == "https://fake.test/stream":
                first = self.chunks[0]
                saved = object_path(self.destination, first["sha256"])
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(object_path(self.source, first["sha256"]), saved)
                kw["on_chunk"](0)
                raise MoqFetchError("network interrupted after first verified chunk")
            return fetched(**kw)
        d = self.make_download()
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=failover), \
             patch("holochain_music.streaming.MAX_BACKOFF", 0.01):
            d.start()
            wait_until(lambda: d.progress()["state"] in ("complete", "unavailable"))
        self.assertEqual(d.progress()["state"], "complete", d.progress())
        self.assertEqual(urls, ["https://fake.test/stream", alternate.url])
        self.assertEqual(calls[0][0], 1)
        self.assertEqual(d.progress()["retries"], 1)

    def test_exhausted_host_retry_preserves_good_chunk_and_uses_new_host(self):
        first = self.chunks[0]
        saved = object_path(self.destination, first["sha256"])
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(object_path(self.source, first["sha256"]), saved)
        d = self.make_download(present={0})
        with patch("holochain_music.streaming.fetch_ciphertext",
                   side_effect=MoqFetchError("host offline")), \
             patch("holochain_music.streaming.MAX_BACKOFF", 0.001):
            d.start()
            wait_until(lambda: d.progress()["state"] == "unavailable")
            wait_until(lambda: not d.is_running())
        alternate = HostCandidate(node_agent="recovered_host", node_key=b"key",
            url="https://recovered.test/stream", fingerprint="22" * 32)
        d.replace_hosts([alternate])
        fetched, _, calls = self.receiver()
        urls = []
        def recovery(**kw):
            urls.append(kw["url"])
            return fetched(**kw)
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=recovery):
            d.start()
            wait_until(lambda: d.progress()["state"] in ("complete", "unavailable"))
        self.assertEqual(d.progress()["state"], "complete", d.progress())
        self.assertEqual(urls, [alternate.url])
        self.assertEqual(calls[0][0], 1)
        self.assertEqual(saved.read_bytes(),
            object_path(self.source, first["sha256"]).read_bytes())

    def test_forged_permanent_grant_cannot_use_managed_offline_controls(self):
        app = self.fake_app()
        forged = copy.deepcopy(app.library.grant.return_value)
        forged["body"]["terms"] = "tampered"
        app.library.grant.return_value = forged
        for command in (app.download, app.pause_download, app.resume_download, app.retry_download):
            with self.assertRaisesRegex(AppError, "could not be verified"):
                command(self.file_id)

    def test_permanent_licence_for_wrong_listener_cannot_download(self):
        app = self.fake_app()
        app.library.meta.return_value["listener_agent"] = "another_listener"
        with self.assertRaisesRegex(AppError, "could not be verified"):
            app.download(self.file_id)

    def test_parallel_start_calls_only_create_one_transfer_worker(self):
        import concurrent.futures
        calls = []
        started = threading.Event()
        def blocked(**kw):
            calls.append(1)
            started.set()
            if not kw["cancel"].wait(4):
                raise AssertionError("worker was not cancelled")
            raise MoqFetchCancelled("paused")
        d = self.make_download()
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=blocked):
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda _: d.start(), range(32)))
            self.assertTrue(started.wait(2))
            self.assertEqual(len(calls), 1)
            self.assertEqual(d.pause()["state"], "paused")
            self.assertFalse(d.is_running())


    def test_native_receiver_shutdown_wait_is_cancellable(self):
        # Simulate a receiver that truthfully reports all verified chunks,
        # then hangs before exiting. Pause must not wait for the hour deadline.
        for chunk in self.chunks:
            saved = object_path(self.destination, chunk["sha256"])
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(object_path(self.source, chunk["sha256"]), saved)
        lines = [dict(kind="chunk_verified", index=chunk["index"],
            sha256=chunk["sha256"], cipher_bytes=chunk["cipher_bytes"])
            for chunk in self.chunks]
        lines.append(dict(kind="fetch_complete", received_chunks=len(self.chunks),
            manifest_sha256=manifest_digest(self.manifest), file_id=self.file_id))
        events = b"".join(json.dumps(line).encode() + b"\\n" for line in lines)
        receiver = MagicMock()
        cancel = threading.Event()
        def wait_for_exit(timeout=None):
            if timeout is None:
                return 0
            cancel.set()
            raise subprocess.TimeoutExpired(cmd="fake-receiver", timeout=timeout)
        receiver.wait.side_effect = wait_for_exit
        reader = MagicMock()
        reader.read.return_value = events
        with patch("music_catalogue.moq_host.subprocess.Popen", return_value=receiver), \
             patch("music_catalogue.moq_host.portable.PipeReader", return_value=reader), \
             patch("music_catalogue.moq_host.portable.supervise"):
            with self.assertRaises(MoqFetchCancelled):
                fetch_ciphertext(moq_binary="fake-receiver", signed_manifest=self.manifest,
                    trusted_artist=public_key_bytes(self.artist),
                    expected_manifest_sha256=manifest_digest(self.manifest),
                    store=self.destination, url="https://127.0.0.1:12345",
                    cert_fingerprint_hex="00" * 32, cancel=cancel)
        receiver.kill.assert_called_once()

    def test_paused_download_stays_protected_from_removal_until_worker_exits(self):
        d = self.make_download()
        app = self.fake_app()
        app._storage_readers = 0
        app.downloads[self.file_id] = d
        app.library.remove_offline_copy.return_value = {"removed_bytes": 0}
        fetch, first, _ = self.receiver(first_chunk_pause=True)
        with patch("holochain_music.streaming.fetch_ciphertext", side_effect=fetch):
            d.start()
            self.assertTrue(first.wait(2))
            with self.assertRaisesRegex(AppError, "download is still active"):
                app.remove_download(self.file_id)
            d.pause()
            app.remove_download(self.file_id)
        app.library.remove_offline_copy.assert_called_once_with(self.file_id)


if __name__ == "__main__":
    unittest.main()
