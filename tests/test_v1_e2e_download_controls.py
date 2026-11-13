"""Offline download controls over the real stack: two app instances, two real
Holochain conductors, a real bootstrap/relay and the artist's authenticated
MoQ/QUIC host throttled to 64 KiB/s so every step happens mid-transfer.

pause (receiver exits, verified chunks kept, no progress) -> resume (continues
from kept chunks) -> listener restart (Download for Offline reuses stored
chunks; the transient pause state is not persisted) -> host outage
(`unavailable` after bounded attempts, Retry fails while down) -> host
restored -> explicit Retry completes from verified chunks -> a damaged local
object is an integrity failure (not an outage) and Remove local copy +
Download for Offline recovers. Content is checked against the artist's PCM.

Same machine, separate conductor processes. Opt-in like test_v1_e2e_flow:
HOLOCHAIN_MUSIC_E2E=1 plus HOLOCHAIN_MOQ_BIN, HOLOCHAIN_MUSIC_BRIDGE_BIN,
HOLOCHAIN_MUSIC_HAPP and holochain/hc/kitsune2-bootstrap-srv on PATH.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from holochain_music.app import AppError, MusicApp
from holochain_music.artist import normalise_wav
from holochain_music.catalogue import ResolveError
from holochain_music.paths import AppPaths
from holochain_storage.package import object_path

from test_v1_e2e_flow import free_port, poll
from v1_fixtures import write_tone


def receivers(store: Path) -> list[int]:
    """Live `holochain-music-moq fetch` processes writing into `store`."""
    found = []
    for entry in Path("/proc").iterdir() if Path("/proc").is_dir() else []:
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            state = (entry / "stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            continue
        if len(argv) > 1 and argv[1] == b"fetch" and str(store).encode() in argv and state != "Z":
            found.append(int(entry.name))
    return found


def valid_chunks(app: MusicApp, manifest: dict) -> dict[int, tuple[int, int]]:
    """index -> (inode, mtime) of every stored chunk whose ciphertext verifies."""
    out = {}
    for chunk in manifest["body"]["chunks"]:
        path = object_path(app.library.cas, chunk["sha256"])
        if path.is_file():
            data = path.read_bytes()
            if len(data) == chunk["cipher_bytes"] and hashlib.sha256(data).hexdigest() == chunk["sha256"]:
                st = path.stat()
                out[chunk["index"]] = (st.st_ino, st.st_mtime_ns)
    return out


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MUSIC_E2E") == "1", "set HOLOCHAIN_MUSIC_E2E=1 for the real flow")
class RealDownloadControls(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="hmdl-", dir=os.environ.get("HOLOCHAIN_MUSIC_E2E_DIR", "/tmp")))
        if os.environ.get("HOLOCHAIN_MUSIC_E2E_KEEP") != "1":
            self.addCleanup(shutil.rmtree, self.base, True)
        self.bootstrap = f"http://127.0.0.1:{free_port()}"

    def make_app(self, name: str) -> MusicApp:
        home = self.base / name
        app = MusicApp(AppPaths(data=home / "data", config=home / "config"))
        app.save_settings(bootstrap_url=self.bootstrap, relay_url=self.bootstrap, audio_backend="null",
                          host_max_rate=64 * 1024)
        app.player.backend = "null"
        self.addCleanup(app.stop)
        return app

    def test_pause_resume_restart_outage_retry_and_integrity_over_real_moq(self):
        artist, listener = self.make_app("artist"), self.make_app("listener")
        artist.start()
        listener.start()
        self.assertTrue(artist.online, artist.status_message)
        self.assertTrue(listener.online, listener.status_message)
        wav, expected = self.base / "tone.wav", self.base / "expected.wav"
        write_tone(wav, seconds=20.0, rate=44100, channels=2)
        normalise_wav(wav, expected)
        artist.artist.save_profile("Download Controls Artist", "Generated test audio only.")
        published = artist.publish_track(wav=wav, title="Download Controls Tone")
        fid, track_id = published["file_id"], published["track_id"]
        poll(lambda: listener.catalogue.resolve(artist.agent, track_id), 420, "host claim/endpoint propagation")
        poll(lambda: listener.request_access(f"{artist.agent}:{track_id}", "perpetual-personal", ""), 120,
             "request delivery")
        requests = poll(lambda: [r for r in artist.artist.requests() if r["file_id"] == fid], 60, "inbox")
        poll(lambda: artist.artist.grant(request_hash=requests[0]["request_hash"], kind="perpetual-personal"),
             120, "grant delivery")
        poll(lambda: listener.sync_grants() or listener.library.grant(fid), 60, "grant import")
        manifest = listener.library.manifest(fid)
        total = len(manifest["body"]["chunks"])
        self.assertGreater(total, 8)

        # ---- pause: the real receiver exits and verified chunks stay ----------
        listener.download(fid)
        poll(lambda: listener.downloads[fid].progress()["available_chunks"] >= 2, 120, "first chunks", 0.2)
        paused = listener.pause_download(fid)
        self.assertEqual(paused["state"], "paused")
        self.assertEqual(receivers(listener.library.cas), [], "MoQ receiver still running after pause")
        kept = valid_chunks(listener, manifest)
        self.assertGreaterEqual(len(kept), paused["available_chunks"])
        time.sleep(6)
        self.assertEqual(listener.downloads[fid].progress()["available_chunks"], paused["available_chunks"])
        self.assertEqual(valid_chunks(listener, manifest), kept, "progress while paused")

        # ---- resume continues from the kept chunks ----------------------------
        self.assertIn(listener.resume_download(fid)["state"], ("downloading", "complete"))
        poll(lambda: len(valid_chunks(listener, manifest)) >= len(kept) + 2, 120, "resumed transfer", 0.5)
        self.assertEqual({i: kept[i] for i in kept}, {i: valid_chunks(listener, manifest)[i] for i in kept})

        # ---- restart: stored chunks are rediscovered, not fetched again -------
        listener.stop()
        self.assertEqual(receivers(listener.library.cas), [])
        saved = valid_chunks(listener, manifest)
        self.assertLess(len(saved), total)
        listener = MusicApp(listener.paths)
        self.addCleanup(listener.stop)
        listener.start()
        self.assertTrue(listener.online, listener.status_message)
        row = next(t for t in listener.library_view() if t["file_id"] == fid)
        self.assertIsNone(row["download"], "a pause/transfer state must not be claimed across restarts")
        with self.assertRaisesRegex(AppError, "No paused transfer in this session"):
            listener.resume_download(fid)
        # A restarted conductor can need a while to reconverge before host
        # resolution answers (the UI shows a "Download not started" toast).
        started = poll(lambda: listener.download(fid), 300, "post-restart host resolution")
        self.assertGreaterEqual(started["available_chunks"], len(saved))
        d = listener.downloads[fid]
        poll(lambda: d.progress()["available_chunks"] >= len(saved) + 1, 120, "post-restart progress", 0.5)

        # ---- host outage -> unavailable; Retry re-resolves and fails while down
        artist.host.stop()
        poll(lambda: d.progress()["state"] == "unavailable", 900, "unavailable after bounded attempts", 1)
        self.assertEqual(d.progress()["failure"], "unreachable")
        before_retry = valid_chunks(listener, manifest)
        with self.assertRaises(ResolveError):
            listener.retry_download(fid)
        self.assertEqual(d.progress()["state"], "unavailable")

        # ---- host restored -> explicit Retry completes from verified chunks ----
        artist.restart_host()
        self.assertIn(listener.retry_download(fid)["state"], ("downloading", "complete"))
        poll(lambda: listener.library.verify_complete(fid), 600, "download completion", 1)
        progress = listener.downloads[fid].progress()
        self.assertEqual(progress["objects_received"], total - len(saved), progress)
        after = valid_chunks(listener, manifest)
        self.assertEqual(len(after), total)
        self.assertTrue(all(after[i] == sig for i, sig in before_retry.items()), "stored chunks rewritten")
        out = self.base / "export.wav"
        listener.export_wav(fid, out)
        self.assertEqual(out.read_bytes(), expected.read_bytes())

        # ---- a damaged local object is an integrity failure, not an outage ----
        chunk = manifest["body"]["chunks"][3]
        object_path(listener.library.cas, chunk["sha256"]).write_bytes(bytes(chunk["cipher_bytes"]))
        self.assertEqual(listener.offline_readiness(fid)["state"], "incomplete")
        listener.download(fid)
        d = listener.downloads[fid]
        poll(lambda: d.progress()["state"] == "unavailable", 60, "integrity verdict", 0.2)
        self.assertEqual(d.progress()["failure"], "integrity")
        with self.assertRaisesRegex(AppError, "Remove the local copy"):
            listener.retry_download(fid)
        listener.remove_download(fid)
        listener.download(fid)
        poll(lambda: listener.library.verify_complete(fid), 600, "re-download completion", 1)
        out.unlink()
        listener.export_wav(fid, out)
        self.assertEqual(out.read_bytes(), expected.read_bytes())


if __name__ == "__main__":
    unittest.main()
