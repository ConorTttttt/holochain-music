"""v1 end-to-end: two real app instances, two real Holochain conductors,
a real bootstrap/relay, the real MoQ host and the real authenticated player.

Artist publishes (encrypt WAV -> host CAS -> catalogue + S2 records -> MoQ
endpoint) -> listener discovers -> unauthorised playback refused -> private
request -> artist approves privately -> listener streams + seeks ->
download completes -> every service stopped -> a fresh process with network
and child processes disabled plays the track and exports the WAV.

Same machine, separate conductor processes. This is NOT a two-computer test.
Opt-in: HOLOCHAIN_MUSIC_E2E=1 plus HOLOCHAIN_MOQ_BIN, HOLOCHAIN_MUSIC_BRIDGE_BIN,
HOLOCHAIN_MUSIC_HAPP and holochain/hc/kitsune2-bootstrap-srv on PATH.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from holochain_music import player as player_mod
from holochain_music.app import AppError, MusicApp
from holochain_music.artist import normalise_wav
from holochain_music.paths import AppPaths

from test_v1_app_player import Recorder, wait_state
from v1_fixtures import Track, write_tone

REPO = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def poll(fn, timeout: float, what: str, interval: float = 2.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except Exception as exc:  # network still converging
            last = exc
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what}: {last!r}")


OFFLINE_SCRIPT = r'''
import hashlib, json, socket, subprocess, sys, time
def refuse(*a, **k):
    raise RuntimeError("network or subprocess use attempted in offline mode")
socket.socket.connect = refuse
socket.create_connection = refuse
subprocess.Popen = refuse
from holochain_music import player as player_mod
class Rec:
    digest = hashlib.sha256(); n = 0
    def __init__(self, fmt): pass
    def write(self, d): Rec.digest.update(d); Rec.n += len(d)
    def close(self): pass
    def abort(self): pass
player_mod.NullOutput = Rec
from holochain_music.app import MusicApp
app = MusicApp()
app.settings["audio_backend"] = "null"; app.player.backend = "null"
app.start(offline=True)
file_id = sys.argv[1]
view = [t for t in app.library_view() if t["file_id"] == file_id][0]
app.player.play(file_id)
deadline = time.monotonic() + 60
while app.player.status()["state"] not in ("finished", "error") and time.monotonic() < deadline:
    time.sleep(0.05)
status = app.player.status()
out = sys.argv[2]
exported = str(app.export_wav(file_id, out))
app.stop()
print(json.dumps({"state": status["state"], "error": status["error"], "source": status["source"],
                  "pcm_sha256": Rec.digest.hexdigest(), "bytes": Rec.n, "offline_ready": view["offline_ready"],
                  "online": app.online, "exported": exported}))
'''


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MUSIC_E2E") == "1", "set HOLOCHAIN_MUSIC_E2E=1 for the real flow")
class EndToEndFlow(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="hme2e-", dir=os.environ.get("HOLOCHAIN_MUSIC_E2E_DIR", "/tmp")))
        if os.environ.get("HOLOCHAIN_MUSIC_E2E_KEEP") != "1":
            self.addCleanup(shutil.rmtree, self.base, True)
        port = free_port()
        self.apps = []
        Recorder.instances = []
        p = mock.patch.object(player_mod, "NullOutput", Recorder)
        p.start()
        self.addCleanup(p.stop)
        self.bootstrap = f"http://127.0.0.1:{port}"

    def make_app(self, name: str) -> MusicApp:
        home = self.base / name
        paths = AppPaths(data=home / "data", config=home / "config")
        app = MusicApp(paths)
        # A slow host (256 KiB/s) so streaming and seeking happen mid-transfer.
        app.save_settings(bootstrap_url=self.bootstrap, relay_url=self.bootstrap, audio_backend="null",
                          host_max_rate=256 * 1024)
        app.player.backend = "null"
        self.apps.append(app)
        self.addCleanup(app.stop)
        return app

    def test_publish_discover_private_grant_stream_seek_download_offline(self):
        timings = {}
        artist, listener = self.make_app("artist"), self.make_app("listener")
        t0 = time.monotonic()
        artist.start()
        listener.start()
        self.assertTrue(artist.online, artist.status_message)
        self.assertTrue(listener.online, listener.status_message)
        timings["both_online_s"] = round(time.monotonic() - t0, 1)

        # ---- artist publishes a generated 30 s 44.1 kHz stereo tone (~21 chunks)
        wav = self.base / "tone.wav"
        write_tone(wav, seconds=30.0, rate=44100, channels=2, extra_chunk=True)
        expected = self.base / "expected.wav"
        normalise_wav(wav, expected)
        expected_pcm = hashlib.sha256(expected.read_bytes()[44:]).hexdigest()
        artist.artist.save_profile("E2E Test Artist", "Generated test audio only.")
        t0 = time.monotonic()
        published = artist.publish_track(wav=wav, title="E2E Tone")
        timings["publish_s"] = round(time.monotonic() - t0, 1)
        self.assertIsNotNone(artist.host and artist.host.ready)
        file_id, track_id = published["file_id"], published["track_id"]
        track_key = f"{artist.agent}:{track_id}"
        # Artist can play own track (self-issued licence, offline-ready).
        own = [t for t in artist.library_view() if t["file_id"] == file_id][0]
        self.assertTrue(own["offline_ready"])

        # ---- listener discovers it through Holochain ------------------------
        t0 = time.monotonic()
        found = poll(lambda: [t for t in listener.catalogue.browse()
                              if t["key"] == track_key and t["artist_name"] != "Unknown artist"], 420,
                     "catalogue + profile propagation")
        timings["discover_s"] = round(time.monotonic() - t0, 1)
        self.assertEqual(found[0]["artist_name"], "E2E Test Artist")
        self.assertEqual(found[0]["title"], "E2E Tone")
        trusted = poll(lambda: listener.catalogue.resolve(artist.agent, track_id), 240,
                       "host claim/endpoint propagation")
        self.assertEqual(trusted.digest, published["manifest_sha256"])

        # ---- unauthorised: no grant -> no audio -----------------------------
        with self.assertRaises(AppError):
            listener.player.play(file_id)
        before = sum(r.bytes for r in Recorder.instances)

        # ---- private request -> private grant -------------------------------
        t0 = time.monotonic()
        poll(lambda: listener.request_access(track_key, "perpetual-personal", "please"), 120, "request delivery")
        with self.assertRaises(AppError):  # in library now, but still no grant
            listener.player.play(file_id)
        requests = poll(lambda: [r for r in artist.artist.requests() if r["file_id"] == file_id], 60, "inbox")
        self.assertEqual(requests[0]["listener_agent"], listener.agent)
        poll(lambda: artist.artist.grant(request_hash=requests[0]["request_hash"], kind="perpetual-personal"),
             120, "grant delivery")
        poll(lambda: listener.sync_grants() or listener.library.grant(file_id), 60, "grant import")
        timings["request_to_grant_s"] = round(time.monotonic() - t0, 1)
        self.assertEqual(listener.library.meta(file_id)["grant_kind"], "perpetual-personal")
        self.assertEqual(sum(r.bytes for r in Recorder.instances), before)

        # ---- stream, then seek during the stream ------------------------------
        Recorder.instances = []
        self.assertFalse(listener.library.verify_complete(file_id))
        listener.player.play(file_id)
        s = wait_state(listener.player, {"playing", "buffering", "error"}, 120)
        self.assertNotEqual(s["state"], "error", s)
        self.assertEqual(s["source"], "streaming")
        total = listener.player.status()["total_frames"]
        target = total * 9 // 10
        self.assertFalse(listener.library.verify_complete(file_id), "seek must happen mid-download")
        listener.player.seek(target)
        s = wait_state(listener.player, {"finished", "error"}, 120)
        self.assertEqual(s["state"], "finished", s)
        timings["stream_first_audio_ms"] = s["time_to_first_audio_ms"]
        seek_pcm = hashlib.sha256(expected.read_bytes()[44 + target * 4:]).hexdigest()
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), seek_pcm)
        poll(lambda: listener.library.verify_complete(file_id), 120, "download completion", 0.5)
        timings["download_progress"] = progress = listener.downloads[file_id].progress()
        self.assertGreater(progress["total_chunks"], 5)
        self.assertGreaterEqual(progress["restarts_for_seek"], 1)

        # ---- full play from local CAS matches the artist's PCM exactly --------
        Recorder.instances = []
        listener.player.play(file_id)
        s = wait_state(listener.player, {"finished", "error"}, 60)
        self.assertEqual((s["state"], s["source"]), ("finished", "offline"), s)
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), expected_pcm)

        # ---- forged grant (wrong artist key) never plays ---------------------
        real = listener.library.grant(file_id)
        forged = Track(self.base / "forged").licence(listener_agent=listener.agent)
        (listener.library.tracks_dir / file_id / "grant.json").write_text(json.dumps(forged))
        Recorder.instances = []
        listener.player.play(file_id)
        self.assertEqual(wait_state(listener.player, {"error", "finished"}, 60)["state"], "error")
        self.assertTrue(all(r.bytes == 0 for r in Recorder.instances))
        (listener.library.tracks_dir / file_id / "grant.json").write_text(json.dumps(real))

        # ---- stop EVERY service, then play in a no-network process -----------
        listener_home = self.base / "listener"
        for app in self.apps:
            app.stop()
        for app in self.apps:
            self.assertFalse(app.conductor and app.conductor.running())
            self.assertFalse(app.host and app.host.running())
        env = {**os.environ, "HOLOCHAIN_MUSIC_HOME": str(listener_home),
               "PYTHONPATH": f"{REPO}:{REPO / 'tests'}"}
        out = self.base / "exported.wav"
        done = subprocess.run([sys.executable, "-c", OFFLINE_SCRIPT, file_id, str(out)], env=env,
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        result = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertEqual((result["state"], result["source"], result["online"]), ("finished", "offline", False), result)
        self.assertTrue(result["offline_ready"])
        self.assertEqual(result["pcm_sha256"], expected_pcm)
        self.assertEqual(Path(result["exported"]).read_bytes(), expected.read_bytes())
        print("\nE2E timings:", json.dumps(timings, default=str), file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
