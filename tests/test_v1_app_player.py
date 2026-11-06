"""v1 app player: offline verified sessions, controls, stale workers, failures.

Uses the real S11 bounded player with a recording NullOutput, so every byte
that would reach a speaker is observed and compared with authenticated PCM.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from holochain_storage.package import object_path
from holochain_music import player as player_mod
from holochain_music.player import Player, SessionSpec, VolumeOutput
from music_catalogue.buffered_playback import NullOutput
from music_catalogue.granted_audio import PlaybackError

from v1_fixtures import Track


class Recorder:
    """Captures what would be written to the device (PCM never persisted)."""
    instances: list = []

    def __init__(self, fmt):
        self.digest, self.bytes, self.closed = hashlib.sha256(), 0, False
        Recorder.instances.append(self)

    def write(self, data):
        self.digest.update(data)
        self.bytes += len(data)

    def close(self):
        self.closed = True

    def abort(self):
        self.closed = True


def wait_state(p: Player, states, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = p.status()
        if s["state"] in states:
            return s
        time.sleep(0.02)
    raise AssertionError(f"player stuck in {p.status()}")


class PlayerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-v1-player-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.track = Track(self.root / "a", seconds=0.6)
        Recorder.instances = []
        patcher = mock.patch.object(player_mod, "NullOutput", Recorder)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.grants = {self.track.file_id: self.track.licence()}

    def spec(self, key, **override):
        t = self.track
        args = dict(key=key, manifest=t.manifest, grant=self.grants[key], artist_key=t.artist_key,
                    owner_agent=t.owner, listener_agent=t.reader, recipient=t.listener, store=t.store)
        args.update(override)
        return SessionSpec(**args)

    def expected_pcm(self, start_frame=0):
        from music_catalogue.seekable_recovery import VerifiedWavSeeker
        s = VerifiedWavSeeker(signed_manifest=self.track.manifest, ciphertext_store=self.track.store,
                              grant=self.grants[self.track.file_id], trusted_artist=self.track.artist_key,
                              owner_agent=self.track.owner, listener_agent=self.track.reader,
                              recipient_private=self.track.listener)
        return b"".join(s.iter_frames(start_frame)), s.frames

    def test_offline_play_outputs_exactly_the_authenticated_pcm(self):
        finished = []
        p = Player(resolve=self.spec, on_finished=finished.append)
        p.play(self.track.file_id)
        s = wait_state(p, {"finished", "error"})
        self.assertEqual(s["state"], "finished", s)
        pcm, frames = self.expected_pcm()
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), hashlib.sha256(pcm).hexdigest())
        self.assertEqual(s["position_frames"], frames)
        self.assertEqual(s["source"], "offline")
        self.assertIsNotNone(s["time_to_first_audio_ms"])
        self.assertEqual(finished, [self.track.file_id])

    def test_pause_resume_seek_and_stop(self):
        p = Player(resolve=self.spec)
        p.play(self.track.file_id)
        wait_state(p, {"playing"})
        p.pause()
        self.assertEqual(p.status()["state"], "paused")
        p.resume()
        self.assertEqual(p.status()["state"], "playing")
        total = p.status()["total_frames"]
        p.seek(total // 2)
        s = wait_state(p, {"finished"})
        pcm, _ = self.expected_pcm(total // 2)
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), hashlib.sha256(pcm).hexdigest())
        with self.assertRaises(PlaybackError):
            p.seek(total)
        p.play(self.track.file_id)
        wait_state(p, {"playing"})
        stopped = p.stop()
        self.assertEqual(stopped["state"], "stopped")
        self.assertNotEqual(stopped["state"], "finished")
        with self.assertRaises(PlaybackError):
            p.pause()

    def test_new_track_supersedes_old_worker_without_state_corruption(self):
        other = Track(self.root / "b", seconds=0.3)
        self.grants[other.file_id] = other.licence()
        gate = threading.Event()

        def resolve(key):
            if key == self.track.file_id:
                spec = self.spec(key)
                original = spec.manifest
                # Slow first session: blocks inside verification-time work.
                class Slow(dict):
                    def __getitem__(s, k):
                        gate.wait(2)
                        return original[k]
                spec.manifest = Slow(original)
                return spec
            return SessionSpec(key=key, manifest=other.manifest, grant=self.grants[key],
                               artist_key=other.artist_key, owner_agent=other.owner,
                               listener_agent=other.reader, recipient=other.listener, store=other.store)
        p = Player(resolve=resolve)
        p.play(self.track.file_id)
        p.play(other.file_id)
        gate.set()
        s = wait_state(p, {"finished", "error"})
        self.assertEqual((s["state"], s["track_key"]), ("finished", other.file_id))
        time.sleep(0.3)
        self.assertEqual(p.status()["track_key"], other.file_id)

    def test_corrupt_ciphertext_never_reaches_output(self):
        chunk = self.track.manifest["body"]["chunks"][2]
        path = object_path(self.track.store, chunk["sha256"])
        data = bytearray(path.read_bytes())
        data[5] ^= 1
        path.write_bytes(data)
        p = Player(resolve=self.spec)
        p.play(self.track.file_id)
        s = wait_state(p, {"error", "finished"})
        self.assertEqual(s["state"], "error")
        self.assertTrue(all(r.bytes == 0 for r in Recorder.instances))

    def test_unauthorised_listener_or_forged_grant_produces_no_audio(self):
        for override in ({"recipient": X25519PrivateKey.generate()}, {"listener_agent": "uhCAkMallory"},
                         {"grant": Track(self.root / "z").licence()}):
            with self.subTest(override=list(override)):
                Recorder.instances = []
                p = Player(resolve=lambda k: self.spec(k, **override))
                p.play(self.track.file_id)
                s = wait_state(p, {"error", "finished"})
                self.assertEqual(s["state"], "error")
                self.assertEqual(Recorder.instances, [])

    def test_expired_stream_grant_is_refused(self):
        grant = self.track.stream_grant(lifetime=1)
        self.grants[self.track.file_id] = grant
        with mock.patch("music_catalogue.content_grants.time.time", return_value=time.time() + 3600):
            p = Player(resolve=self.spec)
            p.play(self.track.file_id)
            s = wait_state(p, {"error", "finished"})
        self.assertEqual(s["state"], "error")

    def test_volume_scales_output_but_not_authenticated_digest(self):
        rec = Recorder(None)
        out = VolumeOutput(rec, lambda: 0.5)
        out.write(b"\x00\x40\x00\xc0")  # +16384, -16384
        self.assertEqual(rec.bytes, 4)
        self.assertEqual(rec.digest.hexdigest(), hashlib.sha256(b"\x00\x20\x00\xe0").hexdigest())
        p = Player(resolve=self.spec)
        with self.assertRaises(PlaybackError):
            p.set_volume(1.5)
        self.assertEqual(p.set_volume(0.25)["volume"], 0.25)


if __name__ == "__main__":
    unittest.main()
