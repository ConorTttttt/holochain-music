"""v1 app streaming: Download manager + Player over the real MoQ host binary."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from holochain_storage.package import canonical, object_path, verify_package
from holochain_music import player as player_mod
from holochain_music.catalogue import HostCandidate, TrustedTrack
from holochain_music.player import Player, SessionSpec
from holochain_music import streaming
from holochain_music.streaming import Download, TrackUnavailable
from music_catalogue.moq_host import MoqHost
from music_catalogue.seekable_recovery import VerifiedWavSeeker

from test_v1_app_player import Recorder, wait_state
from v1_fixtures import Track


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MOQ_BIN"), "set HOLOCHAIN_MOQ_BIN for real QUIC tests")
class StreamingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-v1-stream-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.binary = Path(os.environ["HOLOCHAIN_MOQ_BIN"]).resolve(strict=True)
        # 2 s of 8 kHz mono in 1 KiB chunks: ~32 encrypted objects.
        self.track = Track(self.root / "t", seconds=2.0)
        (self.root / "manifest.json").write_bytes(canonical(self.track.manifest))
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # A fixed port, as the app persists, so the published URL survives restarts.
        self.host = MoqHost(moq_binary=self.binary, store=self.track.store, cert_dir=self.root / "cert",
                            state_dir=self.root / "state", bind=f"127.0.0.1:{port}")
        self.host.set_files([{"manifest": self.root / "manifest.json",
                              "trusted_artist_hex": self.track.artist_key.hex(),
                              "manifest_sha256": self.track.digest}])
        self.host.start()
        self.addCleanup(self.host.stop)
        self.listener_store = self.root / "listener"
        Recorder.instances = []
        p = mock.patch.object(player_mod, "NullOutput", Recorder)
        p.start()
        self.addCleanup(p.stop)

    def download(self, **kw):
        trusted = TrustedTrack("uhCAkArtistAgent", {}, self.track.artist_key, self.track.manifest,
                               self.track.digest, [HostCandidate("uhCAkHost", b"", self.host.url, self.host.fingerprint)])
        d = Download(trusted=trusted, store=self.listener_store, moq_binary=self.binary,
                     stall_timeout=5, **kw)
        self.addCleanup(d.stop)
        return d

    def player_for(self, d, grant):
        t = self.track
        return Player(resolve=lambda key: SessionSpec(
            key=key, manifest=t.manifest, grant=grant, artist_key=t.artist_key, owner_agent=t.owner,
            listener_agent=t.reader, recipient=t.listener, store=self.listener_store, download=d,
            source="streaming"))

    def expected(self, start=0):
        s = VerifiedWavSeeker(signed_manifest=self.track.manifest, ciphertext_store=self.track.store,
                              grant=self.track.licence(), trusted_artist=self.track.artist_key,
                              owner_agent=self.track.owner, listener_agent=self.track.reader,
                              recipient_private=self.track.listener)
        return hashlib.sha256(b"".join(s.iter_frames(start))).hexdigest(), s.frames

    def test_stream_plays_authenticated_pcm_and_completes_download(self):
        d = self.download()
        p = self.player_for(d, self.track.licence())
        p.play(self.track.file_id)
        s = wait_state(p, {"finished", "error"}, timeout=60)
        self.assertEqual(s["state"], "finished", s)
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), self.expected()[0])
        deadline = time.monotonic() + 30
        while d.progress()["state"] != "complete" and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(d.progress()["state"], "complete")
        verify_package(self.track.manifest, self.listener_store, self.track.artist_key)

    def test_seek_far_ahead_restarts_transfer_at_needed_chunk(self):
        d = self.download()
        p = self.player_for(d, self.track.licence())
        p.play(self.track.file_id)
        wait_state(p, {"playing", "buffering"}, timeout=30)
        total = p.status()["total_frames"]
        target = total * 3 // 4
        p.seek(target)
        s = wait_state(p, {"finished", "error"}, timeout=60)
        self.assertEqual(s["state"], "finished", s)
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), self.expected(target)[0])
        deadline = time.monotonic() + 30
        while d.progress()["state"] != "complete" and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(d.progress()["state"], "complete", d.progress())
        self.assertGreaterEqual(d.progress()["restarts_for_seek"], 1)

    def test_corrupt_host_object_is_never_played_and_track_becomes_unavailable(self):
        bad = self.track.manifest["body"]["chunks"][1]
        path = object_path(self.track.store, bad["sha256"])
        data = bytearray(path.read_bytes())
        data[0] ^= 0xFF
        path.write_bytes(data)
        with mock.patch.object(streaming, "MAX_BACKOFF", 0.2):
            d = self.download()
            p = self.player_for(d, self.track.licence())
            p.play(self.track.file_id)
            s = wait_state(p, {"error", "finished"}, timeout=120)
        self.assertEqual(s["state"], "error")
        self.assertEqual(d.progress()["state"], "unavailable")
        self.assertFalse(object_path(self.listener_store, bad["sha256"]).exists())
        # Only PCM from chunk 0 (verified) could have been output; nothing from chunk 1.
        played = sum(r.bytes for r in Recorder.instances)
        self.assertLess(played, self.track.manifest["body"]["chunks"][0]["plain_bytes"])

    def test_host_outage_then_resume_keeps_verified_objects(self):
        d = self.download()
        d.start()
        deadline = time.monotonic() + 30
        while d.progress()["available_chunks"] < 5 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.host.stop()
        with mock.patch.object(streaming, "MAX_BACKOFF", 0.2):
            deadline = time.monotonic() + 90
            while d.progress()["state"] not in ("unavailable", "complete") and time.monotonic() < deadline:
                time.sleep(0.1)
        if d.progress()["state"] == "complete":
            self.skipTest("transfer finished before the host was stopped")
        kept = d.progress()["available_chunks"]
        self.assertGreater(kept, 0)
        self.host.start()
        d.start()
        deadline = time.monotonic() + 60
        while d.progress()["state"] != "complete" and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(d.progress()["state"], "complete", d.progress())
        verify_package(self.track.manifest, self.listener_store, self.track.artist_key)

    def test_wait_for_raises_when_unavailable(self):
        d = self.download()
        d.state, d.error = "unavailable", "test"
        with self.assertRaises(TrackUnavailable):
            d.wait_for(self.track.manifest["body"]["chunks"][0], timeout=1)


if __name__ == "__main__":
    unittest.main()
