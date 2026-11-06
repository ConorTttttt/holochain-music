"""Seek performance and correctness regression tests (offline 5-minute WAV).

Baseline before the fix (packaging/bench-seek.py, 5:31 track, ALSA null):
seek -> first PCM median 3250 ms, p95 3837 ms. Target here: < 500 ms.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import create_package, object_path
import holochain_storage.package as package_mod
from music_catalogue.buffered_playback import AlsaOutput, AudioFormat
from music_catalogue.content_grants import issue_personal_licence
from music_catalogue.granted_audio import PlaybackError
from holochain_music import player as player_mod
from holochain_music.player import Player, SessionSpec

from test_v1_app_player import Recorder

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("bench_seek", REPO / "packaging" / "bench-seek.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)
RATE, FRAME = 44100, 4


class FiveMinuteTrack:
    """One shared encrypted 5:00 44.1 kHz stereo WAV for the module."""
    root = None

    @classmethod
    def get(cls):
        if cls.root is None:
            cls.tmp = tempfile.TemporaryDirectory(prefix="hm-seekperf-")
            cls.root = Path(cls.tmp.name)
            wav = cls.root / "five.wav"
            bench.make_wav(wav, 300)
            cls.pcm = wav.read_bytes()[44:]
            cls.artist = Ed25519PrivateKey.generate()
            cls.store = cls.root / "cas"
            cls.manifest, cls.key = create_package(wav, cls.store, cls.artist)
            wav.unlink()
            cls.listener = X25519PrivateKey.generate()
            pub = cls.listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            cls.grant = issue_personal_licence(owner_signer=cls.artist, owner_agent="uhCAkA", listener_agent="uhCAkL",
                                               recipient_public=pub, signed_manifest=cls.manifest, content_key=cls.key)
        return cls


def tearDownModule():
    if FiveMinuteTrack.root is not None:
        FiveMinuteTrack.tmp.cleanup()


class SeekPerformance(unittest.TestCase):
    def setUp(self):
        self.t = FiveMinuteTrack.get()
        Recorder.instances = []
        p = mock.patch.object(player_mod, "NullOutput", Recorder)
        p.start()
        self.addCleanup(p.stop)
        self.resolves = 0

    def resolve(self, key):
        self.resolves += 1
        from holochain_storage.package import public_key_bytes
        t = self.t
        return SessionSpec(key=key, manifest=t.manifest, grant=t.grant, artist_key=public_key_bytes(t.artist),
                           owner_agent="uhCAkA", listener_agent="uhCAkL", recipient=t.listener, store=t.store)

    def wait(self, p, pred, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            s = p.status()
            if pred(s):
                return s
            time.sleep(0.002)
        raise AssertionError(f"timeout; status={p.status()}")

    def test_repeated_seeks_are_fast_and_verify_whole_file_once(self):
        calls = {"verify_package": 0}
        real_verify = player_mod.verify_package

        def counting(*a, **k):
            calls["verify_package"] += 1
            return real_verify(*a, **k)
        with mock.patch.object(player_mod, "verify_package", counting):
            p = Player(resolve=self.resolve)
            p.play("five")
            self.wait(p, lambda s: s["output_active"])
            total = p.status()["total_frames"]
            self.assertEqual(total, 300 * RATE)
            latencies = []
            import random
            rng = random.Random(3)
            for _ in range(15):
                p.seek(rng.randrange(0, total - RATE))
                self.wait(p, lambda s: s["output_active"] and s["state"] == "playing")
                latencies.append(p.seek_metrics()[-1]["latency_ms"])
                time.sleep(0.15)
            p.stop()
        median = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[-1]
        print(f"\nseek->first PCM over 15 seeks: median {median:.1f} ms, p95 {p95:.1f} ms", file=sys.stderr)
        self.assertLess(median, 500)
        self.assertLess(p95, 500)
        self.assertEqual(calls["verify_package"], 1, "the whole file must be verified once per open, not per seek")
        self.assertEqual(self.resolves, 1, "seeks must not re-resolve or re-open the track")

    def test_seek_output_is_exactly_the_authenticated_pcm_from_the_target(self):
        p = Player(resolve=self.resolve)
        p.play("five")
        self.wait(p, lambda s: s["output_active"])
        target = 300 * RATE - 3 * RATE + 17   # 3 s before the end, odd frame
        p.seek(target)
        self.wait(p, lambda s: s["state"] == "finished", timeout=15)
        expected = hashlib.sha256(self.t.pcm[target * FRAME:]).hexdigest()
        self.assertEqual(Recorder.instances[-1].digest.hexdigest(), expected)

    def test_chunk_tampered_after_open_is_caught_on_seek_and_never_played(self):
        p = Player(resolve=self.resolve)
        p.play("five")
        self.wait(p, lambda s: s["output_active"])
        chunks = self.t.manifest["body"]["chunks"]
        victim = chunks[len(chunks) // 2]
        path = object_path(self.t.store, victim["sha256"])
        original = path.read_bytes()
        tampered = bytearray(original)
        tampered[100] ^= 1
        try:
            path.write_bytes(tampered)
            offset = sum(c["plain_bytes"] for c in chunks[:victim["index"]])
            frame = (offset - 44) // FRAME + 10
            Recorder.instances = []
            p.seek(frame)
            s = self.wait(p, lambda s: s["state"] in ("error", "finished"))
            self.assertEqual(s["state"], "error")
            self.assertTrue(all(r.bytes == 0 for r in Recorder.instances), "tampered audio reached the output")
        finally:
            path.write_bytes(original)
            p.stop()

    def test_rapid_seeks_coalesce_to_the_newest_target(self):
        p = Player(resolve=self.resolve)
        p.play("five")
        self.wait(p, lambda s: s["output_active"])
        targets = [RATE * (10 + 7 * i) for i in range(12)]
        barrier = threading.Barrier(len(targets))
        order = []

        def go(t):
            barrier.wait()
            order.append(t)
            p.seek(t)
        threads = [threading.Thread(target=go, args=(t,)) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join(10)
        s = self.wait(p, lambda s: s["output_active"] and s["state"] == "playing")
        metrics = p.seek_metrics()[-len(targets):]
        executed = [m for m in metrics if not m["coalesced"]]
        self.assertLess(len(executed), len(targets), "no seek was coalesced")
        # The surviving session plays from the last seek that executed, which is
        # the newest request (highest ticket wins; older waiting ones skip).
        self.assertGreaterEqual(s["position_frames"], executed[-1]["target"])
        self.assertLess(s["position_frames"], executed[-1]["target"] + 2 * RATE)
        p.stop()

    def test_status_reports_seeking_target_then_monotonic_position(self):
        p = Player(resolve=self.resolve)
        p.play("five")
        self.wait(p, lambda s: s["output_active"])
        target = 120 * RATE
        before = p.status()["seq"]
        s = p.seek(target)
        self.assertGreater(s["seq"], before)
        if s["state"] == "seeking":
            self.assertEqual(s["position_frames"], target)
            self.assertFalse(s["output_active"])
        self.wait(p, lambda s: s["state"] == "playing")
        last_pos, last_seq = -1, -1
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            s = p.status()
            self.assertGreaterEqual(s["seq"], last_seq)
            self.assertGreaterEqual(s["position_frames"], last_pos, "position moved backwards while playing")
            self.assertGreaterEqual(s["position_frames"], target)
            last_pos, last_seq = s["position_frames"], s["seq"]
            time.sleep(0.02)
        p.stop()


class FastAbort(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "ALSA/aplay backend is Linux-only (WASAPI abort: test_windows_port)")
    def test_output_process_ignoring_sigterm_is_killed_immediately(self):
        stubborn = Path(tempfile.mkdtemp()) / "stubborn-aplay"
        stubborn.write_text("#!/usr/bin/env python3\nimport signal, sys, time\n"
                            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                            "while True:\n    time.sleep(1)\n")
        stubborn.chmod(0o755)
        out = AlsaOutput(AudioFormat(44100, 2, 16), executable=str(stubborn), buffer_us=200_000)
        t = time.perf_counter()
        out.abort()
        elapsed = time.perf_counter() - t
        self.assertLess(elapsed, 0.5, f"abort took {elapsed:.2f} s")
        self.assertIsNotNone(out.proc.poll())

    def test_invalid_buffer_time_refused(self):
        with self.assertRaises(PlaybackError):
            AlsaOutput(AudioFormat(44100, 2, 16), executable="/bin/true", buffer_us=10)


if __name__ == "__main__":
    unittest.main()
