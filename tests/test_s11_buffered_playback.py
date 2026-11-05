"""S11 bounded playout / ALSA adapter tests; no physical speakers needed."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import StorageError, create_package, object_path, public_key_bytes
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import PlaybackError, play_granted_wav
from music_catalogue.buffered_playback import (
    AlsaOutput, AudioFormat, BufferedPcmPlayer, MAX_FRAME_BYTES,
    play_granted_wav_realtime,
)
from test_s10_granted_audio import _wav_bytes


class S11GrantToBufferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="holochain-music-s11-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.owner, self.listener = "Alice", "Bob"
        self.artist = Ed25519PrivateKey.generate()
        self.key = public_key_bytes(self.artist)
        self.reader = X25519PrivateKey.generate()
        listener_public = self.reader.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        wav, self.pcm = _wav_bytes()
        self.root.joinpath("song.wav").write_bytes(wav)
        self.store = self.root / "ciphertext"
        self.manifest, self.secret = create_package(self.root / "song.wav", self.store, self.artist, chunk_size=1024)
        self.grant = issue_content_grant(
            owner_signer=self.artist, owner_agent=self.owner, listener_agent=self.listener,
            recipient_public=listener_public, signed_manifest=self.manifest,
            content_key=self.secret,
        )

    def kwargs(self):
        return dict(signed_manifest=self.manifest, ciphertext_store=self.store,
                    grant=self.grant, trusted_artist=self.key, owner_agent=self.owner,
                    listener_agent=self.listener, recipient_private=self.reader)

    def test_timed_null_pcm_matches_authentic_s10_samples(self):
        began = time.monotonic()
        result = play_granted_wav_realtime(**self.kwargs(), backend="null")
        elapsed = time.monotonic() - began
        self.assertTrue(result["playback_complete"])
        self.assertEqual(result["pcm_sha256"], hashlib.sha256(self.pcm).hexdigest())
        self.assertEqual(result["output_pcm_sha256"], result["pcm_sha256"])
        self.assertEqual(result["output_pcm_bytes"], len(self.pcm))
        self.assertEqual(result["output_frames"], 6000)
        self.assertLessEqual(result["max_buffered_pcm_bytes"], result["buffer_capacity_bytes"])
        self.assertLessEqual(result["buffer_capacity_bytes"], 16 * MAX_FRAME_BYTES)
        self.assertGreaterEqual(elapsed, 0.30)  # actual 0.375 s of PCM
        self.assertLess(elapsed, 3)

    def test_wrong_listener_grant_refuses_before_any_pcm_or_device(self):
        launches = []
        player = BufferedPcmPlayer(output_factory=lambda fmt: launches.append(fmt))
        with self.assertRaises(StorageError):
            play_granted_wav_realtime(**{**self.kwargs(), "listener_agent": "Mallory"}, player=player)
        self.assertEqual(launches, [])

    def test_corrupt_ciphertext_refuses_before_initialising_device(self):
        chunk = self.manifest["body"]["chunks"][3]
        f = object_path(self.store, chunk["sha256"])
        altered = bytearray(f.read_bytes())
        altered[1] ^= 0x01
        f.write_bytes(altered)
        launches = []
        player = BufferedPcmPlayer(output_factory=lambda fmt: launches.append(fmt))
        with self.assertRaises(StorageError):
            play_granted_wav_realtime(**self.kwargs(), player=player)
        self.assertEqual(launches, [])

    def test_realtime_alsa_initialisation_fails_if_aplay_not_available(self):
        with patch("music_catalogue.buffered_playback.shutil.which", return_value=None):
            with self.assertRaises(PlaybackError):
                play_granted_wav_realtime(**self.kwargs(), backend="alsa")

    def test_offline_demo_cli_runs_safely_without_hardware(self):
        completed = subprocess.run(
            [sys.executable, "-m", "music_catalogue.playback_cli",
             "demo", "--backend", "null", "--seconds", "0.2"],
            capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1], timeout=8,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        import json
        report = json.loads(completed.stdout)
        self.assertEqual(report["output_frames"], 3200)
        self.assertTrue(report["playback_complete"])
        self.assertEqual(report["audio_backend"], "null")

    def test_format_callback_precedes_any_pcm_and_matches_wav(self):
        calls = []
        play_granted_wav(**self.kwargs(), pcm_sink=lambda b: calls.append(("audio", len(b))),
                         format_callback=lambda f: calls.append(("format", f)))
        self.assertEqual(calls[0], ("format", {"sample_rate": 16000, "channels": 1,
                                                "bits_per_sample": 16}))
        self.assertEqual(calls[1][0], "audio")


class S11PlaybackEngineTests(unittest.TestCase):
    fmt = dict(sample_rate=16000, channels=1, bits_per_sample=16)

    def test_invalid_frame_size_and_unsupported_format_rejected(self):
        player = BufferedPcmPlayer(prebuffer_blocks=1)
        with self.assertRaises(PlaybackError):
            player.start(dict(sample_rate=12345, channels=1, bits_per_sample=16))
        player.start(self.fmt)
        try:
            with self.assertRaises(PlaybackError):
                player.feed(b"z")
            with self.assertRaises(PlaybackError):
                player.feed(b"0" * 16385)
        finally:
            player.stop()

    def test_pause_resume_preserves_audio_samples(self):
        player = BufferedPcmPlayer(prebuffer_blocks=1, max_blocks=3)
        player.start(self.fmt)
        block = b"\x01\x00" * 1600  # 0.1 sec of mono PCM16
        player.pause()
        producer = threading.Thread(target=lambda: [player.feed(block) for _ in range(4)], daemon=True)
        producer.start()
        time.sleep(0.15)
        self.assertEqual(player._played_bytes, 0)
        player.resume()
        producer.join(timeout=3)
        self.assertFalse(producer.is_alive())
        result = player.finish()
        self.assertEqual(result["output_pcm_bytes"], 4 * len(block))
        self.assertEqual(result["output_frames"], 6400)
        self.assertLessEqual(result["max_buffered_pcm_bytes"], 3 * MAX_FRAME_BYTES)

    def test_stop_discards_queue_and_rejects_more_audio(self):
        player = BufferedPcmPlayer(prebuffer_blocks=2, max_blocks=3)
        player.start(self.fmt)
        player.pause()
        player.feed(b"\x01\x00" * 1024)
        player.stop()
        self.assertEqual(player._played_bytes, 0)
        with self.assertRaises(PlaybackError):
            player.feed(b"\x01\x00" * 1024)
        with self.assertRaises(PlaybackError):
            player.finish()

    def test_underrun_is_reported_when_producer_stalls(self):
        player = BufferedPcmPlayer(prebuffer_blocks=1)
        player.start(self.fmt)
        player.feed(b"\x12\x00" * 800)
        time.sleep(0.20)  # 0.05s of output then queue starves
        player.feed(b"\x34\x00" * 800)
        report = player.finish()
        self.assertGreaterEqual(report["buffer_underruns"], 1)
        self.assertEqual(report["output_frames"], 1600)

    def test_rejects_overlarge_or_duplicate_start_and_invalid_capacity(self):
        with self.assertRaises(PlaybackError):
            BufferedPcmPlayer(max_blocks=0)
        with self.assertRaises(PlaybackError):
            BufferedPcmPlayer(max_blocks=2, prebuffer_blocks=3)
        player = BufferedPcmPlayer(prebuffer_blocks=1)
        player.start(self.fmt)
        try:
            with self.assertRaises(PlaybackError):
                player.start(self.fmt)
        finally:
            player.stop()

    def test_alsa_device_arguments_are_not_shell_executed(self):
        args = []
        class FakePipe:
            closed = False
            def write(self, b):
                return len(b)
            def flush(self):
                pass
            def close(self):
                self.closed = True
        class FakeProc:
            def __init__(self):
                self.stdin = FakePipe()
            def poll(self):
                return None
            def wait(self, timeout=None):
                return 0
        with patch("music_catalogue.buffered_playback.subprocess.Popen", side_effect=lambda a, **kw: (args.append((a,kw)) or FakeProc())):
            device = AlsaOutput(AudioFormat(16000,1,16), device="default", executable="/usr/bin/aplay")
            device.write(b"\0\0")
            device.close()
        self.assertEqual(args[0][0][:7], ["/usr/bin/aplay", "-q", "-t", "raw", "-f", "S16_LE", "-r"])
        self.assertEqual(args[0][0][-2:], ["-D", "default"])
        self.assertNotIn("shell", args[0][1])


if __name__ == "__main__":
    unittest.main()
