"""S13 bounded adaptive PCM and authenticated network-jitter contract tests.

The mock conductor bridge is a unit fixture, not evidence of live QUIC. Real
QUIC + 3-conductor evidence comes exclusively from the Rust S13 Sweettest.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import struct
import tempfile
import threading
import time
import unittest
import wave
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import StorageError, _read_verified_chunk, create_package, manifest_digest, object_path, public_key_bytes
from music_catalogue.adaptive_playback import AdaptivePcmPlayer
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.moq_conductor import ConductorBridgeError
from music_catalogue.streaming_playback import stream_granted_moq_from_live_conductor


class AdaptivePlayerTests(unittest.TestCase):
    fmt = {"sample_rate": 16000, "channels": 1, "bits_per_sample": 16}
    block = b"\x0a\x00" * 2048  # 0.128 second of authenticated PCM16

    def test_refill_after_starvation_is_bounded_and_byte_exact(self):
        player = AdaptivePcmPlayer(initial_blocks=2, ceiling_blocks=6,
                                   growth_blocks=2, stable_blocks=50)
        player.start(self.fmt)
        player.feed(self.block)
        player.feed(self.block)
        deadline = time.monotonic() + 2
        while player._played_bytes < len(self.block) * 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.20)
        self.assertGreaterEqual(player._rebuffer_events, 1)
        for _ in range(8):
            player.feed(self.block)
        out = player.finish(timeout=4)
        self.assertTrue(out["playback_complete"])
        self.assertEqual(out["output_pcm_bytes"], 10 * len(self.block))
        self.assertEqual(out["output_pcm_sha256"], hashlib.sha256(self.block * 10).hexdigest())
        self.assertGreaterEqual(out["rebuffer_events"], 1)
        self.assertEqual(out["rebuffer_events"], out["buffer_underruns"])
        self.assertGreater(out["rebuffer_duration_ms"], 0)
        self.assertLessEqual(out["adaptive_final_target_blocks"], 6)
        self.assertLessEqual(out["max_buffered_pcm_bytes"], 65536)

    def test_threshold_decreases_after_stable_output(self):
        player = AdaptivePcmPlayer(initial_blocks=1, ceiling_blocks=6,
                                   growth_blocks=3, stable_blocks=2)
        player.start(self.fmt)
        player.feed(self.block)
        deadline = time.monotonic() + 2
        while player._played_bytes < len(self.block) and time.monotonic() < deadline:
            time.sleep(0.01)
        deadline = time.monotonic() + 2
        while player._rebuffer_events == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(player._rebuffer_events, 1)
        for _ in range(8):
            player.feed(self.block)
        out = player.finish(timeout=4)
        self.assertEqual(out["adaptive_final_target_blocks"], 1)
        self.assertEqual(out["output_pcm_bytes"], 9 * len(self.block))

    def test_invalid_parameters_and_capacity(self):
        invalid = [dict(initial_blocks=0), dict(initial_blocks=3, ceiling_blocks=2),
                   dict(ceiling_blocks=17), dict(growth_blocks=0),
                   dict(initial_blocks=True), dict(stable_blocks=0),
                   dict(max_blocks=2, ceiling_blocks=4), dict(prebuffer_blocks=2)]
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(PlaybackError):
                AdaptivePcmPlayer(**config)

    def test_pause_resume_does_not_discard_or_inject_pcm(self):
        p = AdaptivePcmPlayer(initial_blocks=1)
        p.start(self.fmt)
        p.pause()
        p.feed(self.block)
        time.sleep(0.1)
        self.assertEqual(p._played_bytes, 0)
        p.resume()
        out = p.finish(timeout=2)
        self.assertEqual(out["output_pcm_sha256"], hashlib.sha256(self.block).hexdigest())

    def test_stop_fails_incomplete_playback_not_false_success(self):
        p = AdaptivePcmPlayer(initial_blocks=1)
        p.start(self.fmt)
        p.pause()
        p.feed(self.block)
        p.stop()
        with self.assertRaises(PlaybackError):
            p.finish()
        with self.assertRaises(PlaybackError):
            p.feed(self.block)


class AdaptiveOverMoqContract(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix="s13-jitter-")
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.signer = Ed25519PrivateKey.generate()
        self.key = public_key_bytes(self.signer)
        self.private = X25519PrivateKey.generate()
        pcm = b"".join(struct.pack("<h", n % 13000) for n in range(16000 * 2))
        self.hash = hashlib.sha256(pcm).hexdigest()
        content = io.BytesIO()
        with wave.open(content, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(pcm)
        (self.root / "source.wav").write_bytes(content.getvalue())
        self.source, self.target = self.root / "source-cas", self.root / "target-cas"
        self.manifest, secret = create_package(self.root / "source.wav", self.source, self.signer, chunk_size=2048)
        self.grant = issue_content_grant(
            owner_signer=self.signer, owner_agent="alice", listener_agent="bob",
            recipient_public=self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            signed_manifest=self.manifest, content_key=secret,
        )
        self.received = len(self.manifest["body"]["chunks"])

    def _run(self, *, corrupted_at=None, fail_at=None, listener="bob", missing_grant=False):
        def transfer(*, on_trusted_manifest, on_verified_chunk, **unused):
            on_trusted_manifest(self.manifest, self.key, "alice", "bob")
            for chunk in self.manifest["body"]["chunks"]:
                i = chunk["index"]
                if i == fail_at:
                    raise ConductorBridgeError("deliberate network interruption")
                src = object_path(self.source, chunk["sha256"])
                dst = object_path(self.target, chunk["sha256"])
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
                if i == corrupted_at:
                    data = bytearray(dst.read_bytes())
                    data[0] ^= 1
                    dst.write_bytes(data)
                _read_verified_chunk(self.target, chunk)
                on_verified_chunk(i)
                # Deterministic bursts and lulls on an in-process fixture.
                if i in (6, 14, 22):
                    time.sleep(0.22)
                else:
                    time.sleep(0.008)
            return dict(verified=True, received_chunks=self.received,
                        cipher_bytes=sum(c["cipher_bytes"] for c in self.manifest["body"]["chunks"]),
                        manifest_sha256=manifest_digest(self.manifest),
                        file_id=self.manifest["body"]["file_id"])
        with patch("music_catalogue.streaming_playback.receive_moq_from_live_conductor", side_effect=transfer):
            return stream_granted_moq_from_live_conductor(
                grant={} if missing_grant else self.grant, recipient_private=self.private,
                bridge_binary=self.root / "bridge", moq_binary=self.root / "moq",
                admin_port=1234, app_id="s13", catalogue_dna="music", storage_dna="storage",
                reader_agent=listener, artist_agent="alice", node_agent="carol",
                track_id="a" * 32, storage_url="http://127.0.0.1:1",
                target_store=self.target, backend="null", timeout=15,
                adaptive_buffer=True,
            )

    def test_jittered_transfer_recovers_exact_pcm_while_overlapping(self):
        out = self._run()
        self.assertTrue(out["adaptive_buffer"])
        self.assertTrue(out["first_pcm_before_last_chunk"])
        self.assertLess(out["first_pcm_after_verified_chunks"], self.received)
        self.assertTrue(out["playback_complete"])
        self.assertEqual(out["verified_ciphertext_chunks"], self.received)
        self.assertEqual(out["output_pcm_sha256"], self.hash)
        self.assertEqual(out["output_pcm_bytes"], 64000)
        self.assertEqual(out["rebuffer_events"], out["buffer_underruns"])
        self.assertLessEqual(out["max_buffered_pcm_bytes"], 65536)

    def test_tampered_ciphertext_never_reports_success(self):
        with self.assertRaises(StorageError):
            self._run(corrupted_at=8)

    def test_network_aborts_fail_closed_even_after_first_pcm(self):
        with self.assertRaises(ConductorBridgeError):
            self._run(fail_at=16)

    def test_bad_grant_rejected_before_any_network_cas(self):
        with self.assertRaises(StorageError):
            self._run(missing_grant=True)
        self.assertFalse((self.target / "objects").exists())

    def test_wrong_listener_rejected_before_network(self):
        with self.assertRaises(PlaybackError):
            self._run(listener="mallory")
        self.assertFalse((self.target / "objects").exists())

    def test_nonboolean_adaptive_setting_refused(self):
        with self.assertRaises(PlaybackError):
            stream_granted_moq_from_live_conductor(
                grant=self.grant, recipient_private=self.private,
                bridge_binary=self.root / "bridge", moq_binary=self.root / "moq",
                admin_port=1234, app_id="s13", catalogue_dna="music", storage_dna="storage",
                reader_agent="bob", artist_agent="alice", node_agent="carol",
                track_id="a" * 32, storage_url="http://127.0.0.1:1",
                target_store=self.target, adaptive_buffer="true",
            )


if __name__ == "__main__":
    unittest.main()
