"""S16 in-flight seek over authenticated MoQ progress (synthetic callback fixture).

This validates real Ed25519/X25519/AES-GCM and timed PCM, but only the
separate three-conductor Sweettest can prove real Holochain/MoQ network flow.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shutil
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import wave

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import (
    StorageError, _read_verified_chunk, create_package, manifest_digest,
    object_path, public_key_bytes,
)
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.inflight_seek import (
    InflightWavSeeker, stream_seek_granted_moq_from_live_conductor,
)
from music_catalogue.streaming_playback import VerifiedChunkGate


class S16Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="s16-grant-seek-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.artist_key = public_key_bytes(self.artist)
        self.listener = X25519PrivateKey.generate()
        self.pcm = b"".join(struct.pack("<h", (i * 37) % 22000 - 11000)
                            for i in range(64_000))
        out = io.BytesIO()
        with wave.open(out, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(self.pcm)
        source = self.root / "demo.wav"
        source.write_bytes(out.getvalue())
        self.source_cas = self.root / "encrypted-host"
        self.listener_cas = self.root / "encrypted-listener"
        self.manifest, key = create_package(source, self.source_cas, self.artist,
                                            chunk_size=4093)  # deliberately odd
        self.grant = issue_content_grant(
            owner_signer=self.artist, owner_agent="alice", listener_agent="bob",
            recipient_public=self.listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            signed_manifest=self.manifest, content_key=key,
        )
        self.chunks = self.manifest["body"]["chunks"]
        self.plan = ((24_000, 4_000), (8_000, 4_000))
        self.sent = 0
        self.first_verified_prefix = 0

    def seeker(self, gate, **changes):
        args = dict(signed_manifest=self.manifest, ciphertext_store=self.listener_cas,
                    grant=self.grant, trusted_artist=self.artist_key,
                    owner_agent="alice", listener_agent="bob",
                    recipient_private=self.listener, chunk_waiter=gate.wait_for)
        args.update(changes)
        return InflightWavSeeker(**args)

    def _copy(self, index):
        chunk = self.chunks[index]
        dest = object_path(self.listener_cas, chunk["sha256"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(object_path(self.source_cas, chunk["sha256"]), dest)
        _read_verified_chunk(self.listener_cas, chunk)

    def run_bridge(self, *, grant=None, fail_index=None, tamper_index=None,
                   plan=None, wait=0.09, backend="null"):
        def verified_receive(**kwargs):
            trusted = kwargs["on_trusted_manifest"]
            notified = kwargs["on_verified_chunk"]
            trusted(self.manifest, self.artist_key, "alice", "bob")
            for chunk in self.chunks:
                index = chunk["index"]
                if index == fail_index:
                    raise RuntimeError("S16 simulated MoQ transport interrupted")
                self._copy(index)
                if index == tamper_index:
                    p = object_path(self.listener_cas, chunk["sha256"])
                    b = bytearray(p.read_bytes())
                    b[-1] ^= 0x01
                    p.write_bytes(b)
                _read_verified_chunk(self.listener_cas, chunk)
                self.sent += 1
                notified(index)
                time.sleep(wait)
            return dict(verified=True, file_id=self.manifest["body"]["file_id"],
                        received_chunks=len(self.chunks),
                        manifest_sha256=manifest_digest(self.manifest))
        with patch("music_catalogue.inflight_seek.receive_moq_from_live_conductor", side_effect=verified_receive):
            return stream_seek_granted_moq_from_live_conductor(
                grant=self.grant if grant is None else grant,
                recipient_private=self.listener,
                bridge_binary=self.root / "bridge", moq_binary=self.root / "moq",
                admin_port=1, app_id="s16-test", catalogue_dna="a", storage_dna="b",
                reader_agent="bob", artist_agent="alice", node_agent="carol",
                track_id="f" * 64, storage_url="http://127.0.0.1:1999",
                target_store=self.listener_cas,
                seek_ranges=self.plan if plan is None else plan,
                backend=backend, timeout=20,
            )

    def test_forward_seek_then_rewind_overlap_verified_moq(self):
        report = self.run_bridge()
        self.assertTrue(report["inflight_seek"])
        self.assertTrue(report["all_seeks_before_last_chunk"])
        self.assertEqual(report["seek_count"], 2)
        self.assertEqual(report["verified_ciphertext_chunks"], len(self.chunks))
        self.assertEqual(report["received_chunks"], len(self.chunks))
        self.assertEqual(report["total_frames"], 64000)
        self.assertEqual([r["seek_start_frame"] for r in report["seek_ranges"]], [24000, 8000])
        for (start, n), result in zip(self.plan, report["seek_ranges"]):
            expected_hash = hashlib.sha256(self.pcm[start * 2:(start + n) * 2]).hexdigest()
            self.assertEqual(result["output_pcm_sha256"], expected_hash)
            self.assertEqual(result["output_frames"], n)
            self.assertTrue(result["playback_complete"])
            self.assertLess(result["first_pcm_after_verified_chunks"], len(self.chunks))
            self.assertLessEqual(result["max_buffered_pcm_bytes"], 65536)

    def test_header_and_backward_seek_before_complete_cas(self):
        gate = VerifiedChunkGate(total=len(self.chunks), stall_timeout=0.2)
        self._copy(0)
        gate.mark(0)
        seeker = self.seeker(gate)
        seeker.open()
        self.assertEqual(seeker.frames, 64000)
        self.assertFalse(object_path(self.listener_cas, self.chunks[-1]["sha256"]).exists())
        gate.fail(RuntimeError("incomplete transport"))
        with self.assertRaises(PlaybackError):
            seeker.play(start_frame=12000, frame_count=500)

    def test_wrong_listener_grant_refused_without_audio(self):
        bad = dict(self.grant)
        bad["body"] = {**self.grant["body"], "listener_agent": "mallory"}
        with self.assertRaises(StorageError):
            self.run_bridge(grant=bad)
        self.assertEqual(self.sent, 0)

    def test_wrong_artist_signer_refused_before_audio(self):
        gate = VerifiedChunkGate(total=len(self.chunks))
        with self.assertRaises(StorageError):
            self.seeker(gate, trusted_artist=public_key_bytes(Ed25519PrivateKey.generate()))

    def test_wrong_private_key_refused_before_audio(self):
        gate = VerifiedChunkGate(total=len(self.chunks))
        with self.assertRaises(StorageError):
            self.seeker(gate, recipient_private=X25519PrivateKey.generate())

    def test_tampered_notified_ciphertext_never_emitted(self):
        with self.assertRaises(StorageError):
            self.run_bridge(tamper_index=0)

    def test_network_break_does_not_claim_success(self):
        with self.assertRaises(RuntimeError):
            self.run_bridge(fail_index=8, wait=0.01)

    def test_network_break_after_some_pcm_also_refuses_full_success(self):
        # A network failure after early authorised PCM must never claim
        # that the entire encrypted song finished successfully.
        with self.assertRaises(RuntimeError):
            self.run_bridge(fail_index=24, wait=0.05)
        self.assertEqual(self.sent, 24)

    def test_seek_bounds_reject_before_device(self):
        gate = VerifiedChunkGate(total=len(self.chunks))
        self._copy(0)
        gate.mark(0)
        seek = self.seeker(gate)
        seek.open()
        for start, count in ((True, 1), (-1, 1), (64001, 1), (63999, 2),
                             (0, -1), (64000, 1), (0, False)):
            with self.subTest(start=start, count=count), self.assertRaises(PlaybackError):
                seek.play(start_frame=start, frame_count=count)

    def test_reject_invalid_seek_plan(self):
        for plan in ((), ((1, 10),) * 5, ([1, 2],), ((True, 10),), ((1, -1), (2, 3),)):
            with self.subTest(plan=plan), self.assertRaises(PlaybackError):
                self.run_bridge(plan=plan)
        self.assertEqual(self.sent, 0)

    def test_inflight_replay_requires_actual_backward_seek(self):
        with self.assertRaises(PlaybackError):
            self.run_bridge(plan=((8000, 4000), (24000, 4000)), wait=0.01)

    def test_seek_range_can_cross_odd_plain_chunk_boundary(self):
        # Verify exact PCM even when the S1 encrypted chunk ends mid PCM sample.
        gate = VerifiedChunkGate(total=len(self.chunks))
        for i in range(len(self.chunks)):
            self._copy(i)
            gate.mark(i)
        gate.finish()
        seeker = self.seeker(gate)
        seeker.open()
        for start, n in ((0, 64), (1020, 4000), (63999, 1)):
            self.assertEqual(b"".join(seeker.iter_frames(start, n)),
                             self.pcm[start * 2:(start + n) * 2])

    def test_mutated_cas_after_open_rejected(self):
        gate = VerifiedChunkGate(total=len(self.chunks))
        for i in range(len(self.chunks)):
            self._copy(i)
            gate.mark(i)
        gate.finish()
        seeker = self.seeker(gate)
        seeker.open()
        chunk = self.chunks[6]
        p = object_path(self.listener_cas, chunk["sha256"])
        data = bytearray(p.read_bytes()); data[0] ^= 0x5A; p.write_bytes(data)
        with self.assertRaises(StorageError):
            seeker.play(start_frame=12_500, frame_count=1000)


if __name__ == "__main__":
    unittest.main()
