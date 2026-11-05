"""S12 stream overlap, malformed progress and fail-closed grant tests.

Rust MoQ and a live three-conductor Sweettest are separate integration gates.
Unit tests here exercise real Ed25519/X25519/AES-GCM with mocked authenticated
conductor callbacks; no fake mock transport is presented as QUIC evidence.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import threading
import time
import unittest
import wave
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import (StorageError, create_package, manifest_digest,
                                       object_path, public_key_bytes)
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.moq_conductor import ConductorBridgeError, _receive_verified_progress
from music_catalogue.streaming_playback import VerifiedChunkGate, stream_granted_moq_from_live_conductor


class TestVerifiedChunkGate(unittest.TestCase):
    def test_requires_correct_order_and_rejects_duplicate(self):
        gate = VerifiedChunkGate(total=3)
        with self.assertRaises(PlaybackError):
            gate.mark(1)
        gate.mark(0)
        with self.assertRaises(PlaybackError):
            gate.mark(0)
        gate.mark(1)
        gate.mark(2)
        gate.finish()
        self.assertEqual(gate.released, 3)
        gate.wait_for({"index": 2})

    def test_waits_for_actual_chunk_and_unblocks_on_fail(self):
        gate = VerifiedChunkGate(total=2, stall_timeout=2)
        result = []
        done = threading.Event()
        def worker():
            try:
                gate.wait_for({"index": 1})
            except PlaybackError:
                result.append("failed")
            finally:
                done.set()
        threading.Thread(target=worker, daemon=True).start()
        gate.mark(0)
        self.assertFalse(done.wait(0.03))
        gate.fail(RuntimeError("network truncated"))
        self.assertTrue(done.wait(2))
        self.assertEqual(result, ["failed"])

    def test_missing_chunk_times_out_and_incomplete_finish_fails(self):
        gate = VerifiedChunkGate(total=2, stall_timeout=0.02)
        with self.assertRaises(PlaybackError):
            gate.wait_for({"index": 0})
        gate.mark(0)
        with self.assertRaises(PlaybackError):
            gate.finish()


class TestStreamingGrant(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="s12-unit-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.signer = Ed25519PrivateKey.generate()
        self.artist_key = public_key_bytes(self.signer)
        self.listener_private = X25519PrivateKey.generate()
        pub = self.listener_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.owner, self.listener = "alice", "bob"
        pcm = b"".join(struct.pack("<h", i % 18000) for i in range(16000 * 2))
        self.expected_pcm = hashlib.sha256(pcm).hexdigest()
        buffer = io.BytesIO()
        with wave.open(buffer, "wb") as audio:
            audio.setnchannels(1); audio.setsampwidth(2); audio.setframerate(16000)
            audio.writeframes(pcm)
        source = self.root / "demo.wav"
        source.write_bytes(buffer.getvalue())
        self.source_cas, self.target_cas = self.root / "source", self.root / "target"
        self.manifest, key = create_package(source, self.source_cas, self.signer, chunk_size=2048)
        self.grant = issue_content_grant(
            owner_signer=self.signer, owner_agent=self.owner,
            listener_agent=self.listener, recipient_public=pub,
            signed_manifest=self.manifest, content_key=key)
        self.expected_report = dict(verified=True,
                                    received_chunks=len(self.manifest["body"]["chunks"]),
                                    cipher_bytes=sum(c["cipher_bytes"] for c in self.manifest["body"]["chunks"]),
                                    manifest_sha256=manifest_digest(self.manifest),
                                    file_id=self.manifest["body"]["file_id"])

    def _run(self, *, grant=None, tamper_index=None, truncate_index=None):
        def live_bridge(*, on_trusted_manifest, on_verified_chunk, **kwargs):
            on_trusted_manifest(self.manifest, self.artist_key, self.owner, self.listener)
            for chunk in self.manifest["body"]["chunks"]:
                if truncate_index == chunk["index"]:
                    raise ConductorBridgeError("synthetic test network dropped")
                src = object_path(self.source_cas, chunk["sha256"])
                dst = object_path(self.target_cas, chunk["sha256"])
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
                if chunk["index"] == tamper_index:
                    data = bytearray(dst.read_bytes()); data[0] ^= 1; dst.write_bytes(data)
                # Real MoQ callback separately verifies signed CAS SHA-256;
                # fake bridge must simulate that exact verification gate.
                from holochain_storage.package import _read_verified_chunk
                _read_verified_chunk(self.target_cas, chunk)
                on_verified_chunk(chunk["index"])
                time.sleep(0.035)
            return dict(self.expected_report)

        with patch("music_catalogue.streaming_playback.receive_moq_from_live_conductor", side_effect=live_bridge):
            return stream_granted_moq_from_live_conductor(
                grant=self.grant if grant is None else grant,
                recipient_private=self.listener_private,
                bridge_binary=self.root / "bridge", moq_binary=self.root / "moq",
                admin_port=1, app_id="music", catalogue_dna="c", storage_dna="s",
                reader_agent=self.listener, artist_agent=self.owner, node_agent="carol",
                track_id="a" * 32, storage_url="http://127.0.0.1:1",
                target_store=self.target_cas, backend="null", timeout=15,
            )

    def test_staged_chunk_decryption_overlaps_final_delivery(self):
        result = self._run()
        self.assertTrue(result["streaming"])
        self.assertTrue(result["playback_complete"])
        self.assertTrue(result["first_pcm_before_last_chunk"])
        self.assertGreater(result["first_pcm_after_verified_chunks"], 0)
        self.assertLess(result["first_pcm_after_verified_chunks"], result["verified_ciphertext_chunks"])
        self.assertEqual(result["pcm_sha256"], self.expected_pcm)
        self.assertEqual(result["output_pcm_sha256"], self.expected_pcm)
        self.assertEqual(result["buffer_capacity_bytes"], 65536)

    def test_wrong_owner_grant_prevents_even_starting_transfer(self):
        bad = dict(self.grant)
        bad["body"] = dict(self.grant["body"])
        bad["body"]["listener_agent"] = "mallory"
        with self.assertRaises(StorageError):
            self._run(grant=bad)
        self.assertFalse((self.target_cas / "objects").exists())

    def test_interrupted_transfer_does_not_report_verified_audio(self):
        with self.assertRaises(ConductorBridgeError):
            self._run(truncate_index=4)

    def test_tampered_staged_object_not_sent_to_pcm(self):
        with self.assertRaises(StorageError):
            self._run(tamper_index=0)


class TestMoqProgressParser(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="s12-progress-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        artist = Ed25519PrivateKey.generate()
        src = self.root / "a.wav"
        src.write_bytes(b"dummy plaintext")
        self.manifest, _ = create_package(src, self.root / "cas", artist, chunk_size=4096)
        self.chunk = self.manifest["body"]["chunks"][0]
        self.target = self.root / "target"

    def _run(self, events, *, copy_object=True):
        if copy_object:
            src = object_path(self.root / "cas", self.chunk["sha256"])
            dest = object_path(self.target, self.chunk["sha256"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
        script = self.root / "progress.py"
        script.write_text("import sys\nfor event in " + repr(events) + ":\n print(event, flush=True)\n")
        notices = []
        result = _receive_verified_progress([sys.executable, str(script)],
                                            self.manifest, self.target,
                                            notices.append, timeout=8)
        return result, notices

    def test_valid_progress_must_match_local_verified_cas(self):
        c = self.chunk
        first = json.dumps(dict(kind="chunk_verified", index=0,
                                sha256=c["sha256"], cipher_bytes=c["cipher_bytes"]))
        last = json.dumps(dict(kind="transfer_complete", verified=True,
                               received_chunks=1, cipher_bytes=c["cipher_bytes"],
                               manifest_sha256=manifest_digest(self.manifest),
                               file_id=self.manifest["body"]["file_id"]))
        report, notices = self._run([first,last])
        self.assertEqual(notices, [0])
        self.assertEqual(report["file_id"], self.manifest["body"]["file_id"])

    def test_progress_without_cas_rejected(self):
        c = self.chunk
        first = json.dumps(dict(kind="chunk_verified", index=0,
                                sha256=c["sha256"], cipher_bytes=c["cipher_bytes"]))
        with self.assertRaises(StorageError):
            self._run([first], copy_object=False)

    def test_early_complete_rejected(self):
        with self.assertRaises(ConductorBridgeError):
            self._run([json.dumps(dict(kind="transfer_complete", verified=True))])

    def test_progress_wrong_index_rejected(self):
        c = self.chunk
        first = json.dumps(dict(kind="chunk_verified", index=10,
                                sha256=c["sha256"], cipher_bytes=c["cipher_bytes"]))
        with self.assertRaises(ConductorBridgeError):
            self._run([first])

    def test_duplicate_progress_rejected(self):
        c = self.chunk
        first = json.dumps(dict(kind="chunk_verified", index=0,
                                sha256=c["sha256"], cipher_bytes=c["cipher_bytes"]))
        with self.assertRaises(ConductorBridgeError):
            self._run([first,first])


if __name__ == "__main__":
    unittest.main()
