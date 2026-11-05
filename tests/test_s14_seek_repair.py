"""S14 owner-granted random-access PCM and pinned-S4 missing-CAS repair.

The S4 reader below is a deterministic unit fixture; only S14's separate
three-conductor Sweettest can validate actual HTTP/QUIC/Holochain networking.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import wave

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.network_client import ReadOnlyStorageNodeClient
from holochain_storage.package import (
    StorageError, _read_verified_chunk, create_package, manifest_digest,
    object_path, public_key_bytes, replicate_package, verify_package,
)
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.seekable_recovery import VerifiedWavSeeker, repair_missing_ciphertext


class FixtureReader(ReadOnlyStorageNodeClient):
    def __init__(self, signed, receipt, source):
        super().__init__("http://127.0.0.1:9999")
        self.signed, self.saved_receipt, self.source = signed, receipt, source
        self.calls = []
        self.mutate = None

    def manifest(self, file_id):
        self.calls.append("manifest")
        return self.signed

    def receipt(self, signed_manifest):
        self.calls.append("receipt")
        return self.saved_receipt

    def _get(self, path):
        self.calls.append(path)
        chunk = int(path.rsplit("/", 1)[-1])
        data = _read_verified_chunk(self.source, self.signed["body"]["chunks"][chunk])
        return self.mutate(data) if self.mutate else data


class S14RecoverySeekTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix="s14-local-")
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.artist, self.node = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.artist_key, self.node_key = public_key_bytes(self.artist), public_key_bytes(self.node)
        self.listener = X25519PrivateKey.generate()
        self.pcm = b"".join(struct.pack("<h", (i * 47) % 20000 - 10000) for i in range(8000))
        content = io.BytesIO()
        with wave.open(content, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(self.pcm)
        (self.root / "source.wav").write_bytes(content.getvalue())
        self.store, self.replica = self.root / "listener", self.root / "host"
        # 333 deliberately splits PCM16 sample frames across encrypted chunks.
        self.manifest, self.secret = create_package(
            self.root / "source.wav", self.replica, self.artist, chunk_size=333)
        self.receipt = replicate_package(self.manifest, self.replica, self.replica,
                                         self.artist_key, self.node)
        self.digest = manifest_digest(self.manifest)
        self.reader = FixtureReader(self.manifest, self.receipt, self.replica)
        self.grant = issue_content_grant(
            owner_signer=self.artist, owner_agent="alice", listener_agent="bob",
            recipient_public=self.listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            signed_manifest=self.manifest, content_key=self.secret)
        self.chunks = self.manifest["body"]["chunks"]

    def repair(self, **changes):
        args = dict(signed_manifest=self.manifest, ciphertext_store=self.store,
                    trusted_artist=self.artist_key, trusted_node=self.node_key,
                    expected_manifest_sha256=self.digest, reader=self.reader)
        args.update(changes)
        return repair_missing_ciphertext(**args)

    def seeker(self, **changes):
        args = dict(signed_manifest=self.manifest, ciphertext_store=self.store,
                    grant=self.grant, trusted_artist=self.artist_key,
                    owner_agent="alice", listener_agent="bob",
                    recipient_private=self.listener)
        args.update(changes)
        return VerifiedWavSeeker(**args)

    def test_two_missing_objects_repaired_without_content_key_on_s4(self):
        # Real mock S4 knows only public signed manifest, receipt and ciphertext.
        for c in self.chunks[:2]:
            dest = object_path(self.store, c["sha256"])
            self.assertFalse(dest.exists())
        # Repair only the first two objects; remaining missing chunks require a
        # larger budget. Mirror all other verified ciphertext locally first.
        from holochain_storage.package import _store_chunk
        for c in self.chunks[2:]:
            _store_chunk(self.store, _read_verified_chunk(self.replica, c))
        result = self.repair()
        self.assertEqual(result["recovered_objects"], 2)
        self.assertEqual(result["reused_objects"], len(self.chunks) - 2)
        self.assertEqual(len([c for c in self.reader.calls if "/chunks/" in c]), 2)
        verify_package(self.manifest, self.store, self.artist_key)
        self.assertTrue(self.seeker().play(start_frame=300, frame_count=200)["seek_complete"])

    def test_repair_no_missing_is_offline_and_idempotent(self):
        self.repair(max_objects=256)
        self.reader.calls.clear()
        result = self.repair()
        self.assertEqual(result["recovered_objects"], 0)
        self.assertEqual(self.reader.calls, [])

    def test_repair_wrong_holochain_manifest_pin_rejected_before_network(self):
        with self.assertRaises(StorageError):
            self.repair(expected_manifest_sha256="0" * 64)
        self.assertEqual(self.reader.calls, [])

    def test_repair_wrong_host_signing_key_refuses_chunk_fetch(self):
        with self.assertRaises(StorageError):
            self.repair(trusted_node=public_key_bytes(Ed25519PrivateKey.generate()))
        self.assertTrue("receipt" in self.reader.calls)
        self.assertFalse(any("/chunks/" in path for path in self.reader.calls))

    def test_repair_wrong_signed_receipt_refuses_chunk_fetch(self):
        other = Ed25519PrivateKey.generate()
        self.reader.saved_receipt = replicate_package(self.manifest, self.replica,
                                                      self.replica, self.artist_key, other)
        with self.assertRaises(StorageError):
            self.repair()
        self.assertFalse(any("/chunks/" in c for c in self.reader.calls))

    def test_corrupt_host_ciphertext_rejected_and_never_saved(self):
        self.reader.mutate = lambda d: d[:-1] + bytes([d[-1] ^ 0xFF])
        with self.assertRaises(StorageError):
            self.repair()
        self.assertFalse(object_path(self.store, self.chunks[0]["sha256"]).exists())

    def test_existing_corrupt_chunk_is_not_replaced_by_repair(self):
        c = self.chunks[0]
        dest = object_path(self.store, c["sha256"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"wrong")
        with self.assertRaises(StorageError):
            self.repair()
        self.assertEqual(self.reader.calls, [])

    def test_repair_fails_closed_when_budget_exceeded(self):
        with self.assertRaises(StorageError):
            self.repair(max_objects=1)
        self.assertEqual(self.reader.calls, [])

    def test_symlinked_object_refused(self):
        c = self.chunks[0]
        p = object_path(self.store, c["sha256"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.symlink_to(self.root / "source.wav")
        with self.assertRaises(StorageError):
            self.repair()
        self.assertEqual(self.reader.calls, [])

    def test_rejects_invalid_budget_and_reader(self):
        with self.assertRaises(StorageError):
            self.repair(max_objects=257)
        with self.assertRaises(StorageError):
            self.repair(reader=object())

    def test_seek_and_replay_with_pcm_split_across_s1_chunks(self):
        self.repair()
        seeker = self.seeker()
        self.assertEqual(seeker.frames, 8000)
        full = b"".join(seeker.iter_frames(0))
        self.assertEqual(full, self.pcm)
        for begin, count in [(0, 30), (177, 1000), (3500, 511), (7999, 1)]:
            with self.subTest(begin=begin):
                slice_pcm = self.pcm[begin * 2:(begin + count) * 2]
                self.assertEqual(b"".join(seeker.iter_frames(begin, count)), slice_pcm)
                played = seeker.play(start_frame=begin, frame_count=count)
                self.assertEqual(played["output_pcm_sha256"], hashlib.sha256(slice_pcm).hexdigest())
                self.assertEqual(played["output_frames"], count)
                self.assertLessEqual(played["max_buffered_pcm_bytes"], 65536)
        first = seeker.play(start_frame=0, frame_count=1000)
        replay = seeker.play(start_frame=0, frame_count=1000)
        self.assertEqual(first["output_pcm_sha256"], replay["output_pcm_sha256"])

    def test_seek_rejects_wrong_reader_and_unauthorised_grant(self):
        self.repair()
        with self.assertRaises(StorageError):
            self.seeker(recipient_private=X25519PrivateKey.generate())
        with self.assertRaises(StorageError):
            self.seeker(listener_agent="mallory")

    def test_out_of_range_seek_is_rejected(self):
        self.repair()
        reader = self.seeker()
        for start, count in [(-1, 1), (8001, 1), (7999, 2), (True, 1), (0, -1)]:
            with self.subTest(start=start, count=count), self.assertRaises(StorageError):
                list(reader.iter_frames(start, count))
        with self.assertRaises(StorageError):
            reader.play(start_frame=8001)
        zero = reader.play(start_frame=8000)
        self.assertEqual(zero["seek_frames"], 0)

    def test_post_open_ciphertext_tampering_fails_before_playback(self):
        self.repair()
        seek = self.seeker()
        chunk = self.chunks[4]
        file = object_path(self.store, chunk["sha256"])
        file.write_bytes(b"corrupt")
        with self.assertRaises(StorageError):
            seek.play(start_frame=200)

    def test_repair_host_manifest_mismatch_refused(self):
        self.reader.signed = {**self.manifest, "signature": "bad"}
        with self.assertRaises(StorageError):
            self.repair()
        self.assertFalse(any("/chunks/" in c for c in self.reader.calls))


if __name__ == "__main__":
    unittest.main()
