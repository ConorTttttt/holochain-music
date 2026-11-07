"""S10 grant and bounded PCM playout checks; no conductor/audio device needed.

A separate Sweettest drives the actual S9 Holochain + MoQ transfer using a
valid WAV fixture. These tests never substitute a fabricated grant signature.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import struct
import tempfile
import unittest
import wave
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import StorageError, create_package, object_path, public_key_bytes
from music_catalogue.content_grants import (
    ContentGrantError, issue_content_grant, unwrap_content_grant,
)
from music_catalogue.granted_audio import PlaybackError, PCM_BLOCK_BYTES, play_granted_wav


def _wav_bytes() -> tuple[bytes, bytes]:
    # Real canonical RIFF/WAVE signed 16-bit mono (not mislabeled FLAC).
    rate = 16000
    pcm = b"".join(struct.pack("<h", int(11000 * math.sin(2 * math.pi * 440 * i / rate)))
                   for i in range(6000))
    f = io.BytesIO()
    with wave.open(f, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(pcm)
    return f.getvalue(), pcm


class S10ContentGrantTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="s10-grant-audio-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.owner = "uhCAkAliceAgent"
        self.listener = "uhCAkBobAgent"
        self.artist = Ed25519PrivateKey.generate()
        self.artist_public = public_key_bytes(self.artist)
        self.reader_private = X25519PrivateKey.generate()
        self.reader_public = self.reader_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        wav, self.pcm = _wav_bytes()
        self.original = wav
        source = self.root / "test.wav"
        source.write_bytes(wav)
        self.store = self.root / "ciphertext"
        self.manifest, self.key = create_package(source, self.store, self.artist, chunk_size=1024)
        self.grant = issue_content_grant(
            owner_signer=self.artist, owner_agent=self.owner,
            listener_agent=self.listener, recipient_public=self.reader_public,
            signed_manifest=self.manifest, content_key=self.key,
        )
        self.sink = []

    def play(self, **overrides):
        kwargs = dict(signed_manifest=self.manifest, ciphertext_store=self.store,
                      grant=self.grant, trusted_artist=self.artist_public,
                      owner_agent=self.owner, listener_agent=self.listener,
                      recipient_private=self.reader_private, pcm_sink=self.sink.append)
        kwargs.update(overrides)
        return play_granted_wav(**kwargs)

    def test_real_signed_grant_decrypts_and_streams_pcm16_to_bounded_sink(self):
        report = self.play()
        self.assertTrue(report["played_pcm"])
        self.assertEqual(b"".join(self.sink), self.pcm)
        self.assertEqual(report["pcm_sha256"], hashlib.sha256(self.pcm).hexdigest())
        self.assertEqual(report["frames"], 6000)
        self.assertEqual(report["sample_rate"], 16000)
        self.assertLessEqual(max(map(len, self.sink)), PCM_BLOCK_BYTES)
        self.assertGreater(len(self.sink), 0)
        payload = json.dumps(self.grant)
        self.assertNotIn(self.key.hex(), payload)
        self.assertNotIn(self.reader_private.private_bytes_raw().hex(), payload)

    def test_wrong_holochain_reader_agent_fails_before_pcm(self):
        with self.assertRaises(ContentGrantError):
            self.play(listener_agent="uhCAkMallory")
        self.assertEqual(self.sink, [])

    def test_reader_must_possess_recipient_private_key(self):
        with self.assertRaises(ContentGrantError):
            self.play(recipient_private=X25519PrivateKey.generate())
        self.assertEqual(self.sink, [])

    def test_grant_payload_tampering_fails_owner_signature(self):
        bad = copy.deepcopy(self.grant)
        bad["body"]["listener_agent"] = "uhCAkMallory"
        with self.assertRaises(ContentGrantError):
            self.play(grant=bad)
        self.assertEqual(self.sink, [])

    def test_grant_signed_by_other_artist_is_untrusted(self):
        other_artist = Ed25519PrivateKey.generate()
        bad = issue_content_grant(
            owner_signer=other_artist, owner_agent=self.owner,
            listener_agent=self.listener, recipient_public=self.reader_public,
            signed_manifest=self._other_signed_manifest(other_artist), content_key=self.key,
        )
        with self.assertRaises(ContentGrantError):
            self.play(grant=bad)
        self.assertEqual(self.sink, [])

    def _other_signed_manifest(self, signer):
        source = self.root / "test.wav"
        package, _ = create_package(source, self.root / "other", signer, chunk_size=1024)
        return package

    def test_old_expired_grant_fails_even_with_valid_signature(self):
        with patch("music_catalogue.content_grants.time.time", return_value=10000):
            old = issue_content_grant(
                owner_signer=self.artist, owner_agent=self.owner,
                listener_agent=self.listener, recipient_public=self.reader_public,
                signed_manifest=self.manifest, content_key=self.key,
                lifetime_seconds=60,
            )
        with self.assertRaises(ContentGrantError):
            self.play(grant=old)
        self.assertEqual(self.sink, [])

    def test_grant_for_another_manifest_cannot_unlock(self):
        other_path = self.root / "other.wav"
        other_path.write_bytes(self.original)
        other_manifest, other_key = create_package(other_path, self.root / "other", self.artist, chunk_size=1024)
        other_grant = issue_content_grant(
            owner_signer=self.artist, owner_agent=self.owner,
            listener_agent=self.listener, recipient_public=self.reader_public,
            signed_manifest=other_manifest, content_key=other_key,
        )
        with self.assertRaises(ContentGrantError):
            self.play(grant=other_grant)
        self.assertEqual(self.sink, [])

    def test_incorrect_owner_or_missing_grant_refused(self):
        with self.assertRaises(ContentGrantError):
            self.play(owner_agent="uhCAkMallory")
        with self.assertRaises(ContentGrantError):
            self.play(grant={})
        self.assertEqual(self.sink, [])

    def test_corrupt_ciphertext_fails_before_any_audio_output(self):
        chunk = self.manifest["body"]["chunks"][-1]
        path = object_path(self.store, chunk["sha256"])
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaises(StorageError):
            self.play()
        self.assertEqual(self.sink, [])

    def test_wrong_key_wrapped_by_real_owner_fails_aes_gcm(self):
        wrong = issue_content_grant(
            owner_signer=self.artist, owner_agent=self.owner,
            listener_agent=self.listener, recipient_public=self.reader_public,
            signed_manifest=self.manifest, content_key=os.urandom(32),
        )
        with self.assertRaises(PlaybackError):
            self.play(grant=wrong)
        self.assertEqual(self.sink, [])

    def test_bad_wav_header_is_rejected(self):
        not_wav = self.root / "not-wav"
        not_wav.write_bytes(b"this is not a real RIFF/WAVE file" * 500)
        manifest, key = create_package(not_wav, self.root / "bad-store", self.artist, chunk_size=1024)
        grant = issue_content_grant(
            owner_signer=self.artist, owner_agent=self.owner,
            listener_agent=self.listener, recipient_public=self.reader_public,
            signed_manifest=manifest, content_key=key,
        )
        with self.assertRaises(PlaybackError):
            self.play(signed_manifest=manifest, ciphertext_store=self.root / "bad-store", grant=grant)
        self.assertEqual(self.sink, [])

    def test_rejects_malformed_grant_lifetime_and_secret_lengths(self):
        for seconds in (0, 86401, True, "100"):
            with self.subTest(seconds=seconds), self.assertRaises(ContentGrantError):
                issue_content_grant(
                    owner_signer=self.artist, owner_agent=self.owner,
                    listener_agent=self.listener, recipient_public=self.reader_public,
                    signed_manifest=self.manifest, content_key=self.key,
                    lifetime_seconds=seconds,
                )
        with self.assertRaises(ContentGrantError):
            issue_content_grant(owner_signer=self.artist, owner_agent=self.owner,
                                listener_agent=self.listener, recipient_public=self.reader_public,
                                signed_manifest=self.manifest, content_key=b"short")


if __name__ == "__main__":
    unittest.main()
