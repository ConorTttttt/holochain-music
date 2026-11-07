"""Shared deterministic fixtures for v1 application tests (generated audio only)."""
from __future__ import annotations

import math
import os
from pathlib import Path
import struct
import wave

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import create_package, manifest_digest, public_key_bytes
from music_catalogue.content_grants import issue_content_grant, issue_personal_licence


def write_tone(path: Path, *, seconds: float = 0.5, rate: int = 8000, channels: int = 1,
               extra_chunk: bool = False) -> int:
    frames = int(seconds * rate)
    pcm = b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / rate))) * channels
                   for i in range(frames))
    with wave.open(str(path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    if extra_chunk:
        # Insert a LIST chunk before "data" like many real-world encoders do.
        data = path.read_bytes()
        idx = data.index(b"data")
        info = b"LIST" + struct.pack("<I", 4) + b"INFO"
        body = data[12:idx] + info + data[idx:]
        path.write_bytes(b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WAVE" + body)
    return frames


class Track:
    """An artist-encrypted canonical WAV, plus listener keys and grants."""

    def __init__(self, root: Path, *, seconds: float = 0.5, chunk_size: int = 1024, rate: int = 8000):
        from holochain_music.artist import normalise_wav
        root.mkdir(parents=True, exist_ok=True)
        raw = root / "raw.wav"
        write_tone(raw, seconds=seconds, rate=rate)
        canonical = root / "canonical.wav"
        self.info = normalise_wav(raw, canonical)
        self.artist = Ed25519PrivateKey.generate()
        self.artist_key = public_key_bytes(self.artist)
        self.store = root / "cas"
        self.manifest, self.content_key = create_package(canonical, self.store, self.artist, chunk_size=chunk_size)
        canonical.unlink()
        raw.unlink()
        self.file_id = self.manifest["body"]["file_id"]
        self.digest = manifest_digest(self.manifest)
        self.listener = X25519PrivateKey.generate()
        self.listener_pub = self.listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.owner, self.reader = "uhCAkArtistAgent", "uhCAkListenerAgent"

    def licence(self, listener_agent: str | None = None):
        return issue_personal_licence(owner_signer=self.artist, owner_agent=self.owner,
                                      listener_agent=listener_agent or self.reader,
                                      recipient_public=self.listener_pub, signed_manifest=self.manifest,
                                      content_key=self.content_key)

    def stream_grant(self, lifetime: int = 600):
        return issue_content_grant(owner_signer=self.artist, owner_agent=self.owner, listener_agent=self.reader,
                                   recipient_public=self.listener_pub, signed_manifest=self.manifest,
                                   content_key=self.content_key, lifetime_seconds=lifetime)


def assert_private(tc, path, mode: int) -> None:
    """POSIX: exact permission bits. Windows: a DACL that grants no other
    ordinary account access (holochain_storage.portable.is_private)."""
    if os.name == "nt":
        from holochain_storage import portable
        tc.assertTrue(portable.is_private(Path(path)), f"{path} is readable by other accounts")
    else:
        tc.assertEqual(Path(path).stat().st_mode & 0o777, mode, str(path))
