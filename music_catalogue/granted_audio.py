"""S10: verify an owner's listener grant, decrypt AES-GCM in bounded chunks,
then feed signed-manifest-authenticated PCM into an audio sink.

Only canonical RIFF/WAVE PCM16 (mono/stereo, 8-48 kHz) is supported here. This
is *not* a FLAC decoder, adaptive streaming player or hardware audio driver.
The default sink is required so tests can exercise PCM playout without a
physical sound device. No decrypted audio file is written by this module.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from holochain_storage.package import (
    StorageError, _aad, _read_verified_chunk, _assert_manifest, _verify_signed,
    from_b64, verify_package,
)
from .content_grants import unwrap_content_grant

PCM_BLOCK_BYTES = 16384
_WAV_HEADER = struct.Struct("<4sI4s4sIHHIIHH4sI")


class PlaybackError(StorageError):
    """Encrypted data cannot be decoded or played as supported WAV PCM."""


class _PlainReader:
    """Forward-only read adapter: at most one decrypted S1 chunk in memory."""

    def __init__(self, chunks, key: bytes, file_id: str, ciphertext_store: Path,
                 chunk_waiter: Callable[[dict], None] | None = None):
        self._chunks = iter(chunks)
        self._aes = AESGCM(key)
        self._file_id = file_id
        self._store = ciphertext_store
        self._chunk_waiter = chunk_waiter
        self._buffer = b""
        self._offset = 0

    def read(self, size: int) -> bytes:
        if type(size) is not int or size < 0 or size > PCM_BLOCK_BYTES:
            raise PlaybackError("invalid or unbounded PCM read")
        parts = []
        total = 0
        while total < size:
            if self._offset >= len(self._buffer):
                try:
                    chunk = next(self._chunks)
                except StopIteration:
                    break
                # S12: wait for this exact, independently verified CAS object.
                # Never read partial .incoming files, skip missing chunks or
                # substitute progress messages for SHA-256/AES-GCM checks.
                if self._chunk_waiter is not None:
                    self._chunk_waiter(chunk)
                ciphertext = _read_verified_chunk(self._store, chunk)
                try:
                    plain = self._aes.decrypt(
                        from_b64(chunk["nonce"], 12), ciphertext,
                        _aad(self._file_id, chunk["index"]),
                    )
                except InvalidTag as exc:
                    raise PlaybackError("AES-GCM rejected content key or chunk") from exc
                if len(plain) != chunk["plain_bytes"]:
                    raise PlaybackError("invalid authenticated plaintext length")
                self._buffer = plain
                self._offset = 0
            count = min(size - total, len(self._buffer) - self._offset)
            parts.append(self._buffer[self._offset:self._offset + count])
            self._offset += count
            total += count
        return b"".join(parts)


def play_granted_wav(
    *, signed_manifest: dict, ciphertext_store: str | Path,
    grant: dict, trusted_artist: bytes, owner_agent: str, listener_agent: str,
    recipient_private: X25519PrivateKey, pcm_sink: Callable[[bytes], None],
    format_callback: Callable[[dict], None] | None = None,
    chunk_waiter: Callable[[dict], None] | None = None,
) -> dict:
    """Verify signed metadata before reading PCM; authenticate every emitted chunk.

    Sends PCM16 little-endian bytes to a caller-provided sink in blocks of at
    most 16 KiB. The sink may be a test hash, a bounded audio queue or a
    local device interface; caller controls timing and output. This operation
    does not grant rights by itself: the owner must authorise issuance.
    """
    if not callable(pcm_sink):
        raise PlaybackError("PCM output sink required")
    if chunk_waiter is None:
        # S10/S11: complete CAS verified before any output (unchanged).
        body = verify_package(signed_manifest, ciphertext_store, trusted_artist)
    else:
        # S12: complete CAS cannot exist before playout; the signed manifest
        # is checked up-front, then each exact ciphertext object and GCM tag
        # is checked immediately before it can supply PCM.
        if not callable(chunk_waiter):
            raise PlaybackError("invalid authenticated chunk waiter")
        body = _verify_signed(signed_manifest, trusted_artist, "manifest")
        _assert_manifest(body)
    content_key = unwrap_content_grant(
        grant, trusted_artist=trusted_artist, owner_agent=owner_agent,
        listener_agent=listener_agent, recipient_private=recipient_private,
        signed_manifest=signed_manifest,
    )
    stream = _PlainReader(body["chunks"], content_key, body["file_id"],
                          Path(ciphertext_store), chunk_waiter=chunk_waiter)
    header = stream.read(_WAV_HEADER.size)
    if len(header) != _WAV_HEADER.size:
        raise PlaybackError("truncated WAV header")
    (riff, riff_len, wave, fmt, fmt_len, audio_format, channels, rate,
     byte_rate, block_align, bits, data_tag, data_len) = _WAV_HEADER.unpack(header)
    if (riff != b"RIFF" or wave != b"WAVE" or fmt != b"fmt " or fmt_len != 16
            or audio_format != 1 or channels not in (1, 2) or bits != 16
            or rate not in (8000, 11025, 16000, 22050, 32000, 44100, 48000)
            or byte_rate != rate * channels * 2 or block_align != channels * 2
            or data_tag != b"data" or riff_len + 8 != body["total_plain_bytes"]
            or data_len + _WAV_HEADER.size != body["total_plain_bytes"]
            or data_len % block_align != 0):
        raise PlaybackError("only canonical bounded RIFF/WAVE PCM16 audio is supported")
    if format_callback is not None:
        if not callable(format_callback):
            raise PlaybackError("PCM format callback must be callable")
        format_callback({"sample_rate": rate, "channels": channels,
                         "bits_per_sample": bits})
    played = 0
    digest = hashlib.sha256()
    # No PCM is emitted before signed metadata, the grant, and the
    # *corresponding* chunk SHA-256 plus AES-GCM tag are authenticated.
    block = PCM_BLOCK_BYTES - PCM_BLOCK_BYTES % block_align
    while played < data_len:
        to_read = min(block, data_len - played)
        audio = stream.read(to_read)
        if len(audio) != to_read:
            raise PlaybackError("WAV payload truncated")
        pcm_sink(audio)
        digest.update(audio)
        played += len(audio)
    if stream.read(1):
        raise PlaybackError("unexpected WAV trailing bytes")
    return {"played_pcm": True, "file_id": body["file_id"],
            "pcm_sha256": digest.hexdigest(), "pcm_bytes": played,
            "frames": played // block_align, "channels": channels,
            "sample_rate": rate, "bits_per_sample": bits,
            "max_sink_block_bytes": block}
