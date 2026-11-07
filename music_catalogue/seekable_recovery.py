"""S14 opt-in authenticated ciphertext repair and frame-exact WAV seek/replay.

S13's real MoQ remains the *primary* streaming path. A missing listener CAS
object can be repaired after transport from the **already Holochain-verified**
S4 storage host, by comparing the S1 artist manifest and the S4 host receipt
against trusted public signing keys and the S5-pinned manifest digest. This is
not QUIC loss repair or MoQ partial-range transport. No content key goes to S4.

The seek reader then works entirely from encrypted local CAS objects and a
valid S10 owner-signed X25519 listener grant. PCM is authenticated per AES-GCM
chunk, delivered in <=16KiB blocks into the existing bounded audio player,
and never written to an intermediate plaintext file. WAV PCM16 only.
"""
from __future__ import annotations

import bisect
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from holochain_storage.network_client import ReadOnlyStorageNodeClient
from holochain_storage.package import (
    StorageError, _aad, _assert_manifest, _read_verified_chunk, _verify_signed,
    from_b64, manifest_digest, object_path, verify_package, verify_receipt,
)
from .buffered_playback import BufferedPcmPlayer, AudioFormat
from .content_grants import unwrap_content_grant
from .granted_audio import PlaybackError, PCM_BLOCK_BYTES, play_granted_wav

WAV_HEADER_BYTES = 44
MAX_REPAIR_OBJECTS = 256


def repair_missing_ciphertext(
    *, signed_manifest: dict, ciphertext_store: str | Path,
    trusted_artist: bytes, trusted_node: bytes, expected_manifest_sha256: str,
    reader: ReadOnlyStorageNodeClient, max_objects: int = MAX_REPAIR_OBJECTS,
) -> dict:
    """Repair missing (not corrupt) CAS objects from the pinned S4 replica.

    Caller must supply the artist and host keys from authenticated S9 local
    Holochain bindings (or equivalently strong independent pins). The receipt
    authenticates storage *acceptance*, not ongoing availability. A hostile
    host can still refuse service; repair makes no availability guarantee.
    """
    if not isinstance(reader, ReadOnlyStorageNodeClient):
        raise PlaybackError("S14 requires an explicit trusted S4 read-only client")
    if type(max_objects) is not int or not 1 <= max_objects <= MAX_REPAIR_OBJECTS:
        raise PlaybackError("invalid bounded repair budget")
    if not isinstance(trusted_node, bytes) or len(trusted_node) != 32:
        raise PlaybackError("trusted Holochain host signer required")
    body = _verify_signed(signed_manifest, trusted_artist, "manifest")
    _assert_manifest(body)
    digest = manifest_digest(signed_manifest)
    if not isinstance(expected_manifest_sha256, str) or digest != expected_manifest_sha256:
        raise PlaybackError("signed manifest does not match authenticated Holochain pin")

    target = Path(ciphertext_store)
    missing: list[dict] = []
    for chunk in body["chunks"]:
        file = object_path(target, chunk["sha256"])
        if file.is_symlink():
            raise PlaybackError("refusing symlinked local ciphertext object")
        if file.exists():
            _read_verified_chunk(target, chunk)  # Corruption is never silently repaired/replaced.
        else:
            missing.append(chunk)
    if len(missing) > max_objects:
        raise PlaybackError("missing objects exceed explicit recovery budget")
    if missing:
        remote = reader.manifest(body["file_id"])
        if manifest_digest(remote) != digest:
            raise PlaybackError("recovery host served a different signed manifest")
        _verify_signed(remote, trusted_artist, "manifest")
        receipt = reader.receipt(signed_manifest)
        verify_receipt(receipt, signed_manifest, trusted_node, trusted_artist)
        for chunk in missing:
            # S4 HTTP is *ciphertext-only*. Caller never shares a private key.
            data = reader._get(f"/v1/packages/{body['file_id']}/chunks/{chunk['index']}")
            if len(data) != chunk["cipher_bytes"] or hashlib.sha256(data).hexdigest() != chunk["sha256"]:
                raise PlaybackError("recovered ciphertext does not match signed manifest")
            destination = object_path(target, chunk["sha256"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink():
                raise PlaybackError("refusing symlinked repair destination")
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".s14-repair-", delete=False) as f:
                    temp_path = Path(f.name)
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                # Atomic no-overwrite create: a competing writer must not let
                # repair replace an already-present or corrupt CAS object.
                try:
                    os.link(temp_path, destination, follow_symlinks=False)
                except FileExistsError:
                    _read_verified_chunk(target, chunk)
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
            _read_verified_chunk(target, chunk)
    verify_package(signed_manifest, target, trusted_artist)
    return {"repair_complete": True, "recovered_objects": len(missing),
            "reused_objects": len(body["chunks"]) - len(missing),
            "total_objects": len(body["chunks"]),
            "manifest_sha256": digest, "repair_transport": "pinned-s4-ciphertext-http"}


class VerifiedWavSeeker:
    """Per-listener authenticated random access to canonical PCM16 WAV frames.

    Construction validates the *entire* signed CAS, S10 grant and WAV framing;
    subsequent read ranges decrypt only the overlapping signed chunks. The
    content key is held in the listener process during the seek session.
    """

    def __init__(self, *, signed_manifest: dict, ciphertext_store: str | Path,
                 grant: dict, trusted_artist: bytes, owner_agent: str,
                 listener_agent: str, recipient_private: X25519PrivateKey):
        body = verify_package(signed_manifest, ciphertext_store, trusted_artist)
        self._signed_manifest = signed_manifest
        self._trusted_artist = trusted_artist
        key = unwrap_content_grant(grant, trusted_artist=trusted_artist,
                                   owner_agent=owner_agent, listener_agent=listener_agent,
                                   recipient_private=recipient_private,
                                   signed_manifest=signed_manifest)
        checked = play_granted_wav(
            signed_manifest=signed_manifest, ciphertext_store=ciphertext_store,
            grant=grant, trusted_artist=trusted_artist, owner_agent=owner_agent,
            listener_agent=listener_agent, recipient_private=recipient_private,
            pcm_sink=lambda _: None,
        )
        self.frames = checked["frames"]
        self.fmt = AudioFormat(checked["sample_rate"], checked["channels"],
                               checked["bits_per_sample"])
        self.file_id = body["file_id"]
        self.store = Path(ciphertext_store)
        self._aes = AESGCM(key)
        self._chunks = body["chunks"]
        self._offsets = [0]
        for chunk in self._chunks:
            self._offsets.append(self._offsets[-1] + chunk["plain_bytes"])
        if self._offsets[-1] != WAV_HEADER_BYTES + self.frames * self.fmt.frame_size:
            raise PlaybackError("invalid authenticated WAV seek layout")

    def iter_frames(self, start_frame: int, frame_count: int | None = None) -> Iterator[bytes]:
        if type(start_frame) is not int or not 0 <= start_frame <= self.frames:
            raise PlaybackError("seek frame outside authenticated WAV")
        if frame_count is None:
            frame_count = self.frames - start_frame
        if type(frame_count) is not int or not 0 <= frame_count <= self.frames - start_frame:
            raise PlaybackError("invalid seek frame count")
        lower = WAV_HEADER_BYTES + start_frame * self.fmt.frame_size
        upper = lower + frame_count * self.fmt.frame_size
        index = bisect.bisect_right(self._offsets, lower) - 1
        carry = b""  # A signed S1 chunk may end mid-PCM-frame.
        while lower < upper:
            if index >= len(self._chunks):
                raise PlaybackError("seek exceeded encrypted chunk layout")
            chunk = self._chunks[index]
            start = self._offsets[index]
            end = self._offsets[index + 1]
            ciphertext = _read_verified_chunk(self.store, chunk)
            try:
                data = self._aes.decrypt(from_b64(chunk["nonce"], 12), ciphertext,
                                         _aad(self.file_id, chunk["index"]))
            except InvalidTag as exc:
                raise PlaybackError("seek rejected unauthenticated AES-GCM content") from exc
            if len(data) != chunk["plain_bytes"]:
                raise PlaybackError("seek decrypted invalid chunk size")
            part = data[lower - start: min(upper, end) - start]
            if not part:
                raise PlaybackError("seek found empty authenticated PCM span")
            combined = carry + part
            aligned = len(combined) - len(combined) % self.fmt.frame_size
            for offset in range(0, aligned, PCM_BLOCK_BYTES):
                yield combined[offset:min(aligned, offset + PCM_BLOCK_BYTES)]
            carry = combined[aligned:]
            lower += len(part)
            index += 1
        if carry:
            raise PlaybackError("authenticated PCM ended in a partial frame")

    def play(self, *, start_frame: int = 0, frame_count: int | None = None,
             backend: str = "null", device: str = "default") -> dict:
        if type(start_frame) is not int or not 0 <= start_frame <= self.frames:
            raise PlaybackError("invalid seek start")
        if frame_count is None:
            frame_count = self.frames - start_frame
        if type(frame_count) is not int or not 0 <= frame_count <= self.frames - start_frame:
            raise PlaybackError("invalid seek playback length")
        if frame_count == 0:
            return {"seek_start_frame": start_frame, "seek_frames": 0,
                    "seek_pcm_sha256": hashlib.sha256(b"").hexdigest(),
                    "seek_complete": True, "output_pcm_bytes": 0,
                    "output_frames": 0, "audio_backend": backend}
        # A local CAS file can change after opening the seek session. Reject
        # changed ciphertext before opening ALSA, then authenticate again
        # inside iter_frames before each PCM block is delivered.
        verify_package(self._signed_manifest, self.store, self._trusted_artist)
        player = BufferedPcmPlayer(backend=backend, device=device)
        digest = hashlib.sha256()
        sent = 0
        try:
            player.start(dict(sample_rate=self.fmt.sample_rate,
                              channels=self.fmt.channels, bits_per_sample=16))
            for block in self.iter_frames(start_frame, frame_count):
                player.feed(block)
                digest.update(block)
                sent += len(block)
            result = player.finish()
            expected_bytes = frame_count * self.fmt.frame_size
            if sent != expected_bytes or result["output_pcm_bytes"] != sent or \
                    result["output_pcm_sha256"] != digest.hexdigest() or \
                    result["output_frames"] != frame_count:
                raise PlaybackError("seek output disagrees with authenticated PCM")
        except BaseException:
            player.stop()
            raise
        return {**result, "seek_start_frame": start_frame, "seek_frames": frame_count,
                "total_frames": self.frames, "seek_pcm_sha256": digest.hexdigest(),
                "seek_complete": True}
