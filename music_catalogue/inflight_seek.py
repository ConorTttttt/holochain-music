"""S16: owner-granted frame-exact seek *during* ordered MoQ ciphertext delivery.

S9 still receives signed-manifest-addressed ciphertext sequentially over real
MoQ/QUIC. The listener can seek to any frame once its exact S1 object arrives;
for an ahead-of-download seek it waits for the required objects. This is NOT a
MoQ random-access/range-request protocol and does not prioritise future chunks.
No unverified ciphertext, AES key, or plaintext leaves the listener's process.
"""
from __future__ import annotations

import bisect
import hashlib
from pathlib import Path
import threading
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from holochain_storage.package import (
    _aad, _assert_manifest, _read_verified_chunk, _verify_signed, from_b64,
    manifest_digest, verify_package,
)
from .buffered_playback import AlsaOutput, AudioFormat, BufferedPcmPlayer, NullOutput
from .content_grants import unwrap_content_grant
from .granted_audio import PCM_BLOCK_BYTES, PlaybackError, _WAV_HEADER
from .moq_conductor import receive_moq_from_live_conductor
from .streaming_playback import VerifiedChunkGate

MAX_SEEK_RANGES = 4
WAV_HEADER_BYTES = _WAV_HEADER.size


class InflightWavSeeker:
    """Seek/replay authenticated PCM16 ranges while CAS is incomplete.

    The caller supplies a chunk waiter backed ONLY by independent S9 verified
    progress, never an untrusted network progress message. Signed manifest
    and listener-specific grant must validate before a device can open.
    Each read *re-verifies* the local CAS hash and AES-GCM tag.
    """

    def __init__(self, *, signed_manifest: dict, ciphertext_store: str | Path,
                 grant: dict, trusted_artist: bytes, owner_agent: str,
                 listener_agent: str, recipient_private: X25519PrivateKey,
                 chunk_waiter: Callable[[dict], None]):
        if not callable(chunk_waiter):
            raise PlaybackError("S16 requires verified in-flight chunk waiter")
        body = _verify_signed(signed_manifest, trusted_artist, "manifest")
        _assert_manifest(body)
        key = unwrap_content_grant(
            grant, trusted_artist=trusted_artist, owner_agent=owner_agent,
            listener_agent=listener_agent, recipient_private=recipient_private,
            signed_manifest=signed_manifest,
        )
        self.file_id = body["file_id"]
        self.store = Path(ciphertext_store)
        self._chunks = body["chunks"]
        self._total_plain_bytes = body["total_plain_bytes"]
        self._aes = AESGCM(key)
        self._waiter = chunk_waiter
        self._offsets = [0]
        for chunk in self._chunks:
            self._offsets.append(self._offsets[-1] + chunk["plain_bytes"])
        if self._offsets[-1] != self._total_plain_bytes or self._total_plain_bytes < WAV_HEADER_BYTES:
            raise PlaybackError("invalid S16 signed plain stream layout")
        self.fmt: AudioFormat | None = None
        self.frames: int | None = None

    def _verified_plain(self, index: int) -> bytes:
        chunk = self._chunks[index]
        self._waiter(chunk)  # waits for exact, independently verified S9 index
        encrypted = _read_verified_chunk(self.store, chunk)
        try:
            decrypted = self._aes.decrypt(
                from_b64(chunk["nonce"], 12), encrypted,
                _aad(self.file_id, chunk["index"]),
            )
        except InvalidTag as exc:
            raise PlaybackError("S16 rejected unauthenticated AES-GCM audio") from exc
        if len(decrypted) != chunk["plain_bytes"]:
            raise PlaybackError("S16 plain chunk size mismatched signed manifest")
        return decrypted

    def open(self) -> None:
        """Validate complete canonical WAV header before any audio device opens."""
        if self.fmt is not None:
            return
        header = bytearray()
        for index in range(len(self._chunks)):
            chunk = self._verified_plain(index)
            header.extend(chunk[:WAV_HEADER_BYTES - len(header)])
            if len(header) == WAV_HEADER_BYTES:
                break
        if len(header) != WAV_HEADER_BYTES:
            raise PlaybackError("S16 truncated signed WAV header")
        (riff, riff_len, wave, fmt, fmt_len, audio_format, channels, rate,
         byte_rate, block_align, bits, data_tag, data_len) = _WAV_HEADER.unpack(header)
        if (riff != b"RIFF" or wave != b"WAVE" or fmt != b"fmt " or fmt_len != 16
                or audio_format != 1 or channels not in (1, 2) or bits != 16
                or rate not in (8000, 11025, 16000, 22050, 32000, 44100, 48000)
                or byte_rate != rate * channels * 2 or block_align != channels * 2
                or data_tag != b"data" or riff_len + 8 != self._total_plain_bytes
                or data_len + WAV_HEADER_BYTES != self._total_plain_bytes
                or data_len % block_align):
            raise PlaybackError("S16 only supports authenticated canonical PCM16 WAV")
        self.fmt = AudioFormat(rate, channels, bits)
        self.frames = data_len // block_align

    def _range(self, start_frame: int, frame_count: int) -> tuple[int, int]:
        if self.fmt is None or self.frames is None:
            raise PlaybackError("S16 WAV header must be authenticated first")
        if type(start_frame) is not int or type(frame_count) is not int or \
                not 0 <= start_frame <= self.frames or \
                not 0 <= frame_count <= self.frames - start_frame:
            raise PlaybackError("S16 seek exceeds authenticated PCM timeline")
        begin = WAV_HEADER_BYTES + start_frame * self.fmt.frame_size
        return begin, begin + frame_count * self.fmt.frame_size

    def iter_frames(self, start_frame: int, frame_count: int):
        lower, upper = self._range(start_frame, frame_count)
        assert self.fmt is not None
        index = bisect.bisect_right(self._offsets, lower) - 1
        carry = b""
        while lower < upper:
            if index >= len(self._chunks):
                raise PlaybackError("S16 sought beyond signed ciphertext")
            start, end = self._offsets[index:index + 2]
            block = self._verified_plain(index)
            piece = block[lower - start:min(upper, end) - start]
            if not piece:
                raise PlaybackError("S16 authenticated seek produced empty span")
            combined = carry + piece
            aligned = len(combined) - len(combined) % self.fmt.frame_size
            for pos in range(0, aligned, PCM_BLOCK_BYTES):
                yield combined[pos:min(pos + PCM_BLOCK_BYTES, aligned)]
            carry = combined[aligned:]
            lower += len(piece)
            index += 1
        if carry:
            raise PlaybackError("S16 authenticated PCM ended mid-frame")

    def play(self, *, start_frame: int, frame_count: int, backend: str = "null",
             device: str = "default", on_first_output: Callable[[], None] | None = None) -> dict:
        self.open()
        self._range(start_frame, frame_count)  # reject before opening sound device
        if backend not in ("null", "alsa"):
            raise PlaybackError("invalid S16 output backend")
        assert self.fmt is not None and self.frames is not None
        fmt = self.fmt
        if on_first_output is None:
            player = BufferedPcmPlayer(backend=backend, device=device)
        else:
            def output_factory(audio_format: AudioFormat):
                underlying = AlsaOutput(audio_format, device=device) if backend == "alsa" else NullOutput(audio_format)
                class Observed:
                    first = True
                    def write(self, data):
                        underlying.write(data)
                        if self.first:
                            self.first = False
                            on_first_output()
                    def close(self): underlying.close()
                    def abort(self): underlying.abort()
                return Observed()
            player = BufferedPcmPlayer(backend=backend, device=device, output_factory=output_factory)
        digest = hashlib.sha256()
        delivered = 0
        player.start(dict(sample_rate=fmt.sample_rate, channels=fmt.channels,
                          bits_per_sample=fmt.bits_per_sample))
        try:
            for pcm in self.iter_frames(start_frame, frame_count):
                digest.update(pcm)
                delivered += len(pcm)
                player.feed(pcm)
            result = player.finish()
            if result["output_pcm_sha256"] != digest.hexdigest() or \
                    delivered != frame_count * fmt.frame_size or \
                    result["output_pcm_bytes"] != delivered or \
                    result["output_frames"] != frame_count:
                raise PlaybackError("S16 PCM output differs from authenticated seek range")
        except BaseException:
            player.stop()
            raise
        return {**result, "seek_start_frame": start_frame, "seek_frames": frame_count,
                "seek_pcm_sha256": digest.hexdigest(), "seek_complete": True}


def stream_seek_granted_moq_from_live_conductor(
    *, grant: dict, recipient_private: X25519PrivateKey,
    bridge_binary: str | Path, moq_binary: str | Path, admin_port: int,
    app_id: str, catalogue_dna: str, storage_dna: str, reader_agent: str,
    artist_agent: str, node_agent: str, track_id: str, storage_url: str,
    target_store: str | Path, seek_ranges: tuple[tuple[int, int], ...],
    catalogue_role: str = "music_catalogue", storage_role: str = "music_storage",
    backend: str = "null", device: str = "default", timeout: int = 150,
) -> dict:
    """Play selected WAV ranges during genuine S9 Holochain-pinned MoQ download.

    The publisher still sends chunks sequentially; forward seeks beyond current
    progress await arrival and do not send on-wire priority/range requests.
    Seeks are issued as a preselected series for this S16 demonstration.
    """
    if not isinstance(seek_ranges, tuple) or not 1 <= len(seek_ranges) <= MAX_SEEK_RANGES or any(
        not isinstance(r, tuple) or len(r) != 2 or
        any(type(x) is not int for x in r) or r[0] < 0 or r[1] <= 0
        for r in seek_ranges
    ):
        raise PlaybackError("invalid bounded S16 seek plan")
    if len(seek_ranges) > 1 and not any(
        seek_ranges[i][0] < seek_ranges[i-1][0]
        for i in range(1, len(seek_ranges))
    ):
        raise PlaybackError("S16 multi-seek plan must include a backward seek")
    if backend not in ("null", "alsa") or type(timeout) is not int or not 1 <= timeout <= 300:
        raise PlaybackError("invalid S16 playback settings")
    if not isinstance(recipient_private, X25519PrivateKey):
        raise PlaybackError("invalid S16 listener key")
    gate: VerifiedChunkGate | None = None
    worker: threading.Thread | None = None
    done = threading.Event()
    errors: list[BaseException] = []
    values: dict = {}
    output_records: list[dict] = []

    def trusted(manifest: dict, artist_key: bytes, owner: str, listener: str) -> None:
        nonlocal gate, worker
        if owner != artist_agent or listener != reader_agent:
            raise PlaybackError("S16 authenticated agent mismatch")
        # Fail before connecting/opening any device. Will be verified again by seeker.
        unwrap_content_grant(grant, trusted_artist=artist_key,
                             owner_agent=owner, listener_agent=listener,
                             recipient_private=recipient_private, signed_manifest=manifest)
        gate = VerifiedChunkGate(total=len(manifest["body"]["chunks"]))
        values["manifest_sha256"] = manifest_digest(manifest)
        values["trusted_artist"] = artist_key
        values["manifest"] = manifest

        def run_seeks() -> None:
            try:
                seeker = InflightWavSeeker(
                    signed_manifest=manifest, ciphertext_store=target_store,
                    grant=grant, trusted_artist=artist_key,
                    owner_agent=owner, listener_agent=listener,
                    recipient_private=recipient_private, chunk_waiter=gate.wait_for)
                seeker.open()
                assert seeker.frames is not None
                results = []
                for start, count in seek_ranges:
                    snapshot: list[tuple[float, int]] = []
                    def first() -> None:
                        if not snapshot:
                            snapshot.append(gate.snapshot())
                    playout = seeker.play(start_frame=start, frame_count=count,
                                          backend=backend, device=device,
                                          on_first_output=first)
                    if not snapshot:
                        raise PlaybackError("S16 seek produced no audio")
                    first_at, first_count = snapshot[0]
                    results.append({**playout, "first_pcm_at": first_at,
                                    "first_pcm_after_verified_chunks": first_count})
                values["seek_results"] = results
                values["total_frames"] = seeker.frames
                values["format"] = seeker.fmt
            except BaseException as exc:
                errors.append(exc)
                gate.fail(exc)
            finally:
                done.set()

        worker = threading.Thread(target=run_seeks, name="s16-inflight-seek", daemon=True)
        worker.start()

    def chunk(index: int) -> None:
        if gate is None:
            raise PlaybackError("S16 chunk arrived before verified manifest")
        if errors:
            raise PlaybackError("S16 playback failed during download") from errors[0]
        gate.mark(index)

    try:
        report = receive_moq_from_live_conductor(
            bridge_binary=bridge_binary, moq_binary=moq_binary,
            admin_port=admin_port, app_id=app_id,
            catalogue_dna=catalogue_dna, storage_dna=storage_dna,
            reader_agent=reader_agent, artist_agent=artist_agent,
            node_agent=node_agent, track_id=track_id,
            storage_url=storage_url, target_store=target_store,
            catalogue_role=catalogue_role, storage_role=storage_role,
            timeout=timeout, on_trusted_manifest=trusted, on_verified_chunk=chunk,
        )
        if gate is None:
            raise PlaybackError("S16 missing Holochain-authenticated MoQ metadata")
        gate.finish()
        if not done.wait(timeout=timeout) or errors:
            raise PlaybackError("S16 authenticated seek failed or timed out") from (errors[0] if errors else None)
        if not report.get("verified") or report["manifest_sha256"] != values["manifest_sha256"]:
            raise PlaybackError("S16 final MoQ receiver report not authenticated")
        verify_package(values["manifest"], target_store, values["trusted_artist"])
        seek_results = values["seek_results"]
        if gate.last_chunk_at is None:
            raise PlaybackError("S16 MoQ produced no verified chunks")
        for r in seek_results:
            if r["first_pcm_after_verified_chunks"] >= gate.total or r["first_pcm_at"] >= gate.last_chunk_at:
                raise PlaybackError("S16 seek did not overlap actual MoQ transfer")
        if len(seek_results) >= 2 and seek_ranges[1][0] >= seek_ranges[0][0]:
            raise PlaybackError("S16 fixture requires an actual backwards seek")
        output_records = [{k: v for k, v in r.items() if k != "first_pcm_at"} for r in seek_results]
        return {**report, "inflight_seek": True, "seek_ranges": output_records,
                "seek_count": len(seek_results),
                "all_seeks_before_last_chunk": True,
                "verified_ciphertext_chunks": gate.released,
                "max_seek_buffered_pcm_bytes": max(r["max_buffered_pcm_bytes"] for r in seek_results),
                "total_frames": values["total_frames"]}
    except BaseException as exc:
        if gate is not None:
            gate.fail(exc)
        if worker is not None:
            worker.join(timeout=5)
        raise
