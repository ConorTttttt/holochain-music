"""S12: grant-verified WAV PCM overlaps with live ciphertext MoQ reception.

Authenticated local S9 conductor supplies endpoint/TLS, S1 manifest/artist
key, host receipt. Rust emits progress only after CAS SHA-256 verification;
Python independently hashes the stored object before publishing its index.
S10 AES-GCM authenticates each chunk before releasing PCM into the S11 64KiB
clocked buffer. Network stalls fail closed; playback is not retried/skipped.

This is finite file streaming from a localhost publisher, NOT seek/replay,
packet-loss concealment, adaptive QoS, public networking or DRM.
"""
from __future__ import annotations

from pathlib import Path
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .buffered_playback import AlsaOutput, AudioFormat, BufferedPcmPlayer, NullOutput, play_granted_wav_realtime
from .adaptive_playback import AdaptivePcmPlayer
from .content_grants import unwrap_content_grant
from holochain_storage.package import manifest_digest
from .granted_audio import PlaybackError
from .moq_conductor import receive_moq_from_live_conductor


class VerifiedChunkGate:
    """Bounded condition signal; only ordered, independently hashed CAS chunks.

    The queue contains only a monotonically increasing index, no PCM or keys.
    Future indices cannot unblock missing earlier chunks. Progress is gated by
    S9 source validation; callers must never construct one from untrusted JSON.
    """

    def __init__(self, *, total: int, stall_timeout: float = 40.0):
        if type(total) is not int or total <= 0 or total > 16384:
            raise PlaybackError("invalid stream chunk count")
        if not 0 < stall_timeout <= 300:
            raise PlaybackError("invalid stream stall timeout")
        self.total = total
        self.stall_timeout = stall_timeout
        self._condition = threading.Condition()
        self._released = 0
        self._failed: BaseException | None = None
        self._complete = False
        self.last_chunk_at: float | None = None

    def mark(self, index: int) -> None:
        with self._condition:
            if self._failed or self._complete or type(index) is not int or index != self._released:
                raise PlaybackError("out-of-order or duplicate authenticated chunk")
            self._released += 1
            self.last_chunk_at = time.monotonic()
            self._condition.notify_all()

    def wait_for(self, chunk: dict) -> None:
        index = chunk["index"]
        end = time.monotonic() + self.stall_timeout
        with self._condition:
            while self._released <= index:
                if self._failed is not None:
                    raise PlaybackError("MoQ transfer failed before required chunk") from self._failed
                if self._complete:
                    raise PlaybackError("MoQ transfer completed without required chunk")
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise PlaybackError("MoQ chunk needed for playback timed out")
                self._condition.wait(remaining)
            if self._failed is not None:
                raise PlaybackError("MoQ transfer was rejected") from self._failed

    def fail(self, exc: BaseException) -> None:
        with self._condition:
            self._failed = exc
            self._condition.notify_all()

    def finish(self) -> None:
        with self._condition:
            if self._failed is not None or self._released != self.total:
                raise PlaybackError("cannot finish incomplete MoQ stream")
            self._complete = True
            self._condition.notify_all()

    def snapshot(self) -> tuple[float, int]:
        """Timestamp and verified count at ONE point in the progress timeline.

        The output thread and receiver progress thread race at chunk boundaries.
        Reading `time.monotonic()` and `released` separately can mix a time
        before the final chunk with a count from after that final chunk.
        """
        with self._condition:
            return time.monotonic(), self._released

    @property
    def released(self) -> int:
        with self._condition:
            return self._released


class _ObservedOutput:
    def __init__(self, output, on_first_output: Callable[[], None]):
        self._output = output
        self._on_first = on_first_output
        self._written = False

    def write(self, data: bytes) -> None:
        self._output.write(data)
        if not self._written:
            self._written = True
            self._on_first()

    def close(self) -> None:
        self._output.close()

    def abort(self) -> None:
        self._output.abort()


def stream_granted_moq_from_live_conductor(
    *, grant: dict, recipient_private: X25519PrivateKey,
    bridge_binary: str | Path, moq_binary: str | Path, admin_port: int,
    app_id: str, catalogue_dna: str, storage_dna: str, reader_agent: str,
    artist_agent: str, node_agent: str, track_id: str, storage_url: str,
    target_store: str | Path, catalogue_role: str = "music_catalogue",
    storage_role: str = "music_storage", backend: str = "null",
    device: str = "default", timeout: int = 120, adaptive_buffer: bool = False,
    include_trust_context: bool = False, allow_lan_moq: bool = False,
) -> dict:
    """Play authenticated PCM while later MoQ chunks are still arriving.

    Default is localhost-only; opt-in RFC1918 LAN needs independently pinned
    Holochain endpoint identity. S9 queries a
    real pinned Holochain conductor before MoQ starts. Caller must obtain the
    owner grant via a trusted rights decision; no key ever reaches S4/MoQ/DHT.
    """
    if type(include_trust_context) is not bool or type(allow_lan_moq) is not bool:
        raise PlaybackError("invalid trusted context or LAN setting")
    if type(adaptive_buffer) is not bool:
        raise PlaybackError("adaptive buffer setting must be boolean")
    if backend not in ("null", "alsa"):
        raise PlaybackError("unsupported S12 output backend")
    if not isinstance(recipient_private, X25519PrivateKey):
        raise PlaybackError("recipient private key required")

    state: dict = {}
    audio_errors: list[BaseException] = []
    finished = threading.Event()
    worker: threading.Thread | None = None
    gate: VerifiedChunkGate | None = None
    player: BufferedPcmPlayer | None = None
    first_output: list[float] = []
    first_output_chunks: list[int] = []

    def trusted(manifest: dict, artist_key: bytes, owner: str, listener: str) -> None:
        nonlocal worker, gate, player
        if owner != artist_agent or listener != reader_agent:
            raise PlaybackError("Holochain authenticated author/reader mismatch")
        # Validate owner's signature, manifest, recipient and grant expiry
        # *before* opening MoQ or a sound device. The second verification in
        # the playout worker is intentional defence in depth.
        unwrap_content_grant(grant, trusted_artist=artist_key,
                             owner_agent=owner, listener_agent=listener,
                             recipient_private=recipient_private,
                             signed_manifest=manifest)
        gate = VerifiedChunkGate(total=len(manifest["body"]["chunks"]))

        def first() -> None:
            if not first_output:
                # Obtain a coherent observation under the same gate lock
                # used by `mark()`: one first-output event, one verified count.
                instant, verified = gate.snapshot()
                first_output.append(instant)
                first_output_chunks.append(verified)

        def make_output(fmt: AudioFormat):
            sink = AlsaOutput(fmt, device=device) if backend == "alsa" else NullOutput(fmt)
            return _ObservedOutput(sink, first)

        player_type = AdaptivePcmPlayer if adaptive_buffer else BufferedPcmPlayer
        player = player_type(backend=backend, device=device, output_factory=make_output)
        state["manifest_sha256"] = manifest_digest(manifest)

        def run_audio() -> None:
            try:
                state["audio"] = play_granted_wav_realtime(
                    signed_manifest=manifest, ciphertext_store=target_store,
                    grant=grant, trusted_artist=artist_key,
                    owner_agent=owner, listener_agent=listener,
                    recipient_private=recipient_private, player=player,
                    chunk_waiter=gate.wait_for,
                )
            except BaseException as exc:
                audio_errors.append(exc)
                gate.fail(exc)
            finally:
                finished.set()

        worker = threading.Thread(target=run_audio, name="s12-granted-pcm", daemon=True)
        worker.start()

    def chunk(index: int) -> None:
        if gate is None:
            raise PlaybackError("MoQ chunk preceded authenticated metadata")
        if audio_errors:
            raise PlaybackError("audio playback failed during MoQ transfer") from audio_errors[0]
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
            timeout=timeout, on_trusted_manifest=trusted,
            on_verified_chunk=chunk, include_trust_context=include_trust_context,
            allow_lan_moq=allow_lan_moq,
        )
        if gate is None:
            raise PlaybackError("trusted MoQ manifest was not supplied")
        gate.finish()
        if not finished.wait(timeout=timeout):
            raise PlaybackError("timed audio output did not finish")
        if audio_errors:
            raise PlaybackError("authenticated playout failed") from audio_errors[0]
        if not first_output or gate.last_chunk_at is None:
            raise PlaybackError("no audio output observed")
        playable = state["audio"]
        if not playable["playback_complete"] or report["manifest_sha256"] != state["manifest_sha256"]:
            raise PlaybackError("S12 output does not match final authenticated transfer")
        return {**report, **playable,
                "streaming": True,
                "adaptive_buffer": adaptive_buffer,
                "first_pcm_before_last_chunk": (
                    first_output_chunks[0] < gate.total and
                    first_output[0] < gate.last_chunk_at
                ),
                "first_pcm_after_verified_chunks": first_output_chunks[0],
                "last_chunk_minus_first_pcm_ms": round((gate.last_chunk_at - first_output[0]) * 1000, 3),
                "verified_ciphertext_chunks": gate.released}
    except BaseException as exc:
        if gate is not None:
            gate.fail(exc)
        if player is not None:
            player.stop()
        if worker is not None:
            worker.join(timeout=5)
        raise
