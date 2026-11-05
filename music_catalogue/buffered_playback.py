"""S11: bounded, clocked PCM16 output after the S10 owner-grant gate.

Never accepts ciphertext or raw content keys itself: the only producer is
S10's signed-manifest + AES-GCM + recipient-grant verified WAV reader. Audio
is queued in small frames, with bounded backpressure; PCM never touches a
plaintext file. `NullOutput` is an observable silent test sink. Real ALSA
uses `aplay` with argv, not a shell. No microphone or network device access.

S11 plays after the finite S9 download; S12 additionally supports opt-in
waiting for independently verified S1 chunks during the same MoQ session.
Neither mode claims seek, adaptive live playback or key revocation.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .granted_audio import PlaybackError, play_granted_wav

MAX_FRAME_BYTES = 4096
MAX_QUEUE_BLOCKS = 16
MIN_START_BLOCKS = 3


@dataclass(frozen=True)
class AudioFormat:
    sample_rate: int
    channels: int
    bits_per_sample: int

    def __post_init__(self):
        if self.sample_rate not in (8000, 11025, 16000, 22050, 32000, 44100, 48000) or \
                self.channels not in (1, 2) or self.bits_per_sample != 16:
            raise PlaybackError("unsupported audio output format")

    @property
    def frame_size(self) -> int:
        return 2 * self.channels

    @property
    def byte_rate(self) -> int:
        return self.sample_rate * self.frame_size


class NullOutput:
    """In-memory, discard-only sink. Never persist/collect plaintext PCM."""

    def __init__(self, fmt: AudioFormat):
        self.fmt = fmt
        self.digest = hashlib.sha256()
        self.written = 0
        self.closed = False

    def write(self, data: bytes) -> None:
        if self.closed:
            raise PlaybackError("output already closed")
        self.digest.update(data)
        self.written += len(data)

    def close(self) -> None:
        self.closed = True

    def abort(self) -> None:
        self.closed = True


class AlsaOutput:
    """Pass RAW S16_LE frames to Linux `aplay`, never an intermediate WAV."""

    def __init__(self, fmt: AudioFormat, *, device: str = "default", executable: str | None = None):
        binary = executable if executable is not None else shutil.which("aplay")
        if not binary:
            raise PlaybackError("ALSA aplay was not found (install alsa-utils)")
        if not isinstance(device, str) or not device or len(device) > 128 or "\x00" in device:
            raise PlaybackError("invalid ALSA device")
        try:
            self.proc = subprocess.Popen(
                [binary, "-q", "-t", "raw", "-f", "S16_LE", "-r", str(fmt.sample_rate),
                 "-c", str(fmt.channels), "-D", device],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise PlaybackError("unable to start ALSA audio output") from exc
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed or self.proc.poll() is not None:
            raise PlaybackError("ALSA audio device closed unexpectedly")
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (OSError, ValueError, BrokenPipeError) as exc:
            raise PlaybackError("ALSA audio output rejected PCM") from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            code = self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired as exc:
            self.abort()
            raise PlaybackError("ALSA output did not drain") from exc
        if code != 0:
            raise PlaybackError("ALSA output exited with an error")

    def abort(self) -> None:
        self._closed = True
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        if self.proc.stdin and not self.proc.stdin.closed:
            try:
                self.proc.stdin.close()
            except OSError:
                pass


class PlaybackStopped(PlaybackError):
    """Listener deliberately stopped playback; not an audio-device failure."""


class BufferedPcmPlayer:
    """Bounded FIFO PCM player. Commands can be called from another thread.

    `feed` backpressures the producer at `max_blocks` and handles S10's <=16KiB
    input by splitting it into <=4KiB blocks. `pause` preserves the queue,
    `resume` continues, and `stop` discards pending PCM and aborts the device.
    All timing uses the local output clock, NOT Holochain or MoQ timestamps.
    """

    def __init__(self, *, backend: str = "null", device: str = "default",
                 max_blocks: int = MAX_QUEUE_BLOCKS,
                 prebuffer_blocks: int = MIN_START_BLOCKS,
                 output_factory: Callable[[AudioFormat], object] | None = None,
                 pace: bool = True):
        if backend not in ("null", "alsa"):
            raise PlaybackError("unknown PCM output backend")
        if type(max_blocks) is not int or not 1 <= max_blocks <= 256:
            raise PlaybackError("invalid audio buffer capacity")
        if type(prebuffer_blocks) is not int or not 1 <= prebuffer_blocks <= max_blocks:
            raise PlaybackError("invalid audio prebuffer")
        if not isinstance(pace, bool):
            raise PlaybackError("invalid pacing mode")
        self.backend, self.device = backend, device
        self.max_blocks, self.prebuffer_blocks, self.pace = max_blocks, prebuffer_blocks, pace
        self._factory = output_factory
        self._queue: deque[bytes] = deque()
        self._cv = threading.Condition()
        self._interrupt = threading.Event()
        self._worker: threading.Thread | None = None
        self._format: AudioFormat | None = None
        self._device = None
        self._finished = self._paused = self._stopped = self._started = False
        self._error: BaseException | None = None
        self._digest = hashlib.sha256()
        self._played_bytes = self._queued_bytes = self._max_seen = self._underruns = 0
        self._callbacks = 0

    def start(self, fmt: dict) -> None:
        if not isinstance(fmt, dict) or set(fmt) != {"sample_rate", "channels", "bits_per_sample"}:
            raise PlaybackError("invalid trusted PCM metadata")
        audio = AudioFormat(**fmt)
        with self._cv:
            if self._stopped:
                raise PlaybackStopped("PCM playback stopped")
            if self._worker is not None:
                raise PlaybackError("PCM player already started")
            # Open before any PCM is accepted, so a missing device fails closed.
            if self._factory is not None:
                output = self._factory(audio)
            elif self.backend == "alsa":
                output = AlsaOutput(audio, device=self.device)
            else:
                output = NullOutput(audio)
            self._device, self._format = output, audio
            self._worker = threading.Thread(target=self._run, name="holochain-music-s11-pcm", daemon=True)
            self._worker.start()

    def _error_or_stop(self):
        if self._error is not None:
            raise PlaybackError("PCM playback device failed") from self._error
        if self._stopped:
            raise PlaybackStopped("PCM playback stopped")

    def feed(self, block: bytes) -> None:
        fmt = self._format
        if fmt is None:
            raise PlaybackError("PCM format not authenticated yet")
        if not isinstance(block, bytes) or not block or len(block) > 16384 or len(block) % fmt.frame_size:
            raise PlaybackError("invalid PCM block size/alignment")
        piece_size = MAX_FRAME_BYTES - MAX_FRAME_BYTES % fmt.frame_size
        for start in range(0, len(block), piece_size):
            piece = block[start:start + piece_size]
            with self._cv:
                while len(self._queue) >= self.max_blocks and not self._stopped and self._error is None:
                    self._cv.wait()
                self._error_or_stop()
                if self._finished:
                    raise PlaybackError("cannot append after stream finished")
                self._queue.append(piece)
                self._queued_bytes += len(piece)
                self._max_seen = max(self._max_seen, self._queued_bytes)
                self._cv.notify_all()

    def pause(self) -> None:
        with self._cv:
            self._error_or_stop()
            if self._worker is None:
                raise PlaybackError("PCM playback not started")
            self._paused = True
            self._cv.notify_all()

    def resume(self) -> None:
        with self._cv:
            self._error_or_stop()
            if self._worker is None:
                raise PlaybackError("PCM playback not started")
            self._paused = False
            self._cv.notify_all()

    def stop(self) -> None:
        with self._cv:
            self._stopped = True
            self._queue.clear()
            self._queued_bytes = 0
            self._paused = False
            self._interrupt.set()
            self._cv.notify_all()
        if self._worker and self._worker is not threading.current_thread():
            self._worker.join(timeout=5)
            if self._worker.is_alive():
                raise PlaybackError("PCM playback worker did not stop")

    def stopped_report(self) -> dict:
        """Report an intentional stop *without* claiming full PCM delivery.

        This is not a success report. Only use it after the caller explicitly
        requested stop, never to downgrade a decoding/ALSA/device error.
        """
        with self._cv:
            if not self._stopped or self._error is not None or (self._worker and self._worker.is_alive()):
                raise PlaybackError("cannot report an unfinished or failed player as stopped")
            return {
                "audio_backend": self.backend,
                "playback_complete": False,
                "playback_stopped": True,
                "output_pcm_sha256": self._digest.hexdigest(),
                "output_pcm_bytes": self._played_bytes,
                "output_frames": self._played_bytes // self._format.frame_size if self._format else 0,
                "max_buffered_pcm_bytes": self._max_seen,
                "buffer_capacity_bytes": self.max_blocks * MAX_FRAME_BYTES,
                "buffer_underruns": self._underruns,
                "audio_blocks_output": self._callbacks,
            }

    def finish(self, *, timeout: float = 60.0) -> dict:
        with self._cv:
            if self._worker is None:
                raise PlaybackError("PCM stream was never started")
            self._error_or_stop()
            self._finished = True
            self._cv.notify_all()
        self._worker.join(timeout=timeout)
        if self._worker.is_alive():
            self.stop()
            raise PlaybackError("PCM playback did not complete within timeout")
        with self._cv:
            self._error_or_stop()
            assert self._format is not None
            return {
                "audio_backend": self.backend,
                "playback_complete": True,
                "output_pcm_sha256": self._digest.hexdigest(),
                "output_pcm_bytes": self._played_bytes,
                "output_frames": self._played_bytes // self._format.frame_size,
                "max_buffered_pcm_bytes": self._max_seen,
                "buffer_capacity_bytes": self.max_blocks * MAX_FRAME_BYTES,
                "buffer_underruns": self._underruns,
                "audio_blocks_output": self._callbacks,
            }

    def _run(self) -> None:
        assert self._format is not None and self._device is not None
        fmt, output = self._format, self._device
        clean = False
        try:
            with self._cv:
                while len(self._queue) < self.prebuffer_blocks and not self._finished and not self._stopped:
                    self._cv.wait()
                self._started = True
            while True:
                with self._cv:
                    while True:
                        if self._stopped:
                            return
                        if self._paused:
                            self._cv.wait()
                            continue
                        if self._queue:
                            block = self._queue.popleft()
                            self._queued_bytes -= len(block)
                            self._cv.notify_all()
                            break
                        if self._finished:
                            clean = True
                            return
                        self._underruns += 1
                        self._cv.wait()
                output.write(block)
                with self._cv:
                    self._digest.update(block)
                    self._played_bytes += len(block)
                    self._callbacks += 1
                # `aplay` may apply its own backpressure, while software pacing
                # also caps how far our small FIFO can run ahead of wall clock.
                if self.pace and self._interrupt.wait(len(block) / fmt.byte_rate):
                    return
        except BaseException as exc:
            with self._cv:
                self._error = exc
                self._stopped = True
                self._cv.notify_all()
        finally:
            try:
                if clean and self._error is None and not self._stopped:
                    output.close()
                else:
                    output.abort()
            except BaseException as exc:
                with self._cv:
                    self._error = exc
                    self._stopped = True
                    self._cv.notify_all()


def play_granted_wav_realtime(
    *, signed_manifest: dict, ciphertext_store: str | Path,
    grant: dict, trusted_artist: bytes, owner_agent: str, listener_agent: str,
    recipient_private: X25519PrivateKey,
    backend: str = "null", device: str = "default",
    player: BufferedPcmPlayer | None = None,
    chunk_waiter: Callable[[dict], None] | None = None,
) -> dict:
    """S10 trusted grant/decrypt gate -> S11 bounded real-time PCM queue.

    S9 ciphertext retrieval occurs before calling this function. Speaker
    output is opt-in (`backend='alsa'`); CI uses a timed `null` sink.
    """
    engine = player if player is not None else BufferedPcmPlayer(backend=backend, device=device)
    try:
        decoded = play_granted_wav(
            signed_manifest=signed_manifest, ciphertext_store=ciphertext_store,
            grant=grant, trusted_artist=trusted_artist, owner_agent=owner_agent,
            listener_agent=listener_agent, recipient_private=recipient_private,
            pcm_sink=engine.feed, format_callback=engine.start,
            chunk_waiter=chunk_waiter,
        )
        playout = engine.finish()
        if playout["output_pcm_sha256"] != decoded["pcm_sha256"] or \
                playout["output_pcm_bytes"] != decoded["pcm_bytes"] or \
                playout["output_frames"] != decoded["frames"]:
            raise PlaybackError("S11 audio output differs from authenticated S10 PCM")
        return {**decoded, **playout}
    except BaseException:
        engine.stop()
        raise
