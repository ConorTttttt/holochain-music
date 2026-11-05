"""Application playback controller over the existing authenticated engines.

Sources (both decrypt only inside this process, chunk by chunk, after the
signed-manifest SHA-256 and AES-GCM checks):

* offline — `VerifiedWavSeeker` (S14) over a complete local CAS;
* streaming — `InflightWavSeeker` (S16) whose chunk waiter is a `Download`
  that fetches from Holochain-authenticated hosts, prioritising seeks.

Commands are serialised; every worker carries a generation number and a
cancel event, so a superseded worker can never change newer state (S18).
PCM goes only to the S11 bounded player; the browser never receives it.
"""
from __future__ import annotations

from array import array
import hashlib
import sys
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from music_catalogue.buffered_playback import (
    AlsaOutput, AudioFormat, BufferedPcmPlayer, NullOutput, PlaybackStopped,
)
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.inflight_seek import InflightWavSeeker
from music_catalogue.seekable_recovery import VerifiedWavSeeker


class VolumeOutput:
    """Software gain applied after the authenticated digest is taken."""

    def __init__(self, inner, gain: Callable[[], float]):
        self.inner, self.gain = inner, gain

    def write(self, data: bytes) -> None:
        g = self.gain()
        if g >= 0.999:
            self.inner.write(data)
            return
        samples = array("h")
        samples.frombytes(data)
        if sys.byteorder != "little":
            samples.byteswap()
        scaled = array("h", (int(s * g) for s in samples))
        if sys.byteorder != "little":
            scaled.byteswap()
        self.inner.write(scaled.tobytes())

    def close(self) -> None:
        self.inner.close()

    def abort(self) -> None:
        self.inner.abort()


class SessionSpec:
    """Everything a worker needs; built by the app from library data."""

    def __init__(self, *, key: str, manifest: dict, grant: dict, artist_key: bytes, owner_agent: str,
                 listener_agent: str, recipient: X25519PrivateKey, store, download=None,
                 source: str = "offline"):
        self.key, self.manifest, self.grant = key, manifest, grant
        self.artist_key, self.owner_agent, self.listener_agent = artist_key, owner_agent, listener_agent
        self.recipient, self.store, self.download, self.source = recipient, store, download, source


class Player:
    def __init__(self, *, backend: str = "null", device: str = "default",
                 resolve: Callable[[str], SessionSpec],
                 on_finished: Callable[[str], None] | None = None,
                 on_started: Callable[[str], None] | None = None):
        if backend not in ("null", "alsa"):
            raise PlaybackError("invalid audio backend")
        self.backend, self.device = backend, device
        self._resolve = resolve
        self._on_finished, self._on_started = on_finished, on_started
        self._commands = threading.RLock()
        self._lock = threading.RLock()
        self._generation = 0
        self._cancel: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._pcm: BufferedPcmPlayer | None = None
        self._spec: SessionSpec | None = None
        self.volume = 1.0
        self._reset(None)

    def _reset(self, key):
        self._key = key
        self._state = "idle" if key is None else "loading"
        self._buffering = False
        self._start_frame = self._position = self._total = self._rate = 0
        self._error = None
        self._result = None
        self._source = None
        self._first_audio_ms = None

    # ---- status ------------------------------------------------------
    def status(self) -> dict:
        with self._lock:
            position = self._position
            if self._pcm is not None and self._state in ("playing", "paused"):
                position = min(self._total, self._start_frame + self._pcm.progress()["output_frames"])
            download = self._spec.download.progress() if self._spec and self._spec.download else None
            return {"state": "buffering" if self._buffering and self._state == "playing" else self._state,
                    "track_key": self._key, "position_frames": position, "total_frames": self._total,
                    "sample_rate": self._rate, "audio_backend": self.backend, "volume": self.volume,
                    "source": self._source, "error": self._error, "download": download,
                    "time_to_first_audio_ms": self._first_audio_ms}

    # ---- commands ----------------------------------------------------
    def set_volume(self, value) -> dict:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
            raise PlaybackError("volume must be between 0 and 1")
        self.volume = float(value)
        return self.status()

    def _stop_worker(self) -> None:
        with self._lock:
            if self._cancel:
                self._cancel.set()
            pcm, thread = self._pcm, self._thread
            self._generation += 1
            self._pcm = self._thread = None
        if pcm is not None:
            try:
                pcm.stop()
            except PlaybackError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    def play(self, key: str, start_frame: int = 0) -> dict:
        if type(start_frame) is not int or start_frame < 0:
            raise PlaybackError("invalid start position")
        with self._commands:
            with self._lock:
                if self._key == key and self._total and start_frame >= self._total:
                    raise PlaybackError("position is beyond the end of the track")
            spec = self._resolve(key)  # may raise a user-facing error before any state change
            self._stop_worker()
            with self._lock:
                self._reset(key)
                self._spec = spec
                self._source = spec.source
                self._start_frame = self._position = start_frame
                generation, cancel = self._generation, threading.Event()
                self._cancel = cancel
                self._thread = threading.Thread(target=self._run, args=(spec, start_frame, generation, cancel),
                                                name="hm-player", daemon=True)
                self._thread.start()
            return self.status()

    def pause(self) -> dict:
        with self._commands, self._lock:
            if self._state != "playing" or self._pcm is None:
                raise PlaybackError("nothing is playing")
            self._pcm.pause()
            self._state = "paused"
            return self.status()

    def resume(self) -> dict:
        with self._commands, self._lock:
            if self._state != "paused" or self._pcm is None:
                raise PlaybackError("nothing is paused")
            self._pcm.resume()
            self._state = "playing"
            return self.status()

    def stop(self) -> dict:
        with self._commands:
            with self._lock:
                self._position = self.status()["position_frames"]
            self._stop_worker()
            with self._lock:
                self._state = "stopped" if self._key else "idle"
                self._buffering = False
                return self.status()

    def seek(self, frame: int) -> dict:
        with self._commands:
            with self._lock:
                if self._key is None or self._state in ("idle", "loading", "error"):
                    raise PlaybackError("nothing to seek")
                if type(frame) is not int or not 0 <= frame < self._total:
                    raise PlaybackError("seek outside the track")
                key = self._key
            # A seek starts a fresh verified session at the exact frame; a
            # short gap is expected and a paused track resumes playing.
            return self.play(key, frame)

    def shutdown(self) -> None:
        self._stop_worker()

    # ---- worker ------------------------------------------------------
    def _current(self, generation, cancel) -> bool:
        return not cancel.is_set() and self._generation == generation

    def _set_buffering(self, generation, cancel, value: bool) -> None:
        with self._lock:
            if self._current(generation, cancel):
                self._buffering = value

    def _run(self, spec: SessionSpec, start_frame: int, generation: int, cancel: threading.Event) -> None:
        pcm: BufferedPcmPlayer | None = None
        began = time.monotonic()
        try:
            if spec.download is None:
                seeker = VerifiedWavSeeker(signed_manifest=spec.manifest, ciphertext_store=spec.store,
                                           grant=spec.grant, trusted_artist=spec.artist_key,
                                           owner_agent=spec.owner_agent, listener_agent=spec.listener_agent,
                                           recipient_private=spec.recipient)
                frames_iter = lambda: seeker.iter_frames(start_frame)
            else:
                download = spec.download
                waiter = lambda chunk: download.wait_for(
                    chunk, cancel=cancel, buffering=lambda v: self._set_buffering(generation, cancel, v))
                seeker = InflightWavSeeker(signed_manifest=spec.manifest, ciphertext_store=spec.store,
                                           grant=spec.grant, trusted_artist=spec.artist_key,
                                           owner_agent=spec.owner_agent, listener_agent=spec.listener_agent,
                                           recipient_private=spec.recipient, chunk_waiter=waiter)
                seeker.open()
                frames_iter = lambda: seeker.iter_frames(start_frame, seeker.frames - start_frame)
            if start_frame >= seeker.frames:
                raise PlaybackError("position is beyond the end of the track")
            fmt = seeker.fmt
            first = {"done": False}

            def factory(audio: AudioFormat):
                inner = AlsaOutput(audio, device=self.device) if self.backend == "alsa" else NullOutput(audio)
                out = VolumeOutput(inner, lambda: self.volume)
                write = out.write

                def observed(data):
                    write(data)
                    if not first["done"]:
                        first["done"] = True
                        with self._lock:
                            if self._current(generation, cancel):
                                self._first_audio_ms = int((time.monotonic() - began) * 1000)
                out.write = observed
                return out
            with self._lock:
                if not self._current(generation, cancel):
                    return
                pcm = BufferedPcmPlayer(backend=self.backend, device=self.device, output_factory=factory)
                self._pcm = pcm
                self._total, self._rate = seeker.frames, fmt.sample_rate
                pcm.start({"sample_rate": fmt.sample_rate, "channels": fmt.channels, "bits_per_sample": 16})
                self._state = "playing"
            if self._on_started:
                self._on_started(spec.key)
            digest, supplied = hashlib.sha256(), 0
            for block in frames_iter():
                if cancel.is_set():
                    raise PlaybackStopped("superseded")
                pcm.feed(block)
                digest.update(block)
                supplied += len(block)
            result = pcm.finish(timeout=24 * 3600)
            expected = (seeker.frames - start_frame) * fmt.frame_size
            if supplied != expected or result["output_pcm_bytes"] != expected or \
                    result["output_pcm_sha256"] != digest.hexdigest():
                raise PlaybackError("audio output differs from authenticated PCM")
            finished = False
            with self._lock:
                if self._current(generation, cancel):
                    self._position, self._state, self._pcm = seeker.frames, "finished", None
                    self._result = {"pcm_sha256": digest.hexdigest(), "frames": seeker.frames - start_frame}
                    finished = True
            if finished and self._on_finished:
                self._on_finished(spec.key)
        except PlaybackStopped:
            with self._lock:
                if self._current(generation, cancel):
                    self._state = "stopped"
        except BaseException as exc:
            if pcm is not None:
                try:
                    pcm.stop()
                except BaseException:
                    pass
            with self._lock:
                if self._current(generation, cancel):
                    self._state, self._pcm = "error", None
                    self._buffering = False
                    # Messages come from our own verifiers; no keys/PCM inside.
                    self._error = str(exc)[:200] or type(exc).__name__
