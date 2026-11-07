"""Application playback controller over the existing authenticated engines.

Sources (both decrypt only inside this process, chunk by chunk, after the
signed-manifest SHA-256 and AES-GCM checks):

* offline — the complete local CAS is verified once (`verify_package`) when
  the track is opened, then read through `InflightWavSeeker` (S16);
* streaming — `InflightWavSeeker` whose chunk waiter is a `Download` that
  fetches from Holochain-authenticated hosts, prioritising seeks.

Either way every chunk is re-read, SHA-256-checked against the signed
manifest and AES-GCM-authenticated immediately before its PCM is emitted.

Commands are serialised; every worker carries a generation number and a
cancel event, so a superseded worker can never change newer state (S18).
PCM goes only to the S11 bounded player; the browser never receives it.

Seeking: a track is opened (and its full package verified) once; seeks reuse
the opened reader and only re-read, re-hash and AES-GCM-decrypt the chunks
they play. The output is restarted so no stale audio is heard; `aplay` is
killed (Linux) or the WASAPI stream aborted (Windows), not drained. State is `seeking` until PCM for the new position has
actually been written, and every status carries a sequence number so a
client can discard responses older than one it already applied.
"""
from __future__ import annotations

from array import array
import copy
import hashlib
import sys
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from music_catalogue.audio_output import open_output, valid_backend
from music_catalogue.buffered_playback import (
    AlsaOutput, AudioFormat, BufferedPcmPlayer, NullOutput, PlaybackStopped,
)
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.inflight_seek import InflightWavSeeker
from holochain_storage.package import verify_package


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

    def diagnostics(self):
        method = getattr(self.inner, "diagnostics", None)
        return method() if method else None

    def set_paused(self, paused):
        method = getattr(self.inner, "set_paused", None)
        if method:
            method(paused)

    def close(self) -> None:
        self.inner.close()

    def interrupt(self) -> None:
        interrupt = getattr(self.inner, "interrupt", None)
        if interrupt is not None:
            interrupt()

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


DEVICE_BUFFER_US = 200_000   # ALSA/WASAPI ring: bounds queued (unheard) audio
START_BURST_SECONDS = 0.25   # written unpaced so playback starts at once
MAX_SEEK_METRICS = 200


class Player:
    def __init__(self, *, backend: str = "null", device: str = "default",
                 resolve: Callable[[str], SessionSpec],
                 on_finished: Callable[[str], None] | None = None,
                 on_started: Callable[[str], None] | None = None):
        if not valid_backend(backend):
            raise PlaybackError("invalid audio backend")
        self.backend, self.device = backend, device
        self._resolve = resolve
        self._on_finished, self._on_started = on_finished, on_started
        self._commands = threading.RLock()
        self._lock = threading.RLock()
        self._generation = 0
        self._cancel: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._retired: set[threading.Thread] = set()  # canceled verification, never an output owner
        self._pcm: BufferedPcmPlayer | None = None
        self._spec: SessionSpec | None = None
        self._reader = None          # opened, verified reader for self._key
        self._seq = 0
        self._seek_ticket = 0
        self._seek_metrics: list[dict] = []
        self.volume = 1.0
        self._reset(None)

    def _reset(self, key):
        self._key = key
        self._set_state("idle" if key is None else "loading")
        self._buffering = False
        self._start_frame = self._position = self._total = self._rate = 0
        self._output_active = False
        self._error = None
        self._result = None
        self._source = None
        self._first_audio_ms = None
        self._reader = None

    def _set_state(self, state: str) -> None:
        self._state = state
        self._seq += 1

    # ---- status ------------------------------------------------------
    def status(self) -> dict:
        with self._lock:
            position = self._position
            if self._pcm is not None and self._output_active and self._state in ("playing", "paused"):
                # Monotonic within a segment: start + frames actually written.
                position = min(self._total, self._start_frame + self._pcm.progress()["output_frames"])
            download = self._spec.download.progress() if self._spec and self._spec.download else None
            state = self._state
            if self._buffering and state in ("playing", "seeking"):
                state = "buffering"
            return {"state": state, "seq": self._seq,
                    "track_key": self._key, "position_frames": position, "total_frames": self._total,
                    "sample_rate": self._rate, "audio_backend": self.backend, "volume": self.volume,
                    "source": self._source, "error": self._error, "download": download,
                    "output_active": self._output_active,
                    "audio_output": self._pcm.progress()["audio_output"] if self._pcm else None,
                    "time_to_first_audio_ms": self._first_audio_ms,
                    "last_seek_ms": self._seek_metrics[-1].get("latency_ms") if self._seek_metrics else None}

    def seek_metrics(self) -> list[dict]:
        with self._lock:
            return [dict(m) for m in self._seek_metrics]

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
            self._retired = {t for t in self._retired if t.is_alive()}
        # Retain ownership until teardown succeeds. Never open a replacement
        # on top of a timed-out worker or an unclosed native stream.
        try:
            if pcm is not None:
                pcm.stop()
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=2)
                if thread.is_alive():
                    if pcm is not None:
                        raise PlaybackError("previous playback worker did not stop; retry after it exits")
                    # Package verification can be slow and owns no output.
                    # Its generation check prevents it from opening a device.
                    # Keep it tracked for shutdown instead of losing the handle.
                    with self._lock:
                        self._retired.add(thread)
        except PlaybackError as exc:
            with self._lock:
                self._set_state("error")
                self._output_active = self._buffering = False
                self._error = str(exc)[:200]
            raise
        with self._lock:
            self._pcm = self._thread = None

    def _launch(self, spec: SessionSpec, start_frame: int, reader=None, metric: dict | None = None) -> None:
        """Caller holds _commands and has stopped the previous worker."""
        with self._lock:
            generation, cancel = self._generation, threading.Event()
            self._cancel = cancel
            self._thread = threading.Thread(target=self._run,
                                            args=(spec, start_frame, generation, cancel, reader, metric),
                                            name="hm-player", daemon=True)
            self._thread.start()

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
            self._launch(spec, start_frame)
            return self.status()

    def pause(self) -> dict:
        with self._commands, self._lock:
            if self._state not in ("playing", "seeking") or self._pcm is None:
                raise PlaybackError("nothing is playing")
            self._pcm.pause()
            self._set_state("paused")
            return self.status()

    def resume(self) -> dict:
        with self._commands, self._lock:
            if self._state != "paused" or self._pcm is None:
                raise PlaybackError("nothing is paused")
            self._pcm.resume()
            self._set_state("playing" if self._output_active else "seeking")
            return self.status()

    def stop(self) -> dict:
        with self._commands:
            with self._lock:
                self._position = self.status()["position_frames"]
            self._stop_worker()
            with self._lock:
                self._set_state("stopped" if self._key else "idle")
                self._buffering = False
                self._output_active = False
                return self.status()

    def seek(self, frame: int) -> dict:
        requested_at = time.perf_counter()
        with self._lock:
            self._seek_ticket += 1
            ticket = self._seek_ticket
        with self._commands:
            with self._lock:
                if ticket != self._seek_ticket:
                    # A newer seek arrived while we waited: only the newest runs.
                    self._seek_metrics.append({"requested_at": requested_at, "target": frame, "coalesced": True})
                    del self._seek_metrics[:-MAX_SEEK_METRICS]
                    return self.status()
                if self._key is None or self._state in ("idle", "loading", "error"):
                    raise PlaybackError("nothing to seek")
                if type(frame) is not int or not 0 <= frame < self._total:
                    raise PlaybackError("seek outside the track")
                spec, reader = self._spec, self._reader
                # Report the target immediately; never the previous segment.
                self._start_frame = self._position = frame
                self._output_active = False
                self._set_state("seeking")
                metric = {"requested_at": requested_at, "target": frame, "coalesced": False}
                self._seek_metrics.append(metric)
                del self._seek_metrics[:-MAX_SEEK_METRICS]
            self._stop_worker()
            with self._lock:
                metric["stopped_at"] = time.perf_counter()
            if reader is None:  # not opened yet (cannot normally happen): full open
                return self.play(spec.key, frame)
            self._launch(spec, frame, reader=reader, metric=metric)
            return self.status()

    def shutdown(self) -> None:
        with self._commands:
            self._stop_worker()
            with self._lock:
                retired = tuple(self._retired)
            for thread in retired:
                thread.join(timeout=2)
                if thread.is_alive():
                    raise PlaybackError("previous verification worker did not stop")
                with self._lock:
                    self._retired.discard(thread)

    # ---- worker ------------------------------------------------------
    def _current(self, generation, cancel) -> bool:
        return not cancel.is_set() and self._generation == generation

    def _set_buffering(self, generation, cancel, value: bool) -> None:
        with self._lock:
            if self._current(generation, cancel):
                self._buffering = value
                self._seq += 1

    def _open(self, spec: SessionSpec):
        """Verify once per track open, then decrypt only the WAV header."""
        if spec.download is None:
            # Complete local copy: verify every ciphertext object once now, so
            # a damaged library is reported before any audio. Each chunk is
            # verified again (SHA-256 + AES-GCM) when it is played.
            verify_package(spec.manifest, spec.store, spec.artist_key)
        reader = InflightWavSeeker(signed_manifest=spec.manifest, ciphertext_store=spec.store,
                                   grant=spec.grant, trusted_artist=spec.artist_key,
                                   owner_agent=spec.owner_agent, listener_agent=spec.listener_agent,
                                   recipient_private=spec.recipient, chunk_waiter=lambda chunk: None)
        if spec.download is not None:
            download = spec.download
            reader._waiter = lambda chunk: download.wait_for(chunk)
        reader.open()
        return reader

    def _run(self, spec: SessionSpec, start_frame: int, generation: int, cancel: threading.Event,
             reader=None, metric: dict | None = None) -> None:
        pcm: BufferedPcmPlayer | None = None
        began = time.perf_counter()
        try:
            if reader is None:
                reader = self._open(spec)
                with self._lock:
                    if not self._current(generation, cancel):
                        return
                    self._reader = reader
            # Per-session view: its own chunk waiter bound to this session's
            # cancel event; the opened key/AES state is shared read-only.
            session = copy.copy(reader)
            if spec.download is not None:
                download = spec.download
                session._waiter = lambda chunk: download.wait_for(
                    chunk, cancel=cancel, buffering=lambda v: self._set_buffering(generation, cancel, v))
            if start_frame >= reader.frames:
                raise PlaybackError("position is beyond the end of the track")
            fmt = reader.fmt
            first = {"done": False}

            def factory(audio: AudioFormat):
                # Module-level names kept as the test seam (tests patch NullOutput).
                if self.backend == "null":
                    inner = NullOutput(audio)
                elif self.backend == "alsa":
                    inner = AlsaOutput(audio, device=self.device, buffer_us=DEVICE_BUFFER_US)
                else:
                    inner = open_output(self.backend, audio, device=self.device, buffer_us=400_000)
                out = VolumeOutput(inner, lambda: self.volume)
                write = out.write

                def observed(data):
                    write(data)
                    if not first["done"]:
                        first["done"] = True
                        now = time.perf_counter()
                        with self._lock:
                            if self._current(generation, cancel):
                                self._output_active = True
                                if self._state in ("loading", "seeking"):
                                    self._set_state("playing")
                                if metric is None:
                                    self._first_audio_ms = int((now - began) * 1000)
                                else:
                                    metric["first_output_at"] = now
                                    metric["latency_ms"] = round((now - metric["requested_at"]) * 1000, 1)
                out.write = observed
                return out
            burst = int(fmt.byte_rate * START_BURST_SECONDS) // fmt.frame_size * fmt.frame_size
            with self._lock:
                if not self._current(generation, cancel):
                    return
                pcm = BufferedPcmPlayer(backend=self.backend, device=self.device, output_factory=factory,
                                        burst_bytes=burst)
                self._pcm = pcm
                self._total, self._rate = reader.frames, fmt.sample_rate
                pcm.start({"sample_rate": fmt.sample_rate, "channels": fmt.channels, "bits_per_sample": 16})
                if metric is None and self._on_started:
                    started = True
                else:
                    started = False
            if started:
                self._on_started(spec.key)
            digest, supplied = hashlib.sha256(), 0
            for block in session.iter_frames(start_frame, reader.frames - start_frame):
                if cancel.is_set():
                    raise PlaybackStopped("superseded")
                pcm.feed(block)
                digest.update(block)
                supplied += len(block)
            result = pcm.finish(timeout=24 * 3600)
            expected = (reader.frames - start_frame) * fmt.frame_size
            if supplied != expected or result["output_pcm_bytes"] != expected or \
                    result["output_pcm_sha256"] != digest.hexdigest():
                raise PlaybackError("audio output differs from authenticated PCM")
            finished = False
            with self._lock:
                if self._current(generation, cancel):
                    self._position, self._pcm = reader.frames, None
                    self._output_active = False
                    self._set_state("finished")
                    self._result = {"pcm_sha256": digest.hexdigest(), "frames": reader.frames - start_frame}
                    finished = True
            if finished and self._on_finished:
                self._on_finished(spec.key)
        except PlaybackStopped:
            with self._lock:
                if self._current(generation, cancel):
                    self._set_state("stopped")
        except BaseException as exc:
            cleanup_failed = False
            if pcm is not None:
                try:
                    pcm.stop()
                except BaseException:
                    cleanup_failed = True
            with self._lock:
                if self._current(generation, cancel):
                    self._pcm = pcm if cleanup_failed else None
                    self._set_state("error")
                    self._buffering = self._output_active = False
                    # Messages come from our own verifiers; no keys/PCM inside.
                    self._error = str(exc)[:200] or type(exc).__name__
        finally:
            with self._lock:
                self._retired.discard(threading.current_thread())
