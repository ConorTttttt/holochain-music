"""Platform audio outputs for already-authenticated PCM16.

Backends (all share the ``write / close / abort`` interface of S11):

* ``null``   — silent, observable test sink (every platform).
* ``alsa``   — Linux, ``aplay`` subprocess (S11, unchanged).
* ``wasapi`` — Windows, PortAudio's WASAPI host API in *shared* mode via the
  ``sounddevice`` package (MIT; PortAudio is MIT-licensed and ships inside
  the Windows wheel). Falls back to PortAudio's MME host API only if WASAPI
  cannot open the device at the track's sample rate.

Security: like ``AlsaOutput``, these classes accept only PCM produced by the
S10/S16 reader *after* the signed-manifest SHA-256 and AES-GCM checks and the
listener grant gate. They never see ciphertext, keys or grants, and never
write PCM to disk. Volume is applied upstream (``VolumeOutput``) after the
authenticated digest is taken, identically on every backend.

Latency/bounding: ``PortAudioOutput`` keeps at most ``buffer_us`` of PCM in
its own ring (default 200 ms, the same bound the ALSA backend gives aplay),
plus the device's own period (~10–30 ms in WASAPI shared mode). ``write``
blocks while the ring is full, which back-pressures the paced S11 worker
exactly as a full aplay pipe does. ``abort`` discards the ring and aborts the
stream immediately, waking any blocked writer — seeks and track changes do
not wait for queued audio to drain.
"""
from __future__ import annotations

import hashlib
import sys
import threading
import time

from .granted_audio import PlaybackError

WASAPI = "Windows WASAPI"
MME = "MME"
DEFAULT_BUFFER_US = 200_000
DEFAULT_LATENCY_S = 0.04


def available_backends() -> tuple[str, ...]:
    if sys.platform == "win32":
        return ("wasapi", "null")
    return ("alsa", "null")


def default_backend() -> str:
    return available_backends()[0]


def valid_backend(name: str) -> bool:
    """Every backend name this build understands (settings may be shared)."""
    return name in ("null", "alsa", "wasapi")


def _load_sounddevice():
    try:
        import sounddevice
    except (ImportError, OSError) as exc:  # OSError: PortAudio DLL missing
        raise PlaybackError("Windows audio output is unavailable (PortAudio/sounddevice not installed)") from exc
    return sounddevice


def resolve_device(sd, device: str, hostapi: str | None):
    """Return a PortAudio device index (or None for the library default).

    ``device`` is ``"default"`` or a case-insensitive substring of an output
    device name within `hostapi` (e.g. ``"Speakers"`` or ``"Headphones"``).
    """
    if not isinstance(device, str) or not device or len(device) > 128 or "\x00" in device:
        raise PlaybackError("invalid audio device")
    if hostapi is None:
        return None if device == "default" else device
    apis = sd.query_hostapis()
    index = next((i for i, api in enumerate(apis) if api["name"] == hostapi), None)
    if index is None:
        raise PlaybackError(f"audio host API {hostapi} is not available")
    if device == "default":
        dev = apis[index].get("default_output_device", -1)
        if dev is None or dev < 0:
            raise PlaybackError("no default audio output device")
        return dev
    wanted = device.lower()
    for i, info in enumerate(sd.query_devices()):
        if info["hostapi"] == index and info["max_output_channels"] > 0 and wanted in info["name"].lower():
            return i
    raise PlaybackError("audio output device not found")


def list_output_devices(hostapi: str | None = WASAPI) -> list[dict]:
    """Names for the settings UI/CLI (``holochain-music audio-devices``)."""
    sd = _load_sounddevice()
    apis = sd.query_hostapis()
    out = []
    for info in sd.query_devices():
        api = apis[info["hostapi"]]["name"]
        if info["max_output_channels"] > 0 and (hostapi is None or api == hostapi):
            out.append({"name": info["name"], "hostapi": api,
                        "default_samplerate": info.get("default_samplerate")})
    return out


class PortAudioOutput:
    """Bounded, callback-driven PCM16 output (WASAPI shared mode on Windows).

    ``sd`` may be injected for tests (a fake with ``RawOutputStream``,
    ``query_hostapis``, ``query_devices``, ``WasapiSettings``).
    """

    def __init__(self, fmt, *, device: str = "default", hostapi: str | None = WASAPI,
                 buffer_us: int = DEFAULT_BUFFER_US, latency: float = DEFAULT_LATENCY_S,
                 fallback_hostapi: str | None = MME, sd=None):
        if type(buffer_us) is not int or not 20_000 <= buffer_us <= 2_000_000:
            raise PlaybackError("invalid audio buffer time")
        self.fmt = fmt
        self._sd = sd if sd is not None else _load_sounddevice()
        frames = max(1, fmt.sample_rate * buffer_us // 1_000_000)
        self._limit = frames * fmt.frame_size
        self._ring = bytearray()
        self._cv = threading.Condition()
        self._draining = self._closed = self._aborted = False
        self._error: str | None = None
        self.underruns = 0
        self.delivered = 0
        self._delivered_digest = hashlib.sha256()
        self.hostapi_used: str | None = None
        self._stream = None
        last: BaseException | None = None
        for api in [hostapi] + ([fallback_hostapi] if fallback_hostapi and fallback_hostapi != hostapi else []):
            try:
                self._stream = self._open(api, device, latency)
                self.hostapi_used = api
                break
            except PlaybackError as exc:
                if "not found" in str(exc) or "invalid audio device" in str(exc):
                    raise  # a named device that does not exist: do not guess another
                last = exc
            except Exception as exc:  # sounddevice.PortAudioError and friends
                last = exc
        if self._stream is None:
            raise PlaybackError("unable to open the audio output device") from last
        try:
            self._stream.start()
        except Exception as exc:
            self._stream.close()
            raise PlaybackError("unable to start the audio output device") from exc

    def _open(self, api: str | None, device: str, latency: float):
        sd = self._sd
        index = resolve_device(sd, device, api)
        extra = None
        if api == WASAPI:
            try:  # shared mode; let WASAPI resample 44.1 kHz to a 48 kHz mix format
                extra = sd.WasapiSettings(exclusive=False, auto_convert=True)
            except TypeError:  # sounddevice < 0.5
                extra = sd.WasapiSettings(exclusive=False)
        return sd.RawOutputStream(samplerate=self.fmt.sample_rate, channels=self.fmt.channels,
                                  dtype="int16", device=index, latency=latency,
                                  callback=self._callback, extra_settings=extra)

    # PortAudio's real-time thread: copy, never block, never allocate much.
    def _callback(self, outdata, frames, _time, status) -> None:
        need = frames * self.fmt.frame_size
        with self._cv:
            take = min(need, len(self._ring))
            if take:
                chunk = bytes(self._ring[:take])
                del self._ring[:take]
                outdata[:take] = chunk
                self.delivered += take
                self._delivered_digest.update(chunk)
            if take < need:
                outdata[take:need] = bytes(need - take)
                if not self._draining and not self._aborted and self.delivered:
                    self.underruns += 1
            if status and getattr(status, "output_underflow", False):
                self.underruns += 1
            self._cv.notify_all()

    def write(self, data: bytes) -> None:
        if len(data) % self.fmt.frame_size:
            raise PlaybackError("unaligned PCM block")
        view = memoryview(data)
        while view:
            with self._cv:
                while (len(self._ring) >= self._limit and not self._closed
                       and not self._aborted and self._error is None):
                    if not self._cv.wait(timeout=2.0) and not self._stream_active():
                        self._error = "audio device stopped consuming PCM"
                if self._aborted or self._closed:
                    raise PlaybackError("audio output closed")
                if self._error:
                    raise PlaybackError(self._error)
                room = self._limit - len(self._ring)
                room -= room % self.fmt.frame_size
                piece, view = view[:room], view[room:]
                self._ring.extend(piece)

    def _stream_active(self) -> bool:
        try:
            return bool(self._stream.active)
        except Exception:
            return False

    def close(self) -> None:
        """Play out everything written, then release the device."""
        with self._cv:
            if self._closed or self._aborted:
                return
            self._draining = True
            budget = len(self._ring) / max(1, self.fmt.byte_rate) + 5.0
            deadline = time.monotonic() + budget
            while self._ring and self._error is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self._cv.wait(timeout=min(left, 0.5))
            drained = not self._ring
            self._closed = True
            self._cv.notify_all()
        try:
            self._stream.stop()   # Pa_StopStream plays out the device buffer
        finally:
            self._stream.close()
        if not drained:
            raise PlaybackError("audio output did not drain")

    def abort(self) -> None:
        """Discard queued audio at once (seek, skip, stop)."""
        with self._cv:
            if self._aborted:
                return
            already_closed = self._closed
            self._aborted = True
            self._ring.clear()
            self._cv.notify_all()
        if already_closed:
            return
        try:
            self._stream.abort()  # Pa_AbortStream: no drain
        except Exception:
            pass
        try:
            self._stream.close()
        except Exception:
            pass

    @property
    def delivered_sha256(self) -> str:
        """SHA-256 of every byte handed to the device (tests/diagnostics)."""
        with self._cv:
            return self._delivered_digest.hexdigest()


def open_output(backend: str, fmt, *, device: str = "default", buffer_us: int | None = None):
    """Open one output for `backend`; fails closed if the device is missing."""
    from .buffered_playback import AlsaOutput, NullOutput
    if backend == "null":
        return NullOutput(fmt)
    if backend == "alsa":
        return AlsaOutput(fmt, device=device, buffer_us=buffer_us)
    if backend == "wasapi":
        return PortAudioOutput(fmt, device=device, buffer_us=buffer_us or DEFAULT_BUFFER_US)
    raise PlaybackError("unknown PCM output backend")
