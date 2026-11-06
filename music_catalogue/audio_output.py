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
its own ring (default 400 ms),
plus the separately requested 100 ms shared-mode device latency. ``write``
blocks while the ring is full, which back-pressures the S11 worker without a second software clock
exactly as a full aplay pipe does. ``abort`` discards the ring and aborts the
stream immediately, waking any blocked writer — seeks and track changes do
not wait for queued audio to drain.
"""
from __future__ import annotations

import atexit
from contextlib import contextmanager
import hashlib
import logging
import sys
import threading
import time

from .granted_audio import PlaybackError

WASAPI = "Windows WASAPI"
MME = "MME"
DEFAULT_BUFFER_US = 400_000
DEFAULT_LATENCY_S = 0.10
LOG = logging.getLogger(__name__)
_RUNTIME_LOCK = threading.Lock()
_MTA_RELEASE = None


def available_backends() -> tuple[str, ...]:
    if sys.platform == "win32":
        return ("wasapi", "null")
    return ("alsa", "null")


def default_backend() -> str:
    return available_backends()[0]


def valid_backend(name: str) -> bool:
    """Every backend name this build understands (settings may be shared)."""
    return name in ("null", "alsa", "wasapi")


def _pin_mta():
    """Keep cached PortAudio COM objects alive between short-lived streams.

    Register BEFORE sounddevice imports: atexit's reverse order then terminates
    PortAudio before releasing its process-lifetime MTA reference. No Python
    worker is kept alive between streams. Windows 11 provides these APIs.
    Caller holds _RUNTIME_LOCK.
    """
    global _MTA_RELEASE
    if _MTA_RELEASE is not None:
        return
    import ctypes
    ole32 = ctypes.WinDLL("ole32")
    ole32.CoIncrementMTAUsage.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    ole32.CoIncrementMTAUsage.restype = ctypes.c_long
    ole32.CoDecrementMTAUsage.argtypes = [ctypes.c_void_p]
    ole32.CoDecrementMTAUsage.restype = ctypes.c_long
    cookie = ctypes.c_void_p()
    hr = ole32.CoIncrementMTAUsage(ctypes.byref(cookie))
    if hr < 0:
        raise PlaybackError(f"audio MTA lifetime initialization failed: HRESULT 0x{hr & 0xffffffff:08x}")

    def release():
        # Called once before DLL/process teardown, after sounddevice's handler.
        result = ole32.CoDecrementMTAUsage(cookie)
        if result < 0:
            LOG.error("audio MTA lifetime release failed: HRESULT 0x%08x", result & 0xffffffff)

    _MTA_RELEASE = release
    atexit.register(release)


def _load_sounddevice():
    global _MTA_RELEASE
    # Also cover enumeration on the CLI/main thread: first import must not
    # initialize PortAudio in an STA that outlives/blocks our MTA stream owners.
    with _com_apartment(), _RUNTIME_LOCK:
        had_mta = _MTA_RELEASE is not None
        if sys.platform == "win32":
            _pin_mta()
        try:
            import sounddevice
        except (ImportError, OSError) as exc:
            if not had_mta and _MTA_RELEASE is not None:
                atexit.unregister(_MTA_RELEASE)
                _MTA_RELEASE()
                _MTA_RELEASE = None
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


@contextmanager
def _com_apartment():
    """WASAPI open/start/marshal/release all run in this thread's MTA."""
    if sys.platform != "win32":
        yield
        return
    import ctypes
    ole32 = ctypes.WinDLL("ole32")
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    hr = ole32.CoInitializeEx(None, 0)  # COINIT_MULTITHREADED
    if hr < 0:
        raise PlaybackError(f"audio COM initialization failed: HRESULT 0x{hr & 0xffffffff:08x}")
    try:
        yield
    finally:
        ole32.CoUninitialize()


def _wave_format(raw):
    """Read only WAVEFORMATEX metadata, never PCM payload."""
    import struct
    tag, channels, rate, byte_rate, align, bits, extra = struct.unpack_from("<HHIIHHH", raw)
    subtype = struct.unpack_from("<I", raw, 24)[0] if tag == 65534 and extra >= 22 else tag
    return dict(tag=tag, subtype=subtype, channels=channels, sample_rate=rate,
                byte_rate=byte_rate, block_align=align, bits_per_sample=bits)


def _wasapi_details(sd, stream, device_index):
    """Optional read-only extensions from the SAME DLL sounddevice loaded.

    Owner thread only. These exports are present in the pinned 0.5.6 wheel;
    older/alternative DLLs can omit them without preventing playback.
    """
    if sys.platform != "win32" or not hasattr(sd, "_libname"):
        return {}
    import ctypes
    details = {}
    try:
        dll = ctypes.CDLL(sd._libname)
        pointer = ctypes.c_void_p(int(sd._ffi.cast("uintptr_t", stream._ptr)))
        fn = dll.PaWasapi_GetFramesPerHostBuffer
        fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        fn.restype = ctypes.c_int
        output_frames = ctypes.c_uint()
        code = fn(pointer, None, ctypes.byref(output_frames))
        details["host_buffer_query_code"] = code
        if code == 0:
            details["host_buffer_max_frames"] = output_frames.value
        for name, export in (("mix_format", "PaWasapi_GetDeviceMixFormat"),
                             ("stream_format", "PaWasapi_GetDeviceCurrentFormat")):
            fn = getattr(dll, export)
            raw = ctypes.create_string_buffer(64)
            if name == "mix_format":
                fn.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]
                args = (raw, len(raw), device_index)
            else:
                fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]
                args = (pointer, raw, len(raw), 1)
            fn.restype = ctypes.c_int
            code = fn(*args)
            details[name + "_query_code"] = code
            if code >= 18:
                details[name] = _wave_format(raw.raw)
    except (AttributeError, OSError, TypeError, ValueError, ctypes.ArgumentError) as exc:
        details["query_unavailable"] = type(exc).__name__
    return details


class _PcmRing:
    """Single-producer/single-consumer fixed ring for bundled CPython (GIL).

    Each side publishes its monotonic cursor AFTER copying. Published unread
    slots cannot be overwritten. Only the producer/owner hashes consumed bytes
    before reuse. Reset is permitted only after native callbacks have stopped.
    Free-threaded Python requires a native atomic ring and is not supported.
    """
    def __init__(self, capacity):
        self.storage = bytearray(capacity)
        self.view = memoryview(self.storage)
        self.capacity = capacity
        self.read = self.written = self.hashed = 0
        self.digest = hashlib.sha256()

    def __len__(self):
        return self.written - self.read

    def collect(self):
        end = self.read
        while self.hashed < end:
            offset = self.hashed % self.capacity
            size = min(end - self.hashed, self.capacity - offset)
            self.digest.update(self.view[offset:offset + size])
            self.hashed += size

    def clear(self):
        self.collect()
        self.written = self.read = self.hashed = 0

    def extend(self, data):
        self.collect()
        offset = self.written % self.capacity
        size = min(len(data), self.capacity - offset)
        self.view[offset:offset + size] = data[:size]
        self.view[:len(data) - size] = data[size:]
        self.written += len(data)

    def transfer(self, outdata, size):
        offset = self.read % self.capacity
        first = min(size, self.capacity - offset)
        outdata[:first] = self.view[offset:offset + first]
        if first < size:
            outdata[first:size] = self.view[:size - first]
        self.read += size


class PortAudioOutput:
    """Bounded PCM16 ring; one owner thread for every native stream operation.

    The owner initializes COM before loading sounddevice, including on the
    second and subsequent playback sessions. No PortAudio calls occur from
    the callback, producer, or command threads. Abort wakes blocked writers
    and drainers before waiting for native teardown and callback completion.
    """

    def __init__(self, fmt, *, device: str = "default", hostapi: str | None = WASAPI,
                 buffer_us: int = DEFAULT_BUFFER_US, latency: float = DEFAULT_LATENCY_S,
                 fallback_hostapi: str | None = MME, sd=None):
        if type(buffer_us) is not int or not 20_000 <= buffer_us <= 2_000_000:
            raise PlaybackError("invalid audio buffer time")
        if sys.implementation.name != "cpython" or (hasattr(sys, "_is_gil_enabled") and not sys._is_gil_enabled()):
            raise PlaybackError("PortAudio PCM ring requires GIL-enabled CPython")
        if sys.byteorder != "little":
            raise PlaybackError("PortAudio PCM16 output requires a little-endian host")
        self.fmt = fmt
        self._sd = sd
        frames = max(1, fmt.sample_rate * buffer_us // 1_000_000)
        self._limit = frames * fmt.frame_size
        self._ring = _PcmRing(self._limit)
        self._prebuffer = min(self._limit, max(fmt.frame_size, fmt.byte_rate * 150 // 1000))
        self._primed = self._paused = False
        self._silence = bytes(4096)
        self._silence_view = memoryview(self._silence)
        self._cv = threading.Condition()
        self._draining = self._closed = self._aborted = False
        self._error: BaseException | None = None
        self._teardown_error: BaseException | None = None
        self._request: str | None = None
        self._ready, self._done = threading.Event(), threading.Event()
        self.underruns = 0
        self.delivered = 0
        self.callback_count = self.host_underflows = self.starved_frames = 0
        self.write_calls = self.partial_writes = 0
        self.lock_misses = self.partial_buffers = self.write_waits = 0
        self.callback_max_s = self.callback_gap_max_s = 0.0
        self.callback_frames_min = self.callback_frames_max = 0
        self.queue_low = self._limit
        self.queue_high = 0
        self._last_callback = None
        self._created_at = time.perf_counter()
        self.first_pcm_ms = None
        self.rebuffer_silence_frames = self.startup_silence_frames = 0
        self._starving = False
        self.stream_starts = 0
        self.actual_latency = self.actual_samplerate = self.actual_blocksize = None
        self.hostapi_used: str | None = None
        self._stream = None
        self.native_details = {}
        self._device_index = None
        self._owner = threading.Thread(target=self._own_stream,
                                       args=(hostapi, fallback_hostapi, device, latency),
                                       name="hm-portaudio-owner", daemon=True)
        self._owner.start()
        self._ready.wait()
        if self._error is not None:
            self._owner.join()  # failed initialization has fully released its resources
            raise PlaybackError(str(self._error)) from self._error

    def _own_stream(self, hostapi, fallback_hostapi, device, latency):
        try:
            with _com_apartment():
                try:
                    self._sd = self._sd if self._sd is not None else _load_sounddevice()
                    last = None
                    apis = [hostapi] + ([fallback_hostapi] if fallback_hostapi and fallback_hostapi != hostapi else [])
                    for api in apis:
                        try:
                            self._stream = self._open(api, device, latency)
                            self.hostapi_used = api
                            break
                        except Exception as exc:
                            LOG.exception("audio stream creation failed: api=%s device=%r rate=%s channels=%s",
                                          api, device, self.fmt.sample_rate, self.fmt.channels)
                            if isinstance(exc, PlaybackError) and ("not found" in str(exc) or "invalid audio device" in str(exc)):
                                raise
                            last = exc
                    if self._stream is None:
                        raise PlaybackError(f"unable to open the audio output device: {last}") from last
                    try:
                        self._stream.start()
                        self.stream_starts += 1
                        self.actual_latency = getattr(self._stream, "latency", None)
                        self.actual_samplerate = getattr(self._stream, "samplerate", None)
                        self.actual_blocksize = getattr(self._stream, "blocksize", None)
                        if self.hostapi_used == WASAPI:
                            self.native_details = _wasapi_details(self._sd, self._stream, self._device_index)
                        version = self._sd.get_portaudio_version() if hasattr(self._sd, "get_portaudio_version") else None
                        LOG.info("audio native format: portaudio=%r details=%s", version, self.native_details)
                    except Exception as exc:
                        raise PlaybackError(f"unable to start the audio output device: {exc}") from exc
                    LOG.info("audio stream started: api=%s rate=%s channels=%s", self.hostapi_used,
                             self.fmt.sample_rate, self.fmt.channels)
                    self._ready.set()
                    next_report = time.monotonic() + 5
                    previous_underruns = 0
                    while True:
                        with self._cv:
                            if self._request is None:
                                self._cv.wait(timeout=0.1)
                            mode = self._request
                        if mode is not None:
                            break
                        if time.monotonic() >= next_report:
                            stats = self.diagnostics()
                            log = LOG.warning if self.underruns > previous_underruns else LOG.info
                            log("audio buffer health: %s", stats)
                            previous_underruns = self.underruns
                            next_report = time.monotonic() + 5
                        # Liveness is queried on the owner, never inside the callback.
                        if not self._stream.active:
                            raise PlaybackError("audio output device stopped unexpectedly (removed or callback failed)")
                    LOG.info("audio stream teardown: api=%s mode=%s", self.hostapi_used, mode)
                    if self._error is not None:
                        LOG.error("audio stream error before teardown: %s", self._error)
                    if mode == "close":
                        self._stream.stop(ignore_errors=False)  # play device buffer at natural EOF
                    else:
                        self._stream.abort(ignore_errors=False)  # discard on seek/stop
                except BaseException as exc:
                    LOG.exception("audio output failure: api=%s", self.hostapi_used)
                    with self._cv:
                        self._error = exc
                        self._cv.notify_all()
                    if self._stream is not None:
                        try:
                            self._stream.abort(ignore_errors=False)
                        except Exception:
                            LOG.exception("audio stream abort during recovery failed")
                finally:
                    if self._stream is not None:
                        try:
                            self._stream.close(ignore_errors=False)
                            LOG.info("audio stream closed: api=%s", self.hostapi_used)
                        except BaseException as exc:
                            LOG.exception("audio stream close failed: api=%s", self.hostapi_used)
                            self._teardown_error = exc
        except BaseException as exc:
            LOG.exception("audio owner initialization failed")
            with self._cv:
                self._error = exc
        finally:
            with self._cv:
                self._closed = True
                LOG.info("audio final buffer health: %s", self.diagnostics())
                if self._teardown_error is None:
                    self._ring.clear()
                self._cv.notify_all()
            self._ready.set()
            self._done.set()

    def _open(self, api: str | None, device: str, latency: float):
        sd = self._sd
        index = resolve_device(sd, device, api)
        self._device_index = index
        infos = sd.query_devices()
        info = infos[index] if isinstance(index, int) else {}
        LOG.info("audio stream creating: api=%s device=%r selected=%r name=%r rate=%s channels=%s latency=%s ring_bytes=%s",
                 api, device, index, info.get("name"), self.fmt.sample_rate, self.fmt.channels, latency, self._limit)
        extra = None
        if api == WASAPI:
            try:
                extra = sd.WasapiSettings(exclusive=False, auto_convert=True)
            except TypeError:
                # Conversion must be explicit; the bundled sounddevice supports it.
                raise PlaybackError("WASAPI shared conversion requires sounddevice with auto_convert")
        return sd.RawOutputStream(samplerate=self.fmt.sample_rate, channels=self.fmt.channels,
                                  dtype="int16", device=index, latency=latency, blocksize=0,
                                  callback=self._callback, extra_settings=extra)

    def _zero(self, outdata, start, end):
        while start < end:
            size = min(end - start, len(self._silence))
            outdata[start:start + size] = self._silence_view[:size]
            start += size

    def _callback(self, outdata, frames, _time, status) -> None:
        began = time.perf_counter()
        need = frames * self.fmt.frame_size
        # Even a structural output-buffer failure must reach the owner.
        try:
            self._zero(outdata, 0, need)
        except Exception as exc:
            self._error = PlaybackError(f"audio callback failed: {type(exc).__name__}")
            self._request = "abort"
            raise
        self.callback_count += 1
        self.callback_frames_min = min(self.callback_frames_min or frames, frames)
        self.callback_frames_max = max(self.callback_frames_max, frames)
        if self._last_callback is not None:
            self.callback_gap_max_s = max(self.callback_gap_max_s, began - self._last_callback)
        self._last_callback = began
        if status and getattr(status, "output_underflow", False):
            self.host_underflows += 1
            self.underruns += 1
        # SPSC cursors avoid taking even a nonblocking producer lock: emitting
        # silence on lock contention would itself introduce discontinuities.
        try:
            if self._aborted or self._closed or self._error or self._paused:
                return
            queued = len(self._ring)
            if not self._primed:
                if queued < self._prebuffer and not self._draining:
                    if self._starving:
                        self.rebuffer_silence_frames += frames
                    else:
                        self.startup_silence_frames += frames
                    return  # intentional startup/recovery silence
                self._primed = True
            take = min(need, queued)
            self._ring.transfer(outdata, take)
            if take and self.first_pcm_ms is None:
                self.first_pcm_ms = round((began - self._created_at) * 1000, 3)
            self.delivered += take
            self.queue_low = min(self.queue_low, queued - take)
            if take < need and not self._draining:
                self.partial_buffers += bool(take)
                self.starved_frames += (need - take) // self.fmt.frame_size
                if not self._starving:
                    self.underruns += 1
                self._starving = True
                self._primed = False  # rebuffer instead of alternating PCM/silence
            elif take:
                self._starving = False
        except Exception as exc:
            self._error = PlaybackError(f"audio callback failed: {type(exc).__name__}")
            self._request = "abort"
            self._zero(outdata, 0, need)
            raise
        finally:
            self.callback_max_s = max(self.callback_max_s, time.perf_counter() - began)

    def set_paused(self, paused):
        with self._cv:
            self._paused = paused

    def diagnostics(self):
        # A scalar snapshot; no PCM, keys, identities or expensive callback work.
        return dict(native=self.native_details, first_pcm_ms=self.first_pcm_ms, delivered_frames=self.delivered // self.fmt.frame_size,
                    rebuffer_silence_frames=self.rebuffer_silence_frames,
                    startup_silence_frames=self.startup_silence_frames, callbacks=self.callback_count, underruns=self.underruns,
                    host_underflows=self.host_underflows, starved_frames=self.starved_frames,
                    lock_misses=self.lock_misses, partial_buffers=self.partial_buffers,
                    write_calls=self.write_calls, partial_writes=self.partial_writes,
                    write_waits=self.write_waits, queued_bytes=len(self._ring),
                    capacity_bytes=self._limit, prebuffer_bytes=self._prebuffer,
                    queue_low_bytes=self.queue_low, queue_high_bytes=self.queue_high,
                    callback_max_ms=round(self.callback_max_s * 1000, 3),
                    callback_gap_max_ms=round(self.callback_gap_max_s * 1000, 3),
                    callback_frames_min=self.callback_frames_min,
                    callback_frames_max=self.callback_frames_max,
                    stream_starts=self.stream_starts, actual_latency_s=self.actual_latency,
                    actual_samplerate=self.actual_samplerate, actual_blocksize=self.actual_blocksize,
                    healthy=self.underruns == 0 and self._error is None and self._teardown_error is None)

    def write(self, data: bytes) -> None:
        self.write_calls += 1
        if len(data) % self.fmt.frame_size:
            raise PlaybackError("unaligned PCM block")
        view = memoryview(data)
        while view:
            with self._cv:
                while (len(self._ring) >= self._limit and not self._closed
                       and not self._aborted and self._error is None):
                    self.write_waits += 1
                    self._cv.wait(timeout=0.005)
                if self._error:
                    raise PlaybackError(f"audio output failed: {self._error}") from self._error
                if self._aborted or self._closed or self._draining:
                    raise PlaybackError("audio output closed")
                room = self._limit - len(self._ring)
                room -= room % self.fmt.frame_size
                piece, view = view[:room], view[room:]
                self.partial_writes += bool(view)
                self._ring.extend(piece)
                self.queue_high = max(self.queue_high, len(self._ring))

    def _join_owner(self):
        self._owner.join(timeout=5)
        if self._owner.is_alive():
            raise PlaybackError("audio stream teardown timed out; device still owned")
        if self._teardown_error is not None:
            raise PlaybackError(f"audio stream close failed: {self._teardown_error}") from self._teardown_error

    def close(self) -> None:
        """Drain at natural EOF; a concurrent abort interrupts the ring wait."""
        with self._cv:
            self._draining = True
            deadline = time.monotonic() + len(self._ring) / max(1, self.fmt.byte_rate) + 5
            while self._ring and not self._aborted and not self._closed and self._error is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    self._error = PlaybackError("audio output did not drain")
                    break
                self._cv.wait(timeout=min(left, 0.005))
            if self._request is None:
                self._request = "abort" if self._error or self._aborted else "close"
            self._cv.notify_all()
        self._join_owner()
        if self._error is not None:
            raise PlaybackError(f"audio output failed: {self._error}") from self._error

    def interrupt(self) -> None:
        """Signal cancellation without waiting (also interrupts an EOF drain)."""
        with self._cv:
            self._aborted = True
            self._request = "abort"
            self._cv.notify_all()

    def abort(self) -> None:
        """Discard PCM and await native close and callback completion."""
        self.interrupt()
        self._join_owner()

    @property
    def delivered_sha256(self) -> str:
        with self._cv:
            self._ring.collect()
            return self._ring.digest.hexdigest()


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
