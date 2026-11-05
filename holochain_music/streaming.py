"""Ciphertext download manager with seek priority and bounded recovery.

One `Download` per track fills the library CAS from authenticated hosts.
Playback asks `wait_for(chunk)`; when that chunk is far from the current
transfer position, the transfer is restarted at the needed index (the v1
host honours subscriber-chosen start indices). After the forward pass, any
gaps are requested explicitly as bounded object sets. Every object is
verified against the signed manifest by the receiver and again here.

Failure policy: per attempt the receiver has a stall timeout; attempts back
off exponentially and rotate across hosts; after MAX_ATTEMPTS consecutive
failures the download enters the explicit `unavailable` state, keeps every
verified object, and can be resumed later. Nothing here can decrypt.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

from holochain_storage.package import StorageError, _read_verified_chunk, verify_package
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.moq_host import MoqFetchCancelled, MoqFetchError, fetch_ciphertext

from .catalogue import TrustedTrack

LOOKAHEAD_CHUNKS = 4
MAX_ATTEMPTS = 6
MAX_BACKOFF = 16.0
BATCH_OBJECTS = 64


class TrackUnavailable(PlaybackError):
    """No authenticated host could supply a required chunk."""


class Download:
    def __init__(self, *, trusted: TrustedTrack, store, moq_binary, allow_lan: bool = False,
                 present: set[int] | None = None, on_complete: Callable[[], None] | None = None,
                 stall_timeout: float = 20.0):
        self.trusted = trusted
        self.store = store
        self.moq_binary = moq_binary
        self.allow_lan = allow_lan
        self.chunks = trusted.manifest["body"]["chunks"]
        self.total = len(self.chunks)
        self.available: set[int] = set(present or ())
        self.on_complete = on_complete
        self.stall_timeout = stall_timeout
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._restart = threading.Event()
        self._priority: int | None = None
        self._position: int | None = None  # next index the active stream will deliver
        self.state = "complete" if len(self.available) == self.total else "idle"
        self.error: str | None = None
        self.attempts = 0
        self.failures = 0
        self.host_index = 0
        self.metrics = {"objects_received": 0, "restarts_for_seek": 0, "retries": 0,
                        "rebuffer_events": 0, "rebuffer_seconds": 0.0, "duplicates_ignored": 0}
        self._thread: threading.Thread | None = None

    # ---- status ------------------------------------------------------
    def progress(self) -> dict:
        with self._cv:
            return {"state": self.state, "available_chunks": len(self.available),
                    "total_chunks": self.total, "error": self.error,
                    "host": self.trusted.hosts[self.host_index % len(self.trusted.hosts)].url
                    if self.trusted.hosts else None, **self.metrics}

    # ---- control -----------------------------------------------------
    def start(self) -> None:
        with self._cv:
            if self.state == "complete" or (self._thread and self._thread.is_alive()):
                return
            self.state, self.error, self.failures = "downloading", None, 0
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="hm-download", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._restart.set()
        with self._cv:
            self._cv.notify_all()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=10)

    def prioritise(self, index: int) -> None:
        with self._cv:
            if index in self.available:
                return
            self._priority = index
            pos = self._position
            far = pos is None or index < pos or index - pos > LOOKAHEAD_CHUNKS
        if far:
            with self._cv:
                self.metrics["restarts_for_seek"] += 1
            self._restart.set()
        if self.state in ("idle", "unavailable", "paused"):
            self.start()

    def wait_for(self, chunk: dict, *, cancel: threading.Event | None = None,
                 timeout: float = 120.0, buffering: Callable[[bool], None] | None = None) -> None:
        """Block until `chunk` is verified in the CAS (used as InflightWavSeeker waiter)."""
        index = chunk["index"]
        with self._cv:
            if index in self.available:
                return
        self.prioritise(index)
        started = time.monotonic()
        if buffering:
            buffering(True)
        with self._cv:
            self.metrics["rebuffer_events"] += 1
        try:
            with self._cv:
                while index not in self.available:
                    if cancel is not None and cancel.is_set():
                        raise PlaybackError("playback cancelled while buffering")
                    if self.state == "unavailable":
                        raise TrackUnavailable(self.error or "track unavailable")
                    if time.monotonic() - started > timeout:
                        raise TrackUnavailable("timed out waiting for encrypted audio")
                    self._cv.wait(0.25)
        finally:
            with self._cv:
                self.metrics["rebuffer_seconds"] = round(self.metrics["rebuffer_seconds"] + time.monotonic() - started, 3)
            if buffering:
                buffering(False)

    # ---- worker ------------------------------------------------------
    def _mark(self, index: int) -> None:
        _read_verified_chunk(self.store, self.chunks[index])
        with self._cv:
            if index in self.available:
                self.metrics["duplicates_ignored"] += 1
            else:
                self.available.add(index)
                self.metrics["objects_received"] += 1
            self._position = index + 1
            if self._priority is not None and self._priority in self.available:
                self._priority = None
            self._cv.notify_all()
        # A seek far away asked us to restart: end this transfer early.
        if self._restart.is_set():
            raise MoqFetchCancelled("restart for seek")

    def _plan(self) -> tuple[int | None, list[int] | None]:
        with self._cv:
            missing = [i for i in range(self.total) if i not in self.available]
            if not missing:
                return None, None
            first = self._priority if self._priority in missing else missing[0]
            tail = [i for i in missing if i >= first]
            if tail == list(range(first, self.total)):
                return first, None
            # Non-contiguous: stream forward from `first` until the next present
            # object would be re-sent; then request the gap set explicitly.
            gap = []
            for i in tail:
                if gap and i != gap[-1] + 1:
                    break
                gap.append(i)
            if len(gap) > BATCH_OBJECTS and gap[-1] == self.total - 1:
                return first, None
            return None, gap[:BATCH_OBJECTS] if gap else missing[:BATCH_OBJECTS]

    def _run(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            start, objects = self._plan()
            if start is None and objects is None:
                try:
                    verify_package(self.trusted.manifest, self.store, self.trusted.artist_key)
                except StorageError as exc:
                    with self._cv:
                        self.state, self.error = "unavailable", f"verification failed: {exc}"[:200]
                        self._cv.notify_all()
                    return
                with self._cv:
                    self.state = "complete"
                    self._cv.notify_all()
                if self.on_complete:
                    self.on_complete()
                return
            host = self.trusted.hosts[self.host_index % len(self.trusted.hosts)]
            self._restart.clear()
            with self._cv:
                self._position = start if start is not None else None
                self.attempts += 1
            try:
                fetch_ciphertext(moq_binary=self.moq_binary, signed_manifest=self.trusted.manifest,
                                 trusted_artist=self.trusted.artist_key,
                                 expected_manifest_sha256=self.trusted.digest, store=self.store,
                                 url=host.url, cert_fingerprint_hex=host.fingerprint,
                                 start_index=start or 0, objects=objects, allow_lan=self.allow_lan,
                                 on_chunk=self._mark, cancel=self._restart,
                                 stall_timeout=self.stall_timeout)
                backoff = 1.0
                with self._cv:
                    self.failures = 0
            except MoqFetchCancelled:
                continue
            except (MoqFetchError, StorageError, OSError) as exc:
                with self._cv:
                    self.failures += 1
                    self.metrics["retries"] += 1
                    self.host_index += 1
                    if self.failures >= MAX_ATTEMPTS:
                        self.state = "unavailable"
                        self.error = f"hosts unreachable after {self.failures} attempts: {exc}"[:200]
                        self._cv.notify_all()
                        return
                    self.state = "retrying"
                if self._restart.wait(min(backoff, MAX_BACKOFF)) and self._stop.is_set():
                    return
                backoff *= 2
                with self._cv:
                    if self.state == "retrying":
                        self.state = "downloading"
        with self._cv:
            if self.state not in ("complete", "unavailable"):
                self.state = "paused"
            self._cv.notify_all()
