"""S13 opt-in adaptive buffering for authenticated finite MoQ music playback.

This module changes *when* authenticated S10 PCM is released, never which
bytes are released. A buffer underrun is reported as a rebuffer interruption:
we do not generate silence, skip ciphertext or synthesize missing samples.

A bandwidth deficit cannot be fixed by buffering. Adaptive mode raises the
refill threshold after starvation, then lowers it slowly after stable output.
The entire PCM queue remains bounded by S11's existing 64 KiB default.
"""
from __future__ import annotations

import time

from .buffered_playback import BufferedPcmPlayer, MAX_FRAME_BYTES, MAX_QUEUE_BLOCKS
from .granted_audio import PlaybackError


class AdaptivePcmPlayer(BufferedPcmPlayer):
    """S11 player with starvation-triggered bounded refill hysteresis.

    The output worker does not emit unauthenticated PCM: only existing S10
    feed() can append data. In particular, this is not a concealment or a
    transport-retry layer. ALSA may buffer output downstream, so measured
    application interruptions are not precise physical speaker dropouts.
    """

    def __init__(self, *, initial_blocks: int = 3, ceiling_blocks: int = 12,
                 growth_blocks: int = 3, stable_blocks: int = 24, **kwargs):
        max_blocks = kwargs.get("max_blocks", MAX_QUEUE_BLOCKS)
        if any(type(value) is not int for value in
               (initial_blocks, ceiling_blocks, growth_blocks, stable_blocks)):
            raise PlaybackError("invalid adaptive buffer configuration")
        if not 1 <= initial_blocks <= ceiling_blocks <= max_blocks or \
                growth_blocks < 1 or stable_blocks < 1:
            raise PlaybackError("invalid adaptive refill threshold")
        if "prebuffer_blocks" in kwargs:
            raise PlaybackError("adaptive mode sets its own initial prebuffer")
        super().__init__(prebuffer_blocks=initial_blocks, **kwargs)
        self._initial_blocks = initial_blocks
        self._ceiling_blocks = ceiling_blocks
        self._growth_blocks = growth_blocks
        self._stable_blocks = stable_blocks
        self._refill_target = initial_blocks
        self._stable_output_blocks = 0
        self._rebuffer_events = 0
        self._rebuffer_seconds = 0.0
        self._startup_seconds = 0.0
        self._start_at = time.monotonic()
        self._first_output_at = None
        self._latest_output_at = None
        self._max_inter_output_ms = 0.0

    def metrics(self) -> dict:
        with self._cv:
            return {
                "adaptive_buffer": True,
                "adaptive_initial_blocks": self._initial_blocks,
                "adaptive_final_target_blocks": self._refill_target,
                "adaptive_ceiling_blocks": self._ceiling_blocks,
                "rebuffer_events": self._rebuffer_events,
                "rebuffer_duration_ms": round(self._rebuffer_seconds * 1000, 3),
                "startup_delay_ms": round(self._startup_seconds * 1000, 3),
                "max_inter_output_ms": round(self._max_inter_output_ms, 3),
            }

    def finish(self, *, timeout: float = 60.0) -> dict:
        report = super().finish(timeout=timeout)
        return {**report, **self.metrics()}

    def _run(self) -> None:
        assert self._format is not None and self._device is not None
        fmt, output = self._format, self._device
        clean = False
        refilling = True
        refill_started = None
        try:
            while True:
                with self._cv:
                    while True:
                        if self._stopped:
                            return
                        if self._paused:
                            self._cv.wait()
                            continue
                        # Only a complete stream may drain fewer than target
                        # blocks: at EOF there is no future network refill.
                        if refilling and len(self._queue) < self._refill_target and not self._finished:
                            self._cv.wait()
                            continue
                        if refilling:
                            refilling = False
                            if refill_started is not None:
                                self._rebuffer_seconds += time.monotonic() - refill_started
                                refill_started = None
                        if self._queue:
                            block = self._queue.popleft()
                            self._queued_bytes -= len(block)
                            self._cv.notify_all()
                            break
                        if self._finished:
                            clean = True
                            return
                        # A single starvation starts ONE rebuffer period,
                        # rather than incrementing per wakeup or per missing
                        # chunk. Threshold growth stays <= max_blocks.
                        self._underruns += 1
                        self._rebuffer_events += 1
                        self._refill_target = min(
                            self._ceiling_blocks,
                            self._refill_target + self._growth_blocks,
                        )
                        self._stable_output_blocks = 0
                        refill_started = time.monotonic()
                        refilling = True
                        self._cv.notify_all()
                output.write(block)
                instant = time.monotonic()
                with self._cv:
                    self._digest.update(block)
                    self._played_bytes += len(block)
                    self._callbacks += 1
                    if self._first_output_at is None:
                        self._first_output_at = instant
                        self._startup_seconds = instant - self._start_at
                    if self._latest_output_at is not None:
                        self._max_inter_output_ms = max(
                            self._max_inter_output_ms,
                            (instant - self._latest_output_at) * 1000,
                        )
                    self._latest_output_at = instant
                    self._stable_output_blocks += 1
                    if self._stable_output_blocks >= self._stable_blocks:
                        self._refill_target = max(self._initial_blocks, self._refill_target - 1)
                        self._stable_output_blocks = 0
                # Remain compatible with the S11 pacing clock and stop wakeup.
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
