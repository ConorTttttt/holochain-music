#!/usr/bin/env python3
"""Clocked offline PCM model; never claims Windows/device or speaker evidence.

Run rc2 baseline with --baseline-audio FILE --baseline-buffered FILE saved before
editing. --pacer-delay-ms adds controlled scheduler overhead ONLY to the software
pacer. The device uses absolute 10 ms deadlines. No ciphertext/network involved;
authenticated multi-minute PCM correctness is tested in test_wasapi_quality.py.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=12)
parser.add_argument('--pacer-delay-ms', type=float, default=2)
parser.add_argument('--baseline-audio')
parser.add_argument('--baseline-buffered')
parser.add_argument('--json')
args = parser.parse_args()
for name, filename in [('audio_output', args.baseline_audio), ('buffered_playback', args.baseline_buffered)]:
    if filename:
        name = 'music_catalogue.' + name
        spec = importlib.util.spec_from_file_location(name, filename)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
from music_catalogue.audio_output import PortAudioOutput
from music_catalogue.buffered_playback import AudioFormat, BufferedPcmPlayer

class Clock:
    def __init__(self, **kw):
        self.kw = kw
        self.active = False
        self.latency = kw['latency']
        self.blocksize = 0
        self.samplerate = kw['samplerate']
        self.callback_max_s = self.callback_gap_max_s = 0
        self.previous = None
        self.callbacks = 0
    def start(self):
        self.active = True
        self.thread = threading.Thread(target=self.run)
        self.thread.start()
    def run(self):
        deadline = time.perf_counter()
        while self.active:
            began = time.perf_counter()
            self.kw['callback'](bytearray(441 * 4), 441, None, None)
            self.callback_max_s = max(self.callback_max_s, time.perf_counter() - began)
            if self.previous is not None:
                self.callback_gap_max_s = max(self.callback_gap_max_s, began - self.previous)
            self.previous = began
            self.callbacks += 1
            deadline += .01
            time.sleep(max(0, deadline - time.perf_counter()))
    def stop(self, **kw):
        self.active = False
        self.thread.join()
    abort = stop
    def close(self, **kw): pass

class Sd:
    def query_hostapis(self):
        return [dict(name='Windows WASAPI', default_output_device=0)]
    def query_devices(self):
        return [dict(name='MODEL 48kHz mix device', hostapi=0, max_output_channels=2, default_samplerate=48000)]
    def WasapiSettings(self, **kw): return kw
    def RawOutputStream(self, **kw):
        self.stream = Clock(**kw)
        return self.stream

fmt = AudioFormat(44100, 2, 16)
sd = Sd()
out = PortAudioOutput(fmt, sd=sd, fallback_hostapi=None)
engine = BufferedPcmPlayer(backend='wasapi', output_factory=lambda f: out, burst_bytes=44100)
real_wait = engine._interrupt.wait
engine._interrupt.wait = lambda delay: real_wait(delay + args.pacer_delay_ms / 1000)
engine.start(dict(sample_rate=44100, channels=2, bits_per_sample=16))
one = b''.join(struct.pack('<hh', i % 20000 - 10000, 10000 - i % 20000) for i in range(44100))
data = one * args.seconds
began = time.perf_counter()
low, high = out._limit, 0
for i in range(0, len(data), 4096):
    engine.feed(data[i:i + 4096])
    occupancy = len(out._ring)
    low, high = min(low, occupancy), max(high, occupancy)
engine.finish(timeout=args.seconds * 2 + 10)
result = dict(model='absolute 10ms Python device clock; not WASAPI hardware', seconds=args.seconds,
    elapsed_s=round(time.perf_counter() - began, 3), injected_pacer_delay_ms=args.pacer_delay_ms,
    underruns=out.underruns, ring_low_bytes=low, ring_high_bytes=high, capacity_bytes=out._limit,
    delivered_bytes=out.delivered, expected_bytes=len(data),
    digest_ok=out.delivered_sha256 == hashlib.sha256(data).hexdigest(),
    callbacks=sd.stream.callbacks, callback_max_ms=round(sd.stream.callback_max_s * 1000, 3),
    callback_gap_max_ms=round(sd.stream.callback_gap_max_s * 1000, 3))
if hasattr(out, 'diagnostics'): result['diagnostics'] = out.diagnostics()
encoded = json.dumps(result, sort_keys=True)
print(encoded)
if args.json: Path(args.json).write_text(encoded + '\n')
