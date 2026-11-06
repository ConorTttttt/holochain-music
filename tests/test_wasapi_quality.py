"""PCM correctness with a manually clocked device; no physical sound claim."""
import hashlib
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
import wave

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from holochain_storage.package import create_package, public_key_bytes
from music_catalogue.content_grants import issue_personal_licence
from music_catalogue.buffered_playback import AudioFormat, BufferedPcmPlayer, play_granted_wav_realtime
from music_catalogue.audio_output import PortAudioOutput
from test_windows_port import FakeSd


class ManualStream:
    def __init__(self, **kw):
        self.kw = kw
        self.active = False
        self.latency = kw['latency']
        self.samplerate = kw['samplerate']
        self.blocksize = 0
    def start(self): self.active = True
    def stop(self, **kw): self.active = False
    abort = stop
    close = stop


class ManualSd(FakeSd):
    def RawOutputStream(self, **kw):
        self.stream = ManualStream(**kw)
        return self.stream


class QualityTests(unittest.TestCase):
    def output(self, rate=44100):
        sd = ManualSd()
        out = PortAudioOutput(AudioFormat(rate, 2, 16), sd=sd, fallback_hostapi=None)
        self.addCleanup(out.abort)
        self.assertEqual(sd.stream.kw['samplerate'], rate)
        self.assertEqual(sd.stream.kw['dtype'], 'int16')
        self.assertEqual(sd.wasapi_args, dict(exclusive=False, auto_convert=True))
        return out

    def callback(self, out, frames, status=None):
        data = bytearray(b'\xa5' * (frames * 4))
        out._callback(data, frames, None, status)
        return bytes(data)

    def test_exact_stereo_both_rates_arbitrary_callbacks_wrap_and_channels(self):
        for rate in (44100, 48000):
            with self.subTest(rate=rate):
                out = self.output(rate)
                pattern = b''.join(struct.pack('<hh', i - 16000, 16000 - i) for i in range(32000))
                source = pattern * 3
                supplied = consumed = 0
                sizes = (1, 3, 7, 257, 441, 480, 1023, 4093, 20000)
                i = 0
                while consumed < len(source):
                    room = out._limit - len(out._ring)
                    piece = source[supplied:supplied + room]
                    if piece:
                        out.write(piece)
                        supplied += len(piece)
                    out._draining = supplied == len(source)
                    frames = sizes[i % len(sizes)]
                    queued = len(out._ring)
                    result = self.callback(out, frames)
                    take = min(queued, frames * 4)
                    self.assertEqual(result[:take], source[consumed:consumed + take])
                    self.assertEqual(result[take:], bytes(len(result) - take))
                    consumed += take
                    i += 1
                out.close()
                self.assertEqual(out.delivered_sha256, hashlib.sha256(source).hexdigest())
                self.assertEqual(out.delivered, len(source))
                self.assertLessEqual(out.queue_high, out._limit)

    def test_prebuffer_partial_underrun_recovery_pause_and_abort_silence(self):
        out = self.output()
        frame = struct.pack('<hh', 1234, -2345)
        out.write(frame * 10)
        self.assertEqual(self.callback(out, 17), bytes(68))
        self.assertEqual(out.delivered, 0)
        out.write(frame * (out._prebuffer // 4 - 10))
        frames = out._prebuffer // 4 + 13
        result = self.callback(out, frames)
        self.assertEqual(result, frame * (out._prebuffer // 4) + bytes(13 * 4))
        self.assertEqual(out.underruns, 1)
        self.assertEqual(out.partial_buffers, 1)
        self.assertEqual(self.callback(out, 19), bytes(76))
        self.assertEqual(out.underruns, 1)
        self.assertEqual(out.rebuffer_silence_frames, 19)
        out.write(frame * (out._prebuffer // 4))
        out.set_paused(True)
        queued = len(out._ring)
        self.assertEqual(self.callback(out, 441), bytes(1764))
        self.assertEqual(len(out._ring), queued)
        out.set_paused(False)
        self.assertEqual(self.callback(out, 441), frame * 441)
        self.assertFalse(out.diagnostics()['healthy'])
        out.abort()
        self.assertEqual(self.callback(out, 513), bytes(2052))
        self.assertEqual(len(out._ring), 0)

    def test_callback_never_waits_for_producer_lock(self):
        out = self.output()
        frame = struct.pack('<hh', 123, -456)
        out.write(frame * (out._prebuffer // 4))
        entered, release = threading.Event(), threading.Event()
        def hold():
            with out._cv:
                entered.set()
                release.wait(2)
        t = threading.Thread(target=hold)
        t.start()
        self.assertTrue(entered.wait(1))
        try:
            began = time.perf_counter()
            self.assertEqual(self.callback(out, 441), frame * 441)
            self.assertLess(time.perf_counter() - began, .1)
            self.assertEqual(out.lock_misses, 0)
            self.assertEqual(out.underruns, 0)
        finally:
            release.set()
            t.join()

    def test_host_underflow_is_distinct_and_visible(self):
        out = self.output()
        class Status: output_underflow = True
        self.callback(out, 480, Status())
        self.assertEqual(out.host_underflows, 1)
        self.assertFalse(out.diagnostics()['healthy'])

    def test_short_eof_below_prebuffer_drains_without_starvation(self):
        out = self.output()
        data = struct.pack('<hh', -32768, 32767) * 11
        out.write(data)
        errors = []
        def close():
            try: out.close()
            except Exception as exc: errors.append(exc)
        t = threading.Thread(target=close)
        t.start()
        deadline = time.monotonic() + 1
        while not out._draining and time.monotonic() < deadline: time.sleep(.001)
        self.assertEqual(self.callback(out, 27), data + bytes(64))
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(out.underruns, 0)
        self.assertEqual(out.delivered_sha256, hashlib.sha256(data).hexdigest())

    def test_authenticated_three_minutes_offline_accelerated_device_clock(self):
        # 180 seconds of exact 44.1 kHz stereo, real licence/AES/SHA path.
        # Device time is advanced manually: this tests continuity, not scheduling.
        rate = 44100
        one = b''.join(struct.pack('<hh', (i % 20000) - 10000, 10000 - (i % 20000)) for i in range(rate))
        expected = hashlib.sha256(one * 180).hexdigest()
        out = self.output()
        engine = BufferedPcmPlayer(backend='wasapi', output_factory=lambda fmt: out)
        def forbidden_wait(*args): raise AssertionError('WASAPI worker must use device backpressure')
        engine._interrupt.wait = forbidden_wait
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wav = root / 'generated.wav'
            with wave.open(str(wav), 'wb') as w:
                w.setparams((2, 2, rate, 0, 'NONE', 'not compressed'))
                for _ in range(180): w.writeframesraw(one)
            artist, recipient = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
            manifest, key = create_package(wav, root / 'cas', artist)
            wav.unlink()
            grant = issue_personal_licence(owner_signer=artist, owner_agent='artist', listener_agent='listener',
                recipient_public=recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                signed_manifest=manifest, content_key=key)
            results, errors = [], []
            def produce():
                try:
                    results.append(play_granted_wav_realtime(signed_manifest=manifest, ciphertext_store=root / 'cas',
                        grant=grant, trusted_artist=public_key_bytes(artist), owner_agent='artist', listener_agent='listener',
                        recipient_private=recipient, player=engine))
                except Exception as exc: errors.append(exc)
            t = threading.Thread(target=produce)
            t.start()
            deadline = time.monotonic() + 40
            i = 0
            captured = hashlib.sha256()
            while t.is_alive() and time.monotonic() < deadline:
                frames = (257, 441, 480, 997)[i % 4]
                # Let the producer fill ahead, as an offline device clock does.
                if len(out._ring) >= max(out._prebuffer, frames * 4) or out._draining:
                    # This synthetic clock checks continuity; contention has a separate test.
                    with out._cv:
                        before = out.delivered
                        block = self.callback(out, frames)
                        captured.update(block[:out.delivered - before])
                    i += 1
                else: time.sleep(.0005)
            if t.is_alive(): engine.stop()
            t.join(2)
            self.assertFalse(t.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(out.delivered, rate * 4 * 180)
            self.assertEqual(out.delivered_sha256, expected)
            self.assertEqual(captured.hexdigest(), expected)
            self.assertEqual(out.underruns, 0)
            self.assertLessEqual(out.queue_high, out._limit)
            self.assertTrue(results[0]['playback_complete'])


class NativeMetadataTests(unittest.TestCase):
    def test_wave_format_pcm_and_extensible_float_metadata(self):
        from music_catalogue.audio_output import _wave_format
        pcm = struct.pack('<HHIIHHH', 1, 2, 44100, 176400, 4, 16, 0) + bytes(46)
        self.assertEqual(_wave_format(pcm)['subtype'], 1)
        self.assertEqual(_wave_format(pcm)['block_align'], 4)
        ext = struct.pack('<HHIIHHHHII', 65534, 2, 48000, 384000, 8, 32, 22, 32, 3, 3) + bytes(36)
        metadata = _wave_format(ext)
        self.assertEqual(metadata['subtype'], 3)
        self.assertEqual(metadata['sample_rate'], 48000)
        self.assertEqual(metadata['channels'], 2)

    def test_owner_diagnostics_query_same_dll_pointer_and_formats(self):
        import ctypes
        from types import SimpleNamespace
        from unittest import mock
        from music_catalogue import audio_output
        raw = struct.pack('<HHIIHHH', 1, 2, 48000, 192000, 4, 16, 0)
        dll = mock.Mock()
        def frames(pointer, input_frames, output_frames):
            self.assertEqual(pointer.value, 1234)
            self.assertIsNone(input_frames)
            ctypes.cast(output_frames, ctypes.POINTER(ctypes.c_uint))[0] = 4800
            return 0
        def mix(buffer, size, device):
            self.assertEqual(device, 2)
            ctypes.memmove(buffer, raw, len(raw))
            return len(raw)
        def current(pointer, buffer, size, output):
            self.assertEqual(pointer.value, 1234)
            self.assertEqual(output, 1)
            ctypes.memmove(buffer, raw, len(raw))
            return len(raw)
        dll.PaWasapi_GetFramesPerHostBuffer.side_effect = frames
        dll.PaWasapi_GetDeviceMixFormat.side_effect = mix
        dll.PaWasapi_GetDeviceCurrentFormat.side_effect = current
        sd = SimpleNamespace(_libname='pinned-portaudio.dll', _ffi=mock.Mock())
        sd._ffi.cast.return_value = 1234
        with mock.patch.object(audio_output.sys, 'platform', 'win32'), mock.patch.object(ctypes, 'CDLL', return_value=dll) as load:
            details = audio_output._wasapi_details(sd, SimpleNamespace(_ptr='ptr'), 2)
        load.assert_called_once_with('pinned-portaudio.dll')
        self.assertEqual(details['host_buffer_max_frames'], 4800)
        self.assertEqual(details['stream_format']['sample_rate'], 48000)
        self.assertEqual(details['mix_format']['bits_per_sample'], 16)

    def test_missing_optional_native_exports_do_not_break_playback(self):
        from types import SimpleNamespace
        from unittest import mock
        from music_catalogue import audio_output
        import ctypes
        sd = SimpleNamespace(_libname='older.dll', _ffi=mock.Mock())
        sd._ffi.cast.return_value = 1234
        with mock.patch.object(audio_output.sys, 'platform', 'win32'), mock.patch.object(ctypes, 'CDLL', return_value=object()):
            self.assertEqual(audio_output._wasapi_details(sd, SimpleNamespace(_ptr='ptr'), 2)['query_unavailable'], 'AttributeError')
