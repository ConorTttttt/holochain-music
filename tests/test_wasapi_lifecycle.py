"""Real authenticated Player, instrumented native stream with thread affinity.

No physical audio. Fails on overlapping stream lifetimes, cross-thread native
calls, callbacks surviving close, stale PCM, blocked-write/drain cancellation.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from holochain_music import player as player_mod
from holochain_music.player import Player, SessionSpec
from music_catalogue import audio_output
from music_catalogue.audio_output import PortAudioOutput
from music_catalogue.buffered_playback import AudioFormat, BufferedPcmPlayer
from music_catalogue.granted_audio import PlaybackError
from test_v1_app_player import wait_state
from test_windows_port import FakeSd, FMT, pcm
from v1_fixtures import Track


def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("condition did not become true")
        time.sleep(0.002)


class NativeStream:
    def __init__(self, sd, **kw):
        self.sd, self.kw = sd, kw
        self.callback = kw['callback']
        self.owner = threading.get_ident()
        self.closed = False
        self.running = threading.Event()
        self.thread = None
        self.calls = []
        self.id = len(sd.streams)
        assert all(s.closed for s in sd.streams), 'replacement opened before old stream closed'
        sd.streams.append(self)
        self.call('open')

    def call(self, operation):
        assert threading.get_ident() == self.owner, 'native operation moved to another thread'
        self.calls.append(operation)
        self.sd.events.append((self.id, operation))

    @property
    def active(self):
        self.call('active')
        if self.sd.fail_active:
            raise RuntimeError('WASAPI AUDCLNT_E_DEVICE_INVALIDATED 0x88890004')
        return self.running.is_set()

    def start(self):
        self.call('start')
        if self.sd.fail_start:
            self.sd.fail_start -= 1
            raise RuntimeError('WASAPI startup HRESULT 0x800401f0')
        self.running.set()
        self.thread = threading.Thread(target=self.clock, name='fake-portaudio-callback')
        self.thread.start()

    def clock(self):
        while self.running.is_set():
            if self.sd.consume.is_set():
                self.callback(bytearray(256 * self.kw['channels'] * 2), 256, None, None)
            self.sd.tick.wait(0.001)

    def stop(self, ignore_errors=True):
        assert not ignore_errors
        self.call('stop')
        self.running.clear()
        if self.thread:
            self.thread.join(1)
        self.sd.stop_entered.set()
        self.sd.stop_release.wait(2)
        if self.sd.fail_stop:
            raise RuntimeError('WASAPI stop failure')

    def abort(self, ignore_errors=True):
        assert not ignore_errors
        self.call('abort')
        self.running.clear()
        if self.thread:
            self.thread.join(1)
        if self.sd.fail_abort:
            raise RuntimeError('WASAPI abort failure')

    def close(self, ignore_errors=True):
        assert not ignore_errors
        self.call('close')
        self.running.clear()
        if self.thread:
            self.thread.join(1)
            assert not self.thread.is_alive(), 'callback leaked'
        self.closed = True
        if self.sd.fail_close:
            raise RuntimeError('WASAPI close failure')


class InstrumentedSd(FakeSd):
    def __init__(self):
        super().__init__()
        self.streams, self.events = [], []
        self.consume, self.tick = threading.Event(), threading.Event()
        self.consume.set()
        self.stop_entered, self.stop_release = threading.Event(), threading.Event()
        self.stop_release.set()
        self.fail_start = self.fail_open = 0
        self.fail_active = self.fail_stop = self.fail_abort = self.fail_close = False

    def RawOutputStream(self, **kw):
        if self.fail_open:
            self.fail_open -= 1
            raise RuntimeError('WASAPI open device unavailable -9985')
        return NativeStream(self, **kw)


class ComApartmentTests(unittest.TestCase):
    def test_com_is_balanced_on_success_and_exception(self):
        import ctypes
        for hr in (0, 1):  # S_OK, S_FALSE both require CoUninitialize
            for fail_body in (False, True):
                with self.subTest(hr=hr, fail_body=fail_body):
                    ole = mock.Mock()
                    ole.CoInitializeEx.return_value = hr
                    with mock.patch.object(ctypes, 'WinDLL', return_value=ole, create=True), \
                            mock.patch.object(audio_output.sys, 'platform', 'win32'):
                        try:
                            with audio_output._com_apartment():
                                if fail_body:
                                    raise RuntimeError('body failure')
                        except RuntimeError:
                            self.assertTrue(fail_body)
                    ole.CoInitializeEx.assert_called_once_with(None, 0)
                    ole.CoUninitialize.assert_called_once_with()

    def test_failed_com_init_is_reported_without_uninitializing(self):
        import ctypes
        ole = mock.Mock()
        ole.CoInitializeEx.return_value = -2147417850  # RPC_E_CHANGED_MODE
        with mock.patch.object(ctypes, 'WinDLL', return_value=ole, create=True), \
                mock.patch.object(audio_output.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(PlaybackError, 'HRESULT 0x80010106'):
                with audio_output._com_apartment():
                    self.fail('COM initialization should have failed')
        ole.CoUninitialize.assert_not_called()


class MtaRuntimeTests(unittest.TestCase):
    def test_runtime_pins_once_before_import_and_releases_after_portaudio(self):
        import builtins
        import ctypes
        events, handlers = [], []
        ole = mock.Mock()
        ole.CoIncrementMTAUsage.side_effect = lambda cookie: events.append('pin') or 0
        ole.CoDecrementMTAUsage.side_effect = lambda cookie: events.append('unpin') or 0
        module = object()
        real_import = builtins.__import__
        imported = False
        def importing(name, *args, **kw):
            nonlocal imported
            if name == 'sounddevice':
                if not imported:
                    events.append('initialize PortAudio')
                    # Mimic sounddevice registering its own exit handler at import.
                    handlers.append(lambda: events.append('terminate PortAudio'))
                    imported = True
                return module
            return real_import(name, *args, **kw)
        with mock.patch.object(audio_output, '_MTA_RELEASE', None), \
                mock.patch.object(audio_output, '_com_apartment', lambda: mock.MagicMock()), \
                mock.patch.object(audio_output.sys, 'platform', 'win32'), \
                mock.patch.object(ctypes, 'WinDLL', return_value=ole, create=True), \
                mock.patch.object(audio_output.atexit, 'register', side_effect=handlers.append), \
                mock.patch.object(builtins, '__import__', side_effect=importing):
            self.assertIs(audio_output._load_sounddevice(), module)
            self.assertIs(audio_output._load_sounddevice(), module)
            self.assertEqual(events, ['pin', 'initialize PortAudio'])
            for handler in reversed(handlers):
                handler()
        self.assertEqual(events, ['pin', 'initialize PortAudio', 'terminate PortAudio', 'unpin'])
        ole.CoIncrementMTAUsage.assert_called_once()
        ole.CoDecrementMTAUsage.assert_called_once()

    def test_import_failure_releases_new_pin_and_allows_retry(self):
        import ctypes
        import sys
        ole = mock.Mock()
        ole.CoIncrementMTAUsage.return_value = 0
        ole.CoDecrementMTAUsage.return_value = 0
        with mock.patch.object(audio_output, '_MTA_RELEASE', None), \
                mock.patch.object(audio_output, '_com_apartment', lambda: mock.MagicMock()), \
                mock.patch.object(audio_output.sys, 'platform', 'win32'), \
                mock.patch.object(ctypes, 'WinDLL', return_value=ole, create=True), \
                mock.patch.object(audio_output.atexit, 'register') as register, \
                mock.patch.object(audio_output.atexit, 'unregister') as unregister, \
                mock.patch.dict(sys.modules, {'sounddevice': None}):
            for _ in range(2):
                with self.assertRaisesRegex(PlaybackError, 'sounddevice not installed'):
                    audio_output._load_sounddevice()
                self.assertIsNone(audio_output._MTA_RELEASE)
            self.assertEqual(register.call_count, 2)
            self.assertEqual(unregister.call_count, 2)
            self.assertEqual(ole.CoIncrementMTAUsage.call_count, 2)
            self.assertEqual(ole.CoDecrementMTAUsage.call_count, 2)

    def test_failed_runtime_pin_does_not_register_release(self):
        import ctypes
        ole = mock.Mock()
        ole.CoIncrementMTAUsage.return_value = -2147024882  # E_OUTOFMEMORY
        with mock.patch.object(audio_output, '_MTA_RELEASE', None), \
                mock.patch.object(ctypes, 'WinDLL', return_value=ole, create=True), \
                mock.patch.object(audio_output.atexit, 'register') as register:
            with self.assertRaisesRegex(PlaybackError, 'HRESULT 0x8007000e'):
                audio_output._pin_mta()
        register.assert_not_called()
        ole.CoDecrementMTAUsage.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.sd = InstrumentedSd()
        self.outputs = []
        self.players = []
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.track = Track(Path(self.tmp.name) / 'a', seconds=1.4, rate=44100)
        self.other = Track(Path(self.tmp.name) / 'b', seconds=0.8, rate=44100)
        self.tracks = {t.file_id: t for t in (self.track, self.other)}
        self.grants = {k: t.licence() for k, t in self.tracks.items()}
        patcher = mock.patch.object(audio_output, '_load_sounddevice', lambda: self.sd)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.cleanup_audio)

    def cleanup_audio(self):
        self.sd.stop_release.set()
        self.sd.consume.set()
        for p in self.players:
            p.shutdown()
        for out in self.outputs:
            out.abort()
        for s in self.sd.streams:
            self.assertTrue(s.closed)
            if s.thread:
                self.assertFalse(s.thread.is_alive(), 'callback leaked')
        self.assertFalse([t for t in threading.enumerate() if t.name in
                          ('hm-portaudio-owner', 'fake-portaudio-callback', 'hm-player', 'holochain-music-s11-pcm')])

    def spec(self, key):
        t = self.tracks[key]
        return SessionSpec(key=key, manifest=t.manifest, grant=self.grants[key], artist_key=t.artist_key,
                           owner_agent=t.owner, listener_agent=t.reader, recipient=t.listener, store=t.store)

    def player(self):
        p = Player(backend='wasapi', resolve=self.spec)
        self.players.append(p)
        return p

    def output(self):
        out = PortAudioOutput(FMT, sd=self.sd)
        self.outputs.append(out)
        return out

    def expected(self, key, start):
        from music_catalogue.seekable_recovery import VerifiedWavSeeker
        t = self.tracks[key]
        reader = VerifiedWavSeeker(signed_manifest=t.manifest, ciphertext_store=t.store, grant=self.grants[key],
                                   trusted_artist=t.artist_key, owner_agent=t.owner, listener_agent=t.reader,
                                   recipient_private=t.listener)
        return hashlib.sha256(b''.join(reader.iter_frames(start))).hexdigest()

    def finished(self, p, key, start):
        state = wait_state(p, {'finished', 'error'})
        self.assertEqual(state['state'], 'finished', state)
        native = self.sd.streams[-1]
        self.assertEqual(native.callback.__self__.delivered_sha256, self.expected(key, start))
        self.assertEqual(native.calls.count('close'), 1)
        self.assertEqual(native.calls.count('stop'), 1)
        self.assertFalse(state['output_active'])

    def test_forward_seek_discards_full_ring_and_unblocks_writer(self):
        self.check_seek(0, 33000)

    def test_backward_seek_discards_full_ring_and_unblocks_writer(self):
        self.check_seek(33000, 4400)

    def check_seek(self, initial, target):
        self.sd.consume.clear()
        p = self.player()
        p.play(self.track.file_id, initial)
        wait_state(p, {'playing'})
        old = self.sd.streams[-1]
        out = old.callback.__self__
        until(lambda: len(out._ring) == out._limit)
        before = time.monotonic()
        p.seek(target)
        self.assertLess(time.monotonic() - before, 0.75)
        self.assertTrue(old.closed)
        self.assertEqual(old.calls.count('abort'), 1)
        self.assertNotIn('stop', old.calls)
        self.assertEqual(len(out._ring), 0)
        # Even a late invocation of the retired callback cannot play old PCM.
        buf = bytearray(b'x' * (256 * out.fmt.frame_size))
        old.callback(buf, 256, None, None)
        self.assertEqual(buf, bytes(len(buf)))
        self.sd.consume.set()
        self.finished(p, self.track.file_id, target)
        self.assertLess(self.sd.events.index((0, 'close')), self.sd.events.index((1, 'open')))

    def test_twenty_track_switches_release_before_reopen_and_no_stale_callback(self):
        self.sd.consume.clear()
        p = self.player()
        for i in range(21):
            key = self.track.file_id if i % 2 == 0 else self.other.file_id
            p.play(key)
            wait_state(p, {'playing'})
            if i:
                previous = self.sd.streams[-2]
                self.assertTrue(previous.closed)
                out = previous.callback.__self__
                data = bytearray(b'x' * (256 * out.fmt.frame_size))
                previous.callback(data, 256, None, None)
                self.assertEqual(data, bytes(len(data)))
        self.sd.consume.set()
        self.finished(p, self.track.file_id, 0)
        self.assertEqual(len(self.sd.streams), 21)

    def test_twenty_alternating_seeks_pause_resume_then_stop_reopen(self):
        import statistics
        self.sd.consume.clear()
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        elapsed = []
        for i in range(20):
            target = 33000 if i % 2 == 0 else 4400
            began = time.perf_counter()
            p.seek(target)
            wait_state(p, {'playing'})
            elapsed.append((time.perf_counter() - began) * 1000)
            p.pause()
            self.assertEqual(p.status()['state'], 'paused')
            p.resume()
        p.stop()
        self.assertTrue(all(s.closed for s in self.sd.streams))
        p.play(self.track.file_id, 4400)
        self.sd.consume.set()
        self.finished(p, self.track.file_id, 4400)
        first_writes = [m['latency_ms'] for m in p.seek_metrics()]
        print('WASAPI fake-device alternating seek->first-write ms: median=%.3f max=%.3f' %
              (statistics.median(first_writes), max(first_writes)))
        self.assertLess(max(elapsed), 750)

    def test_switch_track_while_playing(self):
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        old = self.sd.streams[-1]
        p.play(self.other.file_id)
        self.assertTrue(old.closed)
        self.finished(p, self.other.file_id, 0)

    def test_rapid_repeated_and_concurrent_seeks(self):
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        errors = []
        def seek(frame):
            try:
                p.seek(frame)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=seek, args=(i * 2000,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
            self.assertFalse(t.is_alive())
        self.assertEqual(errors, [])
        p.seek(22000)
        self.finished(p, self.track.file_id, 22000)
        self.assertLessEqual(len(p.seek_metrics()), 200)

    def test_seek_stop_play_again(self):
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        p.seek(22000)
        p.stop()
        self.assertTrue(all(s.closed for s in self.sd.streams))
        p.play(self.other.file_id)
        self.finished(p, self.other.file_id, 0)

    def test_failed_initialization_then_retry(self):
        p = self.player()
        for failure in ('fail_open', 'fail_start'):
            with self.subTest(failure=failure):
                setattr(self.sd, failure, 2 if failure == 'fail_open' else 1)
                with self.assertLogs(audio_output.LOG, 'ERROR') as log:
                    p.play(self.track.file_id)
                    state = wait_state(p, {'error', 'finished'})
                self.assertEqual(state['state'], 'error', state)
                self.assertIn('WASAPI', state['error'])
                self.assertIn('WASAPI', '\n'.join(log.output))
                self.assertFalse(state['output_active'])
                self.assertTrue(all(s.closed for s in self.sd.streams))
                p.play(self.other.file_id)
                self.finished(p, self.other.file_id, 0)

    def test_failed_seek_then_play_recovers(self):
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        self.sd.fail_start = 1
        with self.assertLogs(audio_output.LOG, 'ERROR'):
            p.seek(22000)
            self.assertEqual(wait_state(p, {'error'})['state'], 'error')
        p.play(self.track.file_id, 22000)
        self.finished(p, self.track.file_id, 22000)

    def test_device_removed_wakes_writer_then_retry(self):
        self.sd.consume.clear()
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        self.sd.fail_active = True
        with self.assertLogs(audio_output.LOG, 'ERROR'):
            state = wait_state(p, {'error', 'finished'})
        self.assertEqual(state['state'], 'error', state)
        self.assertIn('0x88890004', state['error'])
        self.assertTrue(all(s.closed for s in self.sd.streams))
        self.sd.fail_active = False
        self.sd.consume.set()
        p.play(self.other.file_id)
        self.finished(p, self.other.file_id, 0)

    def test_abort_interrupts_eof_drain(self):
        self.sd.consume.clear()
        out = self.output()
        out.write(pcm(0.1))
        errors = []
        def close():
            try:
                out.close()
            except Exception as exc:
                errors.append(exc)
        t = threading.Thread(target=close)
        t.start()
        until(lambda: out._draining)
        out.abort()
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.sd.streams[0].calls.count('close'), 1)
        self.assertNotIn('stop', self.sd.streams[0].calls)

    def test_abort_during_native_stop_never_closes_concurrently(self):
        out = self.output()
        self.sd.stop_release.clear()
        errors = []
        def close():
            try:
                out.close()
            except Exception as exc:
                errors.append(exc)
        t = threading.Thread(target=close)
        t.start()
        self.assertTrue(self.sd.stop_entered.wait(1))
        out.interrupt()
        self.sd.stop_release.set()
        out.abort()
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([op for op in self.sd.streams[0].calls if op != 'active'],
                         ['open', 'start', 'stop', 'close'])

    def test_native_stop_failure_closes_and_next_output_recovers(self):
        out = self.output()
        self.sd.fail_stop = True
        with self.assertLogs(audio_output.LOG, 'ERROR'):
            with self.assertRaisesRegex(PlaybackError, 'stop failure'):
                out.close()
        self.assertTrue(self.sd.streams[0].closed)
        self.sd.fail_stop = False
        self.output().abort()

    def test_player_natural_drain_failure_then_retry(self):
        p = self.player()
        self.sd.fail_stop = True
        with self.assertLogs(audio_output.LOG, 'ERROR'):
            p.play(self.other.file_id)
            state = wait_state(p, {'error', 'finished'})
        self.assertEqual(state['state'], 'error', state)
        self.assertTrue(all(s.closed for s in self.sd.streams))
        self.sd.fail_stop = False
        p.play(self.other.file_id)
        self.finished(p, self.other.file_id, 0)

    def test_abort_failure_still_closes_and_retry_recovers(self):
        out = self.output()
        self.sd.fail_abort = True
        with self.assertLogs(audio_output.LOG, 'ERROR'):
            out.abort()
        self.assertTrue(self.sd.streams[0].closed)
        self.sd.fail_abort = False
        self.output().abort()

    def test_close_failure_is_reported_and_never_silently_replaced(self):
        out = self.output()
        self.sd.fail_close = True
        with self.assertLogs(audio_output.LOG, 'ERROR'):
            with self.assertRaisesRegex(PlaybackError, 'close failure'):
                out.abort()
        self.assertFalse(out._owner.is_alive())
        # Native ownership is uncertain: don't claim success on a later stop.
        with self.assertRaisesRegex(PlaybackError, 'close failure'):
            out.abort()
        self.outputs.remove(out)
        self.sd.fail_close = False

    def test_callback_failure_reaches_producer_and_closes_stream(self):
        out = self.output()
        self.sd.consume.clear()
        out.write(pcm(0.01))
        with self.assertRaises(TypeError):
            # Simulate a callback output-buffer failure without logging data.
            out._callback(bytes(1024), 256, None, None)
        until(lambda: out._done.is_set())
        with self.assertRaisesRegex(PlaybackError, 'audio callback failed: TypeError'):
            out.write(pcm(0.01))
        self.assertTrue(self.sd.streams[0].closed)


    def test_pcm_worker_start_failure_releases_stream(self):
        engine = BufferedPcmPlayer(backend='wasapi', output_factory=lambda fmt: self.output())
        real_start = threading.Thread.start
        def start(t):
            if t.name == 'holochain-music-s11-pcm':
                raise RuntimeError('thread unavailable')
            return real_start(t)
        with mock.patch.object(threading.Thread, 'start', start):
            with self.assertRaisesRegex(RuntimeError, 'thread unavailable'):
                engine.start({'sample_rate': 44100, 'channels': 2, 'bits_per_sample': 16})
        self.assertTrue(self.sd.streams[0].closed)

    def test_delayed_teardown_can_be_retried_after_owner_exits(self):
        out = self.output()
        self.sd.stop_release.clear()
        engine = BufferedPcmPlayer(backend='wasapi', output_factory=lambda fmt: out, pace=False)
        engine.start({'sample_rate': 44100, 'channels': 2, 'bits_per_sample': 16})
        real_join = out._join_owner
        def short_join():
            out._owner.join(0.01)
            if out._owner.is_alive():
                raise PlaybackError('audio stream teardown timed out; device still owned')
            real_join()
        with mock.patch.object(out, '_join_owner', short_join):
            engine.feed(pcm(0.02))
            with self.assertRaisesRegex(PlaybackError, 'timed out'):
                engine.finish()
            self.assertIsNotNone(engine._cleanup_error)
            with self.assertRaisesRegex(PlaybackError, 'timed out'):
                engine.stop()
            self.assertFalse(self.sd.streams[0].closed)
            self.sd.stop_release.set()
            self.assertTrue(out._done.wait(1))
            engine.stop()
            self.assertIsNone(engine._cleanup_error)
        self.output().abort()

    def test_app_shutdown_releases_network_resources_when_audio_stop_fails(self):
        import os
        from holochain_music.app import MusicApp
        app = MusicApp.__new__(MusicApp)
        app.player = mock.Mock()
        app.player.shutdown.side_effect = PlaybackError('native teardown timed out')
        app.downloads = {'one': mock.Mock()}
        for name in ('outbox', 'host', 'bridge', 'conductor', 'bootstrap'):
            setattr(app, name, mock.Mock())
        fd = os.open(str(Path(self.tmp.name) / 'lock'), os.O_WRONLY | os.O_CREAT, 0o600)
        app._lock_fd = fd
        with self.assertRaisesRegex(PlaybackError, 'native teardown timed out'):
            app.stop()
        for part in (*app.downloads.values(), app.outbox, app.host, app.bridge, app.conductor, app.bootstrap):
            part.stop.assert_called_once_with()
        self.assertIsNone(app._lock_fd)
        with self.assertRaises(OSError):
            os.fstat(fd)


    def test_canceled_verification_is_tracked_and_never_opens_old_output(self):
        p = self.player()
        entered, release = threading.Event(), threading.Event()
        real_open = p._open
        def slow_open(spec):
            if spec.key == self.track.file_id:
                entered.set()
                release.wait(5)
            return real_open(spec)
        with mock.patch.object(p, '_open', slow_open):
            p.play(self.track.file_id)
            self.assertTrue(entered.wait(1))
            p.play(self.other.file_id)
            release.set()
            self.finished(p, self.other.file_id, 0)
            p.shutdown()
        self.assertEqual(len(self.sd.streams), 1)
        self.assertFalse(p._retired)


    def test_com_scope_wraps_all_native_operations_and_balances_on_failure(self):
        scope = []
        @contextmanager
        def com():
            scope.append(('init', threading.get_ident()))
            try:
                yield
            finally:
                self.assertTrue(all(s.closed for s in self.sd.streams))
                scope.append(('uninit', threading.get_ident()))
        with mock.patch.object(audio_output, '_com_apartment', com):
            self.output().abort()
            self.sd.fail_start = 1
            with self.assertLogs(audio_output.LOG, 'ERROR'):
                with self.assertRaises(PlaybackError):
                    self.output()
        self.assertEqual([op for op, _ in scope], ['init', 'uninit', 'init', 'uninit'])
        self.assertEqual(scope[0][1], scope[1][1])
        self.assertEqual(scope[2][1], scope[3][1])

    def test_teardown_timeout_retains_player_ownership_and_prevents_replacement(self):
        p = self.player()
        p.play(self.track.file_id)
        wait_state(p, {'playing'})
        pcm = p._pcm
        real_stop = pcm.stop
        with mock.patch.object(pcm, 'stop', side_effect=PlaybackError('teardown timed out')):
            with self.assertRaisesRegex(PlaybackError, 'teardown timed out'):
                p.play(self.other.file_id)
            self.assertIs(p._pcm, pcm)
            self.assertEqual(len(self.sd.streams), 1)
            self.assertEqual(p.status()['state'], 'error')
        real_stop()
        p.play(self.other.file_id)
        self.finished(p, self.other.file_id, 0)


if __name__ == '__main__':
    unittest.main()
