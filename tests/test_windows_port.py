"""Cross-platform layer and the Windows (WASAPI/PortAudio) audio backend.

Runs on every platform. Windows-only behaviour (real DACLs, Job Objects,
real WASAPI devices) is covered by `WindowsOnlyTests`, which run only on a
Windows host (the windows-latest CI job). On Linux, the Windows code paths
that are pure Python (threaded pipe reads, ACE classification, SDDL,
directory layout, the PortAudio ring/abort logic) are exercised directly.

Nothing here plays sound: the PortAudio device is a fake clocked consumer
unless HOLOCHAIN_MUSIC_REAL_AUDIO=1 on a Windows machine.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

from holochain_storage import portable
from music_catalogue import audio_output
from music_catalogue.audio_output import PortAudioOutput, resolve_device
from music_catalogue.buffered_playback import AudioFormat, BufferedPcmPlayer
from music_catalogue.granted_audio import PlaybackError

WINDOWS = sys.platform == "win32"


# ---------------------------------------------------------------------------
# A fake PortAudio (the subset of `sounddevice` PortAudioOutput uses)
# ---------------------------------------------------------------------------

class FakeStream:
    instances: list = []

    def __init__(self, sd, *, samplerate, channels, dtype, device, latency, callback, extra_settings, blocksize=0):
        if sd.fail_hostapis and sd.current_hostapi in sd.fail_hostapis:
            raise RuntimeError("PortAudioError: Invalid sample rate")
        assert dtype == "int16"
        assert blocksize == 0
        self.sd, self.rate, self.channels, self.device = sd, samplerate, channels, device
        self.callback, self.extra = callback, extra_settings
        self.period = 256
        self.active = False
        self.closed = False
        self.aborted = False
        self.stopped = False
        self._run = threading.Event()
        self.max_ring_seen = 0
        FakeStream.instances.append(self)

    def start(self):
        self.active = True
        self._run.set()
        threading.Thread(target=self._clock, daemon=True).start()

    def _clock(self):
        frame = 2 * self.channels
        while self._run.is_set():
            buf = bytearray(self.period * frame)
            self.callback(buf, self.period, None, None)
            self.sd.played.extend(buf)
            time.sleep(self.period / self.rate / self.sd.speed)

    def stop(self, ignore_errors=True):
        self.stopped = True
        self._run.clear()
        self.active = False

    def abort(self, ignore_errors=True):
        self.aborted = True
        self._run.clear()
        self.active = False

    def close(self, ignore_errors=True):
        self._run.clear()
        self.closed = True
        self.active = False


class FakeSd:
    """Stands in for the `sounddevice` module."""

    def __init__(self, *, speed=20.0, fail_hostapis=(), wasapi_auto_convert=True):
        self.speed = speed  # >1: the fake device consumes faster than real time
        self.fail_hostapis = set(fail_hostapis)
        self.current_hostapi = None
        self.played = bytearray()
        self.wasapi_auto_convert = wasapi_auto_convert
        self.wasapi_args = None

    def query_hostapis(self):
        return [{"name": "MME", "default_output_device": 0},
                {"name": "Windows WASAPI", "default_output_device": 2}]

    def query_devices(self):
        return [{"name": "Speakers (MME)", "hostapi": 0, "max_output_channels": 2, "default_samplerate": 44100},
                {"name": "Microphone", "hostapi": 1, "max_output_channels": 0, "default_samplerate": 48000},
                {"name": "Speakers (Realtek(R) Audio)", "hostapi": 1, "max_output_channels": 2,
                 "default_samplerate": 48000},
                {"name": "Headphones (USB)", "hostapi": 1, "max_output_channels": 2, "default_samplerate": 48000}]

    def WasapiSettings(self, exclusive=False, **kw):
        if kw and not self.wasapi_auto_convert:
            raise TypeError("unexpected keyword")
        self.wasapi_args = {"exclusive": exclusive, **kw}
        return ("wasapi", exclusive, kw.get("auto_convert"))

    def RawOutputStream(self, **kw):
        idx = kw["device"]
        devices = self.query_devices()
        self.current_hostapi = self.query_hostapis()[devices[idx]["hostapi"]]["name"] if idx is not None else None
        return FakeStream(self, **kw)


FMT = AudioFormat(44100, 2, 16)


def pcm(seconds: float, seed: int = 1) -> bytes:
    n = int(FMT.sample_rate * seconds) * FMT.frame_size
    out = bytearray()
    block = hashlib.sha256(bytes([seed])).digest()
    while len(out) < n:
        block = hashlib.sha256(block).digest()
        out.extend(block)
    return bytes(out[:n])


class PortAudioOutputTests(unittest.TestCase):
    def setUp(self):
        FakeStream.instances = []

    def test_device_resolution(self):
        sd = FakeSd()
        self.assertEqual(resolve_device(sd, "default", "Windows WASAPI"), 2)
        self.assertEqual(resolve_device(sd, "headphones", "Windows WASAPI"), 3)
        self.assertEqual(resolve_device(sd, "default", "MME"), 0)
        self.assertIsNone(resolve_device(sd, "default", None))
        with self.assertRaises(PlaybackError):
            resolve_device(sd, "Microphone", "Windows WASAPI")  # input-only device
        with self.assertRaises(PlaybackError):
            resolve_device(sd, "nope", "Windows WASAPI")
        with self.assertRaises(PlaybackError):
            resolve_device(sd, "default", "ASIO")
        for bad in ("", "x" * 129, "a\x00b", None):
            with self.assertRaises(PlaybackError):
                resolve_device(sd, bad, "Windows WASAPI")

    def test_shared_mode_with_auto_convert(self):
        sd = FakeSd()
        out = PortAudioOutput(FMT, sd=sd)
        out.abort()
        self.assertEqual(out.hostapi_used, "Windows WASAPI")
        self.assertEqual(sd.wasapi_args, {"exclusive": False, "auto_convert": True})
        sd_old = FakeSd(wasapi_auto_convert=False)  # sounddevice < 0.5
        PortAudioOutput(FMT, sd=sd_old).abort()
        self.assertIsNone(sd_old.wasapi_args)  # unsupported conversion uses explicit MME fallback

    def test_falls_back_to_mme_only_when_wasapi_cannot_open(self):
        sd = FakeSd(fail_hostapis={"Windows WASAPI"})
        out = PortAudioOutput(FMT, sd=sd)
        out.abort()
        self.assertEqual(out.hostapi_used, "MME")
        sd = FakeSd(fail_hostapis={"Windows WASAPI", "MME"})
        with self.assertRaises(PlaybackError):
            PortAudioOutput(FMT, sd=sd)
        # A named device that does not exist is an error, never a silent switch.
        with self.assertRaises(PlaybackError):
            PortAudioOutput(FMT, sd=FakeSd(), device="Bluetooth")

    def test_delivers_exactly_the_written_pcm_in_order_and_bounded(self):
        sd = FakeSd(speed=4.0)
        out = PortAudioOutput(FMT, sd=sd, buffer_us=100_000)
        data = pcm(1.0)
        limit = out._limit
        high = 0
        for i in range(0, len(data), 4096):
            out.write(data[i:i + 4096])
            high = max(high, len(out._ring))
        out.close()
        self.assertLessEqual(high, limit)
        self.assertEqual(out.delivered, len(data))
        self.assertEqual(out.delivered_sha256, hashlib.sha256(data).hexdigest())
        # The device saw the PCM contiguously (leading silence allowed only).
        played = bytes(sd.played)
        start = played.find(data[:64])
        self.assertGreaterEqual(start, 0)
        self.assertEqual(played[start:start + len(data)], data)
        self.assertTrue(FakeStream.instances[-1].stopped and FakeStream.instances[-1].closed)

    def test_abort_is_immediate_and_wakes_a_blocked_writer(self):
        sd = FakeSd(speed=0.05)  # device consumes very slowly: the writer will block
        out = PortAudioOutput(FMT, sd=sd, buffer_us=50_000)
        errors, entered = [], threading.Event()

        def writer():
            try:
                entered.set()
                out.write(pcm(2.0))
            except PlaybackError as exc:
                errors.append(exc)
        t = threading.Thread(target=writer)
        t.start()
        entered.wait()
        time.sleep(0.1)
        began = time.perf_counter()
        out.abort()
        t.join(1.0)
        elapsed = time.perf_counter() - began
        self.assertFalse(t.is_alive())
        self.assertLess(elapsed, 0.25)
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(out._ring), 0)
        self.assertTrue(FakeStream.instances[-1].aborted)
        out.abort()  # idempotent
        with self.assertRaises(PlaybackError):
            out.write(pcm(0.01))

    def test_rejects_unaligned_pcm_and_bad_buffer(self):
        out = PortAudioOutput(FMT, sd=FakeSd())
        with self.assertRaises(PlaybackError):
            out.write(b"\x00\x01\x02")
        out.abort()
        with self.assertRaises(PlaybackError):
            PortAudioOutput(FMT, sd=FakeSd(), buffer_us=10)

    def test_buffered_player_pause_resume_stop_over_wasapi(self):
        sd = FakeSd(speed=4.0)
        outputs = []

        def factory(fmt):
            o = PortAudioOutput(fmt, sd=sd, buffer_us=200_000)
            outputs.append(o)
            return o
        player = BufferedPcmPlayer(backend="wasapi", output_factory=factory, burst_bytes=0)
        player.start({"sample_rate": 44100, "channels": 2, "bits_per_sample": 16})
        data = pcm(0.6)
        feeder = threading.Thread(target=lambda: [player.feed(data[i:i + 4096]) for i in range(0, len(data), 4096)])
        feeder.start()
        time.sleep(0.05)
        player.pause()
        time.sleep(0.1)
        player.resume()
        feeder.join(10)
        result = player.finish(timeout=30)
        self.assertEqual(result["output_pcm_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(outputs[0].delivered_sha256, hashlib.sha256(data).hexdigest())

    def test_backend_names(self):
        self.assertTrue(audio_output.valid_backend("wasapi"))
        self.assertFalse(audio_output.valid_backend("pulse"))
        expected = ("wasapi", "null") if WINDOWS else ("alsa", "null")
        self.assertEqual(audio_output.available_backends(), expected)
        with self.assertRaises(PlaybackError):
            BufferedPcmPlayer(backend="pulse")

    def test_missing_portaudio_fails_closed(self):
        with mock.patch.dict(sys.modules, {"sounddevice": None}):
            with self.assertRaises(PlaybackError):
                audio_output.open_output("wasapi", FMT)


class WasapiPlayerPathTests(unittest.TestCase):
    """The real v1 Player (grant gate, SHA-256 + AES-GCM per chunk, seeks)
    driving the Windows backend; only the PortAudio device is fake."""

    def setUp(self):
        from v1_fixtures import Track
        tmp = tempfile.TemporaryDirectory(prefix="hm-wasapi-")
        self.addCleanup(tmp.cleanup)
        self.track = Track(Path(tmp.name) / "a", seconds=0.8)
        self.sd = FakeSd(speed=8.0)
        p = mock.patch.object(audio_output, "_load_sounddevice", lambda: self.sd)
        p.start()
        self.addCleanup(p.stop)
        FakeStream.instances = []

    def spec(self, key, grant=None):
        from holochain_music.player import SessionSpec
        t = self.track
        return SessionSpec(key=key, manifest=t.manifest, grant=grant or t.licence(), artist_key=t.artist_key,
                           owner_agent=t.owner, listener_agent=t.reader, recipient=t.listener, store=t.store)

    def expected(self, start=0):
        from music_catalogue.seekable_recovery import VerifiedWavSeeker
        t = self.track
        s = VerifiedWavSeeker(signed_manifest=t.manifest, ciphertext_store=t.store, grant=t.licence(),
                              trusted_artist=t.artist_key, owner_agent=t.owner, listener_agent=t.reader,
                              recipient_private=t.listener)
        return b"".join(s.iter_frames(start)), s.frames

    def test_full_track_then_seek(self):
        from holochain_music.player import Player
        from test_v1_app_player import wait_state
        p = Player(backend="wasapi", resolve=self.spec)
        p.play(self.track.file_id)
        s = wait_state(p, {"finished", "error"}, timeout=30)
        self.assertEqual(s["state"], "finished", s)
        data, frames = self.expected()
        # Bytes handed to the WASAPI stream == authenticated PCM.
        self.assertEqual(p._result["pcm_sha256"], hashlib.sha256(data).hexdigest())
        # ...and exactly those bytes were handed, in order, to the device
        # callback (underrun padding from the fast fake clock is not PCM).
        self.assertEqual(FakeStream.instances[0].callback.__self__.delivered_sha256,
                         hashlib.sha256(data).hexdigest())
        # Seek: previous stream aborted, new one starts at the frame.
        p.play(self.track.file_id)
        wait_state(p, {"playing"}, timeout=30)
        before = len(FakeStream.instances)
        p.seek(frames // 2)
        s = wait_state(p, {"finished", "error"}, timeout=30)
        self.assertEqual(s["state"], "finished", s)
        self.assertGreater(len(FakeStream.instances), before)
        self.assertTrue(FakeStream.instances[before - 1].aborted)
        half, _ = self.expected(frames // 2)
        self.assertEqual(p._result["pcm_sha256"], hashlib.sha256(half).hexdigest())

    def test_wrong_grant_never_reaches_the_device(self):
        from holochain_music.player import Player
        from test_v1_app_player import wait_state
        from v1_fixtures import Track
        other = Track(Path(tempfile.mkdtemp(prefix="hm-wasapi-o-")), seconds=0.3)
        p = Player(backend="wasapi", resolve=lambda key: self.spec(key, grant=other.licence()))
        p.play(self.track.file_id)
        s = wait_state(p, {"finished", "error"}, timeout=30)
        self.assertEqual(s["state"], "error")
        self.assertEqual(FakeStream.instances, [])  # device never even opened


# ---------------------------------------------------------------------------
# Portability layer
# ---------------------------------------------------------------------------

CHILD = textwrap.dedent("""
    import sys, time
    out = sys.stdout.buffer
    out.write(b'{"a":1}\\n'); out.flush()
    time.sleep(0.4)
    out.write(b'{"b":2}\\n'); out.flush()
    if len(sys.argv) > 1:
        out.write(b"x" * int(sys.argv[1])); out.flush()
""")


class PipeReaderTests(unittest.TestCase):
    def _run(self, threaded, *extra):
        proc = subprocess.Popen([sys.executable, "-c", CHILD, *extra], stdout=subprocess.PIPE, bufsize=0)
        self.addCleanup(proc.wait)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc, portable.PipeReader(proc.stdout, threaded=threaded)

    def check(self, threaded):
        proc, pipe = self._run(threaded)
        first = pipe.read(5)
        self.assertEqual(first, b'{"a":1}\n')
        self.assertIsNone(pipe.read(0.05))  # timeout, not EOF
        got = b""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            data = pipe.read(1)
            if data == b"":
                break
            got += data or b""
        self.assertEqual(got, b'{"b":2}\n')
        self.assertEqual(pipe.read(0.1), b"")  # EOF is sticky
        pipe.close()

    def test_select_mode(self):
        if WINDOWS:
            self.skipTest("select() on pipes is POSIX-only")
        self.check(False)

    def test_threaded_mode_used_on_windows(self):
        self.check(True)

    def test_threaded_mode_is_bounded(self):
        proc, pipe = self._run(True, str(20 * 1024 * 1024))
        time.sleep(1.0)  # consumer stalls; reader must not slurp 20 MiB
        self.assertLessEqual(pipe._queue.qsize(), portable.PipeReader.MAX_QUEUED)
        pipe.close()
        proc.kill()

    def test_bridge_client_over_threaded_pipes(self):
        """The real Bridge client (concurrent JSON-lines routing) on the
        Windows pipe path, against a stand-in bridge executable."""
        from holochain_music.bridge import Bridge, BridgeError
        tmp = Path(tempfile.mkdtemp(prefix="hm-bridge-"))
        script = tmp / "fake_bridge.py"
        script.write_text(textwrap.dedent("""
            import json, sys, threading, time
            out_lock = threading.Lock()
            def send(o):
                with out_lock:
                    sys.stdout.write(json.dumps(o) + "\\n"); sys.stdout.flush()
            send({"ready": True, "whoami": {"agent": "uhCAk", "catalogue_dna": "c", "storage_dna": "s"}})
            def handle(req):
                if req["op"] == "slow":
                    time.sleep(1.0)
                if req["op"] == "fail":
                    return send({"id": req["id"], "ok": False, "error": "nope"})
                send({"id": req["id"], "ok": True, "result": req["op"]})
            for line in sys.stdin:
                threading.Thread(target=handle, args=(json.loads(line),)).start()
        """), encoding="utf-8")
        if WINDOWS:
            launcher = tmp / "bridge.cmd"
            launcher.write_text(f'@"{sys.executable}" "{script}" %*\n')
        else:
            launcher = tmp / "bridge"
            launcher.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{script}' \"$@\"\n")
            launcher.chmod(0o755)
        with mock.patch.dict(os.environ, {"HOLOCHAIN_MUSIC_BRIDGE_BIN": str(launcher)}), \
                mock.patch.object(portable.PipeReader, "force_threaded", True):
            b = Bridge(1234, app_id="x", log_path=tmp / "bridge.log", timeout=10)
            self.assertEqual(b.start()["agent"], "uhCAk")
            self.assertTrue(b._pipe.threaded)
            results = {}
            slow = threading.Thread(target=lambda: results.setdefault("slow", b.call("slow")))
            slow.start()
            time.sleep(0.1)
            began = time.monotonic()
            self.assertEqual(b.call("fast"), "fast")
            self.assertLess(time.monotonic() - began, 0.8, "a slow call must not block others")
            with self.assertRaises(BridgeError):
                b.call("fail")
            slow.join(5)
            self.assertEqual(results["slow"], "slow")
            b.stop()
            with self.assertRaises(BridgeError):
                b.call("fast")


class LockAndPrivacyTests(unittest.TestCase):
    def test_single_instance_lock_across_processes(self):
        tmp = Path(tempfile.mkdtemp(prefix="hm-lock-"))
        lock = tmp / "app.lock"
        fd = portable.lock_file(lock)
        try:
            code = textwrap.dedent(f"""
                import sys
                sys.path.insert(0, {str(Path(portable.__file__).resolve().parents[1])!r})
                from holochain_storage import portable
                try:
                    portable.lock_file(__import__('pathlib').Path({str(lock)!r}))
                except portable.AlreadyLocked:
                    sys.exit(3)
                sys.exit(0)
            """)
            self.assertEqual(subprocess.run([sys.executable, "-c", code]).returncode, 3)
        finally:
            os.close(fd)
        fd = portable.lock_file(lock)  # free again after release
        os.close(fd)

    def test_replace_retries_transient_windows_sharing_violation(self):
        tmp = Path(tempfile.mkdtemp(prefix="hm-repl-"))
        src, dst = tmp / "new", tmp / "dst"
        src.write_text("new")
        dst.write_text("old")
        real, calls = os.replace, []

        def flaky(a, b):
            calls.append(1)
            if len(calls) < 3:
                raise PermissionError(13, "file in use")  # what Windows raises
            real(a, b)
        with mock.patch.object(portable, "IS_WINDOWS", True), mock.patch.object(portable.os, "replace", flaky):
            portable.replace(src, dst, delay=0.001)
        self.assertEqual((len(calls), dst.read_text()), (3, "new"))
        src.write_text("again")
        with mock.patch.object(portable, "IS_WINDOWS", True), \
                mock.patch.object(portable.os, "replace", side_effect=PermissionError(13, "in use")):
            with self.assertRaises(PermissionError):
                portable.replace(src, dst, attempts=3, delay=0.001)
        with mock.patch.object(portable.os, "replace", side_effect=PermissionError(13, "x")):
            if not WINDOWS:  # POSIX never retries: a PermissionError there is real
                with self.assertRaises(PermissionError):
                    portable.replace(src, dst)

    def test_ace_classification(self):
        user = "S-1-5-21-1-2-3-1001"
        ok = [(0, 0, user), (0, 0x13, "S-1-5-18"), (0, 0, "S-1-5-32-544")]
        self.assertTrue(portable.aces_are_private(ok, user))
        self.assertFalse(portable.aces_are_private(None, user))                         # NULL DACL
        self.assertFalse(portable.aces_are_private(ok + [(0, 0, "S-1-5-32-545")], user))  # Users
        self.assertFalse(portable.aces_are_private(ok + [(0, 0, "S-1-1-0")], user))       # Everyone
        self.assertFalse(portable.aces_are_private(ok + [(0, 0, "S-1-5-21-1-2-3-1002")], user))
        self.assertTrue(portable.aces_are_private(ok + [(0, 0x08, "S-1-1-0")], user))     # inherit-only
        self.assertTrue(portable.aces_are_private(ok + [(1, 0, "S-1-1-0")], user))        # deny ACE
        self.assertFalse(portable.aces_are_private(ok + [(5, 0, None)], user))            # object ACE: fail closed

    def test_private_sddl(self):
        user = "S-1-5-21-111-222-333-1001"
        self.assertEqual(portable.private_sddl(user, directory=True),
                         f"D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)")
        self.assertEqual(portable.private_sddl(user, directory=False), f"D:P(A;;FA;;;{user})(A;;FA;;;SY)")
        for bad in ("S-1-5-21-1)(A;;FA;;;WD", "WD", "S-1-x"):
            with self.assertRaises(portable.PortabilityError):
                portable.private_sddl(bad, directory=True)

    def test_windows_directory_layout(self):
        with mock.patch.object(portable, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": str(Path(tempfile.gettempdir()).resolve())}):
            data, config = portable.user_data_root("holochain-music", "HolochainMusic")
        base = Path(tempfile.gettempdir()).resolve() / "HolochainMusic"
        self.assertEqual((data, config), (base / "data", base / "config"))
        self.assertEqual(portable.exe("hc") if WINDOWS else "hc", "hc.exe" if WINDOWS else "hc")
        with mock.patch.object(portable, "IS_WINDOWS", True):
            self.assertEqual(portable.exe("holochain"), "holochain.exe")
            self.assertEqual(portable.exe("x.exe"), "x.exe")

    def test_secret_file_checks(self):
        from holochain_music.keys import KeyStore, KeyStoreError
        tmp = Path(tempfile.mkdtemp(prefix="hm-keys-"))
        ks = KeyStore(tmp / "keys")
        first = ks.listener_public_hex()
        self.assertEqual(KeyStore(tmp / "keys").listener_public_hex(), first)  # persistent identity
        self.assertTrue(portable.is_private(tmp / "keys" / "listener.x25519"))
        if not WINDOWS:
            (tmp / "keys" / "listener.x25519").chmod(0o644)
            with self.assertRaises(KeyStoreError):
                KeyStore(tmp / "keys").listener_x25519()

    def test_installed_layout_finds_bundled_tools(self):
        from holochain_music import binaries
        tmp = Path(tempfile.mkdtemp(prefix="hm-root-"))
        (tmp / "bin").mkdir()
        pkg = tmp / "python" / "holochain_music"
        pkg.mkdir(parents=True)
        fake_file = pkg / "binaries.py"
        with mock.patch.object(binaries, "__file__", str(fake_file)):
            self.assertEqual(binaries.installed_root(), tmp.resolve())
            self.assertIn(tmp.resolve() / "bin", binaries.libexec_dirs())


class AppSettingsTests(unittest.TestCase):
    def test_backend_setting_is_platform_checked_and_migrated(self):
        from holochain_music.app import AppError, MusicApp
        from holochain_music.paths import AppPaths
        tmp = Path(tempfile.mkdtemp(prefix="hm-set-", dir=None if WINDOWS else "/tmp"))
        paths = AppPaths(data=tmp / "d", config=tmp / "c")
        paths.ensure()
        foreign = "wasapi" if not WINDOWS else "alsa"
        paths.settings_file.write_text(json.dumps({"audio_backend": foreign}), encoding="utf-8")
        app = MusicApp(paths)
        self.assertEqual(app.settings["audio_backend"], audio_output.default_backend())
        with self.assertRaises(AppError):
            app.save_settings(audio_backend=foreign)
        app.save_settings(audio_backend="null")


class SessionAndShutdownTests(unittest.TestCase):
    def test_shutdown_route_and_session_file(self):
        import http.client
        from holochain_music import cli
        from holochain_music.app import MusicApp
        from holochain_music.paths import AppPaths
        from holochain_music.server import serve
        tmp = Path(tempfile.mkdtemp(prefix="hm-sess-", dir=None if WINDOWS else "/tmp"))
        app = MusicApp(AppPaths(data=tmp / "d", config=tmp / "c"))
        app.save_settings(audio_backend="null")
        app.start(offline=True)
        server, url = serve(app)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            from holochain_music.library import _atomic_json
            _atomic_json(app.paths.session_file, {"url": url, "pid": os.getpid()})
            self.assertTrue(portable.is_private(app.paths.session_file))
            self.assertEqual(cli._read_session(app.paths)["url"], url)
            port = server.server_address[1]
            # Without the token the shutdown route is refused.
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("POST", "/api/shutdown", body=b"{}", headers={
                "Origin": f"http://127.0.0.1:{port}", "Content-Type": "application/json"})
            self.assertEqual(c.getresponse().status, 401)
            c.close()
            self.assertFalse(app.shutdown_requested.is_set())
            with mock.patch.object(AppPaths, "default", classmethod(lambda cls: app.paths)):
                self.assertEqual(cli.cmd_quit(None), 0)
            self.assertTrue(app.shutdown_requested.wait(5))
        finally:
            server.shutdown()
            server.server_close()
            app.stop()


@unittest.skipUnless(WINDOWS, "Windows host only")
class WindowsOnlyTests(unittest.TestCase):
    def test_private_dir_dacl_is_user_only_and_inherited(self):
        tmp = Path(tempfile.mkdtemp(prefix="hm-acl-"))
        d = tmp / "keys"
        d.mkdir()
        portable.make_private_dir(d)
        self.assertTrue(portable.is_private(d))
        f = d / "secret"
        f.write_bytes(b"x")
        self.assertTrue(portable.is_private(f))
        # Grant Users read access: the key reader must refuse it.
        subprocess.run(["icacls", str(f), "/grant", "*S-1-5-32-545:R"], check=True, capture_output=True)
        self.assertFalse(portable.is_private(f))
        with self.assertRaises(portable.PortabilityError):
            portable.check_secret_file(f)

    def test_job_object_kills_children_with_parent(self):
        code = textwrap.dedent("""
            import subprocess, sys, time
            sys.path.insert(0, sys.argv[1])
            from holochain_storage import portable
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                     **portable.popen_kwargs())
            portable.supervise(child)
            print(child.pid, flush=True)
            time.sleep(60)
        """)
        root = str(Path(portable.__file__).resolve().parents[1])
        parent = subprocess.Popen([sys.executable, "-c", code, root], stdout=subprocess.PIPE, text=True)
        pid = int(parent.stdout.readline())
        parent.kill()
        parent.wait()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True)
            if str(pid) not in r.stdout:
                break
            time.sleep(0.2)
        else:
            self.fail("child outlived its supervisor")

    def test_wasapi_devices_enumerate(self):
        try:
            devices = audio_output.list_output_devices()
        except PlaybackError as exc:
            self.skipTest(f"no PortAudio: {exc}")
        if not devices:
            self.skipTest("no WASAPI output device on this host (CI runners usually have none)")
        self.assertTrue(all(d["hostapi"] == "Windows WASAPI" for d in devices))

    @unittest.skipUnless(os.environ.get("HOLOCHAIN_MUSIC_REAL_AUDIO") == "1", "audible test is opt-in")
    def test_real_wasapi_tone(self):
        import math
        import struct
        frames = 44100
        tone = b"".join(struct.pack("<hh", int(3000 * math.sin(2 * math.pi * 440 * i / 44100)),
                                    int(3000 * math.sin(2 * math.pi * 440 * i / 44100))) for i in range(frames))
        out = PortAudioOutput(FMT)
        for i in range(0, len(tone), 4096):
            out.write(tone[i:i + 4096])
        out.close()
        self.assertEqual(out.delivered, len(tone))


if __name__ == "__main__":
    unittest.main()
