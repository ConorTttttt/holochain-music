"""S18 real S1/AES-GCM/X25519 fixtures and loopback controller/API contracts.

Does NOT claim real multi-host Holochain or public music rights; the S18 UI
consumes only previously authenticated encrypted CAS + signed owner grant.
"""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from urllib import error, request
import wave

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import create_package, public_key_bytes, object_path
from music_catalogue.buffered_playback import BufferedPcmPlayer
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.local_player import LocalPlayerController, load_library, make_handler, _demo_track


class LocalPlayerS18(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="s18-browser-tests-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.listener = X25519PrivateKey.generate()
        self.frames = 32000
        self.pcm = b"".join(struct.pack("<h", (i * 73) % 20000 - 10000) for i in range(self.frames))
        source = self.root / "sample.wav"
        with wave.open(str(source), "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(16000)
            w.writeframes(self.pcm)
        self.store = self.root / "cas"
        self.manifest, secret = create_package(source, self.store, self.artist, chunk_size=333)
        source.unlink()
        self.grant = issue_content_grant(
            owner_signer=self.artist, owner_agent="alice", listener_agent="bob",
            recipient_public=self.listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            signed_manifest=self.manifest, content_key=secret,
        )
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))
        (self.root / "grant.json").write_text(json.dumps(self.grant))
        (self.root / "reader.key").write_bytes(self.listener.private_bytes_raw())
        self.track = {
            "id": "song-01", "title": "Trusted Test Tone", "artist": "Local Example", "album": "Encrypted Demo",
            "manifest": "manifest.json", "ciphertext_store": "cas", "grant": "grant.json",
            "trusted_artist_hex": public_key_bytes(self.artist).hex(),
            "owner_agent": "alice", "listener_agent": "bob", "recipient_private_file": "reader.key",
        }
        self.library_file = self.root / "library.json"
        self.save_library()

    def save_library(self, tracks=None):
        self.library_file.write_text(json.dumps({"tracks": [self.track] if tracks is None else tracks}))

    def controller(self, *, pace=False, factory=None):
        if factory is None:
            factory = lambda: BufferedPcmPlayer(backend="null", pace=pace)
        return LocalPlayerController(load_library(self.library_file), player_factory=factory)

    def wait_for(self, ctrl, *states, timeout=6):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            s = ctrl.status()
            if s["state"] in states:
                return s
            time.sleep(.01)
        self.fail(f"controller never entered {states}: {ctrl.status()}")

    def test_library_labels_exclude_key_material(self):
        tracks = load_library(self.library_file)
        self.assertEqual(tracks[0].id, "song-01")
        self.assertEqual(set(tracks[0].display()), {"id", "title", "artist", "album"})
        self.assertNotIn("grant", json.dumps(tracks[0].display()))

    def test_library_rejects_duplicate_and_unsafe_id(self):
        self.save_library([self.track, self.track])
        with self.assertRaises(PlaybackError):
            load_library(self.library_file)
        bad = dict(self.track, id="../song")
        self.save_library([bad])
        with self.assertRaises(PlaybackError):
            load_library(self.library_file)

    def test_library_rejects_symlinked_key_file(self):
        (self.root / "reader-link").symlink_to(self.root / "reader.key")
        self.save_library([dict(self.track, recipient_private_file="reader-link")])
        with self.assertRaises(PlaybackError):
            load_library(self.library_file)

    def test_library_rejects_unsigned_extra_fields(self):
        self.save_library([dict(self.track, untrusted_network_endpoint="http://evil.test")])
        with self.assertRaises(PlaybackError):
            load_library(self.library_file)

    def test_complete_pcm_digest_matches_verified_source(self):
        ctrl = self.controller()
        initial = ctrl.play("song-01")
        self.assertIn(initial["state"], ("loading", "playing", "finished"))
        s = self.wait_for(ctrl, "finished", "error")
        self.assertEqual(s["state"], "finished", s["error"])
        self.assertEqual(s["result"]["output_pcm_sha256"], hashlib.sha256(self.pcm).hexdigest())
        self.assertEqual(s["result"]["output_frames"], self.frames)
        self.assertLessEqual(s["result"]["max_buffered_pcm_bytes"], 65536)

    def test_frame_exact_seek_and_replay(self):
        ctrl = self.controller()
        ctrl.play("song-01", 777)
        s = self.wait_for(ctrl, "finished", "error")
        self.assertEqual(s["state"], "finished", s["error"])
        self.assertEqual(s["result"]["output_pcm_sha256"], hashlib.sha256(self.pcm[777*2:]).hexdigest())
        self.assertEqual(s["position_frames"], self.frames)
        ctrl.seek(17001)
        s = self.wait_for(ctrl, "finished", "error")
        self.assertEqual(s["result"]["output_pcm_sha256"], hashlib.sha256(self.pcm[17001*2:]).hexdigest())

    def test_unknown_track_and_invalid_frames_refused(self):
        ctrl = self.controller()
        with self.assertRaises(PlaybackError):
            ctrl.play("missing")
        with self.assertRaises(PlaybackError):
            ctrl.play("song-01", True)
        with self.assertRaises(PlaybackError):
            ctrl.play("song-01", -1)
        with self.assertRaises(PlaybackError):
            ctrl.seek(0)

    def test_wrong_grant_rejected_before_any_audio_device(self):
        self.save_library([dict(self.track, listener_agent="mallory")])
        opened = []
        ctrl = self.controller(factory=lambda: opened.append(True) or BufferedPcmPlayer(backend="null"))
        ctrl.play("song-01")
        s = self.wait_for(ctrl, "error")
        self.assertIn("grant", s["error"].lower())
        self.assertEqual(opened, [])

    def test_tampered_ciphertext_never_opens_output(self):
        chunk = self.manifest["body"]["chunks"][0]
        target = object_path(self.store, chunk["sha256"])
        target.write_bytes(b"tampered")
        opened = []
        ctrl = self.controller(factory=lambda: opened.append(True) or BufferedPcmPlayer(backend="null"))
        ctrl.play("song-01")
        self.wait_for(ctrl, "error")
        self.assertEqual(opened, [])

    def test_pause_resume_and_stop_do_not_claim_completion(self):
        ctrl = self.controller(pace=True)
        ctrl.play("song-01")
        self.wait_for(ctrl, "playing", timeout=3)
        ctrl.pause()
        paused = ctrl.status()
        self.assertEqual(paused["state"], "paused")
        time.sleep(.12)
        self.assertEqual(ctrl.status()["position_frames"], paused["position_frames"])
        ctrl.resume()
        self.assertEqual(ctrl.status()["state"], "playing")
        ctrl.stop()
        self.assertEqual(ctrl.status()["state"], "stopped")
        self.assertIsNone(ctrl.status()["result"])

    def test_play_replace_cannot_complete_old_generation(self):
        ctrl = self.controller(pace=True)
        ctrl.play("song-01")
        self.wait_for(ctrl, "playing")
        ctrl.play("song-01", 10000)
        self.wait_for(ctrl, "playing")
        s = ctrl.stop()
        self.assertEqual(s["state"], "stopped")
        self.assertIsNone(s["result"])

    def start_http(self):
        token = "test-token-secret"
        ctrl = self.controller()
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(ctrl, token, port=port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (ctrl.stop(), server.shutdown(), server.server_close(), thread.join(timeout=3)))
        return port, token, ctrl

    def http(self, port, path, *, token=None, data=None, origin=None, host=None, method=None):
        uri = f"http://127.0.0.1:{port}{path}"
        headers = {"Host": host or f"127.0.0.1:{port}"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if origin:
            headers["Origin"] = origin
        if data is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(data).encode()
        req = request.Request(uri, headers=headers, data=data, method=method)
        try:
            with request.urlopen(req, timeout=3) as res:
                return res.status, dict(res.headers), res.read()
        except error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_http_requires_bearer_on_every_api(self):
        port, token, _ = self.start_http()
        self.assertEqual(self.http(port, "/api/library")[0], 401)
        self.assertEqual(self.http(port, "/api/state", token="wrong")[0], 401)
        status, _, b = self.http(port, "/api/library", token=token)
        self.assertEqual(status, 200)
        self.assertNotIn(b"reader.key", b)
        self.assertNotIn(b"trusted_artist_hex", b)
        self.assertNotIn(b"grant", b)

    def test_http_rejects_origin_spoofing_and_dangerous_commands(self):
        port, token, _ = self.start_http()
        self.assertEqual(self.http(port, "/api/play", method="POST", token=token,
                                   origin="http://attacker.invalid", data={"track_id": "song-01"})[0], 403)
        self.assertEqual(self.http(port, "/api/play", method="POST", token=token,
                                   data={"track_id": "song-01", "shell": "bad"})[0], 400)
        self.assertEqual(self.http(port, "/api/seek", method="POST", token=token,
                                   data={"frame": True})[0], 400)
        self.assertEqual(self.http(port, "/api/state", token=token,
                                   host="attack.invalid")[0], 403)

    def test_http_play_and_seek_flow_and_security_headers(self):
        port, token, ctrl = self.start_http()
        status, headers, content = self.http(port, "/", token=None)
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertIn(b"Holochain Music", content)
        status, _, content = self.http(port, "/api/play", method="POST", token=token,
                                      data={"track_id": "song-01"})
        self.assertEqual(status, 200, content)
        self.wait_for(ctrl, "finished", "error")
        status, _, content = self.http(port, "/api/seek", method="POST", token=token,
                                      data={"frame": 4000})
        self.assertEqual(status, 200, content)
        finished = self.wait_for(ctrl, "finished", "error")
        self.assertEqual(finished["state"], "finished", finished["error"])
        self.assertEqual(finished["result"]["output_pcm_sha256"], hashlib.sha256(self.pcm[8000:]).hexdigest())

    def test_demo_is_real_signed_encrypted_local_playback(self):
        with tempfile.TemporaryDirectory(prefix="s18-demo-") as name:
            track = _demo_track(Path(name))
            ctrl = LocalPlayerController([track], player_factory=lambda: BufferedPcmPlayer(backend="null", pace=False))
            ctrl.play(track.id)
            done = self.wait_for(ctrl, "finished", "error")
            self.assertEqual(done["state"], "finished", done["error"])
            self.assertGreater(done["result"]["output_frames"], 16000)


if __name__ == "__main__":
    unittest.main()
