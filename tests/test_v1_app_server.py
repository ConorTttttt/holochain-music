"""v1 local API over real HTTP: security model, data exposure, controls, export."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.package import replicate_package
from music_catalogue.content_grants import issue_personal_licence
from holochain_music import player as player_mod
from holochain_music.app import MusicApp
from holochain_music.artist import normalise_wav
from holochain_music.paths import AppPaths
from holochain_music.server import serve

from test_v1_app_player import Recorder
from v1_fixtures import Track, write_tone


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="hm-api-", dir="/tmp")
        root = Path(cls.tmp.name)
        cls.home = root / "home"
        cls.home.mkdir()
        cls.patches = [mock.patch.dict(os.environ, {"HOME": str(cls.home)}),
                       mock.patch.object(player_mod, "NullOutput", Recorder)]
        for p in cls.patches:
            p.start()
        cls.app = MusicApp(AppPaths(data=root / "a" / "data", config=root / "a" / "config"))
        cls.app.save_settings(audio_backend="null")
        cls.app.player.backend = "null"
        cls.app.start(offline=True)
        # A licensed, fully downloaded track for this app's listener key.
        cls.track = Track(root / "t", seconds=0.5)
        cls.canonical = root / "canonical.wav"
        raw = root / "raw.wav"
        write_tone(raw, seconds=0.5, rate=8000)
        normalise_wav(raw, cls.canonical)
        lib = cls.app.library
        replicate_package(cls.track.manifest, cls.track.store, lib.cas, cls.track.artist_key, Ed25519PrivateKey.generate())
        fid = cls.track.file_id
        lib.add(manifest=cls.track.manifest, meta={
            "manifest_sha256": cls.track.digest, "artist_key_hex": cls.track.artist_key.hex(),
            "artist_agent": cls.track.owner, "listener_agent": cls.track.reader, "artist_name": "Tester",
            "title": "API Tone", "track_key": f"{cls.track.owner}:{'a' * 32}", "duration_ms": 500})
        licence = issue_personal_licence(owner_signer=cls.track.artist, owner_agent=cls.track.owner,
                                         listener_agent=cls.track.reader,
                                         recipient_public=bytes.fromhex(cls.app.keys.listener_public_hex()),
                                         signed_manifest=cls.track.manifest, content_key=cls.track.content_key)
        lib.set_grant(fid, licence, "perpetual-personal")
        lib.verify_complete(fid)
        cls.server, url = serve(cls.app)
        cls.port = cls.server.server_address[1]
        cls.token = url.split("#token=")[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.stop()
        for p in cls.patches:
            p.stop()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, *, token=True, host=None, origin="same", raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            headers["Authorization"] = f"Bearer {self.token if token is True else token}"
        if origin == "same":
            headers["Origin"] = f"http://127.0.0.1:{self.port}"
        elif origin:
            headers["Origin"] = origin
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        payload = r.read()
        c.close()
        try:
            return r.status, json.loads(payload), r
        except ValueError:
            return r.status, payload, r

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_static_ui_has_strict_csp_and_no_inline_script(self):
        status, body, r = self.req("GET", "/", token=False, origin=None)
        self.assertEqual(status, 200)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertNotIn(b"<script>", body)
        self.assertNotIn(b"innerHTML", (Path(__file__).parent.parent / "holochain_music/ui/app.js").read_bytes())

    def test_authentication_host_origin_query_and_size_rules(self):
        self.assertEqual(self.req("GET", "/api/state", token=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/state", token="x" * 43)[0], 401)
        self.assertEqual(self.req("GET", "/api/state", host="evil.example")[0], 403)
        self.assertEqual(self.req("GET", f"/api/state", host=f"192.168.1.5:{self.port}")[0], 403)
        self.assertEqual(self.req("POST", "/api/stop", {}, origin="http://evil.example")[0], 403)
        self.assertEqual(self.req("GET", "/api/state?x=1")[0], 400)
        self.assertEqual(self.req("POST", "/api/volume", raw=b"{" + b" " * 20000 + b"}")[0], 400)
        self.assertEqual(self.req("POST", "/api/volume", {"volume": 0.5, "extra": 1})[0], 400)
        self.assertEqual(self.req("POST", "/api/volume", raw=b"not json")[0], 400)
        self.assertEqual(self.req("GET", "/api/nope")[0], 404)
        self.assertEqual(self.req("OPTIONS", "/api/state")[0], 403)

    def test_browser_never_receives_keys_grants_or_audio(self):
        status, lib, _ = self.req("GET", "/api/library")
        self.assertEqual(status, 200)
        text = json.dumps(lib)
        for secret in ("wrapped_key", "grant_json", "signature", self.track.artist_key.hex(),
                       self.app.keys.listener_x25519().private_bytes_raw().hex()):
            self.assertNotIn(secret, text)
        status, ident, _ = self.req("GET", "/api/identity")
        self.assertNotIn(self.app.keys.listener_x25519().private_bytes_raw().hex(), json.dumps(ident))
        self.assertTrue(lib["tracks"][0]["offline_ready"])

    def test_offline_mode_reports_network_routes_cleanly(self):
        status, body, _ = self.req("POST", "/api/catalogue/browse", {})
        self.assertEqual(status, 400)
        self.assertIn("offline", body["error"])

    def test_play_seek_volume_queue_through_the_api(self):
        fid = self.track.file_id
        self.assertEqual(self.req("POST", "/api/volume", {"volume": 0.5})[1]["volume"], 0.5)
        self.assertEqual(self.req("POST", "/api/volume", {"volume": 2})[0], 400)
        status, s, _ = self.req("POST", "/api/play", {"file_id": fid})
        self.assertEqual(status, 200, s)
        deadline = time.monotonic() + 15
        while self.req("GET", "/api/state")[1]["player"]["state"] not in ("playing", "finished", "error"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        st = self.req("GET", "/api/state")[1]["player"]
        if st["state"] == "playing":
            self.assertEqual(self.req("POST", "/api/seek", {"frame": st["total_frames"] // 2})[0], 200)
        while self.req("GET", "/api/state")[1]["player"]["state"] not in ("finished", "error"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        self.assertEqual(self.req("GET", "/api/state")[1]["player"]["state"], "finished")
        self.assertEqual(self.req("POST", "/api/queue", {"items": ["zz"]})[0], 400)
        self.assertEqual(self.req("POST", "/api/queue", {"items": [fid]})[1]["queue"], [fid])
        self.assertEqual(self.req("POST", "/api/next", {})[0], 200)
        self.assertEqual(self.req("POST", "/api/next", {})[0], 400)  # queue now empty
        self.req("POST", "/api/stop", {})
        self.assertEqual(self.req("POST", "/api/play", {"file_id": "f" * 64})[0], 400)

    def test_export_requires_licence_home_dir_and_new_wav_name(self):
        fid = self.track.file_id
        self.assertEqual(self.req("POST", "/api/export", {"file_id": fid, "path": "/etc/x.wav"})[0], 400)
        self.assertEqual(self.req("POST", "/api/export", {"file_id": fid, "path": str(self.home / "x.txt")})[0], 400)
        status, body, _ = self.req("POST", "/api/export", {"file_id": fid, "path": str(self.home / "Music" / "tone.wav")})
        self.assertEqual(status, 200, body)
        self.assertEqual((self.home / "Music" / "tone.wav").read_bytes(), self.canonical.read_bytes())
        self.assertEqual(self.req("POST", "/api/export", {"file_id": fid, "path": str(self.home / "Music" / "tone.wav")})[0], 400)

    def test_backup_restore_into_new_data_dir_plays_offline(self):
        from holochain_music.keys import export_backup, import_backup
        root = Path(self.tmp.name)
        out = export_backup(sources={"keys": self.app.paths.keys, "library": self.app.paths.library},
                            destination=root / "b.hmb", passphrase="a long backup passphrase")
        new = AppPaths(data=root / "restored" / "data", config=root / "restored" / "config")
        restored = import_backup(source=out, passphrase="a long backup passphrase",
                                 targets={"keys": new.keys, "library": new.library})
        self.assertEqual(sorted(restored), ["keys", "library"])
        other = MusicApp(new)
        other.save_settings(audio_backend="null")
        other.player.backend = "null"
        other.start(offline=True)
        try:
            other.player.play(self.track.file_id)
            deadline = time.monotonic() + 15
            while other.player.status()["state"] not in ("finished", "error"):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.05)
            s = other.player.status()
            self.assertEqual((s["state"], s["source"]), ("finished", "offline"), s)
        finally:
            other.stop()

    def test_settings_validation(self):
        self.assertEqual(self.req("POST", "/api/settings", {"bootstrap_url": "ftp://x"})[0], 400)
        self.assertEqual(self.req("POST", "/api/settings", {"pins": {}})[0], 400)
        status, body, _ = self.req("POST", "/api/settings", {"allow_lan": False})
        self.assertEqual(status, 200)
        self.assertTrue(body["restart_required"])


if __name__ == "__main__":
    unittest.main()
