"""Security tests of the private request/grant inbox with three real agents.

artist publishes; listener and mallory are separate agents with their own
conductors. Opt-in like the main e2e: HOLOCHAIN_MUSIC_E2E=1 (+ binaries).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import time
import unittest

from holochain_music.app import MusicApp
from holochain_music.bridge import BridgeError
from holochain_music.paths import AppPaths

from test_v1_e2e_flow import free_port, poll
from v1_fixtures import Track, write_tone


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MUSIC_E2E") == "1", "set HOLOCHAIN_MUSIC_E2E=1")
class GrantInboxSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix="hmsec-", dir=os.environ.get("HOLOCHAIN_MUSIC_E2E_DIR", "/tmp")))
        cls.boot = f"http://127.0.0.1:{free_port()}"
        cls.apps = {}
        for name in ("artist", "listener", "mallory"):
            app = MusicApp(AppPaths(data=cls.base / name / "data", config=cls.base / name / "config"))
            app.save_settings(bootstrap_url=cls.boot, relay_url=cls.boot, audio_backend="null")
            app.player.backend = "null"
            app.start()
            assert app.online, app.status_message
            cls.apps[name] = app
        cls.artist, cls.listener, cls.mallory = (cls.apps[n] for n in ("artist", "listener", "mallory"))
        cls.artist.artist.save_profile("Sec Artist", "test")
        write_tone(cls.base / "t.wav", seconds=2.0)
        cls.pub = cls.artist.publish_track(wav=cls.base / "t.wav", title="Sec Tone")
        cls.key = f"{cls.artist.agent}:{cls.pub['track_id']}"
        cls.fid = cls.pub["file_id"]
        for app in (cls.listener, cls.mallory):
            poll(lambda: app.catalogue.resolve(cls.artist.agent, cls.pub["track_id"]), 420, "discovery")

    @classmethod
    def tearDownClass(cls):
        for app in cls.apps.values():
            app.stop()
        if os.environ.get("HOLOCHAIN_MUSIC_E2E_KEEP") != "1":
            shutil.rmtree(cls.base, True)

    def inbox(self):
        return self.artist.artist._inbox()

    def raw_request(self, sender, **override):
        request = {"file_id": self.fid, "manifest_sha256": self.pub["manifest_sha256"],
                   "x25519_public_hex": sender.keys.listener_public_hex(), "kind": "stream", "note": ""}
        request.update(override)
        return sender.bridge.call("send_access_request", owner=self.artist.agent, request=request)

    def test_1_malformed_requests_are_refused_and_not_stored(self):
        before = len(self.inbox())
        for bad in ({"kind": "commercial"}, {"note": "x" * 501}, {"x25519_public_hex": "zz"},
                    {"file_id": "A" * 64}, {"note": "bad\x00null"}):
            with self.subTest(bad=list(bad)):
                with self.assertRaises(BridgeError) as ctx:
                    self.raw_request(self.mallory, **bad)
                self.assertNotIn("unreachable", str(ctx.exception),
                                 "a refusal must not look like an offline recipient (it would be retried)")
        self.assertEqual(len(self.inbox()), before)

    def test_2_sender_identity_is_the_verified_provenance(self):
        self.raw_request(self.mallory, note="I am the listener, honest")
        rows = [r for r in self.inbox() if r["note"] == "I am the listener, honest"]
        self.assertEqual([r["listener_agent"] for r in rows], [self.mallory.agent])
        self.assertTrue(all(len(r["nonce"]) == 32 for r in self.inbox()))
        self.assertEqual(len({r["nonce"] for r in self.inbox()}), len(self.inbox()))

    def test_3_forwarded_or_forged_grants_never_authorise_the_listener(self):
        # Mallory obtains a genuine licence for herself...
        self.mallory.request_access(self.key, "perpetual-personal")
        req = poll(lambda: [r for r in self.artist.artist.requests()
                            if r["listener_agent"] == self.mallory.agent and r["kind"] == "perpetual-personal"], 60, "req")
        self.artist.artist.grant(request_hash=req[-1]["request_hash"], kind="perpetual-personal")
        poll(lambda: self.mallory.sync_grants() or self.mallory.library.grant(self.fid), 60, "mallory grant")
        genuine = self.mallory.library.grant(self.fid)
        # ...and forwards it, plus a self-signed forgery, to the listener.
        self.listener.request_access(self.key, "stream")  # listener has a pending library entry
        forged = Track(self.base / "forged").licence(listener_agent=self.listener.agent)
        for grant in (genuine, forged):
            self.mallory.bridge.call("send_grant", listener=self.listener.agent, grant={
                "file_id": self.fid, "manifest_sha256": self.pub["manifest_sha256"],
                "kind": "perpetual-personal", "grant_json": json.dumps(grant)})
        self.assertEqual(self.listener.sync_grants(), 0)
        self.assertIsNone(self.listener.library.grant(self.fid))
        with self.assertRaises(Exception):
            self.listener.player.play(self.fid)

    def test_4_duplicate_delivery_is_harmless(self):
        self.listener.request_access(self.key, "perpetual-personal")
        req = poll(lambda: [r for r in self.artist.artist.requests()
                            if r["listener_agent"] == self.listener.agent and r["kind"] == "perpetual-personal"], 60, "req")
        self.artist.artist.grant(request_hash=req[-1]["request_hash"], kind="perpetual-personal")
        self.assertGreaterEqual(poll(lambda: self.listener.sync_grants(), 60, "grant"), 1)
        first = self.listener.library.grant(self.fid)
        # Re-deliver the identical signed grant: imported 0 times, unchanged.
        self.artist.bridge.call("send_grant", listener=self.listener.agent, grant={
            "file_id": self.fid, "manifest_sha256": self.pub["manifest_sha256"], "kind": "perpetual-personal",
            "grant_json": json.dumps(first)})
        self.assertEqual(self.listener.sync_grants(), 0)
        self.assertEqual(self.listener.library.grant(self.fid), first)

    def test_5_per_sender_rate_limit(self):
        sent = len([r for r in self.inbox() if r["listener_agent"] == self.mallory.agent])
        refused = None
        for i in range(25 - sent):
            try:
                self.raw_request(self.mallory, note=f"spam {i}")
            except BridgeError as exc:
                refused = str(exc)
                break
        self.assertIsNotNone(refused, "rate limit never triggered")
        self.assertIn("rate limited", refused)
        self.assertNotIn("unreachable", refused)
        self.assertEqual(len([r for r in self.inbox() if r["listener_agent"] == self.mallory.agent]), 20)
        # A different sender is unaffected.
        self.raw_request(self.listener, note="still welcome")

    def test_6_request_while_artist_fully_offline_is_queued_then_delivered(self):
        # Runs last: stops and restarts the artist.
        self.artist.stop()
        restarted = MusicApp(self.artist.paths)
        out = self.listener.request_access(self.key, "stream", "queued please")
        self.assertTrue(out.get("queued"), out)
        restarted.start()
        self.assertTrue(restarted.online)
        self.apps["artist"] = restarted
        type(self).artist = restarted
        t0 = time.monotonic()
        # Rediscovering a restarted peer can take minutes (see readiness report).
        poll(lambda: self.listener.outbox.flush()["delivered"] or not self.listener.outbox.items(), 600, "outbox", 5)
        print(f"\nqueued request delivered {time.monotonic() - t0:.0f}s after artist restart", flush=True)
        rows = [r for r in restarted.artist._inbox() if r["note"] == "queued please"]
        self.assertEqual([r["listener_agent"] for r in rows], [self.listener.agent])


if __name__ == "__main__":
    unittest.main()
