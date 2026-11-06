"""Artist request decisions: private persistence, scoped bulk actions, API validation.

These do not need a conductor. The raw inbox is stubbed to model requests
already authenticated and stored on the artist's own source chain.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from holochain_music.artist import ArtistError, ArtistService
from holochain_music.server import routes
from holochain_music.app import AppError

FILE_A = "a" * 64
FILE_B = "b" * 64
OTHER = "c" * 64
DIGEST_A = "d" * 64
DIGEST_B = "e" * 64


def request(hash_, file_id, kind, *, listener="listener-one"):
    return {"request_hash": hash_, "file_id": file_id, "kind": kind,
            "manifest_sha256": DIGEST_A if file_id == FILE_A else DIGEST_B,
            "listener_agent": listener, "note": "please", "received_at": 42,
            "x25519_public_hex": "f" * 64}


def make_artist(root):
    # Exercise the actual decision methods without requiring Holochain startup.
    artist = ArtistService.__new__(ArtistService)
    artist.root = root
    artist._request_lock = threading.RLock()
    artist.my_tracks = lambda: [
        {"file_id": FILE_A, "manifest_sha256": DIGEST_A, "title": "Track A"},
        {"file_id": FILE_B, "manifest_sha256": DIGEST_B, "title": "Track B"},
    ]
    artist._inbox = lambda: [
        request("one", FILE_A, "stream"),
        request("two", FILE_A, "perpetual-personal", listener="listener-two"),
        request("three", FILE_B, "stream"),
        request("foreign", OTHER, "stream"),
        request("wrong-manifest", FILE_A, "stream") | {"manifest_sha256": "0" * 64},
    ]
    artist.issued = lambda: []
    artist.deliver = lambda op, **kw: {"delivered": True}
    return artist


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artist = make_artist(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_only_own_valid_track_requests_with_pending_status(self):
        rows = self.artist.requests()
        self.assertEqual([r["request_hash"] for r in rows], ["one", "two", "three"])
        self.assertEqual([r["status"] for r in rows], ["pending"] * 3)
        self.assertEqual(rows[0]["file_id"], FILE_A)
        self.assertFalse(rows[0]["granted"])

    def test_decline_persists_with_private_file_permissions_and_is_idempotent(self):
        self.assertEqual(self.artist.reject(request_hash="one"), {"declined": True, "delivered": True})
        self.assertTrue(self.artist.reject(request_hash="one")["already_decided"])
        self.assertEqual(self.artist.requests()[0]["status"], "declined")
        self.assertEqual(self.artist.requests()[1]["status"], "pending")
        p = self.root / "request-decisions.json"
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("listener-one", p.read_text())
        restarted = make_artist(self.root)
        self.assertEqual(restarted.requests()[0]["status"], "declined")
        with self.assertRaisesRegex(ArtistError, "already approved or declined"):
            restarted.grant(request_hash="one", kind="stream")

    def test_unknown_foreign_and_previously_granted_request_cannot_be_declined(self):
        for h in ("unknown", "foreign", "wrong-manifest"):
            with self.subTest(hash=h), self.assertRaisesRegex(ArtistError, "unknown access request"):
                self.artist.reject(request_hash=h)
        self.artist.issued = lambda: [
            {"listener_agent": "listener-one", "file_id": FILE_A, "kind": "stream"},
        ]
        self.assertEqual(self.artist.requests()[0]["status"], "approved")
        with self.assertRaisesRegex(ArtistError, "cannot be declined"):
            self.artist.reject(request_hash="one")
        self.assertFalse((self.root / "request-decisions.json").exists())

    def test_identical_legacy_requests_collapse_and_resolution_is_shared(self):
        old = self.artist._inbox
        self.artist._inbox = lambda: [request("duplicate", FILE_A, "stream"), *old()]
        rows = self.artist.requests()
        self.assertEqual([r["request_hash"] for r in rows], ["duplicate", "two", "three"])
        self.assertEqual(rows[0]["duplicate_count"], 2)
        self.artist._save_decision("one", status="declined")
        rows = self.artist.requests()
        self.assertEqual(rows[0]["status"], "declined")
        with self.assertRaisesRegex(ArtistError, "already approved or declined"):
            self.artist.grant(request_hash="duplicate", kind="stream")

    def test_decline_queues_delivery_and_explicit_resend_recovers(self):
        calls = []
        def send(op, **kw):
            calls.append((op, kw))
            return {"queued": True}
        self.artist.deliver = send
        result = self.artist.reject(request_hash="one")
        self.assertTrue(result["queued"])
        self.assertEqual(calls[0][0], "send_decision")
        self.assertEqual(calls[0][1]["listener"], "listener-one")
        self.assertEqual(calls[0][1]["decision"]["file_id"], FILE_A)
        self.assertEqual(calls[0][1]["decision"]["decision"], "declined")
        self.assertEqual(self.artist.requests()[0]["status"], "declined")
        self.assertEqual(self.artist.resend_decline(request_hash="one"), {"queued": True})
        self.assertEqual(len(calls), 2)

    def test_notification_failure_does_not_undo_decline(self):
        from holochain_music.bridge import BridgeError
        self.artist.deliver = lambda op, **kw: (_ for _ in ()).throw(BridgeError("recipient refused"))
        result = self.artist.reject(request_hash="one")
        self.assertTrue(result["declined"])
        self.assertIn("recipient refused", result["notification_error"])
        self.assertEqual(self.artist.requests()[0]["status"], "declined")

    def test_batch_decline_affects_explicit_ids_only_and_is_idempotent(self):
        result = self.artist.decide_batch(action="decline", request_hashes=["two", "three"])
        self.assertEqual((result["processed"], result["succeeded"]), (2, 2))
        self.assertEqual([r["status"] for r in self.artist.requests()],
                         ["pending", "declined", "declined"])
        result = self.artist.decide_batch(action="decline", request_hashes=["three", "one"])
        self.assertEqual(result["succeeded"], 1)
        self.assertFalse(result["results"][0]["ok"])
        self.assertEqual(self.artist.requests()[0]["status"], "declined")

    def test_batch_accept_uses_requested_access_type_and_reports_partial_failures(self):
        issued = []

        def fake_grant(*, request_hash, kind):
            issued.append((request_hash, kind))
            if request_hash == "two":
                raise ArtistError("simulated delivery failure")
            self.artist._save_decision(request_hash, status="approved", kind=kind)
            return {"granted": True, "queued": request_hash == "three"}

        self.artist.grant = fake_grant
        result = self.artist.decide_batch(action="approve", request_hashes=["one", "two", "three"])
        self.assertEqual(issued, [("one", "stream"), ("two", "perpetual-personal"), ("three", "stream")])
        self.assertEqual(result["succeeded"], 2)
        self.assertEqual([r["status"] for r in self.artist.requests()], ["approved", "pending", "approved"])
        self.assertEqual(sum(bool(x.get("queued")) for x in result["results"]), 1)
        self.assertEqual(result["results"][1]["error"], "simulated delivery failure")

    def test_batch_bounds_and_duplicates_are_rejected_before_mutation(self):
        for action, hashes in [
            ("invalid", ["one"]), ("approve", []), ("approve", ["one", "one"]),
            ("approve", ["x"] * 26), ("decline", [42]), ("decline", ["x" * 81]),
            ("decline", "one"),
        ]:
            with self.subTest(action=action, hashes=hashes), self.assertRaises(ArtistError):
                self.artist.decide_batch(action=action, request_hashes=hashes)
        self.assertFalse((self.root / "request-decisions.json").exists())

    def test_api_only_accepts_explicit_ids_and_artist_online(self):
        artist = self.artist

        class FakeApp:
            player = mock.Mock()
            next_track = mock.Mock()
            def __init__(self):
                self.artist = artist
                self.online = True

            def require_online(self):
                if not self.online:
                    raise AppError("offline")

        app = FakeApp()
        table = routes(app)
        one = table[("POST", "/api/artist/reject")]
        batch = table[("POST", "/api/artist/requests/bulk")]
        with self.assertRaises(AppError):
            one({"request_hash": "one", "extra": "unsafe"})
        with self.assertRaises(AppError):
            batch({"action": "decline"})  # cannot derive an all-inbox target on the server
        with self.assertRaises(ArtistError):
            batch({"action": "decline", "request_hashes": ["one", "one"]})
        self.assertTrue(one({"request_hash": "one"})["declined"])
        self.assertEqual(batch({"action": "decline", "request_hashes": ["two"]})["succeeded"], 1)
        app.online = False
        with self.assertRaises(AppError):
            one({"request_hash": "three"})


if __name__ == "__main__":
    unittest.main()
