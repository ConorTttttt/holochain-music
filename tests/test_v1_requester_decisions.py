"""Requester duplicate suppression and verified private decline status, without a conductor."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from holochain_storage.holochain_identity import AuthoredRecord
from holochain_music.app import MusicApp
from holochain_music.library import Library

ARTIST = "uhCAkArtist"
LISTENER = "uhCAkListener"
FILE = "a" * 64
MANIFEST = "b" * 64
TRACK = "c" * 32
REQ = "d" * 32

TRACK_BODY = {
    "schema": "holochain-music/track/v1", "artist_agent": ARTIST,
    "track_id": TRACK, "album_id": None, "title": "Test",
    "duration_ms": 1000, "disc_number": 1, "track_number": 1,
    "audio_format": "audio/wav", "file_id": FILE, "manifest_sha256": MANIFEST,
    "rights_basis": "original_owner",
}


class FakeBridge:
    whoami = {"agent": LISTENER}

    def __init__(self):
        self.decisions = []

    def record(self, operation, **kw):
        assert operation == "get_track"
        return AuthoredRecord(author=ARTIST, action_hash="h", body=dict(TRACK_BODY))

    def call(self, operation, **kw):
        assert operation == "get_inbox_decisions"
        return self.decisions


class RequesterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = MusicApp.__new__(MusicApp)
        self.app.library = Library(Path(self.tmp.name))
        self.app.bridge = FakeBridge()
        self.app.online = True
        self.app.catalogue = mock.Mock()
        self.app.catalogue.profile.return_value = {"display_name": "Artist"}
        self.app.keys = mock.Mock()
        self.app.keys.listener_public_hex.return_value = "e" * 64
        self.app.outbox = mock.Mock()
        self.app.outbox.deliver.return_value = {"delivered": True}
        self.app._request_lock = threading.RLock()
        self.app._sync_lock = threading.Lock()

    def tearDown(self):
        self.tmp.cleanup()

    def test_second_request_does_not_send_or_multiply_entries(self):
        key = ARTIST + ":" + TRACK
        result = self.app.request_access(key, "stream")
        self.assertTrue(result["requested"])
        self.assertFalse(result.get("already_pending", False))
        existing = self.app.library.meta(FILE)
        self.assertEqual(len(existing["request_id"]), 32)
        again = self.app.request_access(key, "stream")
        self.assertTrue(again["already_pending"])
        self.assertEqual(self.app.library.meta(FILE)["request_id"], existing["request_id"])
        self.app.outbox.deliver.assert_called_once()

    def test_duplicate_suppressed_even_when_queued_and_after_restart(self):
        self.app.outbox.deliver.return_value = {"queued": True}
        key = ARTIST + ":" + TRACK
        self.app.request_access(key, "perpetual-personal")
        self.app._request_lock = threading.RLock()  # equivalent to a fresh app instance
        result = self.app.request_access(key, "perpetual-personal")
        self.assertTrue(result["already_pending"])
        self.assertTrue(result["queued"])
        self.app.outbox.deliver.assert_called_once()

    def test_wrong_artist_manifest_kind_and_id_are_not_trusted(self):
        self.app.request_access(ARTIST + ":" + TRACK, "stream")
        request_id = self.app.library.meta(FILE)["request_id"]
        valid = {"schema": "holochain-music/inbox-decision/v1",
                 "owner_agent": ARTIST, "file_id": FILE,
                 "manifest_sha256": MANIFEST, "kind": "stream",
                 "request_id": request_id, "decision": "declined"}
        for diff in ({"owner_agent": "mallory"}, {"manifest_sha256": "0" * 64},
                     {"kind": "perpetual-personal"}, {"request_id": "f" * 32},
                     {"decision": "approved"}, {"file_id": "f" * 64}):
            with self.subTest(diff=diff):
                self.app.bridge.decisions = [{"body": {**valid, **diff}}]
                self.assertEqual(self.app.sync_decisions(), 0)
                self.assertEqual(self.app.library.meta(FILE)["request_status"], "pending")
        self.app.bridge.decisions = [{"body": valid}]
        self.assertEqual(self.app.sync_decisions(), 1)
        self.assertEqual(self.app.library.meta(FILE)["request_status"], "declined")
        self.assertEqual(self.app.sync_decisions(), 0)
        self.app.outbox.deliver.assert_called_once()

    def test_decision_for_previous_request_cannot_deny_new_kind(self):
        self.app.request_access(ARTIST + ":" + TRACK, "stream")
        prev_id = self.app.library.meta(FILE)["request_id"]
        self.app.request_access(ARTIST + ":" + TRACK, "perpetual-personal")
        self.app.bridge.decisions = [{"body": {
            "schema": "holochain-music/inbox-decision/v1", "owner_agent": ARTIST,
            "file_id": FILE, "manifest_sha256": MANIFEST, "kind": "stream",
            "request_id": prev_id, "decision": "declined",
        }}]
        self.assertEqual(self.app.sync_decisions(), 0)
        self.assertEqual(self.app.library.meta(FILE)["request_status"], "pending")

    def test_expired_stream_can_renew_only_once(self):
        from holochain_music.library import _atomic_json
        key = ARTIST + ":" + TRACK
        self.app.request_access(key, "stream")
        self.app.library.update_meta(FILE, request_status="approved",
                                     grant_kind="stream", grant_received_at=100)
        _atomic_json(self.app.library.tracks_dir / FILE / "grant.json",
                     {"body": {"expires_at": 101}})
        new_request = self.app.request_access(key, "stream")
        self.assertTrue(new_request["requested"])
        self.assertFalse(new_request.get("already_pending", False))
        self.assertEqual(self.app.outbox.deliver.call_count, 2)
        self.assertTrue(self.app.request_access(key, "stream")["already_pending"])
        self.assertEqual(self.app.outbox.deliver.call_count, 2)

    def test_expired_stream_renewal_decline_is_visible_with_old_grant_file(self):
        from holochain_music.library import _atomic_json
        key = ARTIST + ":" + TRACK
        self.app.request_access(key, "stream")
        self.app.library.update_meta(FILE, request_status="approved",
                                     grant_kind="stream", grant_received_at=100)
        _atomic_json(self.app.library.tracks_dir / FILE / "grant.json",
                     {"body": {"expires_at": 101}})
        self.app.request_access(key, "stream")
        current_id = self.app.library.meta(FILE)["request_id"]
        self.app.bridge.decisions = [{"body": {
            "schema": "holochain-music/inbox-decision/v1",
            "owner_agent": ARTIST, "file_id": FILE, "manifest_sha256": MANIFEST,
            "kind": "stream", "request_id": current_id, "decision": "declined",
        }}]
        self.assertEqual(self.app.sync_decisions(), 1)
        self.assertEqual(self.app.library.meta(FILE)["request_status"], "declined")

    def test_existing_legacy_request_does_not_send_again(self):
        self.app.library.add_pending(FILE, {
            "artist_agent": ARTIST, "manifest_sha256": MANIFEST,
            "requested": "stream", "title": "Legacy", "request_queued": False,
        })
        self.assertTrue(self.app.request_access(ARTIST + ":" + TRACK, "stream")["already_pending"])
        self.app.outbox.deliver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
