"""Store-and-retry outbox for private request/grant delivery."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from holochain_music.bridge import BridgeError
from holochain_music.outbox import EXPIRY_SECONDS, MAX_ITEMS, Outbox, OutboxError

from v1_fixtures import assert_private


class FakeSend:
    def __init__(self):
        self.mode, self.calls = "ok", []

    def __call__(self, op, **args):
        self.calls.append((op, args))
        if self.mode == "offline":
            raise BridgeError("recipient unreachable (offline?): no peer")
        if self.mode == "ws-timeout":  # call_remote to an offline agent outlives the client socket
            raise BridgeError("Websocket error: Timeout")
        if self.mode == "ratelimited":
            raise BridgeError("rate limited: too many deliveries from you today")
        if self.mode == "invalid":
            raise BridgeError("invalid inbox access request")
        return {"delivered": True}


class OutboxTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-outbox-")
        self.addCleanup(tmp.cleanup)
        self.send, self.now = FakeSend(), [1_000_000.0]
        self.box = Outbox(Path(tmp.name) / "outbox.json", self.send, clock=lambda: self.now[0])
        self.args = {"owner": "uhCAkArtist", "request": {"file_id": "a" * 64, "kind": "stream"}}

    def test_delivers_immediately_when_online(self):
        self.assertEqual(self.box.deliver("send_access_request", **self.args), {"delivered": True})
        self.assertEqual(self.box.items(), [])

    def test_queues_when_offline_then_delivers_on_retry(self):
        self.send.mode = "offline"
        out = self.box.deliver("send_access_request", **self.args)
        self.assertTrue(out["queued"])
        self.assertEqual(self.box.flush(), {"delivered": 0, "expired": 0, "pending": 1})
        self.assertEqual(self.box.items()[0]["attempts"], 2)
        self.send.mode = "ok"
        self.assertEqual(self.box.flush(), {"delivered": 1, "expired": 0, "pending": 0})
        self.assertEqual(self.send.calls[-1], ("send_access_request", self.args))

    def test_offline_recipient_timeout_is_queued(self):
        self.send.mode = "ws-timeout"
        self.assertTrue(self.box.deliver("send_access_request", **self.args)["queued"])

    def test_rate_limit_and_invalid_are_not_queued(self):
        for mode in ("ratelimited", "invalid"):
            self.send.mode = mode
            with self.assertRaises(BridgeError):
                self.box.deliver("send_access_request", **self.args)
        self.assertEqual(self.box.items(), [])

    def test_permanent_failure_on_retry_is_dropped(self):
        self.send.mode = "offline"
        self.box.deliver("send_grant", listener="uhCAkL", grant={"grant_json": "{}"})
        self.send.mode = "ratelimited"
        self.assertEqual(self.box.flush()["pending"], 0)

    def test_one_attempt_per_offline_recipient_per_pass(self):
        self.send.mode = "offline"
        for _ in range(5):
            self.box.deliver("send_access_request", **self.args)
        calls = len(self.send.calls)
        self.assertEqual(self.box.flush()["pending"], 5)
        self.assertEqual(len(self.send.calls) - calls, 1)

    def test_expiry_and_size_bound(self):
        self.send.mode = "offline"
        self.box.deliver("send_access_request", **self.args)
        self.now[0] += EXPIRY_SECONDS + 1
        self.assertEqual(self.box.flush(), {"delivered": 0, "expired": 1, "pending": 0})
        for _ in range(MAX_ITEMS):
            self.box.deliver("send_access_request", **self.args)
        with self.assertRaises(OutboxError):
            self.box.deliver("send_access_request", **self.args)

    def test_only_known_operations(self):
        with self.assertRaises(OutboxError):
            self.box.deliver("publish_track", entry={})

    def test_file_is_private(self):
        self.send.mode = "offline"
        self.box.deliver("send_access_request", **self.args)
        assert_private(self, self.box.path, 0o600)


if __name__ == "__main__":
    unittest.main()
