"""Three real validating-conductor acceptance gate for opt-in grant/v2.

Run ONLY against an explicitly built v2.1 Music hApp:
  HOLOCHAIN_MUSIC_HAPP=/absolute/path/to/holochain_music_v21.happ \
  HOLOCHAIN_MUSIC_V21_E2E=1 python -m unittest discover \
      -s tests -p test_access_grant_v2_real_conductors.py -v

Requires the native Holochain, hc, Music bridge and MoQ binaries. No test
synthetic lifecycle author/position is accepted as authoritative here.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from holochain_music.app import MusicApp
from holochain_music.bridge import BridgeError
from holochain_music.artist import ArtistError
from holochain_music.paths import AppPaths
from holochain_storage import key_lifecycle as kl
from holochain_storage.holochain_identity import OWNER_PURPOSE
from holochain_storage.package import StorageError
from music_catalogue.access_grant_v2 import (
    AccessGrantV2Error, grant_message, verify_access_grant_v2,
)
from test_v1_e2e_flow import free_port, poll
from v1_fixtures import write_tone
from holochain_music.v21_grants import (
    lifecycle_from_conductor, commitment_from_conductor, grant_anchor_from_conductor,
)


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MUSIC_V21_E2E") == "1",
                     "set HOLOCHAIN_MUSIC_V21_E2E=1 with a real dna-v21 hApp")
class AccessGrantV2RealConductors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get("HOLOCHAIN_MUSIC_HAPP"):
            raise RuntimeError("v2.1 hApp must be explicitly pinned by HOLOCHAIN_MUSIC_HAPP")
        cls.root = Path(tempfile.mkdtemp(prefix="hm-grantv2-", dir=os.getenv(
            "HOLOCHAIN_MUSIC_E2E_DIR", "/tmp")))
        cls.boot = f"http://127.0.0.1:{free_port()}"
        cls.apps = {}
        try:
            for name in ("artist", "listener", "mallory"):
                app = MusicApp(AppPaths(data=cls.root / name / "data",
                                        config=cls.root / name / "config"))
                app.save_settings(bootstrap_url=cls.boot, relay_url=cls.boot,
                                  audio_backend="null", key_binding="v2.1",
                                  access_grant_v2=True)
                app.player.backend = "null"
                app.start()
                assert app.online, app.status_message
                cls.apps[name] = app
            cls.artist, cls.listener, cls.mallory = (
                cls.apps[n] for n in ("artist", "listener", "mallory"))
            cls.artist.artist.save_profile("V2 Rotating Artist", "")
            write_tone(cls.root / "tone.wav", seconds=2)
            cls.published = cls.artist.publish_track(wav=cls.root / "tone.wav", title="Rotated tone")
            cls.file_id = cls.published["file_id"]
            cls.key = f"{cls.artist.agent}:{cls.published['track_id']}"
            poll(lambda: cls.listener.catalogue.resolve(
                cls.artist.agent, cls.published["track_id"]), 420,
                 "listener historical manifest + host discovery")
            cls.artist.artist.rotate_key_v21(OWNER_PURPOSE)
            poll(lambda: cls.listener.catalogue.resolve(
                cls.artist.agent, cls.published["track_id"]), 420,
                 "historical S1 content valid after key rotation")
        except BaseException:
            for app in cls.apps.values():
                app.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        for app in cls.apps.values():
            app.stop()
        if os.getenv("HOLOCHAIN_MUSIC_E2E_KEEP") != "1":
            shutil.rmtree(cls.root, ignore_errors=True)

    def test_1_new_licence_for_old_track_after_rotation(self):
        self.listener.request_access(self.key, "perpetual-personal")
        request = poll(lambda: next(
            (r for r in self.artist.artist._inbox()
             if r["listener_agent"] == self.listener.agent and
                r["file_id"] == self.file_id), None), 180, "listener request")
        outcome = self.artist.artist.grant(
            request_hash=request["request_hash"], kind="perpetual-personal")
        self.assertTrue(outcome["granted"])
        poll(lambda: self.listener.sync_grants() > 0, 180, "v2 grant delivery")
        delivery = self.listener.library.grant(self.file_id)
        self.assertEqual(set(delivery), {"grant", "anchor_action"})
        grant = delivery["grant"]
        self.assertEqual(grant["body"]["schema"], "holochain-music/access-grant/v2")
        self.assertEqual(grant["body"]["issuer_key_generation"], "2")
        self.assertNotEqual(grant["body"]["issuer_key_hex"], grant["body"]["manifest_key_hex"])
        self.assertEqual(grant["body"]["manifest_sha256"], self.published["manifest_sha256"])
        self.assertIsNotNone(self.listener.library.v2_evidence(self.file_id))
        cls = type(self)
        cls.delivery = delivery
        cls.request = request

    def test_2_current_lifecycle_and_anchor_are_not_sender_supplied(self):
        lifecycle = lifecycle_from_conductor(self.listener.bridge, self.artist.agent)
        manifest = self.listener.library.manifest(self.file_id)
        commitment = commitment_from_conductor(
            self.listener.bridge, self.artist.agent, manifest, lifecycle)
        anchor = grant_anchor_from_conductor(self.listener.bridge,
                                              self.delivery["anchor_action"], self.artist.agent)
        grant = self.delivery["grant"]
        verified = verify_access_grant_v2(
            grant, signed_manifest=manifest, owner_lifecycle=lifecycle,
            commitment=commitment, anchor=anchor,
            listener_agent=self.listener.agent,
            recipient_public=bytes.fromhex(self.listener.keys.listener_public_hex()))
        verified.authorize("export")
        with self.assertRaises(AccessGrantV2Error) as err:
            verify_access_grant_v2(
                grant, signed_manifest=manifest, owner_lifecycle=lifecycle,
                commitment=commitment, anchor=anchor,
                listener_agent=self.mallory.agent,
                recipient_public=bytes.fromhex(self.mallory.keys.listener_public_hex()))
        self.assertEqual(err.exception.reason, "ListenerMismatch")
        # Merely replaying a signed wrapper with a different anchor fails.
        forged_entry = kl.make_grant_anchor(
            dna_hash=lifecycle.dna_hash, grant_id=grant["body"]["grant_id"],
            grant_message=grant_message(grant["body"]) + b"tampered",
            issuer_key_action=grant["body"]["issuer_key_action"])
        # DNA validates the author itself, not only its supplied entry fields.
        with self.assertRaises(BridgeError) as denied:
            self.mallory.bridge.call("publish_grant_anchor_v2", entry=forged_entry)
        self.assertRegex(str(denied.exception).lower(), "issuer|owner|grant|anchor|author")
        # A live, responsive bridge is mandatory; a transport/timeout failure
        # must never masquerade as a DNA integrity denial.
        self.assertEqual(self.mallory.bridge.call("key_lifecycle_v21_context",
                                                  purpose=OWNER_PURPOSE)["agent"],
                         self.mallory.agent)
        # The original grant id cannot be anchored twice on the artist chain.
        with self.assertRaises(BridgeError) as duplicate:
            self.artist.bridge.call("publish_grant_anchor_v2", entry=anchor.body)
        self.assertRegex(str(duplicate.exception).lower(), "duplicate|grant|anchor|used")

    def test_3_new_grants_refused_after_compromised_revocation(self):
        self.artist.artist.revoke_key_v21(OWNER_PURPOSE, 2, kl.SCOPE_COMPROMISED)
        with self.assertRaises(ArtistError) as stopped:
            self.artist.artist.grant(
                request_hash=self.request["request_hash"], kind="perpetual-personal")
        self.assertRegex(str(stopped.exception).lower(), "active|revoked|lifecycle")
        self.assertEqual(self.artist.bridge.call("key_lifecycle_v21_context",
                                                 purpose=OWNER_PURPOSE)["agent"],
                         self.artist.agent)
        # Pre-revocation anchor still verifies: chain ordering is authoritative.
        delivery = self.delivery
        result = self.listener._verified_v2(
            self.file_id, delivery, self.listener.library.meta(self.file_id))
        result.authorize("export")


if __name__ == "__main__":
    unittest.main()
