"""v1 perpetual personal-use licence: offline, listener-bound, non-expiring."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import b64, canonical, create_package, public_key_bytes
from music_catalogue.content_grants import (
    ContentGrantError, LICENCE_SCHEMA, grant_kind, issue_content_grant,
    issue_personal_licence, unwrap_content_grant,
)


class PersonalLicenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-licence-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "a.bin").write_bytes(os.urandom(3000))
        self.artist = Ed25519PrivateKey.generate()
        self.manifest, self.key = create_package(root / "a.bin", root / "cas", self.artist, chunk_size=1024)
        self.listener = X25519PrivateKey.generate()
        self.listener_pub = self.listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.licence = issue_personal_licence(
            owner_signer=self.artist, owner_agent="uhCAkAlice", listener_agent="uhCAkBob",
            recipient_public=self.listener_pub, signed_manifest=self.manifest, content_key=self.key)

    def unwrap(self, grant, **kw):
        args = dict(trusted_artist=public_key_bytes(self.artist), owner_agent="uhCAkAlice",
                    listener_agent="uhCAkBob", recipient_private=self.listener,
                    signed_manifest=self.manifest)
        args.update(kw)
        return unwrap_content_grant(grant, **args)

    def test_unwraps_and_never_expires(self):
        self.assertEqual(self.unwrap(self.licence), self.key)
        self.assertEqual(grant_kind(self.licence), "perpetual-personal")
        far_future = time.time() + 50 * 365 * 86400
        with mock.patch("music_catalogue.content_grants.time.time", return_value=far_future):
            self.assertEqual(self.unwrap(self.licence), self.key)

    def test_binds_listener_owner_key_and_file(self):
        with self.assertRaises(ContentGrantError):
            self.unwrap(self.licence, listener_agent="uhCAkMallory")
        with self.assertRaises(ContentGrantError):
            self.unwrap(self.licence, owner_agent="uhCAkMallory")
        with self.assertRaises(ContentGrantError):
            self.unwrap(self.licence, recipient_private=X25519PrivateKey.generate())
        with self.assertRaises(ContentGrantError):
            self.unwrap(self.licence, trusted_artist=public_key_bytes(Ed25519PrivateKey.generate()))

    def test_tampering_and_schema_confusion_fail_closed(self):
        for field, value in (("terms", "commercial"), ("issued_at", int(time.time()) + 10_000),
                             ("licence_id", "z" * 32), ("schema", "holochain-music/content-grant/v1")):
            with self.subTest(field=field):
                forged = copy.deepcopy(self.licence)
                forged["body"][field] = value
                with self.assertRaises(ContentGrantError):
                    self.unwrap(forged)
        # Re-signing a licence body with an expiry field added is rejected.
        body = dict(self.licence["body"], expires_at=int(time.time()) + 60)
        resigned = {"body": body, "signer": self.licence["signer"],
                    "signature": b64(self.artist.sign(canonical(body)))}
        with self.assertRaises(ContentGrantError):
            self.unwrap(resigned)

    def test_licence_and_stream_grant_contexts_are_domain_separated(self):
        stream = issue_content_grant(owner_signer=self.artist, owner_agent="uhCAkAlice",
                                     listener_agent="uhCAkBob", recipient_public=self.listener_pub,
                                     signed_manifest=self.manifest, content_key=self.key)
        self.assertEqual(grant_kind(stream), "stream")
        # Graft the stream grant's wrapped key into a validly re-signed licence body.
        body = dict(self.licence["body"])
        for k in ("ephemeral_key_hex", "salt_b64", "nonce_b64", "wrapped_key_b64", "issued_at"):
            body[k] = stream["body"][k]
        grafted = {"body": body, "signer": self.licence["signer"],
                   "signature": b64(self.artist.sign(canonical(body)))}
        with self.assertRaises(ContentGrantError):
            self.unwrap(grafted)
        self.assertEqual(self.licence["body"]["schema"], LICENCE_SCHEMA)


if __name__ == "__main__":
    unittest.main()
