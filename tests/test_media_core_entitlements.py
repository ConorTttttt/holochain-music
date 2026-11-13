"""CORE-005: compare Music's Python grant/licence checks with Media Core's Rust.

Skipped unless HOLOCHAIN_MEDIA_CORE_BIN points at the `holochain-media-core`
executable (ConorTttttt/holochain-media-core, crates/content-cli). Every
grant and licence here is issued by Music's own unchanged
``music_catalogue.content_grants`` code; every case runs BOTH Music's
``unwrap_content_grant`` (plus the app's per-operation gate) and the Rust
``check-access`` command on the same bytes, and requires the same verdict.

The Rust side receives no private key: only the owner-signed grant, the
conductor-authenticated owner records and the listener's X25519 *public* key.
Where Rust authorises at the policy level but Music's AES-GCM unwrap fails
(corrupted wrapped key), the test asserts exactly that documented boundary.
No production path uses the adapter.
"""
from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import media_core_adapter as core
from holochain_storage.grant import create_perpetual_grant
from holochain_storage.holochain_identity import (
    FILE_SCHEMA, KEY_SCHEMA, OWNER_PURPOSE, AuthoredRecord,
)
from holochain_storage.package import (
    StorageError, _sign, b64, create_package, decrypt_package, from_b64, manifest_digest,
    public_key_bytes,
)
from music_catalogue import content_grants as cg

ENABLED = bool(os.environ.get(core.ENV_BINARY))
T0 = 1_760_000_000


def _x_public(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _at(now: int):
    return mock.patch("time.time", return_value=float(now))


class EntitlementAdapterDisabledByDefaultTests(unittest.TestCase):
    def test_check_access_is_unavailable_without_environment(self):
        saved = os.environ.pop(core.ENV_BINARY, None)
        try:
            self.assertFalse(core.enabled())
            record = AuthoredRecord("uhCAkA", "uhCkkA", {})
            with self.assertRaises(core.MediaCoreUnavailable):
                core.check_access({}, {}, "uhCAkA", record, record, "uhCAkB", b"\0" * 32, "stream")
        finally:
            if saved is not None:
                os.environ[core.ENV_BINARY] = saved

    def test_invalid_right_is_a_usage_error_not_a_rejection(self):
        record = AuthoredRecord("uhCAkA", "uhCkkA", {})
        with self.assertRaises(core.MediaCoreUnavailable):
            core.check_access({}, {}, "uhCAkA", record, record, "uhCAkB", b"\0" * 32, "download")


@unittest.skipUnless(ENABLED, f"set {core.ENV_BINARY} to run Media Core comparisons")
class EntitlementComparisonTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="media-core-core005-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.alice = Ed25519PrivateKey.generate()
        self.alice_pub = public_key_bytes(self.alice)
        self.mallory = Ed25519PrivateKey.generate()
        self.bob_x = X25519PrivateKey.generate()
        self.mallory_x = X25519PrivateKey.generate()
        self.owner, self.bob, self.mallory_agent = (
            "uhCAkAliceConductorAuthor", "uhCAkBobConductorAuthor", "uhCAkMalloryConductorAuthor")
        self.plain = {}
        self.packages = {}
        for name, data in (("p", os.urandom(5000)), ("q", os.urandom(300))):
            (self.root / f"{name}.bin").write_bytes(data)
            store = self.root / f"store-{name}"
            manifest, key = create_package(self.root / f"{name}.bin", store, self.alice, chunk_size=1024)
            self.packages[name] = (manifest, key, store)
            self.plain[name] = data
        self.records = {name: self._records(m) for name, (m, _, _) in self.packages.items()}

    def _records(self, manifest: dict) -> dict:
        return dict(
            owner_key_binding=AuthoredRecord(self.owner, "uhCkkOwnerKey", {
                "schema": KEY_SCHEMA, "agent": self.owner, "purpose": OWNER_PURPOSE,
                "signing_key_hex": self.alice_pub.hex()}),
            owner_commitment=AuthoredRecord(self.owner, "uhCkkCommit", {
                "schema": FILE_SCHEMA, "owner_agent": self.owner,
                "file_id": manifest["body"]["file_id"], "manifest_sha256": manifest_digest(manifest)}),
        )

    # ---- issuance through Music's own code -------------------------------
    def stream(self, name="p", *, listener=None, recipient=None, owner=None, signer=None,
               lifetime=1800, issued=T0):
        manifest, key, _ = self.packages[name]
        with _at(issued):
            return cg.issue_content_grant(
                owner_signer=signer or self.alice, owner_agent=owner or self.owner,
                listener_agent=listener or self.bob, recipient_public=_x_public(recipient or self.bob_x),
                signed_manifest=manifest, content_key=key, lifetime_seconds=lifetime)

    def licence(self, name="p", *, listener=None, recipient=None, issued=T0):
        manifest, key, _ = self.packages[name]
        with _at(issued):
            return cg.issue_personal_licence(
                owner_signer=self.alice, owner_agent=self.owner, listener_agent=listener or self.bob,
                recipient_public=_x_public(recipient or self.bob_x), signed_manifest=manifest,
                content_key=key)

    # ---- the two implementations -----------------------------------------
    def python(self, grant, *, name="p", listener=None, recipient=None, right="stream", now=T0 + 10):
        """Music's verdict: unwrap_content_grant + the app.py per-operation gate."""
        try:
            with _at(now):
                key = cg.unwrap_content_grant(
                    grant, trusted_artist=self.alice_pub, owner_agent=self.owner,
                    listener_agent=listener or self.bob, recipient_private=recipient or self.bob_x,
                    signed_manifest=self.packages[name][0])
        except (StorageError, ValueError, TypeError, KeyError, AttributeError):
            return False, None
        allowed = right == "stream" or cg.grant_kind(grant) == "perpetual-personal"
        return allowed, key

    def rust(self, grant, *, name="p", listener=None, recipient=None, right="stream", now=T0 + 10):
        try:
            result = core.check_access(
                grant, self.packages[name][0], self.owner, listener_agent=listener or self.bob,
                recipient_public=_x_public(recipient or self.bob_x), right=right, now=now,
                **self.records[name])
        except core.MediaCoreRejected as exc:
            return False, exc.result
        return True, result

    def assert_same(self, label, grant, **kwargs):
        py_ok, _ = self.python(grant, **kwargs)
        rs_ok, result = self.rust(grant, **kwargs)
        self.assertEqual(py_ok, rs_ok, f"{label}: Python {py_ok} vs Rust {result}")
        return result

    def resign(self, grant, transform, signer=None):
        body = copy.deepcopy(grant["body"])
        transform(body)
        return _sign(body, signer or self.alice)

    # ---- tests -----------------------------------------------------------
    def test_valid_grant_and_licence_agree_for_every_right(self):
        grant, lic = self.stream(), self.licence()
        for right in core.RIGHTS:
            result = self.assert_same(f"grant/{right}", grant, right=right)
            if right == "stream":
                self.assertEqual(result["kind"], "stream")
                self.assertEqual(result["rights"], ["stream"])
                self.assertEqual(result["expires_at"], T0 + 1800)
            else:
                self.assertEqual(result["category"], "denied")
                self.assertEqual(result["reason"], "RightNotGranted")
            result = self.assert_same(f"licence/{right}", lic, right=right)
            self.assertEqual(result["kind"], "perpetual-personal")
            self.assertEqual(result["rights"], ["stream", "managed-offline", "export"])
            self.assertIsNone(result["expires_at"])
            self.assertEqual(result["licence_id"], lic["body"]["licence_id"])

    def test_hkdf_context_is_byte_identical(self):
        grant, lic = self.stream(), self.licence()
        for issued, ctx in ((grant, cg._context(grant["body"])),
                            (lic, cg._licence_context(lic["body"]))):
            _, result = self.rust(issued)
            self.assertEqual(result["hkdf_context_hex"], ctx.hex())

    def test_time_policy_agrees_at_every_boundary(self):
        grant, lic = self.stream(), self.licence()
        for now in (T0 - 121, T0 - 120, T0, T0 + 1799, T0 + 1800, T0 + 86400 * 400):
            self.assert_same(f"grant@{now - T0}", grant, now=now)
            self.assert_same(f"licence@{now - T0}", lic, now=now, right="export")
        big = self.stream(lifetime=cg.MAX_LIFETIME_SECONDS)
        for now in (T0 + cg.MAX_LIFETIME_SECONDS - 1, T0 + cg.MAX_LIFETIME_SECONDS):
            self.assert_same(f"max-lifetime@{now - T0}", big, now=now)
        _, expired = self.rust(grant, now=T0 + 1800)
        self.assertEqual((expired["category"], expired["reason"]), ("validity", "Expired"))

    def test_alice_bob_mallory_adversarial_cases_agree(self):
        grant, lic = self.stream(), self.licence()
        mallory_sig = b64(self.mallory.sign(cg.canonical(grant["body"])))
        forged = dict(copy.deepcopy(grant), signature=mallory_sig)
        cases = [
            ("mallory re-signs", self.resign(grant, lambda b: None, self.mallory), {}),
            ("mallory signature under alice signer", forged, {}),
            ("mallory uses bob grant", grant, {"listener": self.mallory_agent, "recipient": self.mallory_x}),
            ("mallory uses bob licence", lic, {"listener": self.mallory_agent, "recipient": self.mallory_x,
                                               "right": "export"}),
            ("wrong recipient key", grant, {"recipient": self.mallory_x}),
            ("addressed to mallory key", self.stream(recipient=self.mallory_x), {}),
            ("wrong owner agent", self.stream(owner=self.mallory_agent), {}),
            ("replay on other package", grant, {"name": "q"}),
            ("licence replay on other package", lic, {"name": "q", "right": "export"}),
            ("wrong manifest digest", self.resign(grant, lambda b: b.update(manifest_sha256="00" * 32)), {}),
            ("tampered listener", dict(copy.deepcopy(grant), body={**grant["body"], "listener_agent": self.mallory_agent}),
             {"listener": self.mallory_agent}),
            ("unknown terms", self.resign(lic, lambda b: b.update(terms="commercial-use")), {"right": "export"}),
            ("future schema", self.resign(grant, lambda b: b.update(schema="holochain-music/content-grant/v2")), {}),
            ("string timestamp", self.resign(grant, lambda b: b.update(issued_at=str(T0))), {}),
            ("lifetime too long", self.resign(grant, lambda b: b.update(expires_at=T0 + 86401)), {}),
            ("extra field", self.resign(grant, lambda b: b.update(note="x")), {}),
            ("short wrapped key", self.resign(grant, lambda b: b.update(wrapped_key_b64=b64(bytes(47)))), {}),
            ("oversized", self.resign(grant, lambda b: b.update(owner_agent="A" * 5000)), {}),
            ("legacy perpetual grant", create_perpetual_grant(
                self.packages["p"][0], self.alice_pub, self.alice, self.packages["p"][1],
                _x_public(self.bob_x)), {"right": "export"}),
            ("not an object", [grant], {}),
        ]
        for label, candidate, kwargs in cases:
            result = self.assert_same(label, candidate, **kwargs)
            self.assertFalse(result.get("ok", False), label)
            self.assertIn(result["boundary"], ("entitlement", "s2-binding"), label)
        _, wrong_issuer = self.rust(cases[0][1])
        self.assertEqual(wrong_issuer["reason"], "WrongIssuer")
        _, legacy = self.rust(cases[-2][1], right="export")
        self.assertEqual(legacy["reason"], "LegacyPerpetualGrant")

    def test_corrupted_wrapped_key_is_caught_only_by_music_unwrap(self):
        """The documented boundary: Rust authorises the signed policy; the
        recipient's AES-GCM unwrap is what rejects a corrupted wrapped key."""
        def flip(body):
            raw = bytearray(from_b64(body["wrapped_key_b64"], 48))
            raw[5] ^= 1
            body["wrapped_key_b64"] = b64(bytes(raw))
        corrupted = self.resign(self.stream(), flip)
        rs_ok, result = self.rust(corrupted)
        py_ok, _ = self.python(corrupted)
        self.assertTrue(rs_ok, result)
        self.assertEqual(result["certifies"], "policy-only; key unwrap and AES-GCM authentication remain")
        self.assertFalse(py_ok)

    def test_end_to_end_rust_check_then_music_unwrap_and_decrypt(self):
        """Holochain-authenticated owner -> Rust entitlement check -> Music's
        own unwrap -> Music's verified decrypt reproduces the original bytes."""
        for issued, right, now in ((self.licence(), "export", T0 + 86400 * 30),
                                   (self.stream(), "stream", T0 + 60)):
            rs_ok, result = self.rust(issued, right=right, now=now)
            self.assertTrue(rs_ok, result)
            with _at(now):
                key = cg.unwrap_content_grant(
                    issued, trusted_artist=self.alice_pub, owner_agent=self.owner,
                    listener_agent=self.bob, recipient_private=self.bob_x,
                    signed_manifest=self.packages["p"][0])
            out = self.root / f"out-{right}.bin"
            manifest, _, store = self.packages["p"]
            decrypt_package(manifest, store, out, key, self.alice_pub)
            self.assertEqual(out.read_bytes(), self.plain["p"])

    def test_self_licence_pattern_owner_equals_listener(self):
        lic = self.licence(listener=self.owner)
        self.assert_same("self licence", lic, listener=self.owner, right="export")
        rs_ok, _ = self.rust(lic, listener=self.owner, right="export")
        self.assertTrue(rs_ok)


if __name__ == "__main__":
    unittest.main()
