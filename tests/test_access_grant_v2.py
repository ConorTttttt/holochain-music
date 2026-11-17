"""Independent Python contract and security tests for access-grant/v2.

These tests exercise Music's real Ed25519/X25519/HKDF/AESGCM and S1 package
implementation. Conductor authorship/ordering is modelled by SequencedRecord;
real conductor integrity tests are a SEPARATE release gate.
"""
import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import key_lifecycle as kl
from holochain_storage.package import canonical, create_package, public_key_bytes
from music_catalogue.access_grant_v2 import (
    AccessGrantV2Error, _historical_manifest, grant_message, grant_wrap_context,
    issue_access_grant_v2, parse_access_grant_v2, unwrap_access_grant_v2,
    verify_access_grant_v2,
)

DNA = "uhC0kAccessGrantV21TestDNA"
ALICE = "uhCAkAliceV2"
BOB = "uhCAkBobV2"
CAROL = "uhCAkCarolV2"
NOW = 1800000000


def record(author, action, seq, body):
    return kl.SequencedRecord(author, action, seq, body)


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_world():
    g1 = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    g2 = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    bob = X25519PrivateKey.from_private_bytes(bytes(range(4, 36)))
    carol = X25519PrivateKey.from_private_bytes(bytes(range(66, 98)))
    inception = kl.make_inception(g1, dna_hash=DNA, agent=ALICE, purpose=kl.OWNER_PURPOSE)
    transition = kl.make_rotation(
        g2, g1, dna_hash=DNA, agent=ALICE, purpose=kl.OWNER_PURPOSE,
        predecessor_action="alice-g1", predecessor_generation="1")
    lifecycle_rows = [record(ALICE, "alice-g1", 2, inception),
                      record(ALICE, "alice-g2", 6, transition)]
    lifecycle = kl.resolve_key_lifecycle(lifecycle_rows, ALICE, kl.OWNER_PURPOSE, DNA)
    with tempfile.TemporaryDirectory() as path:
        source = Path(path) / "content.bin"
        source.write_bytes(b"music-test\x00" * 100)
        manifest, content_key = create_package(source, Path(path) / "cas", g1)
    commitment = record(ALICE, "alice-commit", 4, {
        "schema": "holochain-storage/file-commitment/v1",
        "owner_agent": ALICE, "file_id": manifest["body"]["file_id"],
        "manifest_sha256": __import__("holochain_storage.package", fromlist=["manifest_digest"]).manifest_digest(manifest),
    })
    return locals()


def signed_grant(world, *, rights=None, term="window", issuer=None, recipient=None,
                 listener=BOB, expires_at=None,
                 recovered_policy=kl.RECOVERED_ISSUER_REJECT):
    rights = ["stream"] if rights is None else rights
    recipient = recipient or world["bob"]
    grant = issue_access_grant_v2(
        issuer_signer=issuer or world["g2"], owner_lifecycle=world["lifecycle"],
        signed_manifest=world["manifest"], commitment=world["commitment"],
        listener_agent=listener, recipient_public=pub(recipient),
        content_key=world["content_key"], rights=rights, term=term,
        issued_at=NOW, not_before=NOW, expires_at=(NOW + 3600 if expires_at is None else expires_at),
        recovered_policy=recovered_policy,
    )
    entry = kl.make_grant_anchor(
        dna_hash=DNA, grant_id=grant["body"]["grant_id"],
        grant_message=grant_message(grant["body"]), issuer_key_action="alice-g2")
    return grant, record(ALICE, "alice-anchor", 7, entry)


def checked(world, grant, anchor, *, listener=BOB, private=None,
            lifecycle=None, commitment=None, manifest=None,
            recovered_policy=kl.RECOVERED_ISSUER_REJECT):
    private = private or world["bob"]
    return verify_access_grant_v2(
        grant, signed_manifest=manifest or world["manifest"],
        owner_lifecycle=lifecycle or world["lifecycle"],
        commitment=commitment or world["commitment"], anchor=anchor,
        listener_agent=listener, recipient_public=pub(private), now=NOW + 120,
        recovered_policy=recovered_policy,
    )


class V2ContractTests(unittest.TestCase):
    def setUp(self):
        self.w = make_world()
        self.grant, self.anchor = signed_grant(self.w)

    def reject(self, category, reason, *, grant=None, anchor="default", **kw):
        with self.assertRaises(AccessGrantV2Error) as ctx:
            checked(self.w, grant if grant is not None else self.grant,
                    self.anchor if anchor == "default" else anchor, **kw)
        self.assertEqual((ctx.exception.category, ctx.exception.reason), (category, reason))

    def test_rotated_artist_can_grant_historical_manifest(self):
        w = self.w
        self.assertNotEqual(w["manifest"]["signer"],
                            base64.b64encode(public_key_bytes(w["g2"])).decode())
        self.assertEqual(w["lifecycle"].classify(public_key_bytes(w["g1"]), kl.HISTORICAL,
                         kl.ChainAnchor(ALICE, w["commitment"].action_seq)), kl.HISTORICAL_ONLY)
        verified = checked(w, self.grant, self.anchor)
        self.assertEqual(verified.body["issuer_key_generation"], "2")
        verified.authorize("stream")
        self.assertEqual(unwrap_access_grant_v2(verified, w["bob"]), w["content_key"])
        with self.assertRaises(AccessGrantV2Error) as exc:
            verified.authorize("export")
        self.assertEqual((exc.exception.category, exc.exception.reason), ("denied", "RightNotGranted"))

    def test_verified_grant_body_is_immutable_after_validation(self):
        # A signed grant arrives as a mutable JSON dict. Neither mutation of
        # the input nor of the exposed body view may change an authorisation
        # already checked against the issuer signature and public anchor.
        verified = checked(self.w, self.grant, self.anchor)
        self.assertEqual(verified.rights, frozenset({"stream"}))
        self.grant["body"]["rights"].append("export")
        self.grant["body"]["recipient_key_hex"] = "00" * 32
        view = verified.body
        view["rights"].append("export")
        view["recipient_key_hex"] = "ff" * 32
        self.assertEqual(verified.rights, frozenset({"stream"}))
        self.assertEqual(verified.body["recipient_key_hex"], pub(self.w["bob"]).hex())
        with self.assertRaises(AccessGrantV2Error) as denied:
            verified.authorize("export")
        self.assertEqual((denied.exception.category, denied.exception.reason),
                         ("denied", "RightNotGranted"))
        self.assertEqual(unwrap_access_grant_v2(verified, self.w["bob"]),
                         self.w["content_key"])

    def test_perpetual_rights_and_recipient(self):
        grant, anchor = signed_grant(
            self.w, rights=["export", "managed-offline", "stream"], term="perpetual",
            expires_at=0, recipient=self.w["carol"], listener=CAROL)
        verified = checked(self.w, grant, anchor, listener=CAROL, private=self.w["carol"])
        for right in ["export", "managed-offline", "stream"]:
            verified.authorize(right)
        self.assertEqual(unwrap_access_grant_v2(verified, self.w["carol"]), self.w["content_key"])
        self.reject("denied", "ListenerMismatch", grant=grant, anchor=anchor)

    def test_scope_signature_and_commitment_mismatches(self):
        self.reject("denied", "RecipientKeyMismatch", private=self.w["carol"])
        self.reject("unavailable", "AnchorNotFound", anchor=None)
        modified = copy.deepcopy(self.grant)
        modified["body"]["file_id"] = "a" * 64
        self.reject("denied", "FileMismatch", grant=modified)
        modified = copy.deepcopy(self.grant)
        modified["body"]["manifest_sha256"] = "a" * 64
        self.reject("denied", "ManifestMismatch", grant=modified)
        modified = copy.deepcopy(self.grant)
        modified["body"]["rights"] = ["export", "stream"]
        self.reject("unauthenticated", "InvalidSignature", grant=modified)
        modified = copy.deepcopy(self.grant)
        modified["body"]["issuer_key_generation"] = "1"
        self.reject("unauthenticated", "IssuerGenerationMismatch", grant=modified)
        altered_anchor = copy.deepcopy(self.anchor)
        altered_anchor.body["grant_commitment"] = "0" * 64
        self.reject("unauthenticated", "AnchorMismatch", anchor=altered_anchor)
        replay_anchor = copy.deepcopy(self.anchor)
        replay_anchor.body["grant_id"] = "1" * 32
        self.reject("unauthenticated", "AnchorMismatch", anchor=replay_anchor)
        other_agent_anchor = copy.deepcopy(self.anchor)
        object.__setattr__(other_agent_anchor, "author", "uhCAkMallory")
        self.reject("unauthenticated", "AnchorMismatch", anchor=other_agent_anchor)

    def test_post_revocation_order_and_pre_revocation_preservation(self):
        w = self.w
        revoke = kl.make_revocation(
            dna_hash=DNA, agent=ALICE, purpose=kl.OWNER_PURPOSE,
            generation="2", signing_key_hex=public_key_bytes(w["g2"]).hex(),
            target_action="alice-g2", scope=kl.SCOPE_COMPROMISED)
        rows = w["lifecycle_rows"] + [record(ALICE, "alice-revoke", 8, revoke)]
        compromised = kl.resolve_key_lifecycle(rows, ALICE, kl.OWNER_PURPOSE, DNA)
        # Anchor at seq7 preceded revocation at seq8: remains historical.
        self.assertEqual(unwrap_access_grant_v2(
            checked(w, self.grant, self.anchor, lifecycle=compromised), w["bob"]), w["content_key"])
        late_anchor = record(ALICE, "late", 9, self.anchor.body)
        self.reject("unauthenticated", "KeyRevoked", anchor=late_anchor, lifecycle=compromised)
        with self.assertRaises((kl.LifecycleError, AccessGrantV2Error)):
            signed_grant({**w, "lifecycle": compromised})

    def test_invalid_historical_manifest_commitment(self):
        late = record(ALICE, "alice-late-commit", 7, self.w["commitment"].body)
        self.reject("unauthenticated", "InvalidHistoricalKey", commitment=late)

    def test_wrapping_is_domain_separated(self):
        b = self.grant["body"]
        self.assertTrue(grant_message(b).startswith(b"holochain-music/access-grant/v2\x00{"))
        self.assertTrue(grant_wrap_context(b).startswith(
            b"holochain-music/access-grant/hkdf-aad/v2\x00{"))
        self.assertNotEqual(grant_wrap_context(b), grant_message(b))
        edited = copy.deepcopy(b)
        edited["recipient_key_hex"] = "a" * 64
        self.assertNotEqual(grant_wrap_context(edited), grant_wrap_context(b))

    def test_parse_exact_fields_and_no_v1_downgrade(self):
        parse_access_grant_v2(canonical(self.grant))
        for bad in [dict(self.grant, signer="xx"),
                    {"body": {"schema": "holochain-music/content-grant/v1"},
                     "signer": "x", "signature": "y"}]:
            with self.assertRaises(AccessGrantV2Error):
                parse_access_grant_v2(bad)
        with self.assertRaises(AccessGrantV2Error) as ctx:
            parse_access_grant_v2(
                b'{"body":{"schema":"x","schema":"y"},"signature_hex":"abcd"}')
        self.assertEqual(ctx.exception.reason, "Structure")

    def test_recovered_issuer_policy(self):
        w = self.w
        g3 = Ed25519PrivateKey.from_private_bytes(bytes(range(99, 131)))
        recovery = kl.make_recovery(
            g3, dna_hash=DNA, agent=ALICE, purpose=kl.OWNER_PURPOSE,
            predecessor_action="alice-g2", predecessor_key_hex=public_key_bytes(w["g2"]).hex(),
            predecessor_generation="2")
        rows = w["lifecycle_rows"] + [record(ALICE, "alice-g3", 9, recovery)]
        recovered = kl.resolve_key_lifecycle(rows, ALICE, kl.OWNER_PURPOSE, DNA)
        local = {**w, "lifecycle": recovered}
        with self.assertRaises(AccessGrantV2Error) as refused:
            signed_grant(local, issuer=g3)
        self.assertEqual(refused.exception.reason, "RecoveredIssuerRefused")
        grant, _ = signed_grant(local, issuer=g3,
                                recovered_policy=kl.RECOVERED_ISSUER_ACCEPT)
        grant["body"]["issuer_key_action"] = "alice-g3"  # Re-sign to reflect actual generation.
        grant["body"]["issuer_key_generation"] = "3"
        grant["body"]["issuer_key_hex"] = public_key_bytes(g3).hex()
        # The issuer helper already uses active g3, this is deliberately idempotent.
        grant["signature_hex"] = g3.sign(grant_message(grant["body"])).hex()
        entry = kl.make_grant_anchor(
            dna_hash=DNA, grant_id=grant["body"]["grant_id"],
            grant_message=grant_message(grant["body"]), issuer_key_action="alice-g3")
        anchor = record(ALICE, "alice-anchor-g3", 10, entry)
        self.reject("unauthenticated", "RecoveredIssuerRefused", grant=grant, anchor=anchor,
                    lifecycle=recovered)
        accepted = checked(w, grant, anchor, lifecycle=recovered,
                           recovered_policy=kl.RECOVERED_ISSUER_ACCEPT)
        self.assertEqual(accepted.issuer_continuity, kl.CONTINUITY_RECOVERED)
        # A recovered G3 grant issuer cannot relabel an original, normally
        # authenticated G1 S1 manifest as recovered historical content.
        self.assertEqual(accepted.owner_assurance, "KeyLifecycleV21")


if __name__ == "__main__":
    unittest.main()
