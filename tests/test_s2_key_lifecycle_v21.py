"""S2 key lifecycle v2.1 and replica-receipt/v2: Python construction and checks.

These cover the client/reader rules. The trust boundary for lifecycle writes
is the v2.1 storage DNA's integrity validation (dna-v21/), exercised against
real Holochain conductors by Holochain Media Core's `s2_key_lifecycle_v21`
Sweettest suite. Disposable synthetic identities only.
"""
from __future__ import annotations

import copy
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_music.artist import ArtistError, ArtistService
from holochain_music.keys import KeyStore
from holochain_storage import key_lifecycle as kl
from holochain_storage.holochain_identity import HOST_PURPOSE, OWNER_PURPOSE, key_binding_v2_message
from holochain_storage.package import StorageError, create_package, public_key_bytes, replicate_package

DNA = "uhC0kStorageV21DnaHashForTestsOnly"
OTHER_DNA = "uhC0kSomeOtherStorageDnaForTests"
ALICE, BOB, CAROL, MALLORY = ("uhCAkAliceTestAgent", "uhCAkBobTestAgent", "uhCAkCarolTestAgent",
                              "uhCAkMalloryTestAgent")


def seq(author, body, action, n):
    return kl.SequencedRecord(author, action, n, body)


class Chain:
    """A disposable agent chain: lifecycle records with increasing action_seq."""

    def __init__(self, agent, purpose=OWNER_PURPOSE, dna=DNA):
        self.agent, self.purpose, self.dna = agent, purpose, dna
        self.records, self.n = [], 10
        self.keys = []

    def add(self, body, action=None):
        self.n += 1
        record = seq(self.agent, body, action or f"uhCkk{self.agent}{self.n}", self.n)
        self.records.append(record)
        return record

    def incept(self, key):
        self.keys.append(key)
        return self.add(kl.make_inception(key, dna_hash=self.dna, agent=self.agent, purpose=self.purpose))

    def rotate(self, new, old, pred):
        self.keys.append(new)
        return self.add(kl.make_rotation(new, old, dna_hash=self.dna, agent=self.agent, purpose=self.purpose,
                                         predecessor_action=pred.action_hash,
                                         predecessor_generation=pred.body["generation"]))

    def recover(self, new, pred):
        self.keys.append(new)
        return self.add(kl.make_recovery(new, dna_hash=self.dna, agent=self.agent, purpose=self.purpose,
                                         predecessor_action=pred.action_hash,
                                         predecessor_key_hex=pred.body["signing_key_hex"],
                                         predecessor_generation=pred.body["generation"]))

    def revoke(self, target, scope):
        return self.add(kl.make_revocation(dna_hash=self.dna, agent=self.agent, purpose=self.purpose,
                                           generation=target.body["generation"],
                                           signing_key_hex=target.body["signing_key_hex"],
                                           target_action=target.action_hash, scope=scope))

    def resolve(self):
        return kl.resolve_key_lifecycle(self.records, self.agent, self.purpose, self.dna)

    def verdict(self, key, use=kl.NEW_OPERATION, anchor=None):
        return kl.evaluate_key(self.records, self.agent, self.purpose, self.dna,
                               public_key_bytes(key).hex(), use, anchor)


def k():
    return Ed25519PrivateKey.generate()


class MessageTests(unittest.TestCase):
    def test_exact_length_prefixed_role_bound_encoding(self):
        fields = [kl.ROLE_SUCCESSOR, kl.LIFECYCLE_SCHEMA, DNA, ALICE, OWNER_PURPOSE, "2", "rotation",
                  "ab" * 32, "uhCkkP", "cd" * 32]
        expected = b"holochain-storage/key-lifecycle/v2.1\x00" + b"".join(
            struct.pack(">I", len(f.encode())) + f.encode() for f in fields)
        self.assertEqual(kl.transition_message(*fields[:1], *fields[2:]), expected)
        self.assertNotEqual(kl.transition_message(kl.ROLE_PREDECESSOR, *fields[2:]), expected)

    def test_domains_are_distinct(self):
        m = kl.transition_message(kl.ROLE_SUCCESSOR, DNA, ALICE, OWNER_PURPOSE, "1", "inception", "ab" * 32, "", "")
        v2 = key_binding_v2_message(DNA, ALICE, OWNER_PURPOSE, "ab" * 32)
        self.assertNotEqual(m[:40], v2[:40])
        self.assertFalse(m.startswith(b"{"))
        self.assertTrue(kl.RECEIPT_V2_DOMAIN.endswith(b"\x00"))

    def test_generations_are_canonical(self):
        for ok in ("1", "2", "1000000"):
            kl.parse_generation(ok)
        for bad in ("", "0", "01", "+1", "1000001", "1.0", 1, None, "١"):
            with self.assertRaises(StorageError):
                kl.parse_generation(bad)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.a1, self.a2, self.a3 = k(), k(), k()
        self.alice = Chain(ALICE)
        self.g1 = self.alice.incept(self.a1)

    def test_inception_is_active(self):
        lc = self.alice.resolve()
        self.assertEqual(lc.active().key, public_key_bytes(self.a1))
        self.assertEqual(lc.active().continuity, kl.CONTINUITY_INCEPTION)
        self.assertEqual(self.alice.verdict(self.a1), kl.ACTIVE)

    def test_normal_rotation(self):
        self.alice.rotate(self.a2, self.a1, self.g1)
        lc = self.alice.resolve()
        self.assertEqual([g.generation for g in lc.generations], [1, 2])
        self.assertEqual(lc.active().key, public_key_bytes(self.a2))
        self.assertEqual(lc.active().continuity, kl.CONTINUITY_ROTATION)
        self.assertEqual(self.alice.verdict(self.a2), kl.ACTIVE)
        self.assertEqual(self.alice.verdict(self.a1), kl.ROTATED)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL), kl.HISTORICAL_ONLY)

    def test_rotation_proofs_bind_everything(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        for name, value in [("purpose", HOST_PURPOSE), ("dna_hash", OTHER_DNA), ("agent", MALLORY),
                            ("generation", "3"), ("signing_key_hex", public_key_bytes(self.a3).hex()),
                            ("predecessor_action", "uhCkkOther"), ("kind", kl.RECOVERY)]:
            body = copy.deepcopy(g2.body)
            body[name] = value
            records = [self.g1, seq(ALICE, body, "uhCkkX", 99)]
            with self.subTest(name), self.assertRaises(StorageError):
                # Resolve for the agent/purpose the modified record claims, so it is selected.
                kl.resolve_key_lifecycle(records, body["agent"], body["purpose"] if name == "purpose" else OWNER_PURPOSE,
                                         DNA)

    def test_mallory_cannot_rotate_alices_key(self):
        # Authored by Mallory: the author must be the agent.
        body = kl.make_rotation(k(), self.a1, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                                predecessor_action=self.g1.action_hash, predecessor_generation="1")
        forged = seq(MALLORY, body, "uhCkkM", 50)
        self.assertEqual(kl.evaluate_key([self.g1, forged], ALICE, OWNER_PURPOSE, DNA,
                                         body["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)

    def test_stolen_media_key_alone_cannot_authorise(self):
        # Mallory holds Alice's media key a1 but not Alice's agent key: every
        # lifecycle record she can author names HER agent, so it can never be
        # part of Alice's lifecycle; relabelling the agent breaks the proof.
        stolen = kl.make_rotation(k(), self.a1, dna_hash=DNA, agent=MALLORY, purpose=OWNER_PURPOSE,
                                  predecessor_action=self.g1.action_hash, predecessor_generation="1")
        relabelled = dict(stolen, agent=ALICE)
        self.assertEqual(kl.evaluate_key([self.g1, seq(ALICE, relabelled, "uhCkkS", 40)], ALICE, OWNER_PURPOSE,
                                         DNA, stolen["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)
        self.assertEqual(self.alice.verdict(self.a1), kl.ACTIVE, "Alice's lifecycle is unchanged")

    def test_cross_purpose_reuse(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        host = dict(g2.body, purpose=HOST_PURPOSE)
        with self.assertRaises(StorageError):
            kl.resolve_key_lifecycle([seq(ALICE, host, "uhCkkH", 70)], ALICE, HOST_PURPOSE, DNA)

    def test_skipped_generation_and_bad_predecessor(self):
        bad = kl.make_rotation(self.a2, self.a1, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                               predecessor_action=self.g1.action_hash, predecessor_generation="2")
        self.assertEqual(bad["generation"], "3")
        self.assertEqual(kl.evaluate_key([self.g1, seq(ALICE, bad, "uhCkkB", 20)], ALICE, OWNER_PURPOSE, DNA,
                                         bad["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)
        orphan = kl.make_rotation(self.a2, self.a1, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                                  predecessor_action="uhCkkUnknown", predecessor_generation="1")
        with self.assertRaisesRegex(StorageError, "incomplete"):
            kl.resolve_key_lifecycle([self.g1, seq(ALICE, orphan, "uhCkkO", 20)], ALICE, OWNER_PURPOSE, DNA)

    def test_competing_successors_and_second_inception_are_ambiguous(self):
        self.alice.rotate(self.a2, self.a1, self.g1)
        fork = kl.make_rotation(self.a3, self.a1, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                                predecessor_action=self.g1.action_hash, predecessor_generation="1")
        records = self.alice.records + [seq(ALICE, fork, "uhCkkF", 90)]
        for key in (self.a1, self.a2, self.a3):
            self.assertEqual(kl.evaluate_key(records, ALICE, OWNER_PURPOSE, DNA, public_key_bytes(key).hex(),
                                             kl.NEW_OPERATION), kl.AMBIGUOUS)
        second = kl.make_inception(self.a3, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE)
        self.assertEqual(kl.evaluate_key([self.g1, seq(ALICE, second, "uhCkkI", 91)], ALICE, OWNER_PURPOSE, DNA,
                                         public_key_bytes(self.a1).hex(), kl.NEW_OPERATION), kl.AMBIGUOUS)

    def test_replay_is_idempotent_or_rejected(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        # The same action delivered twice: one record.
        self.assertEqual(kl.evaluate_key(self.alice.records + [g2], ALICE, OWNER_PURPOSE, DNA,
                                         public_key_bytes(self.a2).hex(), kl.NEW_OPERATION), kl.ACTIVE)
        # The same entry re-authored as a new action: a competing successor.
        self.assertEqual(kl.evaluate_key(self.alice.records + [seq(ALICE, g2.body, "uhCkkR", 80)], ALICE,
                                         OWNER_PURPOSE, DNA, public_key_bytes(self.a2).hex(), kl.NEW_OPERATION),
                         kl.AMBIGUOUS)
        # One action hash with two different bodies is invalid input.
        clash = seq(ALICE, dict(g2.body, generation="5"), g2.action_hash, g2.action_seq)
        self.assertEqual(kl.evaluate_key(self.alice.records + [clash], ALICE, OWNER_PURPOSE, DNA,
                                         public_key_bytes(self.a2).hex(), kl.NEW_OPERATION), kl.INVALID)

    def test_no_reactivation(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        back = kl.make_rotation(self.a1, self.a2, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                                predecessor_action=g2.action_hash, predecessor_generation="2")
        self.assertEqual(kl.evaluate_key(self.alice.records + [seq(ALICE, back, "uhCkkZ", 99)], ALICE,
                                         OWNER_PURPOSE, DNA, public_key_bytes(self.a1).hex(), kl.NEW_OPERATION),
                         kl.INVALID)
        with self.assertRaises(StorageError):
            kl.make_rotation(self.a1, self.a1, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                             predecessor_action=self.g1.action_hash, predecessor_generation="1")

    def test_continuity_and_recovery(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        no_cont = dict(g2.body, continuity_signature_hex="")
        self.assertEqual(kl.evaluate_key([self.g1, seq(ALICE, no_cont, "uhCkkN", 30)], ALICE, OWNER_PURPOSE, DNA,
                                         g2.body["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)
        wrong = kl.make_rotation(self.a2, k(), dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE,
                                 predecessor_action=self.g1.action_hash, predecessor_generation="1")
        self.assertEqual(kl.evaluate_key([self.g1, seq(ALICE, wrong, "uhCkkW", 30)], ALICE, OWNER_PURPOSE, DNA,
                                         wrong["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)
        lost = Chain(ALICE)
        g1 = lost.incept(self.a1)
        lost.recover(self.a2, g1)
        lc = lost.resolve()
        self.assertEqual(lc.active().continuity, kl.CONTINUITY_RECOVERED)
        self.assertEqual(lost.verdict(self.a2), kl.ACTIVE)

    def test_revocation_new_operations_and_history(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        anchor_before = kl.ChainAnchor(ALICE, g2.action_seq - 1)
        anchor_after = kl.ChainAnchor(ALICE, g2.action_seq + 50)
        self.alice.revoke(self.g1, kl.SCOPE_NEW_OPERATIONS)
        self.assertEqual(self.alice.verdict(self.a1), kl.REVOKED)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL), kl.HISTORICAL_ONLY)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL, anchor_before), kl.HISTORICAL_ONLY)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL, anchor_after), kl.REVOKED,
                         "anchored after the key ended: a new operation with a retired key")
        self.assertEqual(self.alice.verdict(self.a2), kl.ACTIVE)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL, kl.ChainAnchor(MALLORY, 1)), kl.INVALID)

    def test_compromised_revocation(self):
        g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        self.alice.revoke(self.g1, kl.SCOPE_COMPROMISED)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL), kl.REVOKED, "unanchored history refused")
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL, kl.ChainAnchor(ALICE, self.g1.action_seq + 0)),
                         kl.HISTORICAL_ONLY)
        self.assertEqual(self.alice.verdict(self.a1, kl.HISTORICAL, kl.ChainAnchor(ALICE, g2.action_seq + 1)),
                         kl.REVOKED)
        # Revoking the active key leaves no active key.
        self.alice.revoke(g2, kl.SCOPE_NEW_OPERATIONS)
        with self.assertRaises(kl.LifecycleError) as ctx:
            self.alice.resolve().active()
        self.assertEqual(ctx.exception.verdict, kl.REVOKED)
        # Only a recovery may follow a revoked key.
        g3 = self.alice.recover(self.a3, g2)
        self.assertEqual(self.alice.verdict(self.a3), kl.ACTIVE)
        self.assertEqual(g3.body["generation"], "3")

    def test_mallory_cannot_revoke_alices_key(self):
        forged = kl.make_revocation(dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE, generation="1",
                                    signing_key_hex=self.g1.body["signing_key_hex"],
                                    target_action=self.g1.action_hash, scope=kl.SCOPE_COMPROMISED)
        self.assertEqual(kl.evaluate_key([self.g1, seq(MALLORY, forged, "uhCkkMr", 60)], ALICE, OWNER_PURPOSE,
                                         DNA, self.g1.body["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)

    def test_invalid_records_are_never_skipped(self):
        broken = dict(self.g1.body, proof_signature_hex="00" * 64)
        self.assertEqual(kl.evaluate_key([seq(ALICE, broken, "uhCkkQ", 5)], ALICE, OWNER_PURPOSE, DNA,
                                         broken["signing_key_hex"], kl.NEW_OPERATION), kl.INVALID)
        self.assertEqual(kl.evaluate_key([], ALICE, OWNER_PURPOSE, DNA, "ab" * 32, kl.NEW_OPERATION), kl.INVALID)
        wrong_dna = Chain(ALICE, dna=OTHER_DNA)
        wrong_dna.incept(self.a1)
        self.assertEqual(kl.evaluate_key(wrong_dna.records, ALICE, OWNER_PURPOSE, DNA,
                                         public_key_bytes(self.a1).hex(), kl.NEW_OPERATION), kl.INVALID)


class ReceiptV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.artist, self.carol_key = k(), k()
        src = root / "track.bin"
        src.write_bytes(bytes(range(256)) * 20)
        self.store, self.replica = root / "a", root / "c"
        self.package, _ = create_package(src, self.store, self.artist, chunk_size=1024)
        self.trusted = public_key_bytes(self.artist)
        self.carol = Chain(CAROL, purpose=HOST_PURPOSE)
        self.c1 = self.carol.incept(self.carol_key)
        self.receipt = kl.replicate_package_v2(
            self.package, self.store, self.replica, self.trusted, self.carol_key, dna_hash=DNA,
            host_agent=CAROL, host_key_generation="1", host_key_action=self.c1.action_hash, owner_agent=ALICE)

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, receipt, **kw):
        args = dict(trusted_artist=self.trusted, dna_hash=DNA, host_agent=CAROL, owner_agent=ALICE,
                    host_lifecycle=self.carol.resolve())
        args.update(kw)
        return kl.verify_replica_receipt_v2(receipt, self.package, **args)

    def test_valid_receipt_and_bytes(self):
        self.assertEqual(self.verify(self.receipt)["host_agent"], CAROL)
        self.assertEqual(self.verify(kl.receipt_v2_bytes(self.receipt))["chunk_count"], "5")
        self.assertEqual(len(kl.receipt_v2_digest(self.receipt)), 64)

    def test_forged_and_misattributed(self):
        forged = dict(self.receipt, signature_hex=k().sign(kl.receipt_v2_message(self.receipt)).hex())
        with self.assertRaisesRegex(StorageError, "signature"):
            self.verify(forged)
        # Mallory's receipt claiming Carol (signed with Mallory's key).
        mallory_key = k()
        mallory = kl.sign_replica_receipt_v2(self.package, node_key=mallory_key, dna_hash=DNA, host_agent=CAROL,
                                             host_key_generation="1", host_key_action=self.c1.action_hash,
                                             owner_agent=ALICE, trusted_artist=self.trusted)
        with self.assertRaises(StorageError):
            self.verify(mallory)
        # Carol's genuine receipt presented as another host's.
        mal = Chain(MALLORY, purpose=HOST_PURPOSE)
        mal.incept(mallory_key)
        with self.assertRaisesRegex(StorageError, "different host"):
            self.verify(self.receipt, host_agent=MALLORY, host_lifecycle=mal.resolve())
        for name, value in [("host_agent", MALLORY), ("owner_agent", BOB), ("dna_hash", OTHER_DNA),
                            ("chunk_count", "4"), ("host_key_generation", "2"), ("context", "other"),
                            ("received_at", "2026-01-01T00:00:00+00:00"), ("file_id", "00" * 32)]:
            with self.subTest(name), self.assertRaises(StorageError):
                self.verify(dict(self.receipt, **{name: value}))
        with self.assertRaises(StorageError):
            self.verify(dict(self.receipt, note="x"))

    def test_rotated_host_key_is_historical(self):
        c2 = self.carol.rotate(k(), self.carol_key, self.c1)
        self.verify(self.receipt)  # historical by default
        with self.assertRaisesRegex(StorageError, "Rotated"):
            self.verify(self.receipt, use=kl.NEW_OPERATION)
        with self.assertRaisesRegex(StorageError, "Rotated"):
            self.verify(self.receipt, anchor=kl.ChainAnchor(CAROL, c2.action_seq + 1))
        self.carol.revoke(self.c1, kl.SCOPE_COMPROMISED)
        with self.assertRaisesRegex(StorageError, "Revoked"):
            self.verify(self.receipt)

    def test_legacy_s1_receipt_is_not_a_v2_receipt(self):
        legacy = replicate_package(self.package, self.store, self.replica, self.trusted, self.carol_key)
        with self.assertRaisesRegex(StorageError, "invalid receipt format"):
            self.verify(legacy)


class GrantAnchorTests(unittest.TestCase):
    """Reader-side grant-anchor rules (the DNA's own rules run in Media Core's
    real-conductor suite)."""

    def setUp(self):
        self.a1, self.a2 = k(), k()
        self.alice = Chain(ALICE)
        self.g1 = self.alice.incept(self.a1)
        self.g2 = self.alice.rotate(self.a2, self.a1, self.g1)
        self.msg = b"holochain-music/access-grant/v2\x00{synthetic signed grant}"
        self.gid = "ab" * 16

    def anchor(self, action=None, author=ALICE, position=None, **changes):
        body = kl.make_grant_anchor(dna_hash=DNA, grant_id=self.gid, grant_message=self.msg,
                                    issuer_key_action=action or self.g2.action_hash)
        body.update(changes)
        self.alice.n += 1
        return seq(author, body, f"uhCkkAnchor{self.alice.n}", position or self.alice.n)

    def verify(self, record, lifecycle=None, **kw):
        args = dict(grant_id=self.gid, grant_message=self.msg, issuer_key_action=self.g2.action_hash)
        args.update(kw)
        return kl.verify_grant_anchor(record, lifecycle or self.alice.resolve(), **args)

    def test_minimal_public_fields(self):
        body = self.anchor().body
        self.assertEqual(set(body), {"schema", "dna_hash", "grant_id", "grant_commitment", "issuer_key_action"})
        self.assertNotIn(self.msg.hex(), repr(body))

    def test_current_key_anchor_verifies(self):
        g = self.verify(self.anchor())
        self.assertEqual(g.generation, 2)

    def test_commitment_is_domain_separated_and_binding(self):
        self.assertNotEqual(kl.grant_anchor_commitment(self.msg),
                            __import__("hashlib").sha256(self.msg).hexdigest())
        with self.assertRaisesRegex(StorageError, "does not match"):
            self.verify(self.anchor(), grant_message=self.msg + b"x")
        with self.assertRaisesRegex(StorageError, "does not match"):
            self.verify(self.anchor(), grant_id="cd" * 16)

    def test_wrong_author_dna_or_shape(self):
        with self.assertRaisesRegex(StorageError, "content owner"):
            self.verify(self.anchor(author=MALLORY))
        with self.assertRaisesRegex(StorageError, "different DNA"):
            self.verify(self.anchor(dna_hash=OTHER_DNA))
        with self.assertRaisesRegex(StorageError, "invalid grant anchor"):
            self.verify(self.anchor(note="x"))

    def test_obsolete_and_revoked_keys(self):
        # g1 named after the rotation: the generation had already ended.
        stale = self.anchor(action=self.g1.action_hash)
        with self.assertRaisesRegex(StorageError, "Rotated"):
            self.verify(stale, issuer_key_action=self.g1.action_hash)
        # An anchor made by g1 BEFORE the rotation stays historical.
        early = self.anchor(action=self.g1.action_hash, position=self.g1.action_seq + 1)
        self.assertEqual(self.verify(early, issuer_key_action=self.g1.action_hash).generation, 1)
        self.alice.revoke(self.g2, kl.SCOPE_COMPROMISED)
        with self.assertRaisesRegex(StorageError, "Revoked"):
            self.verify(self.anchor())
        with self.assertRaisesRegex(StorageError, "precedes"):
            self.verify(self.anchor(position=self.g2.action_seq - 1))

    def test_recovered_issuer_rejected_by_default(self):
        lost = Chain(ALICE)
        g1 = lost.incept(self.a1)
        g2 = lost.recover(self.a2, g1)
        lost.n += 1
        body = kl.make_grant_anchor(dna_hash=DNA, grant_id=self.gid, grant_message=self.msg,
                                    issuer_key_action=g2.action_hash)
        rec = seq(ALICE, body, "uhCkkRecAnchor", lost.n)
        args = dict(grant_id=self.gid, grant_message=self.msg, issuer_key_action=g2.action_hash)
        with self.assertRaisesRegex(StorageError, "recovered without continuity"):
            kl.verify_grant_anchor(rec, lost.resolve(), **args)
        self.assertEqual(kl.verify_grant_anchor(rec, lost.resolve(), recovered_policy="accept", **args).generation, 2)

    def test_not_in_lifecycle(self):
        with self.assertRaisesRegex(StorageError, "not in the owner's lifecycle"):
            self.verify(self.anchor(action="uhCkkNope"), issuer_key_action="uhCkkNope")


class FakeV21Bridge:
    """Stand-in for the v2.1 storage cell: a single source chain. It re-applies
    the reader rules so an invalid write is refused; the real rules run in
    dna-v21 integrity validation (Media Core's real-conductor suite)."""

    def __init__(self, agent):
        self.whoami = {"agent": agent}
        self.rows, self.calls, self.seq = [], [], 3

    def call(self, op, **args):
        self.calls.append((op, args))
        me = self.whoami["agent"]
        if op == "key_lifecycle_v21_context":
            mine = [r for r in self.rows if r.body["purpose"] == args["purpose"]]
            last = [r for r in mine if r.body["schema"] == kl.LIFECYCLE_SCHEMA][-1:]
            if not last:
                return {"dna_hash": DNA, "agent": me, "purpose": args["purpose"], "next_generation": "1",
                        "predecessor_action": "", "predecessor_key_hex": "", "predecessor_generation": "",
                        "predecessor_revoked": False}
            t = last[0]
            return {"dna_hash": DNA, "agent": me, "purpose": args["purpose"],
                    "next_generation": str(int(t.body["generation"]) + 1), "predecessor_action": t.action_hash,
                    "predecessor_key_hex": t.body["signing_key_hex"], "predecessor_generation": t.body["generation"],
                    "predecessor_revoked": any(r.body.get("target_action") == t.action_hash for r in mine)}
        if op in ("publish_key_transition_v21", "publish_key_revocation_v21"):
            self.seq += 1
            row = kl.SequencedRecord(me, f"uhCkk{self.seq}", self.seq, args["entry"])
            kl.resolve_key_lifecycle(self.rows + [row], me, args["entry"]["purpose"], DNA)
            self.rows.append(row)
            return {"action_hash": row.action_hash}
        if op == "get_key_lifecycle_v21":
            return [{"author": r.author, "action_hash": r.action_hash, "action_seq": r.action_seq, "body": r.body}
                    for r in self.rows if r.author == args["agent"]]
        if op in ("publish_file_commitment", "publish_track", "publish_replica_claim"):
            self.seq += 1
            return {"action_hash": f"uhCkk{self.seq}"}
        raise AssertionError(op)


class ArtistLifecycleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.keys = KeyStore(self.root / "keys")
        self.bridge = FakeV21Bridge(ALICE)
        self.artist = ArtistService(bridge=self.bridge, keys=self.keys, host_root=self.root / "host",
                                    key_binding="v2.1")

    def test_inception_uses_existing_key_and_rotation_creates_a_new_one(self):
        gen1 = public_key_bytes(self.keys.artist_ed25519())
        self.assertEqual(public_key_bytes(self.artist._signer(OWNER_PURPOSE)), gen1)
        self.assertEqual(public_key_bytes(self.artist._signer(OWNER_PURPOSE)), gen1)  # idempotent
        self.assertEqual(len([1 for op, _ in self.bridge.calls if op == "publish_key_transition_v21"]), 1)
        out = self.artist.rotate_key_v21(OWNER_PURPOSE)
        self.assertEqual(out["generation"], 2)
        gen2 = public_key_bytes(self.keys.lifecycle_ed25519("artist", 2))
        self.assertEqual(out["signing_key_hex"], gen2.hex())
        self.assertEqual(public_key_bytes(self.artist._signer(OWNER_PURPOSE)), gen2)
        lifecycle = self.artist.lifecycle_v21(OWNER_PURPOSE)
        self.assertEqual(lifecycle.classify(gen1, kl.NEW_OPERATION), kl.ROTATED)
        self.assertEqual(lifecycle.active().continuity, kl.CONTINUITY_ROTATION)
        for secret in (self.keys.artist_ed25519(), self.keys.lifecycle_ed25519("artist", 2)):
            self.assertNotIn(secret.private_bytes_raw().hex(), repr(self.bridge.calls))

    def test_revoked_active_key_signs_nothing_new(self):
        self.artist._signer(OWNER_PURPOSE)
        self.artist.revoke_key_v21(OWNER_PURPOSE, 1, kl.SCOPE_NEW_OPERATIONS)
        with self.assertRaisesRegex(ArtistError, "no active owner-manifest key"):
            self.artist._signer(OWNER_PURPOSE)
        with self.assertRaisesRegex(ArtistError, "local chain and resolved lifecycle disagree|no active"):
            self.artist.rotate_key_v21(OWNER_PURPOSE)

    def test_grants_for_content_signed_by_a_rotated_key_are_refused(self):
        from holochain_storage.package import b64
        old = self.artist._signer(OWNER_PURPOSE)
        manifest = {"signer": b64(public_key_bytes(old))}
        self.assertIs(type(self.artist._grant_signer(manifest)), type(old))
        self.artist.rotate_key_v21(OWNER_PURPOSE)
        with self.assertRaisesRegex(ArtistError, "no longer active"):
            self.artist._grant_signer(manifest)

    def test_lifecycle_keys_are_explicit(self):
        with self.assertRaises(Exception):
            self.keys.lifecycle_ed25519("artist", 2)
        with self.assertRaises(Exception):
            self.keys.lifecycle_ed25519("mallory", 1)

    def test_v1_and_v2_defaults_unchanged(self):
        artist = ArtistService(bridge=self.bridge, keys=self.keys, host_root=self.root / "h2")
        self.assertEqual(artist.key_binding, "v1")
        self.assertEqual(public_key_bytes(artist._signer(OWNER_PURPOSE)), public_key_bytes(self.keys.artist_ed25519()))
        self.assertEqual(self.bridge.calls, [])


if __name__ == "__main__":
    unittest.main()
