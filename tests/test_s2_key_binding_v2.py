"""S2 key-binding v2 (proof of possession): Python construction and checks.

These cover the client-side rules. The trust boundary is the v2 storage DNA's
integrity validation (dna-v2/), which is exercised against real Holochain
conductors by Holochain Media Core's `s2_key_binding_v2` Sweettest suite.
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
from holochain_storage.holochain_identity import (
    ASSURANCE_LEGACY_V1, ASSURANCE_POP_V2, HOST_PURPOSE, KEY_POP_DOMAIN_V2, KEY_SCHEMA,
    KEY_SCHEMA_V2, OWNER_PURPOSE, AuthoredRecord, key_binding_v2_message, key_for_agent,
    key_for_agent_v2, make_key_binding_v2, resolve_signing_key,
)
from holochain_storage.package import StorageError, public_key_bytes

DNA = "uhC0kStorageV2DnaHashForTestsOnly"
OTHER_DNA = "uhC0kSomeOtherStorageDnaForTests"
ALICE, CAROL, MALLORY = "uhCAkAliceTestAgent", "uhCAkCarolTestAgent", "uhCAkMalloryTestAgent"


def record(author: str, body: dict, action: str = "uhCkkAction") -> AuthoredRecord:
    return AuthoredRecord(author, action, body)


class MessageTests(unittest.TestCase):
    def test_exact_length_prefixed_encoding(self):
        fields = [KEY_SCHEMA_V2, DNA, ALICE, OWNER_PURPOSE, "ab" * 32, "1"]
        expected = b"holochain-storage/key-binding-pop/v2\x00" + b"".join(
            struct.pack(">I", len(f.encode())) + f.encode() for f in fields)
        self.assertEqual(key_binding_v2_message(DNA, ALICE, OWNER_PURPOSE, "ab" * 32), expected)
        self.assertTrue(KEY_POP_DOMAIN_V2.endswith(b"\x00"))

    def test_field_boundaries_are_unambiguous(self):
        a = key_binding_v2_message(DNA + "x", ALICE, OWNER_PURPOSE, "ab" * 32)
        b = key_binding_v2_message(DNA, "x" + ALICE, OWNER_PURPOSE, "ab" * 32)
        self.assertNotEqual(a, b)

    def test_domain_differs_from_music_signing_domains(self):
        msg = key_binding_v2_message(DNA, ALICE, OWNER_PURPOSE, "ab" * 32)
        # S1 manifests/receipts sign canonical JSON objects; grants use JSON too.
        self.assertFalse(msg.startswith(b"{"))
        self.assertNotIn(b"holochain-music/", msg[:40])


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.alice_key = Ed25519PrivateKey.generate()
        self.carol_key = Ed25519PrivateKey.generate()
        self.mallory_key = Ed25519PrivateKey.generate()
        self.alice = make_key_binding_v2(self.alice_key, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE)
        self.carol = make_key_binding_v2(self.carol_key, dna_hash=DNA, agent=CAROL, purpose=HOST_PURPOSE)

    def test_a_legitimate_owner_and_j_host(self):
        self.assertEqual(key_for_agent_v2(record(ALICE, self.alice), ALICE, OWNER_PURPOSE, DNA),
                         public_key_bytes(self.alice_key))
        self.assertEqual(key_for_agent_v2(record(CAROL, self.carol), CAROL, HOST_PURPOSE, DNA),
                         public_key_bytes(self.carol_key))

    def test_b_c_mallory_cannot_bind_alices_or_carols_key(self):
        for victim, purpose in ((self.alice, OWNER_PURPOSE), (self.carol, HOST_PURPOSE)):
            stolen = dict(victim, agent=MALLORY)  # copied proof, Mallory's agent
            with self.assertRaisesRegex(StorageError, "proof of possession"):
                key_for_agent_v2(record(MALLORY, stolen), MALLORY, purpose, DNA)
            forged = dict(victim, agent=MALLORY, proof_signature_hex=self.mallory_key.sign(
                key_binding_v2_message(DNA, MALLORY, purpose, victim["signing_key_hex"])).hex())
            with self.assertRaisesRegex(StorageError, "proof of possession"):
                key_for_agent_v2(record(MALLORY, forged), MALLORY, purpose, DNA)

    def test_d_wrong_purpose(self):
        relabelled = dict(self.alice, purpose=HOST_PURPOSE)
        with self.assertRaisesRegex(StorageError, "proof of possession"):
            key_for_agent_v2(record(ALICE, relabelled), ALICE, HOST_PURPOSE, DNA)
        with self.assertRaisesRegex(StorageError, "expected agent/purpose"):
            key_for_agent_v2(record(ALICE, self.alice), ALICE, HOST_PURPOSE, DNA)

    def test_e_wrong_dna_context(self):
        with self.assertRaisesRegex(StorageError, "different DNA"):
            key_for_agent_v2(record(ALICE, self.alice), ALICE, OWNER_PURPOSE, OTHER_DNA)
        moved = dict(self.alice, dna_hash=OTHER_DNA)
        with self.assertRaisesRegex(StorageError, "proof of possession"):
            key_for_agent_v2(record(ALICE, moved), ALICE, OWNER_PURPOSE, OTHER_DNA)

    def test_f_modified_public_key(self):
        swapped = dict(self.alice, signing_key_hex=public_key_bytes(self.mallory_key).hex())
        with self.assertRaisesRegex(StorageError, "proof of possession"):
            key_for_agent_v2(record(ALICE, swapped), ALICE, OWNER_PURPOSE, DNA)

    def test_g_malformed_records(self):
        cases = {
            "missing signature": lambda b: b.pop("proof_signature_hex"),
            "short signature": lambda b: b.update(proof_signature_hex="ab" * 63),
            "uppercase signature": lambda b: b.update(proof_signature_hex=b["proof_signature_hex"].upper()),
            "not hex": lambda b: b.update(proof_signature_hex="zz" * 64),
            "v1 schema": lambda b: b.update(schema=KEY_SCHEMA),
            "unknown purpose": lambda b: b.update(purpose="grant-issuer"),
            "extra field": lambda b: b.update(note="x"),
            "oversized agent": lambda b: b.update(agent="A" * 161),
            "generation 2": lambda b: b.update(generation="2"),
            "numeric generation": lambda b: b.update(generation=1),
            "short key": lambda b: b.update(signing_key_hex="ab" * 31),
        }
        for name, mutate in cases.items():
            body = copy.deepcopy(self.alice)
            mutate(body)
            agent = body.get("agent") if isinstance(body.get("agent"), str) else ALICE
            purpose = body.get("purpose") if body.get("purpose") in (OWNER_PURPOSE, HOST_PURPOSE) else OWNER_PURPOSE
            with self.subTest(name), self.assertRaises(StorageError):
                key_for_agent_v2(record(agent, body), agent, purpose, DNA)

    def test_author_must_match(self):
        with self.assertRaisesRegex(StorageError, "author mismatch"):
            key_for_agent_v2(record(MALLORY, self.alice), ALICE, OWNER_PURPOSE, DNA)

    def test_private_key_never_appears_in_binding(self):
        raw = self.alice_key.private_bytes_raw().hex()
        self.assertNotIn(raw, repr(self.alice))
        self.assertEqual(set(self.alice), {"schema", "dna_hash", "agent", "purpose", "signing_key_hex",
                                           "generation", "proof_signature_hex"})


class ResolutionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.k1, self.k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.v2 = record(ALICE, make_key_binding_v2(self.k1, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE))
        self.v1 = record(ALICE, {"schema": KEY_SCHEMA, "agent": ALICE, "purpose": OWNER_PURPOSE,
                                 "signing_key_hex": public_key_bytes(self.k2).hex()})

    def test_h_duplicates_and_conflicts(self):
        key, level = resolve_signing_key([self.v2, self.v2], ALICE, OWNER_PURPOSE,
                                         require=ASSURANCE_POP_V2, dna_hash=DNA)
        self.assertEqual((key, level), (public_key_bytes(self.k1), ASSURANCE_POP_V2))
        other = record(ALICE, make_key_binding_v2(self.k2, dna_hash=DNA, agent=ALICE, purpose=OWNER_PURPOSE))
        with self.assertRaisesRegex(StorageError, "ambiguous"):
            resolve_signing_key([self.v2, other], ALICE, OWNER_PURPOSE, require=ASSURANCE_POP_V2, dna_hash=DNA)
        with self.assertRaisesRegex(StorageError, "ambiguous"):
            resolve_signing_key([other, self.v2], ALICE, OWNER_PURPOSE, require=ASSURANCE_POP_V2, dna_hash=DNA)

    def test_i_v1_is_never_upgraded_and_v2_never_downgrades(self):
        key, level = resolve_signing_key([self.v1, self.v2], ALICE, OWNER_PURPOSE, require=ASSURANCE_LEGACY_V1)
        self.assertEqual((key, level), (public_key_bytes(self.k2), ASSURANCE_LEGACY_V1))
        with self.assertRaisesRegex(StorageError, "no signing key"):
            resolve_signing_key([self.v1], ALICE, OWNER_PURPOSE, require=ASSURANCE_POP_V2, dna_hash=DNA)
        broken = record(ALICE, dict(self.v2.body, proof_signature_hex="00" * 64))
        with self.assertRaisesRegex(StorageError, "proof of possession"):
            resolve_signing_key([broken, self.v1], ALICE, OWNER_PURPOSE, require=ASSURANCE_POP_V2, dna_hash=DNA)
        with self.assertRaises(StorageError):
            resolve_signing_key([self.v2], ALICE, OWNER_PURPOSE, require="any")
        # The legacy reader keeps working for existing v1 data.
        self.assertEqual(key_for_agent(self.v1, ALICE, OWNER_PURPOSE), public_key_bytes(self.k2))


class FakeV2Bridge:
    """Stand-in for the v2 storage cell. It re-applies the v2 rule so that
    a forged registration is refused; the real rule runs in dna-v2."""

    def __init__(self, agent: str):
        self.whoami = {"agent": agent}
        self.rows: list[AuthoredRecord] = []
        self.calls: list[tuple[str, dict]] = []

    def call(self, op, **args):
        self.calls.append((op, args))
        if op == "key_binding_v2_context":
            return {"schema": KEY_SCHEMA_V2, "dna_hash": DNA, "agent": self.whoami["agent"], "generation": "1"}
        if op == "register_signing_key_v2":
            entry = args["entry"]
            key_for_agent_v2(record(self.whoami["agent"], entry), entry["agent"], entry["purpose"], DNA)
            self.rows.append(record(self.whoami["agent"], entry, f"uhCkk{len(self.rows)}"))
            return {"action_hash": f"uhCkk{len(self.rows)}"}
        raise AssertionError(op)

    def records(self, op, *, agent):
        assert op == "get_signing_keys_v2"
        return [r for r in self.rows if r.author == agent]


class ArtistRegistrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.keys = KeyStore(self.root / "keys")
        self.bridge = FakeV2Bridge(ALICE)
        self.artist = ArtistService(bridge=self.bridge, keys=self.keys, host_root=self.root / "host",
                                    key_binding="v2")

    def test_registers_verified_binding_once_and_sends_no_secret(self):
        public = public_key_bytes(self.keys.artist_ed25519())
        self.artist._ensure_key(OWNER_PURPOSE, public)
        self.artist._ensure_key(OWNER_PURPOSE, public)  # idempotent
        registered = [a for op, a in self.bridge.calls if op == "register_signing_key_v2"]
        self.assertEqual(len(registered), 1)
        secret = self.keys.artist_ed25519().private_bytes_raw().hex()
        self.assertNotIn(secret, repr(self.bridge.calls))
        key, level = resolve_signing_key(self.bridge.rows, ALICE, OWNER_PURPOSE,
                                         require=ASSURANCE_POP_V2, dna_hash=DNA)
        self.assertEqual((key, level), (public, ASSURANCE_POP_V2))
        self.artist._ensure_key(HOST_PURPOSE, public_key_bytes(self.keys.host_ed25519()))
        self.assertEqual(len([1 for op, _ in self.bridge.calls if op == "register_signing_key_v2"]), 2)

    def test_conflicting_existing_key_is_refused(self):
        other = Ed25519PrivateKey.generate()
        self.bridge.rows.append(record(ALICE, make_key_binding_v2(other, dna_hash=DNA, agent=ALICE,
                                                                  purpose=OWNER_PURPOSE)))
        with self.assertRaisesRegex(ArtistError, "different owner-manifest key"):
            self.artist._ensure_key(OWNER_PURPOSE, public_key_bytes(self.keys.artist_ed25519()))

    def test_wrong_cell_agent_and_mismatched_key_are_refused(self):
        self.bridge.whoami = {"agent": ALICE}
        artist = self.artist
        bridge = FakeV2Bridge(ALICE)
        bridge.call = lambda op, **a: {"agent": MALLORY, "dna_hash": DNA} if op == "key_binding_v2_context" else None
        artist.bridge = bridge
        with self.assertRaisesRegex(ArtistError, "agent differs"):
            artist._ensure_key(OWNER_PURPOSE, public_key_bytes(self.keys.artist_ed25519()))
        with self.assertRaisesRegex(ArtistError, "does not match"):
            self.artist._ensure_key(OWNER_PURPOSE, public_key_bytes(Ed25519PrivateKey.generate()))

    def test_default_remains_v1(self):
        artist = ArtistService(bridge=self.bridge, keys=self.keys, host_root=self.root / "h2")
        self.assertEqual(artist.key_binding, "v1")
        with self.assertRaises(ArtistError):
            ArtistService(bridge=self.bridge, keys=self.keys, host_root=self.root / "h3", key_binding="v3")


if __name__ == "__main__":
    unittest.main()
