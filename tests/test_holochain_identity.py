"""S2 binding contract tests: conductor-provided author must match every claim.

These test verification logic and adversarial cases, not conductor gossip or
Holochain action verification. Those require separate two-conductor tests.
"""

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import StorageError, create_package, replicate_package, canonical, manifest_digest, sha256
from holochain_storage.holochain_identity import (
    AuthoredRecord, KEY_SCHEMA, FILE_SCHEMA, REPLICA_SCHEMA, OWNER_PURPOSE, HOST_PURPOSE,
    key_for_agent, verify_owned_manifest, verify_replica_claim,
)


def pubhex(priv):
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class IdentityBindingTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)
        src = self.base / 'file.txt'
        src.write_bytes(b'file-independent content' * 50)
        self.owner, self.node, self.eve = (Ed25519PrivateKey.generate() for _ in range(3))
        self.owner_agent = 'uhCAkAliceValidatedByConductor'
        self.node_agent = 'uhCAkBobValidatedByConductor'
        self.eve_agent = 'uhCAkEveValidatedByConductor'
        self.pkg, _ = create_package(src, self.base / 'owner', self.owner)
        self.receipt = replicate_package(self.pkg, self.base / 'owner', self.base / 'node',
                                         bytes.fromhex(pubhex(self.owner)), self.node)
        self.owner_key = AuthoredRecord(self.owner_agent, 'action:o:key', {
            'schema': KEY_SCHEMA, 'agent': self.owner_agent, 'purpose': OWNER_PURPOSE,
            'signing_key_hex': pubhex(self.owner),
        })
        self.node_key = AuthoredRecord(self.node_agent, 'action:n:key', {
            'schema': KEY_SCHEMA, 'agent': self.node_agent, 'purpose': HOST_PURPOSE,
            'signing_key_hex': pubhex(self.node),
        })
        self.commit = AuthoredRecord(self.owner_agent, 'action:o:commit', {
            'schema': FILE_SCHEMA, 'owner_agent': self.owner_agent,
            'file_id': self.pkg['body']['file_id'], 'manifest_sha256': manifest_digest(self.pkg),
        })
        self.claim = AuthoredRecord(self.node_agent, 'action:n:claim', {
            'schema': REPLICA_SCHEMA, 'node_agent': self.node_agent, 'owner_agent': self.owner_agent,
            'file_id': self.pkg['body']['file_id'], 'manifest_sha256': manifest_digest(self.pkg),
            'receipt_sha256': sha256(canonical(self.receipt)),
        })

    def test_owner_and_node_claims_authenticate(self):
        self.assertEqual(verify_owned_manifest(self.pkg, self.owner_agent, self.owner_key, self.commit)['file_id'],
                         self.pkg['body']['file_id'])
        self.assertEqual(verify_replica_claim(self.receipt, self.pkg, self.owner_agent,
                          self.node_agent, self.owner_key, self.node_key, self.commit, self.claim)['chunk_count'],
                         len(self.pkg['body']['chunks']))

    def test_forged_owner_action_rejected(self):
        tampered = AuthoredRecord(self.eve_agent, 'action:e:key', self.owner_key.body)
        with self.assertRaisesRegex(StorageError, 'author mismatch'):
            verify_owned_manifest(self.pkg, self.owner_agent, tampered, self.commit)

    def test_self_declared_key_not_authoritatively_bound(self):
        forged = AuthoredRecord(self.owner_agent, 'action:e:key', {
            **self.owner_key.body, 'agent': self.node_agent,
        })
        with self.assertRaisesRegex(StorageError, 'not bound'):
            key_for_agent(forged, self.owner_agent, OWNER_PURPOSE)

    def test_key_purpose_mismatch_rejected(self):
        with self.assertRaisesRegex(StorageError, 'not bound'):
            key_for_agent(self.owner_key, self.owner_agent, HOST_PURPOSE)

    def test_forged_storage_node_authorship_rejected(self):
        altered = AuthoredRecord(self.eve_agent, self.claim.action_hash, self.claim.body)
        with self.assertRaisesRegex(StorageError, 'author mismatch'):
            verify_replica_claim(self.receipt, self.pkg, self.owner_agent, self.node_agent,
                                 self.owner_key, self.node_key, self.commit, altered)

    def test_manifest_swap_rejected(self):
        other = self.base / 'other.txt'
        other.write_bytes(b'another file')
        other_pkg, _ = create_package(other, self.base / 'owner', self.owner)
        with self.assertRaisesRegex(StorageError, 'does not match'):
            verify_owned_manifest(other_pkg, self.owner_agent, self.owner_key, self.commit)

    def test_receipt_swap_rejected(self):
        tampered = copy.deepcopy(self.receipt)
        tampered['body']['chunk_count'] += 1
        with self.assertRaises(StorageError):
            verify_replica_claim(tampered, self.pkg, self.owner_agent, self.node_agent,
                                 self.owner_key, self.node_key, self.commit, self.claim)

    def test_claim_digest_mismatch_rejected(self):
        forged = AuthoredRecord(self.node_agent, 'action:n:claim', {
            **self.claim.body, 'receipt_sha256': 'a'*64,
        })
        with self.assertRaisesRegex(StorageError, 'claim does not match'):
            verify_replica_claim(self.receipt, self.pkg, self.owner_agent, self.node_agent,
                                 self.owner_key, self.node_key, self.commit, forged)

    def test_hex_field_validation(self):
        forged = AuthoredRecord(self.owner_agent, 'action:key', {
            **self.owner_key.body, 'signing_key_hex': 'invalid',
        })
        with self.assertRaisesRegex(StorageError, '32-byte hex'):
            key_for_agent(forged, self.owner_agent, OWNER_PURPOSE)

    def test_extra_key_material_in_record_rejected(self):
        forged = AuthoredRecord(self.owner_agent, 'action:key', {
            **self.owner_key.body, 'secret': 'should not exist',
        })
        with self.assertRaisesRegex(StorageError, 'invalid Holochain'):
            key_for_agent(forged, self.owner_agent, OWNER_PURPOSE)

    def test_missing_holochain_action_hash_rejected(self):
        forged = AuthoredRecord(self.owner_agent, '', self.owner_key.body)
        with self.assertRaisesRegex(StorageError, 'author mismatch'):
            key_for_agent(forged, self.owner_agent, OWNER_PURPOSE)

    def test_unrelated_signing_key_rejected_even_if_same_agent(self):
        forged = AuthoredRecord(self.owner_agent, 'action:key', {
            **self.owner_key.body, 'signing_key_hex': pubhex(self.eve),
        })
        with self.assertRaisesRegex(StorageError, 'untrusted manifest signer'):
            verify_owned_manifest(self.pkg, self.owner_agent, forged, self.commit)


if __name__ == '__main__':
    unittest.main()
