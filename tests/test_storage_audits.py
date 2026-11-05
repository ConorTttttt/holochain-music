"""S3: adversarial ciphertext audit, replay and replica repair tests."""

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import (
    AuditVerifier, StorageError, answer_challenge, create_package,
    create_perpetual_grant, decrypt_package, make_challenge,
    open_perpetual_grant, repair_full_replica, replicate_package,
    verify_challenge_response, verify_package, verify_receipt,
)
from holochain_storage.package import _sign, b64, object_path


class AuditAndRepairTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.artist = Ed25519PrivateKey.generate()
        self.node = Ed25519PrivateKey.generate()
        self.node_b = Ed25519PrivateKey.generate()
        self.attacker = Ed25519PrivateKey.generate()
        self.artist_pk = self.artist.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.node_pk = self.node.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.node_b_pk = self.node_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.file = self.root / 'song.ogg'
        self.content = b'Copyrighted song bytes omitted; these are arbitrary test bytes.\x00' * 80
        self.file.write_bytes(self.content)
        self.owner = self.root / 'owner'
        self.host_a = self.root / 'host_a'
        self.host_b = self.root / 'host_b'
        self.package, self.key = create_package(self.file, self.owner, self.artist, chunk_size=119)
        self.receipt_a = replicate_package(self.package, self.owner, self.host_a, self.artist_pk, self.node)
        self.receipt_b = replicate_package(self.package, self.owner, self.host_b, self.artist_pk, self.node_b)

    def _audit(self, *, host=None, node=None, pk=None, now=1000, count=4, ttl=60):
        target = host or self.host_a
        node = node or self.node
        pk = pk or self.node_pk
        verifier = AuditVerifier()
        c = verifier.issue(self.package, self.artist_pk, pk, now=now, sample_count=count, ttl_seconds=ttl)
        r = answer_challenge(c, self.package, target, self.artist_pk, node)
        return verifier, c, r

    def test_valid_response_is_signed_and_one_time(self):
        verifier, c, r = self._audit()
        result = verifier.verify(c, r, self.package, self.artist_pk, self.node_pk, now=1001)
        self.assertEqual(result.sampled_chunks, 4)
        self.assertEqual(result.manifest_sha256, c['manifest_sha256'])
        with self.assertRaisesRegex(StorageError, 'already-used'):
            verifier.verify(c, r, self.package, self.artist_pk, self.node_pk, now=1002)

    def test_new_challenge_has_unpredictable_nonce(self):
        c1 = make_challenge(self.package, self.artist_pk, self.node_pk, now=1000)
        c2 = make_challenge(self.package, self.artist_pk, self.node_pk, now=1000)
        self.assertNotEqual(c1['nonce'], c2['nonce'])

    def test_response_replay_for_different_challenge_rejected(self):
        verifier, c1, r1 = self._audit()
        c2 = verifier.issue(self.package, self.artist_pk, self.node_pk, now=1001)
        with self.assertRaisesRegex(StorageError, 'does not match challenge'):
            verifier.verify(c2, r1, self.package, self.artist_pk, self.node_pk, now=1002)
        self.assertEqual(verifier.verify(c1, r1, self.package, self.artist_pk, self.node_pk, now=1002).sampled_chunks, 4)

    def test_wrong_signer_rejected(self):
        verifier, c, r = self._audit()
        forged = _sign(r['body'], self.attacker)
        with self.assertRaisesRegex(StorageError, 'untrusted'):
            verifier.verify(c, forged, self.package, self.artist_pk, self.node_pk, now=1001)

    def test_target_node_mismatch_rejected(self):
        c = make_challenge(self.package, self.artist_pk, self.node_pk, now=1000)
        with self.assertRaisesRegex(StorageError, 'different node'):
            answer_challenge(c, self.package, self.host_b, self.artist_pk, self.node_b)

    def test_modified_nonce_rejected_even_for_valid_response(self):
        verifier, c, r = self._audit()
        changed = copy.deepcopy(c)
        changed['nonce'] = b64(bytes([88])*32)
        with self.assertRaisesRegex(StorageError, 'unknown'):
            verifier.verify(changed, r, self.package, self.artist_pk, self.node_pk, now=1001)

    def test_expired_challenge_rejected(self):
        verifier, c, r = self._audit(ttl=5)
        with self.assertRaisesRegex(StorageError, 'expired'):
            verifier.verify(c, r, self.package, self.artist_pk, self.node_pk, now=1006)

    def test_not_yet_active_rejected(self):
        verifier, c, r = self._audit(now=1000)
        with self.assertRaisesRegex(StorageError, 'not yet active'):
            verifier.verify(c, r, self.package, self.artist_pk, self.node_pk, now=999)

    def test_tampered_sample_detected_even_when_node_signs(self):
        verifier, c, r = self._audit()
        altered = copy.deepcopy(r['body'])
        altered['samples'][0]['ciphertext'] = b64(b'corrupt')
        forged_by_node = _sign(altered, self.node)
        with self.assertRaises(StorageError):
            verifier.verify(c, forged_by_node, self.package, self.artist_pk, self.node_pk, now=1001)

    def test_missing_sample_rejected(self):
        verifier, c, r = self._audit()
        altered = copy.deepcopy(r['body'])
        altered['samples'].pop()
        with self.assertRaisesRegex(StorageError, 'wrong audit sample count'):
            verifier.verify(c, _sign(altered, self.node), self.package, self.artist_pk, self.node_pk, now=1001)

    def test_wrong_sample_index_rejected(self):
        verifier, c, r = self._audit()
        altered = copy.deepcopy(r['body'])
        altered['samples'][0]['index'] += 1
        with self.assertRaisesRegex(StorageError, 'wrong audit sample position'):
            verifier.verify(c, _sign(altered, self.node), self.package, self.artist_pk, self.node_pk, now=1001)

    def test_out_of_order_sample_indices_rejected(self):
        verifier, c, r = self._audit()
        forged = copy.deepcopy(c)
        forged['indices'] = forged['indices'][::-1]
        with self.assertRaises(StorageError):
            verifier.verify(forged, r, self.package, self.artist_pk, self.node_pk, now=1001)

    def test_corrupt_or_missing_requested_ciphertext_fails_node_response(self):
        c = make_challenge(self.package, self.artist_pk, self.node_pk, sample_count=1, now=1000)
        chunk = self.package['body']['chunks'][c['indices'][0]]
        object_path(self.host_a, chunk['sha256']).unlink()
        with self.assertRaisesRegex(StorageError, 'missing chunk'):
            answer_challenge(c, self.package, self.host_a, self.artist_pk, self.node)

    def test_receipt_not_proof_of_availability(self):
        verify_receipt(self.receipt_a, self.package, self.node_pk, self.artist_pk)
        c = make_challenge(self.package, self.artist_pk, self.node_pk, sample_count=1, now=1000)
        chunk = self.package['body']['chunks'][c['indices'][0]]
        object_path(self.host_a, chunk['sha256']).unlink()
        with self.assertRaises(StorageError):
            answer_challenge(c, self.package, self.host_a, self.artist_pk, self.node)
        # Receipt still verifies: it recorded prior acceptance only.
        verify_receipt(self.receipt_a, self.package, self.node_pk, self.artist_pk)

    def test_missing_chunk_repair_creates_fresh_receipt(self):
        damaged = self.package['body']['chunks'][2]
        object_path(self.host_a, damaged['sha256']).unlink()
        repaired = repair_full_replica(self.package, [self.host_b], self.host_a, self.artist_pk, self.node)
        self.assertEqual(repaired.missing_repaired, 1)
        self.assertEqual(repaired.corrupt_replaced, 0)
        verify_receipt(repaired.receipt, self.package, self.node_pk, self.artist_pk)
        verify_package(self.package, self.host_a, self.artist_pk)

    def test_corrupt_chunk_repair_from_second_replica(self):
        damaged = self.package['body']['chunks'][2]
        object_path(self.host_a, damaged['sha256']).write_bytes(b'garbage')
        repaired = repair_full_replica(self.package, [self.host_b], self.host_a, self.artist_pk, self.node)
        self.assertEqual(repaired.corrupt_replaced, 1)
        verify_package(self.package, self.host_a, self.artist_pk)

    def test_repair_rejects_invalid_source_and_uses_next(self):
        damaged = self.package['body']['chunks'][2]
        object_path(self.host_b, damaged['sha256']).unlink()
        object_path(self.host_a, damaged['sha256']).unlink()
        repaired = repair_full_replica(self.package, [self.host_b, self.owner], self.host_a, self.artist_pk, self.node)
        self.assertEqual(repaired.source, str(self.owner))
        self.assertEqual(repaired.missing_repaired, 1)

    def test_repair_cannot_use_damaged_source_or_destination_as_source(self):
        damaged = self.package['body']['chunks'][2]
        object_path(self.host_b, damaged['sha256']).unlink()
        object_path(self.owner, damaged['sha256']).unlink()
        object_path(self.host_a, damaged['sha256']).unlink()
        with self.assertRaisesRegex(StorageError, 'no independently verified source'):
            repair_full_replica(self.package, [self.host_a, self.host_b, self.owner], self.host_a, self.artist_pk, self.node)

    def test_repair_refuses_symlinked_destination(self):
        damaged = self.package['body']['chunks'][2]
        target = object_path(self.host_a, damaged['sha256'])
        target.unlink()
        target.symlink_to(self.file)
        with self.assertRaisesRegex(StorageError, 'symlinked'):
            repair_full_replica(self.package, [self.host_b], self.host_a, self.artist_pk, self.node)
        self.assertEqual(self.file.read_bytes(), self.content)

    def test_empty_file_cannot_pretend_to_be_audited(self):
        empty = self.root / 'zero'
        empty.write_bytes(b'')
        p, _ = create_package(empty, self.root/'zero-store', self.artist)
        with self.assertRaisesRegex(StorageError, 'empty packages'):
            make_challenge(p, self.artist_pk, self.node_pk)

    def test_rejects_invalid_sampling_parameters(self):
        with self.assertRaises(StorageError):
            make_challenge(self.package, self.artist_pk, self.node_pk, ttl_seconds=0)
        with self.assertRaises(StorageError):
            make_challenge(self.package, self.artist_pk, self.node_pk, sample_count=999)
        with self.assertRaises(StorageError):
            make_challenge(self.package, self.artist_pk, self.node_pk, sample_count=True)

    def test_offline_buyer_after_audit_failure_and_repair(self):
        buyer = X25519PrivateKey.generate()
        buyer_pk = buyer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        grant = create_perpetual_grant(self.package, self.artist_pk, self.artist, self.key, buyer_pk)
        buyer_key = open_perpetual_grant(grant, self.package, self.artist_pk, buyer)
        damaged = self.package['body']['chunks'][4]
        object_path(self.host_a, damaged['sha256']).unlink()
        # Verify the missing chunk fails, then repair using an independent full copy.
        with self.assertRaises(StorageError):
            verify_package(self.package, self.host_a, self.artist_pk)
        repair_full_replica(self.package, [self.host_b], self.host_a, self.artist_pk, self.node)
        verifier, c, r = self._audit(host=self.host_a, node=self.node, pk=self.node_pk)
        verifier.verify(c, r, self.package, self.artist_pk, self.node_pk, now=1001)
        # Owner goes away: independent buyer export must continue to work.
        for item in self.owner.rglob('*'):
            if item.is_file():
                item.unlink()
        path = decrypt_package(self.package, self.host_a, self.root / 'owned-song.flac', buyer_key, self.artist_pk)
        self.assertEqual(path.read_bytes(), self.content)


if __name__ == '__main__':
    unittest.main()
