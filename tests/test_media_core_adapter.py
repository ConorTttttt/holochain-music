"""Opt-in comparison of Music's Python S1/S2 path with Holochain Media Core.

Skipped unless HOLOCHAIN_MEDIA_CORE_BIN points at the `holochain-media-core`
executable (ConorTttttt/holochain-media-core, crates/content-cli). Every case
runs BOTH implementations on the SAME Music-generated package and requires the
same verdict. No production path uses the adapter; these tests only show it is
safe to evaluate. Licence, playback and offline-readiness behaviour are
exercised through Music's unchanged functions reading a Media Core store.
"""
from __future__ import annotations

import io
import math
import os
import struct
import tempfile
import unittest
import wave
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_music.library import Library
from holochain_storage import media_core_adapter as core
from holochain_storage.holochain_identity import (
    FILE_SCHEMA, HOST_PURPOSE, KEY_SCHEMA, OWNER_PURPOSE, REPLICA_SCHEMA, AuthoredRecord,
    verify_owned_manifest, verify_replica_claim,
)
from holochain_storage.package import (
    StorageError, _sign, canonical, create_package, decrypt_package, manifest_digest, object_path,
    public_key_bytes, replicate_package, sha256, verify_package, verify_receipt,
)
from music_catalogue.content_grants import (
    ContentGrantError, issue_personal_licence, unwrap_content_grant,
)
from music_catalogue.granted_audio import play_granted_wav

ENABLED = bool(os.environ.get(core.ENV_BINARY))


def _wav() -> tuple[bytes, bytes]:
    rate = 16000
    pcm = b"".join(struct.pack("<h", int(9000 * math.sin(2 * math.pi * 330 * i / rate)))
                   for i in range(8000))
    out = io.BytesIO()
    with wave.open(out, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return out.getvalue(), pcm


class AdapterDisabledByDefaultTests(unittest.TestCase):
    def test_disabled_without_environment(self):
        saved = os.environ.pop(core.ENV_BINARY, None)
        try:
            self.assertFalse(core.enabled())
            with self.assertRaises(core.MediaCoreUnavailable):
                core.audit_cas({}, b"\0" * 32, "/nonexistent")
        finally:
            if saved is not None:
                os.environ[core.ENV_BINARY] = saved

    def test_relative_or_missing_binary_is_unavailable_not_rejected(self):
        saved = os.environ.get(core.ENV_BINARY)
        try:
            for bad in ("holochain-media-core", "/nonexistent/holochain-media-core"):
                os.environ[core.ENV_BINARY] = bad
                with self.assertRaises(core.MediaCoreUnavailable):
                    core.binary()
        finally:
            if saved is None:
                os.environ.pop(core.ENV_BINARY, None)
            else:
                os.environ[core.ENV_BINARY] = saved


@unittest.skipUnless(ENABLED, f"set {core.ENV_BINARY} to run Media Core comparisons")
class MediaCoreComparisonTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="media-core-adapter-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.artist_pub = public_key_bytes(self.artist)
        self.host = Ed25519PrivateKey.generate()
        self.host_pub = public_key_bytes(self.host)
        self.wav, self.pcm = _wav()
        (self.root / "track.wav").write_bytes(self.wav)
        self.origin = self.root / "origin"
        self.manifest, self.key = create_package(self.root / "track.wav", self.origin, self.artist,
                                                 chunk_size=2048)
        self.receipt = replicate_package(self.manifest, self.origin, self.root / "host",
                                         self.artist_pub, self.host)
        self.owner_agent, self.node_agent = "uhCAkAliceConductorAuthor", "uhCAkCarolConductorAuthor"
        self.listener = "uhCAkBobConductorAuthor"
        file_id, digest = self.manifest["body"]["file_id"], manifest_digest(self.manifest)
        self.records = dict(
            owner_key_binding=AuthoredRecord(self.owner_agent, "uhCkkOwnerKey", {
                "schema": KEY_SCHEMA, "agent": self.owner_agent, "purpose": OWNER_PURPOSE,
                "signing_key_hex": self.artist_pub.hex()}),
            node_key_binding=AuthoredRecord(self.node_agent, "uhCkkNodeKey", {
                "schema": KEY_SCHEMA, "agent": self.node_agent, "purpose": HOST_PURPOSE,
                "signing_key_hex": self.host_pub.hex()}),
            owner_commitment=AuthoredRecord(self.owner_agent, "uhCkkCommit", {
                "schema": FILE_SCHEMA, "owner_agent": self.owner_agent, "file_id": file_id,
                "manifest_sha256": digest}),
            node_claim=AuthoredRecord(self.node_agent, "uhCkkClaim", {
                "schema": REPLICA_SCHEMA, "node_agent": self.node_agent,
                "owner_agent": self.owner_agent, "file_id": file_id, "manifest_sha256": digest,
                "receipt_sha256": sha256(canonical(self.receipt))}),
        )

    def both_identity(self, receipt=None, manifest=None, **records):
        recs = {**self.records, **records}
        receipt = receipt or self.receipt
        manifest = manifest or self.manifest
        python = rust = None
        try:
            verify_owned_manifest(manifest, self.owner_agent, recs["owner_key_binding"],
                                  recs["owner_commitment"])
            verify_replica_claim(receipt, manifest, self.owner_agent, self.node_agent,
                                 recs["owner_key_binding"], recs["node_key_binding"],
                                 recs["owner_commitment"], recs["node_claim"])
            python = True
        except StorageError:
            python = False
        try:
            core.verify_replica_claim(receipt, manifest, self.owner_agent, self.node_agent,
                                      recs["owner_key_binding"], recs["node_key_binding"],
                                      recs["owner_commitment"], recs["node_claim"])
            rust = True
        except core.MediaCoreRejected:
            rust = False
        return python, rust

    # 1-2. Existing S1 package and signatures accepted by both; same digest.
    def test_existing_package_and_signature_accepted_with_identical_digest(self):
        verify_package(self.manifest, self.origin, self.artist_pub)
        result = core.verify_manifest(self.manifest, self.artist_pub, manifest_digest(self.manifest))
        self.assertEqual(result["manifest_sha256"], manifest_digest(self.manifest))
        self.assertEqual(result["file_id"], self.manifest["body"]["file_id"])
        self.assertEqual(result["chunk_count"], len(self.manifest["body"]["chunks"]))
        self.assertEqual(result["total_plain_bytes"], len(self.wav))

    def test_tampered_or_wrong_signer_manifest_rejected_by_both(self):
        tampered = {**self.manifest, "body": {**self.manifest["body"], "chunk_size": 4096}}
        other = Ed25519PrivateKey.generate()
        resigned = _sign(self.manifest["body"], other)
        for bad, key in ((tampered, self.artist_pub), (resigned, self.artist_pub),
                         (self.manifest, public_key_bytes(other))):
            with self.assertRaises(StorageError):
                verify_package(bad, self.origin, key)
            with self.assertRaises(core.MediaCoreRejected) as caught:
                core.verify_manifest(bad, key)
            self.assertEqual(caught.exception.boundary, "s1-manifest")
        with self.assertRaises(core.MediaCoreRejected) as caught:
            core.verify_manifest(self.manifest, self.artist_pub, "00" * 32)
        self.assertEqual(caught.exception.boundary, "manifest-digest-pin")

    # 3. Existing artist and host identities verified identically.
    def test_receipt_and_s2_bindings_agree(self):
        verify_receipt(self.receipt, self.manifest, self.host_pub, self.artist_pub)
        rust = core.verify_receipt(self.receipt, self.manifest, self.host_pub, self.artist_pub)
        self.assertEqual(rust["receipt_sha256"], sha256(canonical(self.receipt)))
        self.assertEqual(self.both_identity(), (True, True))
        mallory = "uhCAkMalloryConductorAuthor"
        forged_key = AuthoredRecord(mallory, "uhCkkForged", {
            **self.records["owner_key_binding"].body})
        wrong_purpose = AuthoredRecord(self.node_agent, "uhCkkNodeKey", {
            **self.records["node_key_binding"].body, "purpose": OWNER_PURPOSE})
        wrong_claim = AuthoredRecord(self.node_agent, "uhCkkClaim", {
            **self.records["node_claim"].body, "receipt_sha256": "00" * 32})
        wrong_commit = AuthoredRecord(self.owner_agent, "uhCkkCommit", {
            **self.records["owner_commitment"].body, "manifest_sha256": "11" * 32})
        forged_receipt = _sign(self.receipt["body"], Ed25519PrivateKey.generate())
        for case, kwargs in {
            "owner key authored by another agent": dict(owner_key_binding=forged_key),
            "host key bound for the wrong purpose": dict(node_key_binding=wrong_purpose),
            "claim commits to another receipt": dict(node_claim=wrong_claim),
            "commitment pins another manifest": dict(owner_commitment=wrong_commit),
        }.items():
            self.assertEqual(self.both_identity(**kwargs), (False, False), case)
        self.assertEqual(self.both_identity(receipt=forged_receipt), (False, False))

    # 4-5, 8. Ciphertext stored/retrieved; corruption rejected; readiness.
    def test_import_into_library_cas_keeps_offline_readiness_accurate(self):
        library = Library(self.root / "library")
        file_id = self.manifest["body"]["file_id"]
        library.add(manifest=self.manifest, meta={
            "manifest_sha256": manifest_digest(self.manifest),
            "artist_key_hex": self.artist_pub.hex(), "title": "adapter fixture"})
        self.assertFalse(library.verify_complete(file_id))
        before = core.audit_cas(self.manifest, self.artist_pub, library.cas)["store"]
        self.assertFalse(before["offline_ready"])
        imported = core.import_into_cas(self.manifest, self.artist_pub, self.origin, library.cas)
        n = len(self.manifest["body"]["chunks"])
        self.assertEqual((imported["imported"], imported["store"]["verified"]), (n, n))
        # Music's own readiness check agrees with Media Core's audit.
        self.assertTrue(library.verify_complete(file_id))
        self.assertEqual(library.present_chunks(self.manifest), set(range(n)))
        again = core.import_into_cas(self.manifest, self.artist_pub, self.origin, library.cas)
        self.assertEqual((again["imported"], again["already_verified"]), (0, n))
        # Same-length corruption: both report not-ready, Media Core counts it.
        chunk = self.manifest["body"]["chunks"][2]
        path = object_path(library.cas, chunk["sha256"])
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(bytes(data))
        self.assertFalse(library.verify_complete(file_id))
        audit = core.audit_cas(self.manifest, self.artist_pub, library.cas)["store"]
        self.assertEqual((audit["corrupt"], audit["offline_ready"]), (1, False))
        # Repair only from a verified source.
        core.import_into_cas(self.manifest, self.artist_pub, self.origin, library.cas)
        self.assertTrue(library.verify_complete(file_id))

    def test_corrupt_or_truncated_source_chunk_is_never_imported(self):
        chunk = self.manifest["body"]["chunks"][1]
        path = object_path(self.origin, chunk["sha256"])
        path.write_bytes(path.read_bytes()[:-1])
        cas = self.root / "cas"
        with self.assertRaises(core.MediaCoreRejected) as caught:
            core.import_into_cas(self.manifest, self.artist_pub, self.origin, cas)
        self.assertEqual(caught.exception.result["failed_index"], 1)
        self.assertEqual(caught.exception.result["store"]["missing"],
                         len(self.manifest["body"]["chunks"]) - 1)
        with self.assertRaises(StorageError):
            verify_package(self.manifest, self.origin, self.artist_pub)
        self.assertFalse(object_path(cas, chunk["sha256"]).exists())

    # 6-7. Licence handling and playback unchanged when reading a Core store.
    def test_licence_decrypt_and_pcm_playback_from_media_core_store(self):
        bob = X25519PrivateKey.generate()
        bob_pub = bob.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        licence = issue_personal_licence(
            owner_signer=self.artist, owner_agent=self.owner_agent, listener_agent=self.listener,
            recipient_public=bob_pub, signed_manifest=self.manifest, content_key=self.key)
        cas = self.root / "cas"
        core.import_into_cas(self.manifest, self.artist_pub, self.origin, cas)
        results = {}
        for label, store in (("python-store", self.origin), ("media-core-cas", cas)):
            sink = []
            report = play_granted_wav(
                signed_manifest=self.manifest, ciphertext_store=store, grant=licence,
                trusted_artist=self.artist_pub, owner_agent=self.owner_agent,
                listener_agent=self.listener, recipient_private=bob, pcm_sink=sink.append)
            self.assertEqual(b"".join(sink), self.pcm, label)
            results[label] = report["pcm_sha256"]
            out = self.root / f"{label}.wav"
            decrypt_package(self.manifest, store, out,
                            unwrap_content_grant(
                                licence, trusted_artist=self.artist_pub,
                                owner_agent=self.owner_agent, listener_agent=self.listener,
                                recipient_private=bob, signed_manifest=self.manifest),
                            self.artist_pub)
            self.assertEqual(out.read_bytes(), self.wav, label)
        self.assertEqual(results["python-store"], results["media-core-cas"])
        # Ciphertext availability in the Core store does not authorise access.
        with self.assertRaises(ContentGrantError):
            unwrap_content_grant(licence, trusted_artist=self.artist_pub,
                                 owner_agent=self.owner_agent, listener_agent=self.listener,
                                 recipient_private=X25519PrivateKey.generate(),
                                 signed_manifest=self.manifest)

    def test_adapter_interface_accepts_no_secret_material(self):
        # The CLI has no flag for keys/grants; an unknown flag is a usage
        # failure (MediaCoreUnavailable), never a verification result.
        with self.assertRaises(core.MediaCoreUnavailable):
            core._run(["audit", "--content-key", self.key.hex()])


if __name__ == "__main__":
    unittest.main()
