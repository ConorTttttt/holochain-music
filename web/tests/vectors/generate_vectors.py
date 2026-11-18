#!/usr/bin/env python3
"""Generate browser compatibility vectors from the NATIVE Python v1 code.

Every vector is produced by, and every expected verdict is confirmed against,
the unchanged desktop implementation (holochain_storage.package,
holochain_storage.holochain_identity, music_catalogue.content_grants). The
browser test-suite then asserts identical accept/reject decisions and bytes.

TEST-ONLY KEY MATERIAL: the vectors deliberately contain throwaway private
keys and content keys so that browser code can be exercised. They are
generated fresh, never derived from a user key, and must never be reused.

Usage: python3 web/tests/vectors/generate_vectors.py OUT.json
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat  # noqa: E402

from holochain_storage import package as pkg  # noqa: E402
from holochain_storage.holochain_identity import AuthoredRecord, verify_replica_claim  # noqa: E402
from music_catalogue import content_grants as cg  # noqa: E402
from music_catalogue.contract import CatalogueError, validate_track  # noqa: E402

OWNER_AGENT = "uhCAk" + "A" * 48
LISTENER_AGENT = "uhCAk" + "B" * 48
OTHER_LISTENER = "uhCAk" + "C" * 48
NODE_AGENT = "uhCAk" + "D" * 48


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def x25519_jwk(private: X25519PrivateKey) -> dict:
    raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "X25519", "d": b64url(raw), "x": b64url(pub)}


def pub_raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def wav_bytes(seconds: float = 0.25, rate: int = 8000, channels: int = 1) -> bytes:
    frames = int(seconds * rate)
    data = bytes((i * 7) % 256 for i in range(frames * channels * 2))
    header = (b"RIFF" + (36 + len(data)).to_bytes(4, "little") + b"WAVEfmt "
              + (16).to_bytes(4, "little") + (1).to_bytes(2, "little") + channels.to_bytes(2, "little")
              + rate.to_bytes(4, "little") + (rate * channels * 2).to_bytes(4, "little")
              + (channels * 2).to_bytes(2, "little") + (16).to_bytes(2, "little")
              + b"data" + len(data).to_bytes(4, "little"))
    return header + data


def python_unwrap(grant, **kw) -> tuple[bool, str | None, str | None]:
    try:
        key = cg.unwrap_content_grant(grant, **kw)
        return True, key.hex(), None
    except cg.ContentGrantError as exc:
        return False, None, str(exc)


def main(out: Path) -> None:
    work = Path(tempfile.mkdtemp(prefix="hm-web-vectors-"))
    artist = Ed25519PrivateKey.generate()
    other_artist = Ed25519PrivateKey.generate()
    node = Ed25519PrivateKey.generate()
    listener_x = X25519PrivateKey.generate()
    other_x = X25519PrivateKey.generate()

    audio = wav_bytes()
    src = work / "tone.wav"
    src.write_bytes(audio)
    store = work / "store"
    # Small chunks so the vector exercises several AES-GCM objects.
    manifest, content_key = pkg.create_package(src, store, artist, chunk_size=1024)
    body = manifest["body"]
    digest = pkg.manifest_digest(manifest)
    chunks = [b64(pkg._read_verified_chunk(store, c)) for c in body["chunks"]]

    # A second package from the same artist: a valid grant for it must never
    # unlock the first file.
    src2 = work / "other.wav"
    src2.write_bytes(wav_bytes(0.1))
    other_manifest, _ = pkg.create_package(src2, work / "store2", artist, chunk_size=1024)

    receipt = pkg.replicate_package(manifest, store, work / "replica", pub_raw(artist), node)

    def rec(author, body_, h="uhCkkHASH"):
        return AuthoredRecord(author=author, action_hash=h, body=body_)

    owner_binding = {"schema": "holochain-storage/key-binding/v1", "agent": OWNER_AGENT,
                     "purpose": "owner-manifest", "signing_key_hex": pub_raw(artist).hex()}
    node_binding = {"schema": "holochain-storage/key-binding/v1", "agent": NODE_AGENT,
                    "purpose": "host-receipt", "signing_key_hex": pub_raw(node).hex()}
    commitment = {"schema": "holochain-storage/file-commitment/v1", "owner_agent": OWNER_AGENT,
                  "file_id": body["file_id"], "manifest_sha256": digest}
    claim = {"schema": "holochain-storage/replica-claim/v1", "node_agent": NODE_AGENT, "owner_agent": OWNER_AGENT,
             "file_id": body["file_id"], "manifest_sha256": digest,
             "receipt_sha256": pkg.sha256(pkg.canonical(receipt))}
    verify_replica_claim(receipt, manifest, OWNER_AGENT, NODE_AGENT, rec(OWNER_AGENT, owner_binding),
                         rec(NODE_AGENT, node_binding), rec(OWNER_AGENT, commitment), rec(NODE_AGENT, claim))

    track = {"schema": "holochain-music/track/v1", "artist_agent": OWNER_AGENT, "track_id": "1" * 32,
             "album_id": None, "title": "Vector Tone", "duration_ms": 250, "disc_number": 1, "track_number": 1,
             "audio_format": "audio/wav", "file_id": body["file_id"], "manifest_sha256": digest,
             "rights_basis": "original_owner"}
    validate_track(track, author=OWNER_AGENT)
    track_cases = [{"name": "valid", "track": track, "author": OWNER_AGENT, "valid": True}]
    for name, mutate, author in [
        ("wrong-author", {}, LISTENER_AGENT),
        ("title-leading-space", {"title": " Tone"}, OWNER_AGENT),
        ("title-trailing-nbsp", {"title": "Tone "}, OWNER_AGENT),
        ("title-file-separator", {"title": "Tone\x1c"}, OWNER_AGENT),
        ("title-bom-is-not-python-space", {"title": "﻿Tone"}, OWNER_AGENT),
        ("title-unicode", {"title": "Tōne – 東京 😀"}, OWNER_AGENT),
        ("uppercase-file-id", {"file_id": body["file_id"].upper()}, OWNER_AGENT),
        ("bool-duration", {"duration_ms": True}, OWNER_AGENT),
        ("zero-duration", {"duration_ms": 0}, OWNER_AGENT),
        ("bad-format", {"audio_format": "application/zip"}, OWNER_AGENT),
        ("extra-field", {"extra": 1}, OWNER_AGENT),
    ]:
        t = {**track, **mutate}
        try:
            validate_track(t, author=author)
            ok = True
        except CatalogueError:
            ok = False
        track_cases.append({"name": name, "track": t, "author": author, "valid": ok})

    now = int(time.time())
    stream = cg.issue_content_grant(owner_signer=artist, owner_agent=OWNER_AGENT, listener_agent=LISTENER_AGENT,
                                    recipient_public=pub_raw(listener_x), signed_manifest=manifest,
                                    content_key=content_key, lifetime_seconds=3600)
    licence = cg.issue_personal_licence(owner_signer=artist, owner_agent=OWNER_AGENT, listener_agent=LISTENER_AGENT,
                                        recipient_public=pub_raw(listener_x), signed_manifest=manifest,
                                        content_key=content_key)
    other_grant = cg.issue_content_grant(owner_signer=artist, owner_agent=OWNER_AGENT, listener_agent=LISTENER_AGENT,
                                         recipient_public=pub_raw(listener_x), signed_manifest=other_manifest,
                                         content_key=os.urandom(32), lifetime_seconds=3600)
    forged_by_other = cg.issue_content_grant(owner_signer=other_artist, owner_agent=OWNER_AGENT,
                                             listener_agent=LISTENER_AGENT, recipient_public=pub_raw(listener_x),
                                             signed_manifest=_resign(manifest, other_artist),
                                             content_key=content_key, lifetime_seconds=3600)
    for_other_listener = cg.issue_content_grant(owner_signer=artist, owner_agent=OWNER_AGENT,
                                                listener_agent=OTHER_LISTENER, recipient_public=pub_raw(other_x),
                                                signed_manifest=manifest, content_key=content_key,
                                                lifetime_seconds=3600)

    def resign_body(grant, signer=artist):
        g = copy.deepcopy(grant)
        g["signature"] = b64(signer.sign(pkg.canonical(g["body"])))
        return g

    def mutate(grant, **fields):
        g = copy.deepcopy(grant)
        g["body"].update(fields)
        return g

    tampered_wrapped = copy.deepcopy(stream)
    wk = bytearray(base64.b64decode(tampered_wrapped["body"]["wrapped_key_b64"]))
    wk[0] ^= 1
    tampered_wrapped["body"]["wrapped_key_b64"] = b64(bytes(wk))
    # Artist-signed but with corrupted ciphertext: signature OK, GCM must fail.
    resigned_corrupt = resign_body(tampered_wrapped)

    expired = resign_body(mutate(stream, issued_at=now - 7200, expires_at=now - 3600))
    future = resign_body(mutate(stream, issued_at=now + 3600, expires_at=now + 7200))
    too_long = resign_body(mutate(stream, expires_at=stream["body"]["issued_at"] + 86401))
    v2 = resign_body(mutate(stream, schema="holochain-music/content-grant/v2"))
    bad_terms = resign_body(mutate(licence, terms="commercial"))
    swapped_signature = copy.deepcopy(stream)
    swapped_signature["signature"] = licence["signature"]

    listener_kw = dict(trusted_artist=pub_raw(artist), owner_agent=OWNER_AGENT, listener_agent=LISTENER_AGENT,
                       recipient_private=listener_x, signed_manifest=manifest)
    grant_cases = []

    def case(name, grant, recipient="listener", listener=LISTENER_AGENT, owner=OWNER_AGENT,
             trusted=None, manifest_doc=None):
        kw = dict(listener_kw)
        kw["recipient_private"] = listener_x if recipient == "listener" else other_x
        kw["listener_agent"] = listener
        kw["owner_agent"] = owner
        if trusted is not None:
            kw["trusted_artist"] = trusted
        if manifest_doc is not None:
            kw["signed_manifest"] = manifest_doc
        ok, key, err = python_unwrap(grant, **kw)
        grant_cases.append({
            "name": name, "grant": grant, "recipient": recipient, "listener_agent": listener,
            "owner_agent": owner, "trusted_artist_hex": kw["trusted_artist"].hex(),
            "manifest": "primary" if kw["signed_manifest"] is manifest else "other",
            "python_valid": ok, "python_key_hex": key, "python_error": err,
        })

    case("stream-valid", stream)
    case("licence-valid", licence)
    case("duplicate-delivery-same-grant", copy.deepcopy(stream))
    case("wrong-recipient-key", stream, recipient="other")
    case("wrong-listener-agent", stream, listener=OTHER_LISTENER)
    case("cross-listener-grant-reuse", for_other_listener)
    case("cross-listener-grant-reuse-with-their-identity", for_other_listener, listener=OTHER_LISTENER)
    case("wrong-owner-agent", stream, owner=LISTENER_AGENT)
    case("forged-by-other-artist", forged_by_other)
    case("trusting-wrong-artist-key", stream, trusted=pub_raw(other_artist))
    case("grant-for-other-file", other_grant)
    case("wrong-manifest-supplied", stream, manifest_doc=other_manifest)
    case("tampered-wrapped-key-unsigned", tampered_wrapped)
    case("tampered-wrapped-key-resigned", resigned_corrupt)
    case("tampered-listener-field", mutate(stream, listener_agent=OTHER_LISTENER))
    case("swapped-signature", swapped_signature)
    case("expired", expired)
    case("issued-in-future", future)
    case("lifetime-over-24h", too_long)
    case("unsupported-version", v2)
    case("licence-bad-terms", bad_terms)
    case("extra-envelope-field", {**stream, "extra": 1})
    case("missing-body-field", {**stream, "body": {k: v for k, v in stream["body"].items() if k != "salt_b64"}})

    if not [c for c in grant_cases if c["python_valid"]]:
        raise SystemExit("positive vectors failed in Python")

    canonical_cases = []
    for value in [
        {"z": 1, "a": [True, False, None], "m": {"y": "", "b": "x"}},
        {"é": 1, "e": 2, "｡": 3, "😀": 4, "": 5},
        {"s": "quote\" back\\ slash/ nl\n tab\t cr\r bs\b ff\f nul\x00 us\x1f del\x7f ls  é 😀"},
        {"n": [0, -1, 9007199254740991, -9007199254740991]},
        [],
        {},
    ]:
        canonical_cases.append({"value": value, "canonical_b64": b64(pkg.canonical(value)),
                                "sha256": pkg.sha256(pkg.canonical(value))})

    doc = {
        "generator": "web/tests/vectors/generate_vectors.py",
        "warning": "TEST-ONLY throwaway keys. Never reuse.",
        "generated_at": now,
        "agents": {"owner": OWNER_AGENT, "listener": LISTENER_AGENT, "other_listener": OTHER_LISTENER, "node": NODE_AGENT},
        "keys": {
            "artist_public_hex": pub_raw(artist).hex(),
            "other_artist_public_hex": pub_raw(other_artist).hex(),
            "node_public_hex": pub_raw(node).hex(),
            "listener_x25519_jwk": x25519_jwk(listener_x),
            "listener_x25519_public_hex": pub_raw(listener_x).hex(),
            "other_x25519_jwk": x25519_jwk(other_x),
            "other_x25519_public_hex": pub_raw(other_x).hex(),
            "content_key_hex": content_key.hex(),
        },
        "canonical": canonical_cases,
        "package": {
            "manifest": manifest, "manifest_sha256": digest, "chunks_b64": chunks,
            "plaintext_sha256": hashlib.sha256(audio).hexdigest(), "plaintext_bytes": len(audio),
            "other_manifest": other_manifest, "receipt": receipt,
            "receipt_sha256": pkg.sha256(pkg.canonical(receipt)),
        },
        "records": {"owner_binding": owner_binding, "node_binding": node_binding,
                    "commitment": commitment, "claim": claim},
        "tracks": track_cases,
        "grants": grant_cases,
    }
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False))
    print(f"wrote {out} ({len(grant_cases)} grant cases, {len(chunks)} chunks)")


def _resign(manifest: dict, signer: Ed25519PrivateKey) -> dict:
    """Same manifest body signed by a different artist key."""
    return {"body": manifest["body"], "signer": b64(pub_raw(signer)),
            "signature": b64(signer.sign(pkg.canonical(manifest["body"])))}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(Path(sys.argv[1]))
