"""S10: owner-signed, reader-specific envelope for one S1 AES-256 content key.

This is NOT a payment or global entitlement service. Grant issuance is an
explicit *owner decision* after authenticating a buyer out of band. A local
listener verifies the registered S2 owner-manifest Ed25519 key, exact S1 file,
listener agent, X25519 recipient key and expiry before unwrapping the key.

Only the signed, X25519-encrypted grant may be shared. Neither this key nor an
X25519 *private* key belongs in the Holochain DHT, S4 or MoQ.
"""
from __future__ import annotations

import os
import time
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import (
    StorageError, _assert_manifest, _verify_signed, b64, canonical, from_b64,
    manifest_digest, public_key_bytes,
)

GRANT_SCHEMA = "holochain-music/content-grant/v1"
# v1 app: owner-issued, non-expiring personal-use licence for offline access.
# Same primitives as the S10 grant; a different HKDF context domain prevents a
# licence and a streaming grant from ever being confused for one another.
LICENCE_SCHEMA = "holochain-music/personal-licence/v1"
LICENCE_TERMS = "perpetual-personal-use"
MAX_GRANT_BYTES = 4096
MAX_LIFETIME_SECONDS = 86400
CLOCK_SKEW_SECONDS = 120
_HEX = frozenset("0123456789abcdef")
_FIELDS = {
    "schema", "owner_agent", "listener_agent", "file_id", "manifest_sha256",
    "recipient_key_hex", "ephemeral_key_hex", "salt_b64", "nonce_b64",
    "wrapped_key_b64", "issued_at", "expires_at",
}


_LICENCE_FIELDS = (_FIELDS - {"expires_at"}) | {"licence_id", "terms"}


class ContentGrantError(StorageError):
    """Missing, forged, expired or incorrectly addressed content-key grant."""


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 160 or "\x00" in value:
        raise ContentGrantError(f"invalid {label}")
    return value


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise ContentGrantError(f"invalid {label}")
    return value


def _manifest(signed_manifest: dict, trusted_artist: bytes) -> tuple[str, str]:
    # Authenticate the manifest independently, not merely its unsigned body.
    try:
        body = _verify_signed(signed_manifest, trusted_artist, "manifest")
        _assert_manifest(body)
    except (StorageError, TypeError, ValueError) as exc:
        raise ContentGrantError("invalid signed S1 manifest") from exc
    return body["file_id"], manifest_digest(signed_manifest)


def _context(body: dict) -> bytes:
    return b"holochain-music/content-grant/hkdf-aad/v1\x00" + canonical({
        "schema": body["schema"], "owner_agent": body["owner_agent"],
        "listener_agent": body["listener_agent"], "file_id": body["file_id"],
        "manifest_sha256": body["manifest_sha256"],
        "recipient_key_hex": body["recipient_key_hex"],
        "issued_at": body["issued_at"], "expires_at": body["expires_at"],
    })


def _licence_context(body: dict) -> bytes:
    return b"holochain-music/personal-licence/hkdf-aad/v1\x00" + canonical({
        "schema": body["schema"], "owner_agent": body["owner_agent"],
        "listener_agent": body["listener_agent"], "file_id": body["file_id"],
        "manifest_sha256": body["manifest_sha256"],
        "recipient_key_hex": body["recipient_key_hex"],
        "issued_at": body["issued_at"], "licence_id": body["licence_id"],
        "terms": body["terms"],
    })


def _key(shared: bytes, salt: bytes, context: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context).derive(shared)


def issue_content_grant(
    *, owner_signer: Ed25519PrivateKey, owner_agent: str,
    listener_agent: str, recipient_public: bytes,
    signed_manifest: dict, content_key: bytes, lifetime_seconds: int = 1800,
) -> dict:
    """Owner explicitly grants one listener access to one exact S1 file.

    Caller MUST authenticate the listener agent and their X25519 public key
    before issuing; this method cannot prove that binding or a payment.
    """
    _identity(owner_agent, "owner agent")
    _identity(listener_agent, "listener agent")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= MAX_LIFETIME_SECONDS:
        raise ContentGrantError("invalid grant lifetime")
    if not isinstance(owner_signer, Ed25519PrivateKey):
        raise ContentGrantError("owner signing key required")
    if not isinstance(content_key, bytes) or len(content_key) != 32:
        raise ContentGrantError("AES-256 content key must have 32 bytes")
    if not isinstance(recipient_public, bytes) or len(recipient_public) != 32:
        raise ContentGrantError("recipient X25519 public key must have 32 bytes")
    try:
        recipient = X25519PublicKey.from_public_bytes(recipient_public)
    except ValueError as exc:
        raise ContentGrantError("invalid recipient X25519 key") from exc
    artist_public = public_key_bytes(owner_signer)
    file_id, digest = _manifest(signed_manifest, artist_public)
    now = int(time.time())
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    salt, nonce = os.urandom(16), os.urandom(12)
    body = {
        "schema": GRANT_SCHEMA, "owner_agent": owner_agent,
        "listener_agent": listener_agent, "file_id": file_id,
        "manifest_sha256": digest, "recipient_key_hex": recipient_public.hex(),
        "ephemeral_key_hex": ephemeral_public.hex(), "salt_b64": b64(salt),
        "nonce_b64": b64(nonce), "issued_at": now,
        "expires_at": now + lifetime_seconds,
    }
    context = _context(body)
    # The ephemeral X25519 key is never stored or returned, only its public key.
    try:
        wrapped = AESGCM(_key(ephemeral.exchange(recipient), salt, context)).encrypt(
            nonce, content_key, context)
    except ValueError as exc:
        raise ContentGrantError("cannot wrap key for recipient") from exc
    body["wrapped_key_b64"] = b64(wrapped)
    result = {"body": body, "signer": b64(artist_public),
              "signature": b64(owner_signer.sign(canonical(body)))}
    if len(canonical(result)) > MAX_GRANT_BYTES:
        raise ContentGrantError("grant exceeds size limit")
    return result


def issue_personal_licence(
    *, owner_signer: Ed25519PrivateKey, owner_agent: str,
    listener_agent: str, recipient_public: bytes,
    signed_manifest: dict, content_key: bytes,
) -> dict:
    """Owner grants one listener a *non-expiring* personal-use licence.

    This is a deliberate artist decision. Once issued, the listener can play
    and export the track offline indefinitely: it cannot be revoked
    cryptographically. It is not a payment record or a copyright transfer.
    """
    _identity(owner_agent, "owner agent")
    _identity(listener_agent, "listener agent")
    if not isinstance(owner_signer, Ed25519PrivateKey):
        raise ContentGrantError("owner signing key required")
    if not isinstance(content_key, bytes) or len(content_key) != 32:
        raise ContentGrantError("AES-256 content key must have 32 bytes")
    if not isinstance(recipient_public, bytes) or len(recipient_public) != 32:
        raise ContentGrantError("recipient X25519 public key must have 32 bytes")
    try:
        recipient = X25519PublicKey.from_public_bytes(recipient_public)
    except ValueError as exc:
        raise ContentGrantError("invalid recipient X25519 key") from exc
    artist_public = public_key_bytes(owner_signer)
    file_id, digest = _manifest(signed_manifest, artist_public)
    ephemeral = X25519PrivateKey.generate()
    salt, nonce = os.urandom(16), os.urandom(12)
    body = {
        "schema": LICENCE_SCHEMA, "owner_agent": owner_agent,
        "listener_agent": listener_agent, "file_id": file_id,
        "manifest_sha256": digest, "recipient_key_hex": recipient_public.hex(),
        "ephemeral_key_hex": ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "salt_b64": b64(salt), "nonce_b64": b64(nonce), "issued_at": int(time.time()),
        "licence_id": os.urandom(16).hex(), "terms": LICENCE_TERMS,
    }
    context = _licence_context(body)
    try:
        wrapped = AESGCM(_key(ephemeral.exchange(recipient), salt, context)).encrypt(nonce, content_key, context)
    except ValueError as exc:
        raise ContentGrantError("cannot wrap key for recipient") from exc
    body["wrapped_key_b64"] = b64(wrapped)
    result = {"body": body, "signer": b64(artist_public),
              "signature": b64(owner_signer.sign(canonical(body)))}
    if len(canonical(result)) > MAX_GRANT_BYTES:
        raise ContentGrantError("licence exceeds size limit")
    return result


def grant_kind(grant: dict) -> str:
    """Public, *unauthenticated* classification for display/routing only."""
    schema = grant.get("body", {}).get("schema") if isinstance(grant, dict) else None
    if schema == LICENCE_SCHEMA:
        return "perpetual-personal"
    if schema == GRANT_SCHEMA:
        return "stream"
    raise ContentGrantError("unknown grant schema")


def unwrap_content_grant(
    grant: dict, *, trusted_artist: bytes, owner_agent: str,
    listener_agent: str, recipient_private: X25519PrivateKey,
    signed_manifest: dict,
) -> bytes:
    """Verify owner signature + listener/file bindings, then unwrap AES key.

    `trusted_artist` MUST come from the local conductor's validated S2
    owner-manifest key binding (or an independently pinned equivalent), NOT
    from `grant['signer']`. `listener_agent` must come from Bob's authenticated
    local Holochain conductor, not from the grant itself.
    """
    _identity(owner_agent, "owner agent")
    _identity(listener_agent, "listener agent")
    if not isinstance(recipient_private, X25519PrivateKey):
        raise ContentGrantError("reader X25519 private key required")
    if not isinstance(trusted_artist, bytes) or len(trusted_artist) != 32:
        raise ContentGrantError("trusted registered artist key required")
    file_id, digest = _manifest(signed_manifest, trusted_artist)
    if not isinstance(grant, dict) or set(grant) != {"body", "signer", "signature"}:
        raise ContentGrantError("invalid grant envelope")
    try:
        if len(canonical(grant)) > MAX_GRANT_BYTES:
            raise ContentGrantError("oversized grant")
        signer = from_b64(grant["signer"], 32)
        signature = from_b64(grant["signature"], 64)
        if signer != trusted_artist:
            raise ContentGrantError("grant not signed by registered artist")
        body = grant["body"]
        licence = isinstance(body, dict) and body.get("schema") == LICENCE_SCHEMA
        if not isinstance(body, dict) or set(body) != (_LICENCE_FIELDS if licence else _FIELDS):
            raise ContentGrantError("invalid grant body")
        Ed25519PublicKey.from_public_bytes(trusted_artist).verify(signature, canonical(body))
        if body["schema"] != (LICENCE_SCHEMA if licence else GRANT_SCHEMA) or body["owner_agent"] != owner_agent or \
                body["listener_agent"] != listener_agent or body["file_id"] != file_id or \
                body["manifest_sha256"] != digest:
            raise ContentGrantError("grant not valid for this listener/owner/file")
        _hex32(body["recipient_key_hex"], "recipient public key")
        _hex32(body["ephemeral_key_hex"], "ephemeral public key")
        now = int(time.time())
        if licence:
            # Offline use must not depend on a correct clock beyond "not
            # issued in the future"; there is deliberately no expiry.
            if type(body["issued_at"]) is not int or body["issued_at"] > now + CLOCK_SKEW_SECONDS \
                    or body["terms"] != LICENCE_TERMS:
                raise ContentGrantError("invalid licence terms or issue time")
            licence_id = body["licence_id"]
            if not isinstance(licence_id, str) or len(licence_id) != 32 or any(c not in _HEX for c in licence_id):
                raise ContentGrantError("invalid licence ID")
        else:
            if type(body["issued_at"]) is not int or type(body["expires_at"]) is not int:
                raise ContentGrantError("invalid grant timestamps")
            if body["issued_at"] > now + CLOCK_SKEW_SECONDS or \
                    body["expires_at"] <= now or \
                    not 1 <= body["expires_at"] - body["issued_at"] <= MAX_LIFETIME_SECONDS:
                raise ContentGrantError("grant is expired or outside its validity window")
        expected_public = recipient_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if expected_public.hex() != body["recipient_key_hex"]:
            raise ContentGrantError("grant not addressed to this X25519 reader")
        salt = from_b64(body["salt_b64"], 16)
        nonce = from_b64(body["nonce_b64"], 12)
        ciphertext = from_b64(body["wrapped_key_b64"], 48)
        eph = X25519PublicKey.from_public_bytes(bytes.fromhex(body["ephemeral_key_hex"]))
        context = _licence_context(body) if licence else _context(body)
        key = AESGCM(_key(recipient_private.exchange(eph), salt, context)).decrypt(
            nonce, ciphertext, context)
        if len(key) != 32:
            raise ContentGrantError("unwrapped key is not AES-256")
        return key
    except (InvalidSignature, InvalidTag) as exc:
        raise ContentGrantError("grant signature or key authentication failed") from exc
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, ContentGrantError):
            raise
        raise ContentGrantError("invalid grant encoding or cryptographic field") from exc
