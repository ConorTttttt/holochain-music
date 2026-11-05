"""Offline-capable perpetual *personal-use* decryption grants (not payments/DRM).

A signed grant wraps an existing package content key to a buyer's X25519 key.
It is independent of the host's ability to read music and has no platform
online check. A proof of purchase / settlement protocol is not implemented.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .package import (
    StorageError, _assert_manifest, _sign, _verify_signed, b64, from_b64,
    manifest_digest,
)

GRANT_SCHEMA = "holochain-music/personal-perpetual-grant/v1"


def _derive(shared: bytes, manifest_hash: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(manifest_hash),
                info=b"holochain-storage/recipient-wrap/v1").derive(shared)


def create_perpetual_grant(package: dict[str, Any], trusted_artist: bytes, artist_private: Ed25519PrivateKey,
                           content_key: bytes, buyer_pubkey: bytes) -> dict[str, Any]:
    """After a separately verified purchase, sign a non-expiring personal-use grant."""
    body = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(body)
    if not isinstance(content_key, bytes) or len(content_key) != 32:
        raise StorageError("invalid content key")
    if not isinstance(buyer_pubkey, bytes) or len(buyer_pubkey) != 32:
        raise StorageError("invalid buyer key")
    if artist_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != trusted_artist:
        raise StorageError("artist signing key mismatch")
    ephemeral = X25519PrivateKey.generate()
    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(buyer_pubkey))
    except ValueError as exc:
        raise StorageError("invalid buyer public key") from exc
    manifest_hash = manifest_digest(package)
    nonce = os.urandom(12)
    aad = bytes.fromhex(manifest_hash) + buyer_pubkey
    wrapped = AESGCM(_derive(shared, manifest_hash)).encrypt(nonce, content_key, aad)
    grant = {
        "schema": GRANT_SCHEMA,
        "manifest_sha256": manifest_hash,
        "file_id": body["file_id"],
        "license": "perpetual-personal-use",
        "buyer_public_key": b64(buyer_pubkey),
        "ephemeral_public_key": b64(ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "nonce": b64(nonce), "wrapped_key": b64(wrapped),
        "granted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return _sign(grant, artist_private)


def open_perpetual_grant(grant: dict[str, Any], package: dict[str, Any], trusted_artist: bytes,
                         buyer_private: X25519PrivateKey) -> bytes:
    """Buyer obtains the content key offline; independent of platform availability."""
    manifest = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(manifest)
    body = _verify_signed(grant, trusted_artist, "grant")
    if not isinstance(body, dict) or set(body) != {
        "schema", "manifest_sha256", "file_id", "license", "buyer_public_key",
        "ephemeral_public_key", "nonce", "wrapped_key", "granted_at"
    }:
        raise StorageError("invalid grant structure")
    if body["schema"] != GRANT_SCHEMA or body["license"] != "perpetual-personal-use" or body["file_id"] != manifest["file_id"] or body["manifest_sha256"] != manifest_digest(package):
        raise StorageError("grant does not match the package")
    buyer_pubkey = buyer_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if from_b64(body["buyer_public_key"], 32) != buyer_pubkey:
        raise StorageError("grant belongs to another buyer")
    try:
        shared = buyer_private.exchange(X25519PublicKey.from_public_bytes(from_b64(body["ephemeral_public_key"], 32)))
    except ValueError as exc:
        raise StorageError("invalid ephemeral public key") from exc
    try:
        key = AESGCM(_derive(shared, body["manifest_sha256"])).decrypt(
            from_b64(body["nonce"], 12), from_b64(body["wrapped_key"], 48),
            bytes.fromhex(body["manifest_sha256"]) + buyer_pubkey)
    except InvalidTag as exc:
        raise StorageError("cannot unwrap buyer content key") from exc
    if len(key) != 32:
        raise StorageError("unexpected content key size")
    return key
