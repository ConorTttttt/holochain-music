"""Opt-in access-grant/v2. Private recipient-side cryptography; no transport key APIs.

Only records returned by the caller's *validating local Holochain conductor*
may be supplied as lifecycle, commitment and anchor arguments. An anchor on
its own never authenticates a grant. v1 issuance/verification is unchanged.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import key_lifecycle as kl
from holochain_storage.package import (
    StorageError, _assert_manifest, _verify_signed, b64, canonical, manifest_digest,
    public_key_bytes,
)
from music_catalogue.content_grants import _key

SCHEMA = "holochain-music/access-grant/v2"
DOMAIN = b"holochain-music/access-grant/v2\x00"
WRAP_DOMAIN = b"holochain-music/access-grant/hkdf-aad/v2\x00"
WRAP_ALGORITHM = "x25519-hkdf-sha256-aes256gcm/v2"
FIELDS = frozenset({
    "schema", "grant_id", "dna_hash", "owner_agent", "issuer_agent",
    "issuer_purpose", "issuer_key_hex", "issuer_key_generation",
    "issuer_key_action", "file_id", "manifest_sha256", "manifest_key_hex",
    "listener_agent", "recipient_key_hex", "rights", "term",
    "issued_at", "not_before", "expires_at", "basis", "entitlement_ref",
    "key_wrap", "ephemeral_key_hex", "salt_b64", "nonce_b64", "wrapped_key_b64",
})
WRAP_FIELDS = frozenset({"ephemeral_key_hex", "salt_b64", "nonce_b64", "wrapped_key_b64"})
RIGHTS = frozenset({"export", "managed-offline", "stream"})
MAX_CANONICAL_BYTES = 4096
MAX_INPUT_BYTES = 16384
_HEX = re.compile(r"[0-9a-f]+\Z")


class AccessGrantV2Error(StorageError):
    """Stable category + reason, shared with Rust negative vectors."""

    def __init__(self, category: str, reason: str):
        self.category, self.reason = category, reason
        super().__init__(f"{category}: {reason}")


def _fail(category: str, reason: str) -> None:
    raise AccessGrantV2Error(category, reason)


def _hex(value: Any, count: int, reason: str) -> bytes:
    if not isinstance(value, str) or len(value) != count * 2 or not _HEX.fullmatch(value):
        _fail("malformed", reason)
    return bytes.fromhex(value)


def _identity(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 160 or "\x00" in value:
        _fail("malformed", reason)
    return value


def _b64(value: Any, count: int) -> bytes:
    if not isinstance(value, str):
        _fail("malformed", "KeyEnvelope")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _fail("malformed", "KeyEnvelope")
    if len(data) != count or b64(data) != value:
        _fail("malformed", "KeyEnvelope")
    return data


def _int(value: Any) -> int:
    if type(value) is not int or not -(2**63) <= value < 2**63:
        _fail("validity", "InvalidTimestamp")
    return value


def _no_duplicate(pairs: list[tuple[str, Any]]) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            _fail("malformed", "Structure")
        out[key] = value
    return out


def parse_access_grant_v2(value: bytes | str | dict) -> dict:
    """Exact envelope/body and canonical scalar encodings, no v1 fallback."""
    if isinstance(value, bytes):
        if len(value) > MAX_INPUT_BYTES:
            _fail("malformed", "TooLarge")
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            _fail("malformed", "Json")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_INPUT_BYTES:
            _fail("malformed", "TooLarge")
        try:
            value = json.loads(value, object_pairs_hook=_no_duplicate,
                               parse_constant=lambda _: _fail("malformed", "NonCanonicalNumber"))
        except (ValueError, UnicodeDecodeError) as exc:
            if isinstance(exc, AccessGrantV2Error):
                raise
            _fail("malformed", "Json")
    if not isinstance(value, dict) or set(value) != {"body", "signature_hex"}:
        if isinstance(value, dict) and "signer" in value:
            _fail("unsupported", "WrongVersion")
        _fail("malformed", "Structure")
    body = value["body"]
    if not isinstance(body, dict) or set(body) != FIELDS:
        _fail("malformed", "Structure")
    if body["schema"] != SCHEMA:
        _fail("unsupported", "WrongVersion")
    if any(not isinstance(v, str) for k, v in body.items()
           if k not in ("rights", "issued_at", "not_before", "expires_at")):
        _fail("malformed", "Structure")
    if not isinstance(body["rights"], list) or any(not isinstance(r, str) for r in body["rights"]):
        _fail("malformed", "Structure")
    for k in ("issued_at", "not_before", "expires_at"):
        _int(body[k])
    _hex(value["signature_hex"], 64, "Signature")
    for field, n in (("grant_id", 16), ("issuer_key_hex", 32), ("file_id", 32),
                     ("manifest_sha256", 32), ("manifest_key_hex", 32),
                     ("recipient_key_hex", 32), ("ephemeral_key_hex", 32)):
        _hex(body[field], n, field)
    if body["entitlement_ref"]:
        _hex(body["entitlement_ref"], 32, "entitlement_ref")
    for field in ("dna_hash", "owner_agent", "issuer_agent", "issuer_key_action", "listener_agent"):
        _identity(body[field], field)
    try:
        kl.parse_generation(body["issuer_key_generation"])
    except StorageError:
        _fail("malformed", "IssuerGeneration")
    if (body["issuer_purpose"] != kl.OWNER_PURPOSE or
            body["basis"] != "owner-decision" or body["key_wrap"] != WRAP_ALGORITHM):
        _fail("unsupported", "Terms")
    _b64(body["salt_b64"], 16)
    _b64(body["nonce_b64"], 12)
    _b64(body["wrapped_key_b64"], 48)
    if not body["rights"] or body["rights"] != sorted(set(body["rights"])) or not set(body["rights"]) <= RIGHTS:
        _fail("unsupported", "Terms")
    try:
        if len(canonical(value)) > MAX_CANONICAL_BYTES:
            _fail("malformed", "TooLarge")
    except (TypeError, ValueError, OverflowError):
        _fail("malformed", "NonCanonicalNumber")
    return value


def grant_message(body: dict) -> bytes:
    return DOMAIN + canonical(body)


def grant_wrap_context(body: dict) -> bytes:
    return WRAP_DOMAIN + canonical({k: v for k, v in body.items() if k not in WRAP_FIELDS})


def _historical_manifest(signed_manifest: dict, lifecycle: kl.KeyLifecycle,
                         commitment: kl.SequencedRecord) -> tuple[str, str, str]:
    """Content check A: authentic historical signature AND agent's chain commitment."""
    if not isinstance(lifecycle, kl.KeyLifecycle) or lifecycle.purpose != kl.OWNER_PURPOSE:
        _fail("unauthenticated", "IssuerNotInLifecycle")
    if (not isinstance(commitment, kl.SequencedRecord) or commitment.author != lifecycle.agent or
            not isinstance(commitment.action_seq, int)):
        _fail("unavailable", "CommitmentNotFound")
    pinned = commitment.body
    if (not isinstance(pinned, dict) or set(pinned) !=
            {"schema", "owner_agent", "file_id", "manifest_sha256"} or
            pinned["schema"] != "holochain-storage/file-commitment/v1" or
            pinned["owner_agent"] != lifecycle.agent):
        _fail("unauthenticated", "ManifestMismatch")
    if not isinstance(signed_manifest, dict) or set(signed_manifest) != {"body", "signer", "signature"}:
        _fail("malformed", "Manifest")
    try:
        # The signed S1 envelope names a historical key, NOT the v2 issuer.
        signer = base64.b64decode(signed_manifest["signer"], validate=True)
        if len(signer) != 32 or b64(signer) != signed_manifest["signer"]:
            _fail("malformed", "Manifest")
        generation = lifecycle.find(signer)
        if commitment.action_seq <= generation.action_seq:
            _fail("unauthenticated", "InvalidHistoricalKey")
        state = lifecycle.classify(signer, kl.HISTORICAL,
                                   kl.ChainAnchor(commitment.author, commitment.action_seq))
        if state not in (kl.ACTIVE, kl.HISTORICAL_ONLY):
            _fail("unauthenticated", "InvalidHistoricalKey")
        manifest = _verify_signed(signed_manifest, signer, "manifest")
        _assert_manifest(manifest)
        digest = manifest_digest(signed_manifest)
    except AccessGrantV2Error:
        raise
    except (StorageError, KeyError, ValueError, TypeError, AttributeError) as exc:
        _fail("unauthenticated", "InvalidHistoricalKey")
    if pinned["file_id"] != manifest["file_id"] or pinned["manifest_sha256"] != digest:
        _fail("denied", "ManifestMismatch")
    return manifest["file_id"], digest, signer.hex()


@dataclass(frozen=True)
class VerifiedAccessGrantV2:
    body: dict
    anchor_seq: int
    issuer_continuity: str
    owner_assurance: str
    context: bytes

    @property
    def rights(self) -> frozenset[str]:
        return frozenset(self.body["rights"])

    def authorize(self, right: str) -> None:
        if right not in self.rights:
            _fail("denied", "RightNotGranted")


def _terms(body: dict, now: int) -> None:
    rights = frozenset(body["rights"])
    issued, start, end = body["issued_at"], body["not_before"], body["expires_at"]
    if issued > now + 120:
        _fail("validity", "NotYetValid")
    if body["term"] == "perpetual":
        if end != 0 or start != issued:
            _fail("unsupported", "Terms")
        if rights not in (frozenset({"stream"}), RIGHTS):
            _fail("unsupported", "Terms")
    elif body["term"] == "window":
        if rights != frozenset({"stream"}) or not start < end or end - start > 86400:
            _fail("unsupported", "Terms")
        if now < start:
            _fail("validity", "NotYetValid")
        if now >= end:
            _fail("validity", "Expired")
    else:
        _fail("unsupported", "Terms")


def verify_access_grant_v2(
    grant: bytes | str | dict, *, signed_manifest: dict,
    owner_lifecycle: kl.KeyLifecycle, commitment: kl.SequencedRecord,
    anchor: kl.SequencedRecord | None, listener_agent: str,
    recipient_public: bytes, now: int | None = None,
    recovered_policy: str = kl.RECOVERED_ISSUER_REJECT,
) -> VerifiedAccessGrantV2:
    """Verify both historical content and *anchored* current grant authority.

    All lifecycle/anchor/commitment objects must originate from a validating
    local conductor, not a remote sender or a grant's untrusted fields.
    """
    env = parse_access_grant_v2(grant)
    if recovered_policy not in (kl.RECOVERED_ISSUER_REJECT, kl.RECOVERED_ISSUER_ACCEPT):
        _fail("unsupported", "RecoveryPolicy")
    b = env["body"]
    file_id, digest, historical_key = _historical_manifest(signed_manifest, owner_lifecycle, commitment)
    if b["owner_agent"] != owner_lifecycle.agent or b["issuer_agent"] != owner_lifecycle.agent:
        _fail("denied", "OwnerMismatch")
    if b["dna_hash"] != owner_lifecycle.dna_hash:
        _fail("denied", "NetworkMismatch")
    if b["file_id"] != file_id:
        _fail("denied", "FileMismatch")
    if b["manifest_sha256"] != digest or b["manifest_key_hex"] != historical_key:
        _fail("denied", "ManifestMismatch")
    if b["listener_agent"] != _identity(listener_agent, "listener_agent"):
        _fail("denied", "ListenerMismatch")
    if (not isinstance(recipient_public, bytes) or len(recipient_public) != 32 or
            b["recipient_key_hex"] != recipient_public.hex()):
        _fail("denied", "RecipientKeyMismatch")
    generation = next((g for g in owner_lifecycle.generations
                       if g.action_hash == b["issuer_key_action"]), None)
    if generation is None:
        _fail("unauthenticated", "IssuerNotInLifecycle")
    if (str(generation.generation) != b["issuer_key_generation"] or
            generation.key.hex() != b["issuer_key_hex"]):
        _fail("unauthenticated", "IssuerGenerationMismatch")
    message = grant_message(b)
    try:
        Ed25519PublicKey.from_public_bytes(generation.key).verify(
            bytes.fromhex(env["signature_hex"]), message)
    except (InvalidSignature, ValueError):
        _fail("unauthenticated", "InvalidSignature")
    if anchor is None:
        _fail("unavailable", "AnchorNotFound")
    try:
        kl.verify_grant_anchor(anchor, owner_lifecycle, grant_id=b["grant_id"],
                               grant_message=message, issuer_key_action=b["issuer_key_action"],
                               recovered_policy=recovered_policy)
    except kl.LifecycleError as exc:
        message_text = str(exc).lower()
        if exc.verdict == kl.ROTATED:
            _fail("unauthenticated", "KeyRotated")
        if exc.verdict == kl.REVOKED:
            _fail("unauthenticated", "KeyRevoked")
        if "recovered" in message_text:
            _fail("unauthenticated", "RecoveredIssuerRefused")
        if "does not match" in message_text or "not authored" in message_text:
            _fail("unauthenticated", "AnchorMismatch")
        _fail("unauthenticated", "InvalidAnchor")
    _terms(b, int(time.time()) if now is None else _int(now))
    assurance = ("KeyLifecycleRecoveredV21"
                 if any(g.kind == kl.RECOVERY for g in owner_lifecycle.generations
                        if g.generation <= generation.generation)
                 else "KeyLifecycleV21")
    return VerifiedAccessGrantV2(b, anchor.action_seq, generation.continuity,
                                 assurance, grant_wrap_context(b))


def issue_access_grant_v2(
    *, issuer_signer: Ed25519PrivateKey, owner_lifecycle: kl.KeyLifecycle,
    signed_manifest: dict, commitment: kl.SequencedRecord,
    listener_agent: str, recipient_public: bytes, content_key: bytes,
    rights: list[str], term: str, issued_at: int | None = None,
    not_before: int | None = None, expires_at: int = 0,
    grant_id: bytes | None = None, entitlement_ref: str = "",
) -> dict:
    """Only issue with the active *current* owner key; verify historical S1 content."""
    if not isinstance(issuer_signer, Ed25519PrivateKey):
        _fail("malformed", "IssuerKey")
    if not isinstance(owner_lifecycle, kl.KeyLifecycle):
        _fail("unauthenticated", "IssuerNotInLifecycle")
    try:
        issuer = owner_lifecycle.active()
    except kl.LifecycleError:
        _fail("unauthenticated", "IssuerNotActive")
    if public_key_bytes(issuer_signer) != issuer.key:
        _fail("unauthenticated", "IssuerNotActive")
    file_id, digest, manifest_key_hex = _historical_manifest(
        signed_manifest, owner_lifecycle, commitment)
    if not isinstance(content_key, bytes) or len(content_key) != 32:
        _fail("malformed", "ContentKey")
    if not isinstance(recipient_public, bytes) or len(recipient_public) != 32:
        _fail("malformed", "RecipientKey")
    _identity(listener_agent, "listener_agent")
    if grant_id is None:
        grant_id = os.urandom(16)
    if not isinstance(grant_id, bytes) or len(grant_id) != 16:
        _fail("malformed", "GrantId")
    if entitlement_ref:
        _hex(entitlement_ref, 32, "entitlement_ref")
    now = int(time.time()) if issued_at is None else _int(issued_at)
    start = now if not_before is None else _int(not_before)
    body = {
        "schema": SCHEMA, "grant_id": grant_id.hex(), "dna_hash": owner_lifecycle.dna_hash,
        "owner_agent": owner_lifecycle.agent, "issuer_agent": owner_lifecycle.agent,
        "issuer_purpose": kl.OWNER_PURPOSE, "issuer_key_hex": issuer.key.hex(),
        "issuer_key_generation": str(issuer.generation), "issuer_key_action": issuer.action_hash,
        "file_id": file_id, "manifest_sha256": digest, "manifest_key_hex": manifest_key_hex,
        "listener_agent": listener_agent, "recipient_key_hex": recipient_public.hex(),
        "rights": rights, "term": term, "issued_at": now, "not_before": start,
        "expires_at": _int(expires_at), "basis": "owner-decision",
        "entitlement_ref": entitlement_ref, "key_wrap": WRAP_ALGORITHM,
        "ephemeral_key_hex": "", "salt_b64": "", "nonce_b64": "",
        "wrapped_key_b64": "",
    }
    _terms(body, now)
    if not rights or rights != sorted(set(rights)) or not set(rights) <= RIGHTS:
        _fail("unsupported", "Terms")
    ephemeral = X25519PrivateKey.generate()
    body["ephemeral_key_hex"] = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    salt, nonce = os.urandom(16), os.urandom(12)
    body["salt_b64"], body["nonce_b64"] = b64(salt), b64(nonce)
    context = grant_wrap_context(body)
    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
        wrapped = AESGCM(_key(shared, salt, context)).encrypt(nonce, content_key, context)
    except ValueError:
        _fail("malformed", "RecipientKey")
    body["wrapped_key_b64"] = b64(wrapped)
    env = {"body": body, "signature_hex": issuer_signer.sign(grant_message(body)).hex()}
    parse_access_grant_v2(env)
    return env


def unwrap_access_grant_v2(verified: VerifiedAccessGrantV2,
                           recipient_private: X25519PrivateKey) -> bytes:
    """Recipient app ONLY. Never call from transport, CAS, relay or metadata services."""
    if not isinstance(verified, VerifiedAccessGrantV2) or not isinstance(recipient_private, X25519PrivateKey):
        _fail("unauthenticated", "UnverifiedGrant")
    b = verified.body
    key_public = recipient_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if key_public.hex() != b["recipient_key_hex"]:
        _fail("denied", "RecipientKeyMismatch")
    try:
        shared = recipient_private.exchange(X25519PublicKey.from_public_bytes(
            bytes.fromhex(b["ephemeral_key_hex"])))
        key = AESGCM(_key(shared, _b64(b["salt_b64"], 16), verified.context)).decrypt(
            _b64(b["nonce_b64"], 12), _b64(b["wrapped_key_b64"], 48), verified.context)
    except (InvalidTag, ValueError):
        _fail("unauthenticated", "KeyAuthenticationFailed")
    if len(key) != 32:
        _fail("malformed", "KeyEnvelope")
    return key
