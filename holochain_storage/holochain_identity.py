"""S2 identity proof checks for Holochain-authored storage metadata.

The trusted boundary is a *validated Holochain conductor response*. A caller
must NOT construct an AuthoredRecord from arbitrary HTTP input or from the
untrusted `author` property in a user-supplied JSON document. The record's
`author` is the author of its validated Holochain action, as returned by the
trusted local conductor/DNA. This module does NOT verify Holochain signatures
on its own. It verifies that these authenticated bindings match the existing
S1 Ed25519 manifest and storage-node receipt signatures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .package import (
    StorageError, _assert_manifest, _verify_signed, canonical, manifest_digest,
    public_key_bytes, sha256, verify_receipt,
)

KEY_SCHEMA = "holochain-storage/key-binding/v1"
FILE_SCHEMA = "holochain-storage/file-commitment/v1"
REPLICA_SCHEMA = "holochain-storage/replica-claim/v1"
OWNER_PURPOSE = "owner-manifest"
HOST_PURPOSE = "host-receipt"
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AuthoredRecord:
    """One entry fetched by a *trusted Holochain conductor* and its action author."""

    author: str  # conductor-verifiable author, NOT a user-supplied body field
    action_hash: str
    body: dict[str, Any]


def _verified_claim(record: AuthoredRecord, expected_author: str, schema: str,
                    fields: set[str]) -> dict[str, Any]:
    if not isinstance(record, AuthoredRecord) or not isinstance(expected_author, str) or not expected_author:
        raise StorageError("missing authenticated Holochain record/agent")
    if record.author != expected_author or not isinstance(record.action_hash, str) or not record.action_hash:
        raise StorageError("Holochain action author mismatch")
    if not isinstance(record.body, dict) or set(record.body) != fields or record.body.get("schema") != schema:
        raise StorageError("invalid Holochain storage record")
    return record.body


def _hex64(text: Any) -> str:
    if not isinstance(text, str) or not _HEX_64.fullmatch(text):
        raise StorageError("invalid 32-byte hex field")
    return text


def key_for_agent(record: AuthoredRecord, agent: str, purpose: str) -> bytes:
    """Return Ed25519 key explicitly bound to a validated agent action.

    Key registration is author-controlled; key rotation/revocation is not yet
    modelled. Pick an unambiguous binding according to application policy.
    """
    if purpose not in (OWNER_PURPOSE, HOST_PURPOSE):
        raise StorageError("unsupported signing key purpose")
    body = _verified_claim(record, agent, KEY_SCHEMA,
                           {"schema", "agent", "purpose", "signing_key_hex"})
    if body["agent"] != agent or body["purpose"] != purpose:
        raise StorageError("signing key not bound to expected agent/purpose")
    return bytes.fromhex(_hex64(body["signing_key_hex"]))


def verify_owned_manifest(package: dict[str, Any], owner_agent: str,
                          key_binding: AuthoredRecord, commitment: AuthoredRecord) -> dict[str, Any]:
    """Authenticate signed manifest against owner-authored on-DHT commitment."""
    body = _verified_claim(commitment, owner_agent, FILE_SCHEMA,
                           {"schema", "owner_agent", "file_id", "manifest_sha256"})
    owner_key = key_for_agent(key_binding, owner_agent, OWNER_PURPOSE)
    manifest = _verify_signed(package, owner_key, "manifest")
    _assert_manifest(manifest)
    if (body["owner_agent"] != owner_agent
        or body["file_id"] != manifest["file_id"]
        or body["manifest_sha256"] != manifest_digest(package)):
        raise StorageError("owner commitment does not match signed manifest")
    return manifest


def verify_replica_claim(receipt: dict[str, Any], package: dict[str, Any],
                         owner_agent: str, node_agent: str,
                         owner_key_binding: AuthoredRecord, node_key_binding: AuthoredRecord,
                         owner_commitment: AuthoredRecord, node_claim: AuthoredRecord) -> dict[str, Any]:
    """Verify a host-authored DHT claim + signed receipt for one signed package.

    This only proves signed acceptance/claim at that moment, NOT current custody.
    """
    manifest = verify_owned_manifest(package, owner_agent, owner_key_binding, owner_commitment)
    node_key = key_for_agent(node_key_binding, node_agent, HOST_PURPOSE)
    owner_key = key_for_agent(owner_key_binding, owner_agent, OWNER_PURPOSE)
    receipt_body = verify_receipt(receipt, package, node_key, owner_key)
    claim = _verified_claim(node_claim, node_agent, REPLICA_SCHEMA,
                            {"schema", "node_agent", "owner_agent", "file_id", "manifest_sha256", "receipt_sha256"})
    if (claim["node_agent"] != node_agent
        or claim["owner_agent"] != owner_agent
        or claim["file_id"] != manifest["file_id"]
        or claim["manifest_sha256"] != manifest_digest(package)
        or claim["receipt_sha256"] != sha256(canonical(receipt))):
        raise StorageError("storage node claim does not match receipt/package")
    return receipt_body


# ---- S2 key-binding v2: proof of possession --------------------------------
#
# v1 bindings prove only that the *agent* authored a claim about a public key;
# anyone can bind someone else's public key. A v2 binding additionally carries
# an Ed25519 signature, made with the bound key itself, over a domain-separated
# message naming the DNA, agent, purpose, key and generation. The v2 storage
# DNA (`dna-v2/`) verifies it in integrity validation; readers verify it again
# here. v1 and v2 are distinct assurance levels and are never mixed.

KEY_SCHEMA_V2 = "holochain-storage/key-binding/v2"
KEY_POP_DOMAIN_V2 = b"holochain-storage/key-binding-pop/v2\x00"
KEY_GENERATION_V2 = "1"
KEY_V2_FIELDS = frozenset({"schema", "dna_hash", "agent", "purpose", "signing_key_hex",
                           "generation", "proof_signature_hex"})
ASSURANCE_LEGACY_V1 = "legacy-authored-v1"
ASSURANCE_POP_V2 = "proof-of-possession-v2"
_HEX_128 = re.compile(r"[0-9a-f]{128}\Z")
_MAX_IDENTITY = 160


def key_binding_v2_message(dna_hash: str, agent: str, purpose: str, signing_key_hex: str,
                           generation: str = KEY_GENERATION_V2) -> bytes:
    """Exact signed bytes: domain || u32be(len(f)) || f for each field, in order
    schema, dna_hash, agent, purpose, signing_key_hex, generation."""
    out = bytearray(KEY_POP_DOMAIN_V2)
    for field in (KEY_SCHEMA_V2, dna_hash, agent, purpose, signing_key_hex, generation):
        if not isinstance(field, str):
            raise StorageError("key binding fields must be strings")
        raw = field.encode("utf-8")
        out += len(raw).to_bytes(4, "big") + raw
    return bytes(out)


def _identity(text, label: str) -> str:
    if not isinstance(text, str) or not text or len(text) > _MAX_IDENTITY or "\x00" in text:
        raise StorageError(f"invalid {label}")
    return text


def make_key_binding_v2(signing_key: Ed25519PrivateKey, *, dna_hash: str, agent: str,
                        purpose: str) -> dict[str, str]:
    """Sign a v2 binding LOCALLY. Only the public key and the proof leave this
    process; the private key is never sent to the conductor."""
    if purpose not in (OWNER_PURPOSE, HOST_PURPOSE):
        raise StorageError("unsupported signing key purpose")
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise StorageError("Ed25519 signing key required")
    _identity(dna_hash, "DNA hash")
    _identity(agent, "agent")
    key_hex = public_key_bytes(signing_key).hex()
    proof = signing_key.sign(key_binding_v2_message(dna_hash, agent, purpose, key_hex))
    return {"schema": KEY_SCHEMA_V2, "dna_hash": dna_hash, "agent": agent, "purpose": purpose,
            "signing_key_hex": key_hex, "generation": KEY_GENERATION_V2,
            "proof_signature_hex": proof.hex()}


def key_for_agent_v2(record: AuthoredRecord, agent: str, purpose: str, dna_hash: str) -> bytes:
    """Return the Ed25519 key of a v2 binding authored by `agent` for `purpose`
    on the DNA `dna_hash`, after verifying its proof of possession."""
    if purpose not in (OWNER_PURPOSE, HOST_PURPOSE):
        raise StorageError("unsupported signing key purpose")
    _identity(dna_hash, "DNA hash")
    body = _verified_claim(record, agent, KEY_SCHEMA_V2, set(KEY_V2_FIELDS))
    if any(not isinstance(v, str) for v in body.values()):
        raise StorageError("invalid Holochain storage record")
    if body["agent"] != agent or body["purpose"] != purpose:
        raise StorageError("signing key not bound to expected agent/purpose")
    if body["dna_hash"] != dna_hash:
        raise StorageError("key binding is for a different DNA")
    if body["generation"] != KEY_GENERATION_V2:
        raise StorageError("unsupported key generation")
    key = bytes.fromhex(_hex64(body["signing_key_hex"]))
    if not _HEX_128.fullmatch(body["proof_signature_hex"]):
        raise StorageError("invalid proof signature encoding")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(body["proof_signature_hex"]),
            key_binding_v2_message(dna_hash, agent, purpose, body["signing_key_hex"]))
    except (InvalidSignature, ValueError) as exc:
        raise StorageError("proof of possession does not verify") from exc
    return key


def resolve_signing_key(records: list[AuthoredRecord], agent: str, purpose: str, *,
                        require: str, dna_hash: str | None = None) -> tuple[bytes, str]:
    """Explicit-policy key resolution; returns (key, assurance).

    * ``require=ASSURANCE_POP_V2``: only v2 records count; any v2 record for
      this agent/purpose that fails verification is an error (never skipped,
      never a fallback to v1); several *distinct* keys are ambiguous.
    * ``require=ASSURANCE_LEGACY_V1``: v1 records only, for historical reads on
      the v1 network; the result is labelled legacy.
    No first-match or latest-match rule is applied.
    """
    if require == ASSURANCE_POP_V2:
        if dna_hash is None:
            raise StorageError("v2 resolution needs the DNA hash of the reader's cell")
        candidates = [r for r in records if isinstance(r, AuthoredRecord)
                      and isinstance(r.body, dict) and r.body.get("schema") == KEY_SCHEMA_V2
                      and r.body.get("agent") == agent and r.body.get("purpose") == purpose]
        keys = {key_for_agent_v2(r, agent, purpose, dna_hash) for r in candidates}
    elif require == ASSURANCE_LEGACY_V1:
        candidates = [r for r in records if isinstance(r, AuthoredRecord)
                      and isinstance(r.body, dict) and r.body.get("schema") == KEY_SCHEMA
                      and r.body.get("agent") == agent and r.body.get("purpose") == purpose]
        keys = {key_for_agent(r, agent, purpose) for r in candidates}
    else:
        raise StorageError("unknown key binding assurance policy")
    if not keys:
        raise StorageError("no signing key binding for this agent/purpose")
    if len(keys) > 1:
        raise StorageError("ambiguous signing key bindings: rotation policy required")
    return next(iter(keys)), require
