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

from .package import (
    StorageError, _assert_manifest, _verify_signed, canonical, manifest_digest,
    sha256, verify_receipt,
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
