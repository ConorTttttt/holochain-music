"""Validated local-conductor evidence for opt-in v2.1 grant operations.

Do not call these helpers with remote-supplied JSON: the bridge must be the
authenticated bridge to the reader's own validating storage cell. In
particular, the delivered grant's anchor hash is a lookup hint, not evidence.
"""
from __future__ import annotations

from typing import Any

from holochain_storage import key_lifecycle as kl
from holochain_storage.holochain_identity import OWNER_PURPOSE, HOST_PURPOSE
from holochain_storage.package import StorageError, manifest_digest

from music_catalogue.access_grant_v2 import _historical_manifest


def _row(value: Any) -> kl.SequencedRecord:
    if (not isinstance(value, dict) or set(value) !=
            {"author", "action_hash", "action_seq", "body"} or
            not isinstance(value["author"], str) or
            not isinstance(value["action_hash"], str) or
            type(value["action_seq"]) is not int or
            not isinstance(value["body"], dict)):
        raise StorageError("invalid authenticated conductor row")
    return kl.SequencedRecord(value["author"], value["action_hash"],
                              value["action_seq"], value["body"])


def lifecycle_from_conductor(bridge, owner_agent: str, purpose: str = OWNER_PURPOSE) -> kl.KeyLifecycle:
    """Resolve the owner's complete verified lifecycle against the reader DNA."""
    if purpose not in (OWNER_PURPOSE, HOST_PURPOSE):
        raise StorageError("unsupported lifecycle purpose")
    context = bridge.call("key_lifecycle_v21_context", purpose=purpose)
    if (not isinstance(context, dict) or not isinstance(context.get("dna_hash"), str)
            or not context["dna_hash"]):
        raise StorageError("v2.1 storage lifecycle unavailable")
    rows = bridge.call("get_key_lifecycle_v21", agent=owner_agent)
    if not isinstance(rows, list):
        raise StorageError("incomplete v2.1 lifecycle")
    return kl.resolve_key_lifecycle([_row(row) for row in rows],
                                    owner_agent, purpose, context["dna_hash"])


def commitment_from_conductor(bridge, owner_agent: str, signed_manifest: dict,
                              lifecycle: kl.KeyLifecycle) -> kl.SequencedRecord:
    """Find the earliest *valid* owner commitment, with authenticated position.

    A later duplicate commitment does not turn an invalid old manifest into a
    historically valid one; each candidate is individually classified at
    its original chain position. Missing or ambiguous evidence fails closed.
    """
    try:
        body = signed_manifest["body"]
        file_id = body["file_id"]
        digest = manifest_digest(signed_manifest)
    except (KeyError, ValueError, TypeError) as exc:
        raise StorageError("malformed signed manifest") from exc
    candidates = []
    for rec in bridge.records("get_file_commitments", agent=owner_agent):
        if (rec.author != owner_agent or not isinstance(rec.body, dict) or
                rec.body.get("schema") != "holochain-storage/file-commitment/v1" or
                rec.body.get("owner_agent") != owner_agent or
                rec.body.get("file_id") != file_id or
                rec.body.get("manifest_sha256") != digest):
            continue
        pos = bridge.call("get_action_position_v21", action_hash=rec.action_hash)
        if not isinstance(pos, dict) or pos.get("author") != owner_agent or pos.get("action_hash") != rec.action_hash:
            continue
        row = kl.SequencedRecord(owner_agent, rec.action_hash, pos.get("action_seq"), rec.body)
        try:
            _historical_manifest(signed_manifest, lifecycle, row)
            candidates.append(row)
        except StorageError:
            continue
    if not candidates:
        raise StorageError("no authenticated historical manifest commitment")
    return min(candidates, key=lambda row: row.action_seq)


def grant_anchor_from_conductor(bridge, action_hash: str, owner_agent: str) -> kl.SequencedRecord:
    """Retrieve a public grant anchor, authenticated by the conductor (not the message)."""
    if not isinstance(action_hash, str) or not action_hash or len(action_hash) > 160:
        raise StorageError("invalid grant anchor reference")
    row = bridge.call("get_grant_anchor_v2", action_hash=action_hash)
    if row is None:
        raise StorageError("grant anchor not yet available")
    record = _row(row)
    if record.action_hash != action_hash or record.author != owner_agent:
        raise StorageError("grant anchor action or author mismatch")
    return record
