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


def verify_delivery_from_conductor(bridge, delivery: dict, signed_manifest: dict,
                                   owner_agent: str, listener_agent: str,
                                   recipient_public: bytes, *, now: int | None = None):
    """Accept a delivered v2 grant ONLY after fetching independent chain evidence.

    Returns the verified entitlement plus a local-only offline evidence snapshot.
    The snapshot must be written only after success, never accepted from peers.
    """
    from music_catalogue.access_grant_v2 import (
        parse_access_grant_v2, verify_access_grant_v2,
    )

    if not isinstance(delivery, dict) or set(delivery) != {"grant", "anchor_action"}:
        raise StorageError("invalid access-grant/v2 delivery wrapper")
    grant = parse_access_grant_v2(delivery["grant"])
    lifecycle = lifecycle_from_conductor(bridge, owner_agent)
    commitment = commitment_from_conductor(bridge, owner_agent, signed_manifest, lifecycle)
    anchor = grant_anchor_from_conductor(bridge, delivery["anchor_action"], owner_agent)
    verified = verify_access_grant_v2(
        grant, signed_manifest=signed_manifest, owner_lifecycle=lifecycle,
        commitment=commitment, anchor=anchor, listener_agent=listener_agent,
        recipient_public=recipient_public, now=now)
    rows = bridge.call("get_key_lifecycle_v21", agent=owner_agent)
    # Re-resolve exactly what is stored for offline use. DHT views may differ
    # between calls; no mixed or incomplete lifecycle is accepted.
    cached = kl.resolve_key_lifecycle([_row(row) for row in rows], owner_agent,
                                      OWNER_PURPOSE, lifecycle.dna_hash)
    confirmed = verify_access_grant_v2(
        grant, signed_manifest=signed_manifest, owner_lifecycle=cached,
        commitment=commitment, anchor=anchor, listener_agent=listener_agent,
        recipient_public=recipient_public, now=now)
    snapshot = {
        "schema": "holochain-music/local-v2-verified-evidence/v1",
        "owner_agent": owner_agent, "dna_hash": lifecycle.dna_hash,
        "lifecycle": rows,
        "commitment": {"author": commitment.author, "action_hash": commitment.action_hash,
                       "action_seq": commitment.action_seq, "body": commitment.body},
        "anchor": {"author": anchor.author, "action_hash": anchor.action_hash,
                   "action_seq": anchor.action_seq, "body": anchor.body},
    }
    return confirmed, snapshot


def verify_cached_delivery(evidence: dict, delivery: dict, signed_manifest: dict,
                           owner_agent: str, dna_hash: str, listener_agent: str,
                           recipient_public: bytes, *, now: int | None = None):
    """Offline replay of a successful prior online acceptance, fail closed.

    The local library must never import this snapshot from a remote request.
    It represents the reader's last validated conductor view; it cannot prove
    that newer revocations have arrived during offline playback.
    """
    from music_catalogue.access_grant_v2 import verify_access_grant_v2

    if (not isinstance(evidence, dict) or set(evidence) !=
            {"schema", "owner_agent", "dna_hash", "lifecycle", "commitment", "anchor"} or
            evidence["schema"] != "holochain-music/local-v2-verified-evidence/v1" or
            evidence["owner_agent"] != owner_agent or evidence["dna_hash"] != dna_hash or
            not isinstance(delivery, dict) or set(delivery) != {"grant", "anchor_action"} or
            not isinstance(evidence["lifecycle"], list)):
        raise StorageError("no trusted offline v2 authority snapshot")
    lifecycle = kl.resolve_key_lifecycle([_row(row) for row in evidence["lifecycle"]],
                                         owner_agent, OWNER_PURPOSE, dna_hash)
    commitment, anchor = _row(evidence["commitment"]), _row(evidence["anchor"])
    if delivery["anchor_action"] != anchor.action_hash:
        raise StorageError("offline anchor differs from verified delivery")
    return verify_access_grant_v2(
        delivery["grant"], signed_manifest=signed_manifest, owner_lifecycle=lifecycle,
        commitment=commitment, anchor=anchor, listener_agent=listener_agent,
        recipient_public=recipient_public, now=now)
