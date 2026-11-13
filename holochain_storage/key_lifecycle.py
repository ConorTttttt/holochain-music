"""S2 key lifecycle v2.1: rotation, recovery, revocation and host-attributed
replica receipts (``holochain-storage/replica-receipt/v2``).

Opt-in, for the separately versioned v2.1 storage DNA (``dna-v21/``). The v1
and v2 identity paths in :mod:`holochain_storage.holochain_identity` and the
S1 receipt in :mod:`holochain_storage.package` are unchanged.

Authority model
* The Holochain agent (action author) is the only authority for every
  lifecycle step. A media signing key never authorises a lifecycle step by
  itself: possessing another agent's Ed25519 media key does not let anyone
  author an action as that agent.
* Every new key proves possession by signing the complete transition.
* A normal rotation also carries a continuity signature by the predecessor
  key over the same complete transition. A recovery has none and is labelled
  ``recovered-without-continuity``.

Ordering is the author's own source chain (``action_seq`` and predecessor
references), never a timestamp. Private keys are never sent to a zome.

The trust boundary is unchanged from S2: a :class:`SequencedRecord` must come
from a trusted, validating local conductor (author and chain position are the
validated action's, not body fields).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .holochain_identity import HOST_PURPOSE, OWNER_PURPOSE
from .package import (
    StorageError, _read_verified_chunk, _store_chunk, _verify_signed, _assert_manifest,
    manifest_digest, public_key_bytes, verify_package,
)

LIFECYCLE_SCHEMA = "holochain-storage/key-lifecycle/v2.1"
REVOCATION_SCHEMA = "holochain-storage/key-revocation/v2.1"
LIFECYCLE_DOMAIN = b"holochain-storage/key-lifecycle/v2.1\x00"
ROLE_SUCCESSOR = "successor-possession"
ROLE_PREDECESSOR = "predecessor-continuity"
INCEPTION, ROTATION, RECOVERY = "inception", "rotation", "recovery"
AUTHORITY_AGENT = "holochain-agent"
SCOPE_NEW_OPERATIONS = "new-operations"
SCOPE_COMPROMISED = "compromised"
MAX_GENERATION = 1_000_000

TRANSITION_FIELDS = frozenset({
    "schema", "dna_hash", "agent", "purpose", "generation", "kind", "signing_key_hex",
    "predecessor_action", "predecessor_key_hex", "proof_signature_hex", "continuity_signature_hex"})
REVOCATION_FIELDS = frozenset({
    "schema", "dna_hash", "agent", "purpose", "generation", "signing_key_hex", "target_action",
    "authority", "scope"})

# Validity verdicts (identical spelling to Media Core's KeyValidity).
ACTIVE, ROTATED, REVOKED = "Active", "Rotated", "Revoked"
HISTORICAL_ONLY, AMBIGUOUS, INVALID = "HistoricalOnly", "Ambiguous", "Invalid"
# Continuity labels.
CONTINUITY_INCEPTION = "inception"
CONTINUITY_ROTATION = "rotation"
CONTINUITY_RECOVERED = "recovered-without-continuity"
# Uses.
NEW_OPERATION = "new-operation"
HISTORICAL = "historical"

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_128 = re.compile(r"[0-9a-f]{128}\Z")
_MAX_TEXT = 160


class LifecycleError(StorageError):
    """A lifecycle could not be resolved. ``verdict`` is the KeyValidity it maps to."""

    def __init__(self, message: str, verdict: str = INVALID):
        super().__init__(message)
        self.verdict = verdict


@dataclass(frozen=True)
class SequencedRecord:
    """A lifecycle or anchor record from a *trusted conductor*, with the
    validated action author, action hash and position on the author's chain."""

    author: str
    action_hash: str
    action_seq: int
    body: dict[str, Any]


@dataclass(frozen=True)
class ChainAnchor:
    """Position of an agent-authored record (a file commitment, a replica
    claim) on its author's chain, from a trusted conductor."""

    author: str
    action_seq: int


# ---- canonical messages --------------------------------------------------

def _lp(out: bytearray, field_value: str) -> None:
    if not isinstance(field_value, str):
        raise StorageError("lifecycle fields must be strings")
    raw = field_value.encode("utf-8")
    out += len(raw).to_bytes(4, "big") + raw


def transition_message(role: str, dna_hash: str, agent: str, purpose: str, generation: str,
                       kind: str, signing_key_hex: str, predecessor_action: str,
                       predecessor_key_hex: str) -> bytes:
    """Exact signed bytes: ``LIFECYCLE_DOMAIN || u32be(len(f)) || f`` for f in
    role, schema, dna_hash, agent, purpose, generation, kind, signing_key_hex,
    predecessor_action, predecessor_key_hex (UTF-8)."""
    out = bytearray(LIFECYCLE_DOMAIN)
    for value in (role, LIFECYCLE_SCHEMA, dna_hash, agent, purpose, generation, kind,
                  signing_key_hex, predecessor_action, predecessor_key_hex):
        _lp(out, value)
    return bytes(out)


def _message_for(body: dict[str, str], role: str) -> bytes:
    return transition_message(role, body["dna_hash"], body["agent"], body["purpose"],
                              body["generation"], body["kind"], body["signing_key_hex"],
                              body["predecessor_action"], body["predecessor_key_hex"])


def parse_generation(text: Any) -> int:
    if (not isinstance(text, str) or not text or len(text) > 7 or not text.isascii()
            or not text.isdigit() or text.startswith("0")):
        raise LifecycleError("invalid key generation")
    value = int(text)
    if not 1 <= value <= MAX_GENERATION:
        raise LifecycleError("invalid key generation")
    return value


def _identity(text: Any, label: str) -> str:
    if not isinstance(text, str) or not text or len(text) > _MAX_TEXT or "\x00" in text:
        raise StorageError(f"invalid {label}")
    return text


def _purpose(purpose: Any) -> str:
    if purpose not in (OWNER_PURPOSE, HOST_PURPOSE):
        raise LifecycleError("unsupported signing key purpose")
    return purpose


# ---- creating lifecycle entries (signed locally) --------------------------

def _signer(key: Any) -> Ed25519PrivateKey:
    if not isinstance(key, Ed25519PrivateKey):
        raise StorageError("Ed25519 signing key required")
    return key


def make_inception(signing_key: Ed25519PrivateKey, *, dna_hash: str, agent: str,
                   purpose: str) -> dict[str, str]:
    """Generation 1 for ``purpose``. Only public data leaves this process."""
    _signer(signing_key)
    body = {"schema": LIFECYCLE_SCHEMA, "dna_hash": _identity(dna_hash, "DNA hash"),
            "agent": _identity(agent, "agent"), "purpose": _purpose(purpose), "generation": "1",
            "kind": INCEPTION, "signing_key_hex": public_key_bytes(signing_key).hex(),
            "predecessor_action": "", "predecessor_key_hex": "", "proof_signature_hex": "",
            "continuity_signature_hex": ""}
    body["proof_signature_hex"] = signing_key.sign(_message_for(body, ROLE_SUCCESSOR)).hex()
    return body


def _successor(new_key: Ed25519PrivateKey, *, kind: str, dna_hash: str, agent: str, purpose: str,
               predecessor_action: str, predecessor_key_hex: str, predecessor_generation: str,
               ) -> dict[str, str]:
    _signer(new_key)
    generation = str(parse_generation(predecessor_generation) + 1)
    if not _HEX_64.fullmatch(predecessor_key_hex or ""):
        raise StorageError("invalid predecessor key")
    new_hex = public_key_bytes(new_key).hex()
    if new_hex == predecessor_key_hex:
        raise StorageError("a successor must use a new signing key")
    body = {"schema": LIFECYCLE_SCHEMA, "dna_hash": _identity(dna_hash, "DNA hash"),
            "agent": _identity(agent, "agent"), "purpose": _purpose(purpose),
            "generation": generation, "kind": kind, "signing_key_hex": new_hex,
            "predecessor_action": _identity(predecessor_action, "predecessor action"),
            "predecessor_key_hex": predecessor_key_hex, "proof_signature_hex": "",
            "continuity_signature_hex": ""}
    body["proof_signature_hex"] = new_key.sign(_message_for(body, ROLE_SUCCESSOR)).hex()
    return body


def make_rotation(new_key: Ed25519PrivateKey, predecessor_key: Ed25519PrivateKey, *,
                  dna_hash: str, agent: str, purpose: str, predecessor_action: str,
                  predecessor_generation: str) -> dict[str, str]:
    """Normal rotation: the new key proves possession and the predecessor key
    signs continuity over the complete transition."""
    _signer(predecessor_key)
    body = _successor(new_key, kind=ROTATION, dna_hash=dna_hash, agent=agent, purpose=purpose,
                      predecessor_action=predecessor_action,
                      predecessor_key_hex=public_key_bytes(predecessor_key).hex(),
                      predecessor_generation=predecessor_generation)
    body["continuity_signature_hex"] = predecessor_key.sign(_message_for(body, ROLE_PREDECESSOR)).hex()
    return body


def make_recovery(new_key: Ed25519PrivateKey, *, dna_hash: str, agent: str, purpose: str,
                  predecessor_action: str, predecessor_key_hex: str,
                  predecessor_generation: str) -> dict[str, str]:
    """Recovery after a lost or compromised predecessor key: authorised by the
    agent alone (the action author), no continuity signature."""
    return _successor(new_key, kind=RECOVERY, dna_hash=dna_hash, agent=agent, purpose=purpose,
                      predecessor_action=predecessor_action, predecessor_key_hex=predecessor_key_hex,
                      predecessor_generation=predecessor_generation)


def make_revocation(*, dna_hash: str, agent: str, purpose: str, generation: str,
                    signing_key_hex: str, target_action: str, scope: str) -> dict[str, str]:
    """Agent-authorised revocation of one exact generation. No key signs it:
    the Holochain agent is the revocation authority."""
    if scope not in (SCOPE_NEW_OPERATIONS, SCOPE_COMPROMISED):
        raise LifecycleError("unsupported revocation scope")
    parse_generation(generation)
    if not _HEX_64.fullmatch(signing_key_hex or ""):
        raise StorageError("invalid public key encoding")
    return {"schema": REVOCATION_SCHEMA, "dna_hash": _identity(dna_hash, "DNA hash"),
            "agent": _identity(agent, "agent"), "purpose": _purpose(purpose), "generation": generation,
            "signing_key_hex": signing_key_hex, "target_action": _identity(target_action, "target action"),
            "authority": AUTHORITY_AGENT, "scope": scope}


# ---- verification and resolution -----------------------------------------

def _verify(key_hex: str, signature_hex: str, message: bytes, what: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(signature_hex), message)
    except (InvalidSignature, ValueError) as exc:
        raise LifecycleError(f"{what} does not verify") from exc


def _checked(record: Any, agent: str, dna_hash: str) -> tuple[str, dict[str, str]]:
    """Structure + signatures of one record. Returns (schema, body)."""
    if (not isinstance(record, SequencedRecord) or not isinstance(record.body, dict)
            or not isinstance(record.action_hash, str) or not record.action_hash
            or type(record.action_seq) is not int or not 0 <= record.action_seq < 2**32):
        raise LifecycleError("missing authenticated Holochain record")
    if record.author != agent:
        raise LifecycleError("Holochain action author mismatch")
    body = record.body
    schema = body.get("schema")
    fields = {LIFECYCLE_SCHEMA: TRANSITION_FIELDS, REVOCATION_SCHEMA: REVOCATION_FIELDS}.get(schema)
    if fields is None or set(body) != fields or any(not isinstance(v, str) for v in body.values()):
        raise LifecycleError("invalid Holochain storage record")
    if body["agent"] != agent:
        raise LifecycleError("signing key not bound to expected agent/purpose")
    if body["dna_hash"] != dna_hash:
        raise LifecycleError("key lifecycle entry is for a different DNA")
    _purpose(body["purpose"])
    parse_generation(body["generation"])
    if not _HEX_64.fullmatch(body["signing_key_hex"]):
        raise LifecycleError("invalid public key encoding")
    if schema == REVOCATION_SCHEMA:
        if body["authority"] != AUTHORITY_AGENT or body["scope"] not in (SCOPE_NEW_OPERATIONS, SCOPE_COMPROMISED):
            raise LifecycleError("unsupported revocation authority or scope")
        return schema, body
    if not _HEX_128.fullmatch(body["proof_signature_hex"]):
        raise LifecycleError("invalid proof signature encoding")
    kind = body["kind"]
    if kind == INCEPTION:
        if body["generation"] != "1" or body["predecessor_action"] or body["predecessor_key_hex"] \
                or body["continuity_signature_hex"]:
            raise LifecycleError("invalid inception")
    elif kind in (ROTATION, RECOVERY):
        if (not body["predecessor_action"] or len(body["predecessor_action"]) > _MAX_TEXT
                or not _HEX_64.fullmatch(body["predecessor_key_hex"])):
            raise LifecycleError("invalid predecessor reference")
        if kind == ROTATION:
            if not _HEX_128.fullmatch(body["continuity_signature_hex"]):
                raise LifecycleError("invalid continuity signature encoding")
            _verify(body["predecessor_key_hex"], body["continuity_signature_hex"],
                    _message_for(body, ROLE_PREDECESSOR), "continuity signature")
        elif body["continuity_signature_hex"]:
            raise LifecycleError("a recovery carries no continuity signature")
    else:
        raise LifecycleError("unsupported key transition kind")
    _verify(body["signing_key_hex"], body["proof_signature_hex"], _message_for(body, ROLE_SUCCESSOR),
            "proof of possession")
    return schema, body


@dataclass
class KeyGeneration:
    generation: int
    key: bytes
    action_hash: str
    action_seq: int
    kind: str
    # Position after which this key may not authorise new operations
    # (its successor or its first revocation); None while active.
    end_seq: int | None = None
    # Earliest compromised revocation position, if any.
    compromised_seq: int | None = None
    revoked_scopes: list[str] = field(default_factory=list)

    @property
    def continuity(self) -> str:
        return {INCEPTION: CONTINUITY_INCEPTION, ROTATION: CONTINUITY_ROTATION}.get(
            self.kind, CONTINUITY_RECOVERED)


@dataclass
class KeyLifecycle:
    agent: str
    purpose: str
    dna_hash: str
    generations: list[KeyGeneration]

    @property
    def tip(self) -> KeyGeneration:
        return self.generations[-1]

    def active(self) -> KeyGeneration:
        tip = self.tip
        if tip.revoked_scopes:
            raise LifecycleError("the current key is revoked", REVOKED)
        return tip

    def find(self, key: bytes) -> KeyGeneration:
        for g in self.generations:
            if g.key == key:
                return g
        raise LifecycleError("signing key not bound to expected agent/purpose")

    def classify(self, key: bytes, use: str, anchor: ChainAnchor | None = None) -> str:
        """KeyValidity of ``key`` for ``use`` (see docs: historical policy)."""
        try:
            g = self.find(key)
        except LifecycleError:
            return INVALID
        active_now = g is self.tip and not g.revoked_scopes
        if use == NEW_OPERATION:
            if active_now:
                return ACTIVE
            return REVOKED if g.revoked_scopes else ROTATED
        if use != HISTORICAL:
            return INVALID
        if anchor is not None:
            if not isinstance(anchor, ChainAnchor) or anchor.author != self.agent:
                return INVALID
            if g.end_seq is not None and anchor.action_seq > g.end_seq:
                # The agent anchored this artifact after the key stopped being
                # valid for new operations: it is a new operation with a stale key.
                return REVOKED if g.revoked_scopes else ROTATED
            return ACTIVE if active_now else HISTORICAL_ONLY
        if g.compromised_seq is not None:
            return REVOKED
        return ACTIVE if active_now else HISTORICAL_ONLY

    def require(self, key: bytes, use: str, anchor: ChainAnchor | None = None) -> KeyGeneration:
        verdict = self.classify(key, use, anchor)
        if verdict not in (ACTIVE, HISTORICAL_ONLY):
            raise LifecycleError(f"signing key is not acceptable for this use: {verdict}", verdict)
        return self.find(key)


def resolve_key_lifecycle(records: list[SequencedRecord], agent: str, purpose: str,
                          dna_hash: str) -> KeyLifecycle:
    """Verify every v2.1 record for ``agent``/``purpose`` and rebuild the
    single lineage by predecessor references. Fails closed: an invalid record
    is an error (never skipped), forks are ``Ambiguous``, a gap is an error."""
    _identity(agent, "agent")
    _identity(dna_hash, "DNA hash")
    _purpose(purpose)
    selected: dict[str, SequencedRecord] = {}
    for r in records:
        if not isinstance(r, SequencedRecord) or not isinstance(r.body, dict):
            continue
        if (r.body.get("schema") in (LIFECYCLE_SCHEMA, REVOCATION_SCHEMA)
                and r.body.get("agent") == agent and r.body.get("purpose") == purpose):
            prior = selected.get(r.action_hash)
            if prior is not None and prior != r:
                raise LifecycleError("conflicting records for one action")
            selected[r.action_hash] = r
    if not selected:
        raise LifecycleError("no key lifecycle for this agent/purpose")
    transitions, revocations = [], []
    for r in selected.values():
        schema, body = _checked(r, agent, dna_hash)
        (transitions if schema == LIFECYCLE_SCHEMA else revocations).append((r, body))
    inceptions = [t for t in transitions if t[1]["kind"] == INCEPTION]
    if len(inceptions) > 1:
        raise LifecycleError("more than one inception for this purpose", AMBIGUOUS)
    if not inceptions:
        raise LifecycleError("key lifecycle incomplete: no inception")
    record, body = inceptions[0]
    generations = [KeyGeneration(1, bytes.fromhex(body["signing_key_hex"]), record.action_hash,
                                 record.action_seq, INCEPTION)]
    visited = {record.action_hash}
    while True:
        current = generations[-1]
        successors = [t for t in transitions if t[1]["predecessor_action"] == current.action_hash]
        if not successors:
            break
        if len(successors) > 1:
            raise LifecycleError("competing successors for one generation", AMBIGUOUS)
        record, body = successors[0]
        key = bytes.fromhex(body["signing_key_hex"])
        if (parse_generation(body["generation"]) != current.generation + 1
                or body["predecessor_key_hex"] != current.key.hex()
                or any(g.key == key for g in generations)
                or record.action_seq <= current.action_seq):
            raise LifecycleError("invalid successor transition")
        generations.append(KeyGeneration(current.generation + 1, key, record.action_hash,
                                         record.action_seq, body["kind"]))
        visited.add(record.action_hash)
    if len(visited) != len(transitions):
        raise LifecycleError("key lifecycle incomplete: transition with unknown predecessor")
    by_action = {g.action_hash: g for g in generations}
    for i, g in enumerate(generations[:-1]):
        g.end_seq = generations[i + 1].action_seq
    for record, body in sorted(revocations, key=lambda x: x[0].action_seq):
        target = by_action.get(body["target_action"])
        if target is None:
            raise LifecycleError("key lifecycle incomplete: revocation of unknown transition")
        if (str(target.generation) != body["generation"] or target.key.hex() != body["signing_key_hex"]
                or record.action_seq <= target.action_seq or body["scope"] in target.revoked_scopes
                or SCOPE_COMPROMISED in target.revoked_scopes):
            raise LifecycleError("invalid revocation")
        target.revoked_scopes.append(body["scope"])
        target.end_seq = record.action_seq if target.end_seq is None else min(target.end_seq, record.action_seq)
        if body["scope"] == SCOPE_COMPROMISED:
            target.compromised_seq = record.action_seq
    # A rotation (continuity) may not follow a revoked key (the DNA enforces this).
    for i, g in enumerate(generations[1:], start=1):
        prev = generations[i - 1]
        if g.kind == ROTATION and prev.revoked_scopes and prev.end_seq is not None and prev.end_seq < g.action_seq:
            raise LifecycleError("rotation after revocation")
    return KeyLifecycle(agent, purpose, dna_hash, generations)


def evaluate_key(records: list[SequencedRecord], agent: str, purpose: str, dna_hash: str,
                 key_hex: str, use: str, anchor: ChainAnchor | None = None) -> str:
    """Total classifier: one of Active, Rotated, Revoked, HistoricalOnly,
    Ambiguous, Invalid."""
    try:
        lifecycle = resolve_key_lifecycle(records, agent, purpose, dna_hash)
    except LifecycleError as exc:
        return exc.verdict
    except StorageError:
        return INVALID
    if not isinstance(key_hex, str) or not _HEX_64.fullmatch(key_hex):
        return INVALID
    return lifecycle.classify(bytes.fromhex(key_hex), use, anchor)


# ---- host-attributed replica receipts (replica-receipt/v2) -----------------

RECEIPT_V2_SCHEMA = "holochain-storage/replica-receipt/v2"
RECEIPT_V2_DOMAIN = b"holochain-storage/replica-receipt/v2\x00"
RECEIPT_V2_CONTEXT = "replica-acceptance"
RECEIPT_V2_SIGNED_FIELDS = (
    "schema", "dna_hash", "host_agent", "host_key_hex", "host_key_generation", "host_key_action",
    "owner_agent", "file_id", "manifest_sha256", "chunk_count", "received_at", "context")
RECEIPT_V2_FIELDS = frozenset(RECEIPT_V2_SIGNED_FIELDS) | {"signature_hex"}
MAX_RECEIPT_V2_BYTES = 4096
_RECEIVED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_COUNT = re.compile(r"[1-9][0-9]{0,6}\Z")


def receipt_v2_message(body: dict[str, str]) -> bytes:
    """``RECEIPT_V2_DOMAIN || u32be(len(f)) || f`` over the signed fields in
    their fixed order. No JSON canonicalisation is involved."""
    out = bytearray(RECEIPT_V2_DOMAIN)
    for name in RECEIPT_V2_SIGNED_FIELDS:
        _lp(out, body[name])
    return bytes(out)


def receipt_v2_digest(receipt: dict[str, str]) -> str:
    """SHA-256 of the signed message: the ``receipt_sha256`` a v2.1 replica
    claim names for a v2 receipt."""
    return hashlib.sha256(receipt_v2_message(receipt)).hexdigest()


def receipt_v2_bytes(receipt: dict[str, str]) -> bytes:
    """Transport encoding (any JSON object with exactly these string fields is
    accepted by verifiers; this one is sorted and compact)."""
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _received_at_ok(text: str) -> bool:
    if not _RECEIVED_AT.fullmatch(text):
        return False
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign_replica_receipt_v2(package: dict[str, Any], *, node_key: Ed25519PrivateKey, dna_hash: str,
                            host_agent: str, host_key_generation: str, host_key_action: str,
                            owner_agent: str, trusted_artist: bytes,
                            received_at: str | None = None) -> dict[str, str]:
    """Sign a v2 receipt for an already verified complete replica."""
    _signer(node_key)
    manifest = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(manifest)
    parse_generation(host_key_generation)
    body = {"schema": RECEIPT_V2_SCHEMA, "dna_hash": _identity(dna_hash, "DNA hash"),
            "host_agent": _identity(host_agent, "host agent"),
            "host_key_hex": public_key_bytes(node_key).hex(), "host_key_generation": host_key_generation,
            "host_key_action": _identity(host_key_action, "host key action"),
            "owner_agent": _identity(owner_agent, "owner agent"), "file_id": manifest["file_id"],
            "manifest_sha256": manifest_digest(package), "chunk_count": str(len(manifest["chunks"])),
            "received_at": received_at or _utc_now(), "context": RECEIPT_V2_CONTEXT}
    if not _received_at_ok(body["received_at"]):
        raise StorageError("invalid receipt timestamp")
    body["signature_hex"] = node_key.sign(receipt_v2_message(body)).hex()
    return body


def replicate_package_v2(package: dict[str, Any], source_store: str | Path, replica_store: str | Path,
                         trusted_artist: bytes, node_key: Ed25519PrivateKey, **attribution: str) -> dict[str, str]:
    """Like S1 ``replicate_package`` (complete verified copy), but signs a
    host-attributed v2 receipt. The S1 receipt format is unchanged."""
    body = verify_package(package, source_store, trusted_artist)
    for chunk in body["chunks"]:
        _store_chunk(Path(replica_store), _read_verified_chunk(Path(source_store), chunk))
    verify_package(package, replica_store, trusted_artist)
    return sign_replica_receipt_v2(package, node_key=node_key, trusted_artist=trusted_artist, **attribution)


def verify_replica_receipt_v2(receipt: Any, package: dict[str, Any], *, trusted_artist: bytes,
                              dna_hash: str, host_agent: str, owner_agent: str,
                              host_lifecycle: KeyLifecycle, use: str = HISTORICAL,
                              anchor: ChainAnchor | None = None) -> dict[str, str]:
    """Verify a v2 receipt: exact fields, this DNA, this host agent and owner,
    this exact signed package, a host key generation from the host's verified
    lifecycle acceptable for ``use`` (historical by default: a receipt is a
    historical acceptance claim, not proof of current custody)."""
    if isinstance(receipt, (bytes, bytearray)):
        if len(receipt) > MAX_RECEIPT_V2_BYTES:
            raise StorageError("receipt exceeds size limit")
        try:
            receipt = json.loads(receipt)
        except (ValueError, UnicodeDecodeError) as exc:
            raise StorageError("invalid receipt format") from exc
    if (not isinstance(receipt, dict) or set(receipt) != RECEIPT_V2_FIELDS
            or any(not isinstance(v, str) for v in receipt.values())):
        raise StorageError("invalid receipt format")
    if receipt["schema"] != RECEIPT_V2_SCHEMA or receipt["context"] != RECEIPT_V2_CONTEXT:
        raise StorageError("invalid receipt format")
    if receipt["dna_hash"] != dna_hash:
        raise StorageError("receipt is for a different DNA")
    if receipt["host_agent"] != host_agent or host_lifecycle.agent != host_agent \
            or host_lifecycle.purpose != HOST_PURPOSE or host_lifecycle.dna_hash != dna_hash:
        raise StorageError("receipt names a different host")
    if receipt["owner_agent"] != owner_agent:
        raise StorageError("receipt names a different owner")
    manifest = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(manifest)
    if receipt["file_id"] != manifest["file_id"] or receipt["manifest_sha256"] != manifest_digest(package):
        raise StorageError("receipt references different package")
    if not _COUNT.fullmatch(receipt["chunk_count"]) or int(receipt["chunk_count"]) != len(manifest["chunks"]):
        raise StorageError("receipt chunk count mismatch")
    if not _received_at_ok(receipt["received_at"]):
        raise StorageError("invalid receipt timestamp")
    if not _HEX_64.fullmatch(receipt["host_key_hex"]) or not _HEX_128.fullmatch(receipt["signature_hex"]):
        raise StorageError("invalid receipt format")
    generation = host_lifecycle.require(bytes.fromhex(receipt["host_key_hex"]), use, anchor)
    if (str(generation.generation) != receipt["host_key_generation"]
            or generation.action_hash != receipt["host_key_action"]):
        raise StorageError("receipt host key generation does not match the host's lifecycle")
    try:
        Ed25519PublicKey.from_public_bytes(generation.key).verify(
            bytes.fromhex(receipt["signature_hex"]), receipt_v2_message(receipt))
    except (InvalidSignature, ValueError) as exc:
        raise StorageError("invalid receipt signature") from exc
    return receipt
