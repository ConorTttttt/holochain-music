"""Replay-resistant *spot-check* challenges for encrypted full replicas.

A successful challenge proves that one signer could return the selected,
authenticated ciphertext chunks at the time of the check; it is NOT a
formal proof of retrievability or of independent physical node custody.

This is a local protocol prototype: a production verifier must persist its
challenge registry, authenticate agents through S2, and enforce rate limits
and deadlines at the transport boundary. No challenges, response bytes, or
secrets belong on the Holochain DHT.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .package import (
    StorageError, _assert_manifest, _read_verified_chunk, _sign, _verify_signed,
    b64, canonical, from_b64, manifest_digest, public_key_bytes, sha256,
)

CHALLENGE_SCHEMA = "holochain-storage/audit-challenge/v1"
RESPONSE_SCHEMA = "holochain-storage/audit-response/v1"
MAX_SAMPLE_COUNT = 8
MAX_SAMPLE_CIPHER_BYTES = 5 * 1024 * 1024
MAX_CHALLENGE_TTL = 300  # seconds
MAX_PENDING_CHALLENGES = 4096


def _clock(now: int | None) -> int:
    result = int(time.time()) if now is None else now
    if type(result) is not int or result < 0:
        raise StorageError("invalid audit clock")
    return result


def _validated_challenge(challenge: Any, manifest: dict[str, Any], node_key: bytes) -> dict[str, Any]:
    if not isinstance(challenge, dict) or set(challenge) != {
        "schema", "manifest_sha256", "file_id", "node_key", "nonce",
        "issued_at", "expires_at", "indices",
    } or challenge["schema"] != CHALLENGE_SCHEMA:
        raise StorageError("invalid storage challenge")
    if challenge["manifest_sha256"] != manifest_digest(manifest) or challenge["file_id"] != manifest["body"]["file_id"]:
        raise StorageError("challenge targets a different package")
    if from_b64(challenge["node_key"], 32) != node_key:
        raise StorageError("challenge targets a different node")
    from_b64(challenge["nonce"], 32)
    issued, expires = challenge["issued_at"], challenge["expires_at"]
    if type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= MAX_CHALLENGE_TTL:
        raise StorageError("invalid challenge lifetime")
    chunks, indices = manifest["body"]["chunks"], challenge["indices"]
    if (not isinstance(indices, list) or not 1 <= len(indices) <= MAX_SAMPLE_COUNT
        or any(type(i) is not int or i < 0 or i >= len(chunks) for i in indices)
        or indices != sorted(set(indices))):
        raise StorageError("invalid challenge sample indices")
    if sum(chunks[i]["cipher_bytes"] for i in indices) > MAX_SAMPLE_CIPHER_BYTES:
        raise StorageError("challenge exceeds ciphertext budget")
    return challenge


def make_challenge(package: dict[str, Any], trusted_artist: bytes, trusted_node: bytes,
                   *, sample_count: int = 4, ttl_seconds: int = 60,
                   now: int | None = None) -> dict[str, Any]:
    """Select unpredictable positions using a CSPRNG, bound by an audit byte budget.

    No challenge for an empty file: there are no bytes to inspect.
    Node keys are expected to be independently authenticated (S2).
    """
    body = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(body)
    if len(body["chunks"]) == 0:
        raise StorageError("empty packages have no ciphertext to challenge")
    if not isinstance(trusted_node, bytes) or len(trusted_node) != 32:
        raise StorageError("invalid trusted storage node key")
    if type(sample_count) is not int or not 1 <= sample_count <= MAX_SAMPLE_COUNT:
        raise StorageError("invalid challenge sample count")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_CHALLENGE_TTL:
        raise StorageError("invalid challenge TTL")
    picked, used = [], 0
    # Shuffle with a cryptographically secure RNG; sample without replacement.
    possibilities = list(range(len(body["chunks"])))
    secrets.SystemRandom().shuffle(possibilities)
    for i in possibilities:
        size = body["chunks"][i]["cipher_bytes"]
        if used + size <= MAX_SAMPLE_CIPHER_BYTES:
            picked.append(i)
            used += size
            if len(picked) >= sample_count:
                break
    if not picked:
        raise StorageError("no sample fits audit byte budget")
    t = _clock(now)
    return {
        "schema": CHALLENGE_SCHEMA,
        "manifest_sha256": manifest_digest(package), "file_id": body["file_id"],
        "node_key": b64(trusted_node), "nonce": b64(os.urandom(32)),
        "issued_at": t, "expires_at": t + ttl_seconds, "indices": sorted(picked),
    }


def answer_challenge(challenge: dict[str, Any], package: dict[str, Any],
                     node_store: str, trusted_artist: bytes,
                     node_private: Ed25519PrivateKey) -> dict[str, Any]:
    """Node signs *actual ciphertext*, never content keys or plaintext.

    The node must fetch all requested chunks and verify each digest. An
    ordinary signature over the manifest alone cannot answer this audit.
    """
    body = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(body)
    _validated_challenge(challenge, package, public_key_bytes(node_private))
    samples = []
    for i in challenge["indices"]:
        ciphertext = _read_verified_chunk(node_store, body["chunks"][i])
        samples.append({"index": i, "ciphertext": b64(ciphertext)})
    return _sign({
        "schema": RESPONSE_SCHEMA,
        "challenge_sha256": sha256(canonical(challenge)),
        "samples": samples,
    }, node_private)


def verify_challenge_response(challenge: dict[str, Any], response: dict[str, Any],
                              package: dict[str, Any], trusted_artist: bytes,
                              trusted_node: bytes) -> int:
    """Verify signed ciphertext samples. Caller MUST enforce challenge freshness/one-shot use."""
    body = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(body)
    _validated_challenge(challenge, package, trusted_node)
    payload = _verify_signed(response, trusted_node, "audit response")
    if set(payload) != {"schema", "challenge_sha256", "samples"} or payload["schema"] != RESPONSE_SCHEMA:
        raise StorageError("invalid audit response")
    if payload["challenge_sha256"] != sha256(canonical(challenge)):
        raise StorageError("audit response does not match challenge")
    samples = payload["samples"]
    if not isinstance(samples, list) or len(samples) != len(challenge["indices"]):
        raise StorageError("wrong audit sample count")
    for i, sample in zip(challenge["indices"], samples):
        if not isinstance(sample, dict) or set(sample) != {"index", "ciphertext"} or type(sample["index"]) is not int or sample["index"] != i:
            raise StorageError("wrong audit sample position")
        encoded = sample["ciphertext"]
        # Bound decoding before allocating for an attacker-controlled string.
        expected = body["chunks"][i]
        if not isinstance(encoded, str) or len(encoded) > 4 * ((expected["cipher_bytes"] + 2) // 3):
            raise StorageError("oversized audit sample")
        raw = from_b64(encoded, expected["cipher_bytes"])
        if sha256(raw) != expected["sha256"]:
            raise StorageError("audit sample failed ciphertext integrity")
    return len(samples)


@dataclass(frozen=True)
class AuditResult:
    manifest_sha256: str
    node_key: str
    nonce: str
    sampled_chunks: int
    verified_at: int


class AuditVerifier:
    """One-use, short-lived outstanding challenge registry (in-memory v1).

    Untrusted responses consume a matching challenge *before* verification:
    invalid responses cannot be retried indefinitely. Do not use standalone
    `verify_challenge_response` as an acceptance path without freshness state.
    """

    def __init__(self) -> None:
        self._pending: dict[str, dict[str, Any]] = {}

    def issue(self, package: dict[str, Any], trusted_artist: bytes, trusted_node: bytes,
              *, sample_count: int = 4, ttl_seconds: int = 60,
              now: int | None = None) -> dict[str, Any]:
        clock = _clock(now)
        # Expired challenges must not accumulate indefinitely in long-lived verifiers.
        self._pending = {nonce: c for nonce, c in self._pending.items() if c["expires_at"] >= clock}
        if len(self._pending) >= MAX_PENDING_CHALLENGES:
            raise StorageError("too many pending audit challenges")
        challenge = make_challenge(package, trusted_artist, trusted_node,
                                   sample_count=sample_count, ttl_seconds=ttl_seconds, now=clock)
        self._pending[challenge["nonce"]] = challenge
        return challenge

    def verify(self, challenge: dict[str, Any], response: dict[str, Any], package: dict[str, Any],
               trusted_artist: bytes, trusted_node: bytes, *, now: int | None = None) -> AuditResult:
        t = _clock(now)
        if not isinstance(challenge, dict) or not isinstance(challenge.get("nonce"), str):
            raise StorageError("unknown audit challenge")
        nonce = challenge["nonce"]
        original = self._pending.pop(nonce, None)
        if original is None or canonical(original) != canonical(challenge):
            raise StorageError("unknown, modified or already-used audit challenge")
        if t < original["issued_at"] or t > original["expires_at"]:
            raise StorageError("audit challenge expired or not yet active")
        count = verify_challenge_response(original, response, package, trusted_artist, trusted_node)
        return AuditResult(original["manifest_sha256"], original["node_key"], nonce, count, t)
