# S3 — Verifiable encrypted replica audits and repair (prototype)

**Status:** Local protocol slice. Does not require Holochain or MoQ to run. S2's validated agent/host signing-key bindings should be passed in as the `trusted_artist` and `trusted_node` keys once its real-conductor integration is ready. Never trust an unsigned public-key field as authentication.

## What this implements

- An auditor selects a cryptographically random 32-byte challenge nonce and up to eight randomly chosen ciphertext chunk indices from a **signed file manifest**. It binds the expected host key, exact signed-manifest digest, expiration time and index selection.
- The target node reads and SHA-256 verifies the requested ciphertext, then signs a response containing those bytes and a digest of the exact challenge.
- An `AuditVerifier` accepts a response **once** for a registered, unexpired challenge and verifies the expected node signature and every sampled chunk. It consumes invalid responses too. Only short-lived outstanding challenges are kept in memory.
- A conservative local `repair_full_replica` function selects a **fully verified** alternative source, restores missing or corrupt ciphertext chunks, verifies the complete destination and issues a **new** signed acceptance receipt.
- Existing artist-signed X25519-wrapped buyer grants still permit independent plaintext export after the artist goes offline. A new end-to-end regression demonstrates that path following failed storage and repair.

## Run it

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

Minimal use (example only; keys must be authenticated through S2 before production):

```python
from holochain_storage import AuditVerifier, answer_challenge, repair_full_replica

verifier = AuditVerifier()
challenge = verifier.issue(package, artist_pubkey, node_pubkey, sample_count=4)
response = answer_challenge(challenge, package, node_storage_dir, artist_pubkey, node_signing_key)
result = verifier.verify(challenge, response, package, artist_pubkey, node_pubkey)
print(result.sampled_chunks)

# On a failed audit, restore the host's encrypted data from a separate verified copy.
repair = repair_full_replica(package, [alternative_replica_dir], node_storage_dir,
                             artist_pubkey, node_signing_key)
```

## Security statement: what a success proves and what it does not

**Proves:** A holder of the authenticated node's signing key returned the requested signed-manifest-matching ciphertext chunks in response to a fresh, unpredictable challenge before the verifier's expiry deadline.

**Does NOT prove:** The entire file is retrievable (non-sampled chunks may be missing); the node independently stores the chunks (it can fetch them from elsewhere); an auditable persistent lease; secure key custody; data durability under crash or network outage; or mathematically rigorous Proof of Retrievability (PoR). A malicious signer could intentionally withhold or delete any unchallenged content. Host responses must not be posted as media objects or large proofs to the Holochain DHT.

Sampling only gives *detection probability* under assumptions about missing chunks. If `m` of `N` chunks are missing and `k` are sampled uniformly without replacement, the chance of missing all missing chunks is `C(N-m,k)/C(N,k)` when `k <= N-m`. This is not a formal custody proof. Small files may be completely sampled; large files are not.

## What is deliberately deferred

- **Networked storage daemon:** At present a host is a local filesystem directory. Add signed authenticated request/response and constrained streaming over QUIC before claiming a distributed service.
- **Durable replay protection:** `AuditVerifier` holds pending challenges in memory. A production auditor must persist its nonce registry and challenge/result history across restarts, with bounded cleanup and rate limiting.
- **DoS and quotas:** Byte budgets and expiry are enforced on challenge structure. Network gateways still need authentication, upload/download limits, bandwidth quotas, concurrency caps and transport-level deadlines.
- **Multi-file atomic repair:** A restored object is atomically replaced, then the whole file is verified, but a power failure can leave a partially repaired replica. Host should withhold acceptance until complete verification and persist a recovery journal.
- **Adversarial filesystem:** These local functions are not safe when untrusted processes can modify host storage directories, including symlink replacement races. Production host should run with isolated directories and atomic dirfd/openat operations.
- **Verified payments and rights:** Existing perpetual buyer grants do not establish that payment has been made or that the seller is licensed to sell. A separate settlement and rights boundary must be implemented before automatic grant issuance.
- **Holochain integration:** S2 must supply authoritative keys, publish small commitments/results (not bulk challenge bytes), and validate claims against authored records.

## Practical availability policy (proposed, not yet implemented)

1. Start with three complete encrypted replicas across independently operated nodes.
2. Run periodic unpredictable spot checks at random intervals, plus checks after hosting/ownership changes.
3. Record auditor identity, selected manifest, node, time, sampled count, result and latency as small metadata (without exposing raw ciphertext challenge data publicly).
4. On failure, mark the node *suspect* rather than immediately deleting its registration; retry under bounded policy from another verifier and retrieve data from known-good replicas.
5. Restore at least the agreed replication factor by re-replicating from a fully verified source; verify all ciphertext and obtain a new receipt.
6. Define incentives, dispute handling and an independently reviewed rigorous PoR design if contractual claims require it.

Source of truth: [GitHub S3 issue](https://github.com/ConorTttttt/holochain-music/issues/3). The S2 identity PR remains separately reviewable and is not changed by this work.
