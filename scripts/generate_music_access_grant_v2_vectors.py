#!/usr/bin/env python3
"""Generate independent Music/Python cryptographic vectors for Media Core Rust.

Runs the real Music S1 signing, v2.1 lifecycle and v2 grant/key-wrap
implementations. Rust MUST independently recompute all signatures, canonical
bytes, permissions and chain ordering; no Python verification verdict is
trusted by Rust except as an expected result to compare against.

Usage: python scripts/generate_music_access_grant_v2_vectors.py > /tmp/grants.json
       MUSIC_ACCESS_GRANT_V2_VECTORS=/tmp/grants.json cargo test -p holochain-content-core
"""
from __future__ import annotations

import copy
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from holochain_storage import key_lifecycle as kl
from holochain_storage.package import canonical
from music_catalogue.access_grant_v2 import (
    AccessGrantV2Error, grant_message, grant_wrap_context, verify_access_grant_v2,
)
from test_access_grant_v2 import (
    ALICE, BOB, CAROL, DNA, NOW, checked, make_world, pub, record, signed_grant,
)


def case(name, world, grant, anchor, *,
         recipient=None, listener=BOB, commitment=None, rows=None, expected=None):
    recipient = recipient or world["bob"]
    rows = world["lifecycle_rows"] if rows is None else rows
    lifecycle = kl.resolve_key_lifecycle(rows, ALICE, kl.OWNER_PURPOSE, DNA)
    commitment = commitment or world["commitment"]
    if expected is None:
        try:
            verified = verify_access_grant_v2(
                grant, signed_manifest=world["manifest"], owner_lifecycle=lifecycle,
                commitment=commitment, anchor=anchor, listener_agent=listener,
                recipient_public=pub(recipient), now=NOW + 120)
            verified.authorize("stream")
            expected = {"category": "ok", "reason": "ok"}
        except AccessGrantV2Error as exc:
            expected = {"category": exc.category, "reason": exc.reason}
    return {
        "name": name, "grant_text": canonical(grant).decode("utf-8"),
        "anchor": asdict(anchor) if anchor is not None else None,
        "commitment": asdict(commitment), "lifecycle_records": [asdict(r) for r in rows],
        "listener_agent": listener, "recipient_key_hex": pub(recipient).hex(),
        "expected": expected,
    }


def main():
    world = make_world()
    grant, anchor = signed_grant(world)
    cases = [case("valid-after-rotation", world, grant, anchor),
             case("no-anchor", world, grant, None),
             case("wrong-recipient", world, grant, anchor, recipient=world["carol"]),
             case("wrong-listener", world, grant, anchor, listener=CAROL)]
    for name, changes in [
        ("wrong-package", {"file_id": "a" * 64}),
        ("wrong-manifest-digest", {"manifest_sha256": "a" * 64}),
        ("modified-unsigned-rights", {"rights": ["export", "stream"]}),
        ("wrong-issuer-generation", {"issuer_key_generation": "1"}),
    ]:
        altered = copy.deepcopy(grant)
        altered["body"].update(changes)
        cases.append(case(name, world, altered, anchor))
    bad_anchor = copy.deepcopy(anchor)
    bad_anchor.body["grant_commitment"] = "f" * 64
    cases.append(case("bad-anchor-commitment", world, grant, bad_anchor))
    duplicate_id = copy.deepcopy(anchor)
    duplicate_id.body["grant_id"] = "f" * 32
    cases.append(case("reused-anchor-id", world, grant, duplicate_id))
    later_commitment = record(ALICE, "late-commit", 8, world["commitment"].body)
    cases.append(case("invalid-historical-commit", world, grant, anchor,
                      commitment=later_commitment, expected={
                          "category": "unauthenticated", "reason": "InvalidHistoricalKey"}))
    revocation = kl.make_revocation(
        dna_hash=DNA, agent=ALICE, purpose=kl.OWNER_PURPOSE,
        generation="2", signing_key_hex=world["g2"].public_key()
        .public_bytes_raw().hex(), target_action="alice-g2", scope=kl.SCOPE_COMPROMISED)
    rev_rows = world["lifecycle_rows"] + [record(ALICE, "revoke-g2", 8, revocation)]
    cases.append(case("revoked-after-anchor-preserves-old", world, grant, anchor,
                      rows=rev_rows))
    late = record(ALICE, "late-anchor", 9, anchor.body)
    cases.append(case("revoked-before-anchor", world, grant, late, rows=rev_rows))
    vectors = {
        "schema": "holochain-media-core/music-access-grant-v2-vectors/v1",
        "generator": "holochain-music/scripts/generate_music_access_grant_v2_vectors.py",
        "source": "Music S1 + Python cryptography + v2.1 lifecycle",
        "dna_hash": DNA,
        "owner_agent": ALICE,
        "manifest_text": canonical(world["manifest"]).decode("utf-8"),
        "signed_message_hex": grant_message(grant["body"]).hex(),
        "wrap_context_hex": grant_wrap_context(grant["body"]).hex(),
        "cases": cases,
    }
    json.dump(vectors, sys.stdout, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
