"""S9 real-conductor MoQ listener stage for the two-DNA Sweettest.

Everything used to authenticate the MoQ receiver's URL, certificate and
manifest comes from Bob's validating Holochain conductor or S1/S4 signature
verification; the MoQ publisher readiness file is NOT consumed here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from holochain_storage.package import decrypt_package, manifest_digest, sha256, verify_package
from music_catalogue.moq_conductor import receive_moq_from_live_conductor


def main():
    p = argparse.ArgumentParser()
    for arg in ("root", "bridge_binary", "moq_binary"):
        p.add_argument("--" + arg.replace("_", "-"), type=Path, required=True)
    p.add_argument("--node-url", required=True)
    p.add_argument("--admin-port", required=True, type=int)
    for arg in ("app_id", "catalogue_dna", "storage_dna", "reader_agent",
                "artist_agent", "node_agent", "track_id", "catalogue_role", "storage_role"):
        p.add_argument("--" + arg.replace("_", "-"), required=True)
    args = p.parse_args()
    root = args.root
    fixture = json.loads((root / "fixture.json").read_text())
    if args.track_id != fixture["track_id"]:
        raise ValueError("test-fixture track mismatch")
    report = receive_moq_from_live_conductor(
        bridge_binary=args.bridge_binary, moq_binary=args.moq_binary,
        admin_port=args.admin_port, app_id=args.app_id,
        catalogue_dna=args.catalogue_dna, storage_dna=args.storage_dna,
        reader_agent=args.reader_agent, artist_agent=args.artist_agent,
        node_agent=args.node_agent, track_id=args.track_id,
        storage_url=args.node_url, target_store=root / "bob-moq-store",
        catalogue_role=args.catalogue_role, storage_role=args.storage_role,
    )
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest_digest(manifest) != fixture["manifest_sha256"]:
        raise ValueError("test-fixture manifest mismatch")
    artist_pub = bytes.fromhex(fixture["artist_public_hex"])
    verify_package(manifest, root / "bob-moq-store", artist_pub)
    # The AES key stays in the test runner. No user entitlement is implied.
    recovered = decrypt_package(
        manifest, root / "bob-moq-store", root / "recovered-moq.flac",
        (root / "content.key").read_bytes(), artist_pub,
    )
    actual = sha256(recovered.read_bytes())
    if actual != fixture["sample_sha256"]:
        raise ValueError("S9 decrypted bytes differ from synthetic source")
    print(json.dumps({"verified": True, "sha256": actual,
                      "file_id": report["file_id"],
                      "ciphertext_chunks": report["received_chunks"]}, sort_keys=True))


if __name__ == "__main__":
    main()
