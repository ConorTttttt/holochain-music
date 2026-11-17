#!/usr/bin/env python3
"""Opt-in, diagnostic Music-vs-Rust performance observations (not an SLO gate).

Runs on *the same host* and test-generated encrypted bytes. Rust import and
Python replicate_package have slightly different responsibilities: Python
signs a receipt, Rust does not. Do not present their ratio as a crypto speedup.
Neither path is enabled in Music's production application.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage import media_core_adapter as core
from holochain_storage.package import (
    _assert_manifest, _verify_signed, create_package, public_key_bytes,
    replicate_package, verify_package,
)


def samples(fn, rounds):
    readings = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        readings.append(round((time.perf_counter() - start) * 1000, 4))
    return {"samples_ms": readings, "median_ms": round(statistics.median(readings), 4)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--sizes-kib", type=int, nargs="+", default=[128, 4096])
    args = parser.parse_args()
    if not (1 <= args.rounds <= 30 and all(1 <= n <= 65536 for n in args.sizes_kib)):
        parser.error("1-30 rounds, each input 1-65536 KiB")
    executable = core.binary()
    if executable is None:
        parser.error(f"set {core.ENV_BINARY} to the absolute Media Core CLI path")

    result = {"platform": platform.platform(), "python": platform.python_version(),
              "media_core_binary": str(executable), "rounds": args.rounds,
              "note": "diagnostic medians; Python transfer signs a host receipt; Rust import does not",
              "sizes": []}
    with tempfile.TemporaryDirectory(prefix="music-core-benchmark-") as directory:
        root = Path(directory)
        artist = Ed25519PrivateKey.generate()
        host = Ed25519PrivateKey.generate()
        artist_public = public_key_bytes(artist)
        for size_kib in args.sizes_kib:
            original = root / f"plain-{size_kib}.bin"
            # Never pass this plaintext or either private key to the CLI.
            original.write_bytes(os.urandom(size_kib * 1024))
            origin = root / f"origin-{size_kib}"
            manifest, _secret = create_package(original, origin, artist, chunk_size=256 * 1024)

            def python_manifest():
                body = _verify_signed(manifest, artist_public, "manifest")
                _assert_manifest(body)

            def rust_manifest():
                core.verify_manifest(manifest, artist_public)

            first_cli = samples(rust_manifest, 1)  # includes first process launch
            python_metadata = samples(python_manifest, args.rounds)
            rust_metadata = samples(rust_manifest, args.rounds)
            python_integrity = samples(
                lambda: verify_package(manifest, origin, artist_public), args.rounds)

            python_transfers = []
            rust_transfers = []
            for round_index in range(args.rounds):
                py_target = root / f"py-{size_kib}-{round_index}"
                rust_target = root / f"rs-{size_kib}-{round_index}"
                start = time.perf_counter()
                replicate_package(manifest, origin, py_target, artist_public, host)
                python_transfers.append(round((time.perf_counter() - start) * 1000, 4))
                start = time.perf_counter()
                core.import_into_cas(manifest, artist_public, origin, rust_target)
                rust_transfers.append(round((time.perf_counter() - start) * 1000, 4))
            rust_cas = root / f"rs-{size_kib}-{args.rounds - 1}"
            rust_audit = samples(
                lambda: core.audit_cas(manifest, artist_public, rust_cas), args.rounds)
            result["sizes"].append({
                "kib": size_kib, "chunk_count": len(manifest["body"]["chunks"]),
                "first_cli_verify_ms": first_cli["samples_ms"][0],
                "python_manifest_metadata": python_metadata,
                "rust_cli_manifest_metadata": rust_metadata,
                "python_store_integrity": python_integrity,
                "rust_cli_store_audit": rust_audit,
                "python_replicate_and_sign": {
                    "samples_ms": python_transfers,
                    "median_ms": round(statistics.median(python_transfers), 4)},
                "rust_cli_import": {
                    "samples_ms": rust_transfers,
                    "median_ms": round(statistics.median(rust_transfers), 4)},
            })
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
