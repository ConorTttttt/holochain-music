#!/usr/bin/env python3
"""Verify an independently approved private-test manifest and local packages.

Stdlib only. HASH VERIFIED is *not* a build-provenance, signature, CI, audio,
security, or hardware acceptance verdict.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_manifest(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("manifest must have schema_version 1")
    if not isinstance(data.get("approval_id"), str) or not data["approval_id"].strip() or "PLACEHOLDER" in data["approval_id"].upper():
        raise ValueError("missing actual owner approval_id")
    if not isinstance(data.get("source_sha"), str) or not GIT_SHA.fullmatch(data["source_sha"]):
        raise ValueError("source_sha must be a full 40-character lowercase Git SHA")
    items = data.get("artifacts")
    if not isinstance(items, list) or not items:
        raise ValueError("manifest must list at least one artifact")
    names = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("artifact entry must be an object")
        name = item.get("filename")
        if not isinstance(name, str) or not name or name in {".", ".."} or pathlib.PurePath(name).name != name or "\\" in name or "/" in name:
            raise ValueError("artifact filename must be a basename")
        if name in names:
            raise ValueError("duplicate artifact filename")
        names.add(name)
        if not isinstance(item.get("platform"), str) or not item["platform"].strip():
            raise ValueError("artifact requires platform")
        if not isinstance(item.get("size_bytes"), int) or isinstance(item["size_bytes"], bool) or item["size_bytes"] <= 0:
            raise ValueError("artifact requires positive size_bytes")
        if not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(item["sha256"]):
            raise ValueError("artifact requires lowercase SHA-256")
    return {item["filename"]: item for item in items}


def run(args):
    manifest_path = pathlib.Path(args.manifest)
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 65536:
        raise ValueError("missing, symlinked or oversized approval manifest")
    observed_manifest_sha = digest(manifest_path)
    if observed_manifest_sha != args.approved_manifest_sha256:
        raise ValueError("manifest SHA-256 differs from independently approved value")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = check_manifest(manifest)
    if manifest["source_sha"] != args.expected_source_sha:
        raise ValueError("source SHA differs from independently confirmed build commit")
    seen = set()
    checks = []
    for given in args.artifact:
        path = pathlib.Path(given)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"artifact missing or symlinked: {path.name}")
        name = path.name
        if name in seen:
            raise ValueError(f"artifact supplied twice: {name}")
        seen.add(name)
        expected = entries.get(name)
        if expected is None:
            raise ValueError(f"artifact not approved in manifest: {name}")
        observed_size = path.stat().st_size
        if observed_size != expected["size_bytes"]:
            raise ValueError(f"artifact size mismatch: {name}")
        observed_sha = digest(path)
        if observed_sha != expected["sha256"]:
            raise ValueError(f"artifact SHA-256 mismatch: {name}")
        checks.append({"platform": expected["platform"], "filename": name,
                       "bytes": observed_size, "sha256": observed_sha})
    return {"status": "HASH_VERIFIED_NOT_HARDWARE_ACCEPTANCE", "approval_id": manifest["approval_id"],
            "source_sha": manifest["source_sha"], "approved_manifest_sha256": observed_manifest_sha,
            "artifacts_checked": checks, "artifacts_not_checked_here": sorted(set(entries) - seen)}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True, help="Owner-approved manifest from Agent 3")
    p.add_argument("--approved-manifest-sha256", required=True,
                   help="64 hex chars obtained independently from the release owner, not copied from the manifest")
    p.add_argument("--expected-source-sha", required=True,
                   help="40 hex chars independently confirmed as the package-producing commit")
    p.add_argument("--artifact", action="append", required=True, help="Exact local .deb or .exe file; repeat as needed")
    args = p.parse_args(argv)
    if not SHA256.fullmatch(args.approved_manifest_sha256) or not GIT_SHA.fullmatch(args.expected_source_sha):
        p.error("expected SHA-256 and Git commit must be full lowercase hexadecimal hashes")
    try:
        verdict = run(args)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED_HASH_OR_PROVENANCE", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(verdict, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
