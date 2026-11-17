#!/usr/bin/env python3
"""Strict source preflight and external evidence for private RC packages.

No tag, release or publication is created. Uses only the Python standard library.
An evidence JSON file is not a cryptographic attestation of the builder: retain
the CI run/logs and review its inputs before accepting the candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LINUX_PATHS = (
    "usr/bin/holochain-music",
    "usr/lib/holochain-music/bin/hc",
    "usr/lib/holochain-music/bin/holochain",
    "usr/lib/holochain-music/bin/holochain-music-moq",
    "usr/lib/holochain-music/bin/kitsune2-bootstrap-srv",
    "usr/lib/holochain-music/bin/music_app_bridge",
    "usr/lib/holochain-music/holochain_music.happ",
)
WINDOWS_PATHS = (
    "HolochainMusic.exe", "holochain-music.exe",
    "bin/hc.exe", "bin/holochain.exe",
    "bin/holochain-music-moq.exe", "bin/kitsune2-bootstrap-srv.exe",
    "bin/music_app_bridge.exe", "holochain_music.happ",
    "docs/SOURCE_COMMIT.txt",
)


def cmd(*parts: str, timeout: int = 20) -> str:
    return subprocess.check_output(parts, text=True, stderr=subprocess.STDOUT,
                                   timeout=timeout).strip()


def git(*parts: str) -> str:
    return cmd("git", "-C", str(ROOT), *parts)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def versions() -> str:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    init = (ROOT / "holochain_music/__init__.py").read_text(encoding="utf-8")
    # Both of these files have one top-level version assignment.
    a = re.findall(r'(?m)^version\s*=\s*"([^"]+)"\s*$', pyproject)
    b = re.findall(r'(?m)^__version__\s*=\s*"([^"]+)"\s*$', init)
    if len(a) != 1 or len(b) != 1 or a[0] != b[0]:
        raise ValueError("pyproject.toml and __init__.py versions disagree")
    if not re.fullmatch(r"\d+\.\d+\.\d+rc\d+", a[0]):
        raise ValueError("unexpected RC identifier; obtain owner approval first")
    return a[0]


def verify_source(expected: str, clean: bool) -> str:
    if not re.fullmatch("[0-9a-f]{40}", expected):
        raise ValueError("specify an exact 40-character source commit")
    actual = git("rev-parse", "HEAD")
    if actual != expected:
        raise ValueError(f"checked-out commit {actual} differs from {expected}")
    if clean:
        # Build tools write ignored/untracked outputs, but tracked source files
        # and untracked files under packaged Python trees must not be changed.
        changed = git("status", "--porcelain", "--untracked-files=no")
        untracked = git("ls-files", "--others", "--exclude-standard", "--",
                        "holochain_music", "music_catalogue", "holochain_storage")
        if changed or untracked:
            raise ValueError("source worktree is not clean; commit/review changes first:\n"
                             + changed + "\n" + untracked)
    return versions()


def tool_versions() -> dict[str, str]:
    commands = {
        "git": ("git", "--version"),
        "python3": ("python3", "--version"),
        "pip": ("python3", "-m", "pip", "--version"),
        "rustc": ("rustc", "--version"),
        "cargo": ("cargo", "--version"),
        "hc": ("hc", "--version"),
        "holochain": ("holochain", "--version"),
        "dpkg-deb": ("dpkg-deb", "--version"),
        "fakeroot": ("fakeroot", "-v"),
        "makensis": ("makensis", "-VERSION"),
        "mingw-gcc": ("x86_64-w64-mingw32-gcc", "--version"),
    }
    found = {}
    for name, argv in commands.items():
        try:
            found[name] = cmd(*argv, timeout=5).splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            found[name] = "NOT AVAILABLE"
    return found


def read_manifest(path: Path) -> dict[str, str]:
    manifest = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] in manifest:
            raise ValueError(f"invalid/duplicate checksum row: {line!r}")
        manifest[match[2]] = match[1]
    return manifest


def linux_bundled(artifact: Path, contents: Path,
                  expected: str, version: str) -> dict[str, str]:
    package_version = cmd("dpkg-deb", "-f", str(artifact), "Version")
    if package_version != version.replace("rc", "~rc"):
        raise ValueError(f".deb control version mismatch: {package_version}")
    with tempfile.TemporaryDirectory(prefix="hm-rc-audit-") as temp:
        cmd("dpkg-deb", "-x", str(artifact), temp, timeout=120)
        root = Path(temp)
        marker = root / "usr/share/doc/holochain-music/SOURCE_COMMIT.txt"
        if not marker.is_file() or f"commit={expected}\n" not in marker.read_text():
            raise ValueError("source commit marker missing/mismatched in .deb")
        # Compare every installed file against the separately generated stage
        # checksum manifest; a stale or spliced sidecar must fail closed.
        listed = read_manifest(contents)
        actual = {path.relative_to(root).as_posix()
                  for path in (root / "usr").rglob("*") if path.is_file()}
        if set(listed) != actual:
            raise ValueError(f".deb contents mismatch: missing={sorted(actual - set(listed))}, "
                             f"unexpected={sorted(set(listed) - actual)}")
        for name in sorted(actual):
            if sha(root / name) != listed[name]:
                raise ValueError(f".deb staged checksum mismatch: {name}")
        missing = sorted(set(LINUX_PATHS) - actual)
        if missing:
            raise ValueError(f".deb missing significant bundled files: {missing}")
        return {name: listed[name] for name in LINUX_PATHS}


def windows_bundled(contents: Path) -> dict[str, str]:
    # NSIS extraction/installation is checked separately on a Windows runner.
    manifest = read_manifest(contents)
    missing = sorted(set(WINDOWS_PATHS) - manifest.keys())
    if missing:
        raise ValueError(f"Windows contents manifest missing: {missing}")
    return {name: manifest[name] for name in WINDOWS_PATHS}


def record(args: argparse.Namespace, version: str) -> None:
    artifact = Path(args.artifact).resolve()
    contents = Path(args.contents).resolve()
    if not artifact.is_file() or not contents.is_file():
        raise ValueError("package and contents checksum file must already exist")
    platform_name = args.platform
    canonical = (f"holochain-music_{version.replace('rc', '~rc')}_amd64.deb"
                 if platform_name == "linux" else
                 f"HolochainMusic-{version.replace('rc', '-rc')}-windows-x64.exe")
    if artifact.name != canonical:
        raise ValueError(f"version/artefact mismatch: expected {canonical}")
    bundled = (linux_bundled(artifact, contents, args.commit, version) if platform_name == "linux"
               else windows_bundled(contents))
    inputs = {}
    for raw in args.input:
        if "=" not in raw:
            raise ValueError("--input needs LABEL=FILE")
        name, filename = raw.split("=", 1)
        path = Path(filename).resolve()
        if not name or not path.is_file() or name in inputs:
            raise ValueError(f"invalid input {raw}")
        inputs[name] = {"path": str(path), "sha256": sha(path)}
    logs = {}
    for filename in args.test_log:
        path = Path(filename).resolve()
        if not path.is_file():
            raise ValueError(f"test log absent: {path}")
        logs[path.name] = sha(path)
    locks = {}
    for rel in ("pyproject.toml", "dna/Cargo.lock", "music-dna/Cargo.lock",
                "music-e2e/Cargo.lock", "crates/moq-music/Cargo.lock",
                "crates/storage-node/Cargo.lock", "packaging/windows/inputs.sha256"):
        path = ROOT / rel
        if path.is_file():
            locks[rel] = sha(path)
    evidence = {
        "status": "DRAFT / PRIVATE TEST ONLY / NOT APPROVED FOR DISTRIBUTION",
        "source_commit": args.commit,
        "source_tree": git("rev-parse", "HEAD^{tree}"),
        "commit_unix_timestamp": int(git("show", "-s", "--format=%ct", args.commit)),
        "source_date_epoch": int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
        "version_python": version,
        "platform": platform_name,
        "artifact": artifact.name,
        "artifact_size": artifact.stat().st_size,
        "artifact_sha256": sha(artifact),
        "contents_manifest": contents.name,
        "contents_manifest_sha256": sha(contents),
        "bundled_sha256": bundled,
        "external_input_sha256": inputs,
        "source_dependency_lock_sha256": locks,
        "builder": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "runner_os": os.environ.get("RUNNER_OS"),
            "tool_versions": tool_versions(),
        },
        "test_logs_sha256": logs,
        "test_conclusion": "NOT EVALUATED BY THIS SCRIPT; review CI/hardware evidence",
        "content_verification": (
            "All extracted Debian files checked against sidecar"
            if platform_name == "linux"
            else "Windows stage checksum only; NSIS installation verification pending"
        ),
    }
    if evidence["source_date_epoch"] != evidence["commit_unix_timestamp"]:
        raise ValueError("SOURCE_DATE_EPOCH must match the pinned source commit time")
    sidecar = artifact.with_name(artifact.name + ".sha256")
    sidecar.write_text(f"{evidence['artifact_sha256']}  {artifact.name}\n", encoding="utf-8")
    manifest = artifact.with_name(artifact.name + ".provenance.json")
    manifest.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Recorded {sidecar} and {manifest} (NO release or approval)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "record"))
    parser.add_argument("--commit", required=True)
    parser.add_argument("--platform", choices=("linux", "windows"))
    parser.add_argument("--artifact")
    parser.add_argument("--contents")
    parser.add_argument("--input", action="append", default=[], metavar="LABEL=FILE")
    parser.add_argument("--test-log", action="append", default=[])
    args = parser.parse_args()
    try:
        version = verify_source(args.commit, clean=args.action == "preflight")
        if args.action == "record":
            if not all((args.platform, args.artifact, args.contents)):
                parser.error("record requires --platform, --artifact and --contents")
            record(args, version)
        else:
            print(f"Source OK: {args.commit}; version {version}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"RC evidence error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
