"""Prepare and inspect a disposable, fully licensed offline audio test profile.

Usage on Ubuntu (run from the Holochain Music repo root):
  python3 tests/manual_offline_storage_fixture.py init /mnt/holochain/hm42-smoke-demo
  HOLOCHAIN_MUSIC_HOME=/mnt/holochain/hm42-smoke-demo \
    python3 -m holochain_music.cli start --offline --audio null
  # Visit Your Library -> Offline: Verify, Stop (if playing), Remove local copy.
  python3 tests/manual_offline_storage_fixture.py after /mnt/holochain/hm42-smoke-demo

This script never reads the user's default music profile. Initialization refuses
existing directories and is confined to brand-new /mnt/holochain/hm42-smoke-*
paths. It never performs storage removal: that is deliberately done through
the application's real authenticated, confirmed browser UI. Never run this
against real listener identities, published tracks or purchased music.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import wave

# Also work when executed as 'python3 tests/manual_offline_storage_fixture.py'
# from a source checkout without an editable pip installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from holochain_music.keys import KeyStore
from holochain_music.library import Library
from holochain_music.paths import AppPaths
from holochain_storage.package import create_package, manifest_digest, object_path, public_key_bytes
from music_catalogue.content_grants import issue_personal_licence, unwrap_content_grant

MARKER = ".hm42-disposable-offline-fixture.json"
TEST_ROOT_PARENT = Path("/mnt/holochain")
TEST_ROOT_PREFIX = "hm42-smoke-"
SAMPLE_RATE = 48000
SECONDS = 12


def permitted_profile(value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ValueError("provide an absolute, non-symlink test profile under /mnt/holochain")
    profile = candidate.resolve()
    if profile.parent != TEST_ROOT_PARENT.resolve() or not profile.name.startswith(TEST_ROOT_PREFIX):
        raise ValueError("test profile must be a direct /mnt/holochain/hm42-smoke-* directory")
    if profile == TEST_ROOT_PARENT or profile == Path.home():
        raise ValueError("refusing a real music profile or home directory")
    return profile


def wav_tone(path: Path) -> None:
    # Synthetic 440Hz tone, not copyrighted audio or a user's private music.
    with wave.open(str(path), "wb") as out:
        out.setnchannels(2)
        out.setsampwidth(2)
        out.setframerate(SAMPLE_RATE)
        # Write bounded chunks rather than build a large in-memory PCM array.
        for start in range(0, SAMPLE_RATE * SECONDS, 2400):
            end = min(start + 2400, SAMPLE_RATE * SECONDS)
            frames = bytearray()
            for n in range(start, end):
                sample = int(32767 * 0.08 * math.sin(2 * math.pi * 440 * n / SAMPLE_RATE))
                frames.extend(struct.pack("<hh", sample, sample))
            out.writeframesraw(frames)
        out.writeframes(b"")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def init(profile: Path) -> None:
    # No shutil.rmtree, no reuse/overwrite of previous profiles, and no
    # generic delete function: the only automatic cleanup is generated WAV
    # source data inside a temporary subdirectory newly created below root.
    if profile.exists() or profile.is_symlink():
        raise ValueError("test path already exists; choose a fresh hm42-smoke-* name")
    profile.mkdir(mode=0o700)
    paths = AppPaths(data=profile / "data", config=profile / "config")
    paths.ensure()
    keys = KeyStore(paths.keys)
    library = Library(paths.library)
    signer = keys.artist_ed25519()
    owner_agent, listener_agent = "hm42-disposable-artist", "hm42-disposable-listener"

    with tempfile.TemporaryDirectory(prefix="generated-wav-", dir=profile) as scratch:
        wav_path = Path(scratch) / "disposable-test-tone.wav"
        wav_tone(wav_path)
        manifest, content_key = create_package(wav_path, library.cas, signer, chunk_size=262144)

    file_id = manifest["body"]["file_id"]
    licence = issue_personal_licence(
        owner_signer=signer, owner_agent=owner_agent, listener_agent=listener_agent,
        recipient_public=bytes.fromhex(keys.listener_public_hex()),
        signed_manifest=manifest, content_key=content_key,
    )
    checked_key = unwrap_content_grant(
        licence, trusted_artist=public_key_bytes(signer), owner_agent=owner_agent,
        listener_agent=listener_agent, recipient_private=keys.listener_x25519(),
        signed_manifest=manifest,
    )
    if checked_key != content_key:
        raise AssertionError("test licence cannot unwrap on this test identity")
    library.add(manifest=manifest, meta={
        "track_key": owner_agent + ":" + ("d" * 32),
        "title": "Disposable Storage Test Tone (12 seconds)",
        "artist_agent": owner_agent, "artist_name": "Offline Test Fixture",
        "listener_agent": listener_agent,
        "album_id": None, "album_title": None,
        "duration_ms": SECONDS * 1000, "track_number": 1,
        "manifest_sha256": manifest_digest(manifest),
        "artist_key_hex": public_key_bytes(signer).hex(),
    })
    library.set_grant(file_id, licence, "perpetual-personal")
    if not library.verify_complete(file_id):
        raise AssertionError("generated encrypted test audio did not verify")
    library.save_playlists([{
        "id": "4" * 16, "name": "Disposable offline removal check", "tracks": [file_id],
    }])

    track_dir = library.tracks_dir / file_id
    marker = {
        "file_id": file_id, "owner_agent": owner_agent, "listener_agent": listener_agent,
        "grant_sha256": digest(track_dir / "grant.json"),
        "manifest_sha256": digest(track_dir / "manifest.json"),
        "playlists_sha256": digest(library.root / "playlists.json"),
        "chunk_digests": [chunk["sha256"] for chunk in manifest["body"]["chunks"]],
    }
    marker_file = profile / MARKER
    marker_file.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
    marker_file.chmod(0o600)

    print("Disposable offline fixture created successfully.")
    print("Profile:", profile)
    print("Track:", file_id)
    print("All encrypted chunks, local licence and listener key verified.")
    print("Launch Holochain Music in --offline --audio null with this profile.")
    print("No existing profiles or user music were opened or altered.")


def inspect(profile: Path, *, removed: bool) -> None:
    marker_file = profile / MARKER
    if marker_file.is_symlink() or not marker_file.is_file():
        raise ValueError("missing fixture marker; refusing to inspect an unknown profile")
    marker = json.loads(marker_file.read_text(encoding="utf-8"))
    paths = AppPaths(data=profile / "data", config=profile / "config")
    library = Library(paths.library)
    fid = marker["file_id"]
    track_dir = library.tracks_dir / fid
    if not track_dir.is_dir() or track_dir.is_symlink():
        raise AssertionError("test library track metadata directory was deleted")
    for filename, expected in (
        ("grant.json", marker["grant_sha256"]),
        ("manifest.json", marker["manifest_sha256"]),
    ):
        if digest(track_dir / filename) != expected:
            raise AssertionError("test " + filename + " was unexpectedly changed or removed")
    if digest(library.root / "playlists.json") != marker["playlists_sha256"]:
        raise AssertionError("test playlist was unexpectedly changed or removed")

    keys = KeyStore(paths.keys)
    grant = library.grant(fid)
    meta = library.meta(fid)
    if meta is None or grant is None:
        raise AssertionError("test metadata or permanent licence was removed")
    unwrapped = unwrap_content_grant(
        grant, trusted_artist=bytes.fromhex(meta["artist_key_hex"]),
        owner_agent=marker["owner_agent"], listener_agent=marker["listener_agent"],
        recipient_private=keys.listener_x25519(), signed_manifest=library.manifest(fid),
    )
    if len(unwrapped) != 32:
        raise AssertionError("test decryption key unavailable")
    present = [
        obj for obj in marker["chunk_digests"]
        if object_path(library.cas, obj).is_file()
    ]
    if removed:
        if present or meta.get("complete"):
            raise AssertionError("some test encrypted audio remains or its complete flag is still set")
        print("PASS: Test encrypted download removed. Licence, key, track and playlist preserved.")
    else:
        if len(present) != len(marker["chunk_digests"]) or not library.verify_complete(fid):
            raise AssertionError("test encrypted download is not fully ready before removal")
        print("PASS: Test encrypted audio, licence, key and playlist are available before removal.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "before", "after"))
    parser.add_argument("profile", help="new or existing /mnt/holochain/hm42-smoke-* test profile")
    args = parser.parse_args()
    try:
        profile = permitted_profile(args.profile)
        if args.action == "init":
            init(profile)
        elif args.action == "before":
            inspect(profile, removed=False)
        else:
            inspect(profile, removed=True)
    except (OSError, ValueError, AssertionError, KeyError, TypeError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
