"""The listener's local music library: ciphertext, manifests and grants only.

Layout under the private data directory::

    library/cas/objects/sha256/..          encrypted chunks (shared CAS)
    library/tracks/<file_id>/manifest.json signed S1 manifest (public)
    library/tracks/<file_id>/grant.json    artist-signed grant/licence
    library/tracks/<file_id>/meta.json     verified catalogue facts + pins
    library/playlists.json, history.json   user data

No plaintext audio and no content key is ever stored here. Everything
needed for offline playback of a perpetual licence is in this directory plus
the listener X25519 key, so a backup of `keys/` + `library/` restores access.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time

from holochain_storage import portable
from holochain_storage.package import (
    StorageError, _assert_manifest, _verify_signed, canonical, manifest_digest, object_path, verify_package,
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_PLAYLISTS = 200
MAX_PLAYLIST_TRACKS = 1000
MAX_HISTORY = 200


class LibraryError(RuntimeError):
    pass


def _atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp, 0o600)
        portable.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def _read_json(path: Path, limit: int = 8 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise LibraryError(f"missing or unsafe library file {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def file_key(file_id: str) -> str:
    if not isinstance(file_id, str) or not _HEX64.fullmatch(file_id):
        raise LibraryError("invalid file ID")
    return file_id


class Library:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.cas = self.root / "cas"
        self.tracks_dir = self.root / "tracks"
        for d in (self.root, self.cas, self.tracks_dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)
        self._lock = threading.RLock()

    def _dir(self, file_id: str) -> Path:
        return self.tracks_dir / file_key(file_id)

    # ---- tracks -------------------------------------------------------
    def add(self, *, manifest: dict, meta: dict) -> None:
        file_id = file_key(manifest["body"]["file_id"])
        if manifest_digest(manifest) != meta.get("manifest_sha256"):
            raise LibraryError("manifest digest does not match library metadata")
        with self._lock:
            d = self._dir(file_id)
            d.mkdir(exist_ok=True)
            d.chmod(0o700)
            path = d / "manifest.json"
            if not path.exists():
                _atomic_json(path, manifest)
            elif manifest_digest(_read_json(path)) != meta["manifest_sha256"]:
                raise LibraryError("a different manifest is already stored for this file")
            existing = self.meta(file_id) or {}
            _atomic_json(d / "meta.json", {**existing, **meta, "file_id": file_id,
                                           "added_at": existing.get("added_at", int(time.time()))})

    def add_pending(self, file_id: str, meta: dict) -> None:
        """Record a requested track before its manifest is fetched from a host
        (the artist and host may be offline). Never playable without a grant."""
        with self._lock:
            d = self._dir(file_id)
            d.mkdir(exist_ok=True)
            d.chmod(0o700)
            existing = self.meta(file_id) or {}
            _atomic_json(d / "meta.json", {**meta, **existing, "file_id": file_key(file_id),
                                           "added_at": existing.get("added_at", int(time.time()))})

    def has_manifest(self, file_id: str) -> bool:
        return (self._dir(file_id) / "manifest.json").is_file()

    def set_grant(self, file_id: str, grant: dict, kind: str) -> None:
        with self._lock:
            d = self._dir(file_id)
            if not (d / "meta.json").is_file() or not (d / "manifest.json").is_file():
                raise LibraryError("add the verified track before its grant")
            current = self.meta(file_id) or {}
            # Never downgrade a perpetual licence to a streaming grant.
            if current.get("grant_kind") == "perpetual-personal" and kind != "perpetual-personal":
                return
            _atomic_json(d / "grant.json", grant)
            self.update_meta(file_id, grant_kind=kind, grant_received_at=int(time.time()))

    def update_meta(self, file_id: str, **fields) -> None:
        with self._lock:
            meta = self.meta(file_id)
            if meta is None:
                raise LibraryError("unknown library track")
            meta.update(fields)
            _atomic_json(self._dir(file_id) / "meta.json", meta)

    def meta(self, file_id: str) -> dict | None:
        path = self._dir(file_id) / "meta.json"
        return _read_json(path, 1024 * 1024) if path.is_file() else None

    def manifest(self, file_id: str) -> dict:
        return _read_json(self._dir(file_id) / "manifest.json")

    def grant(self, file_id: str) -> dict | None:
        path = self._dir(file_id) / "grant.json"
        return _read_json(path, 16 * 1024) if path.is_file() else None

    def all(self) -> list[dict]:
        rows = []
        for d in sorted(self.tracks_dir.iterdir()) if self.tracks_dir.is_dir() else []:
            if d.is_dir() and not d.is_symlink() and _HEX64.fullmatch(d.name) and (d / "meta.json").is_file():
                try:
                    rows.append(_read_json(d / "meta.json", 1024 * 1024))
                except (LibraryError, ValueError):
                    continue
        return rows

    def present_chunks(self, manifest: dict) -> set[int]:
        present = set()
        for chunk in manifest["body"]["chunks"]:
            path = object_path(self.cas, chunk["sha256"])
            if path.is_file() and not path.is_symlink() and path.stat().st_size == chunk["cipher_bytes"]:
                present.add(chunk["index"])
        return present

    def verify_complete(self, file_id: str) -> bool:
        meta = self.meta(file_id)
        if meta is None:
            return False
        try:
            verify_package(self.manifest(file_id), self.cas, bytes.fromhex(meta["artist_key_hex"]))
        except (StorageError, LibraryError, KeyError, ValueError):
            if meta.get("complete"):
                self.update_meta(file_id, complete=False)
            return False
        if not meta.get("complete"):
            self.update_meta(file_id, complete=True, completed_at=int(time.time()))
        return True

    # ---- explicitly requested storage management ---------------------
    def storage_usage(self) -> dict:
        """Count local library files, not exports, keys or host-owned objects.

        This is an on-demand filesystem scan (not a polling-loop operation).
        Sizes describe allocated file content, not deduplicated disk blocks,
        filesystem quota or permission to remove those files.
        """
        def count_files(root: Path, *, objects_only: bool = False) -> tuple[int, int>:
            total, count = 0, 0
            if not root.is_dir() or root.is_symlink():
                return total, count
            for base, dirs, names in os.walk(root, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(base) / name).is_symlink()]
                for name in names:
                    path = Path(base) / name
                    if path.is_symlink() or not path.is_file():
                        continue
                    if objects_only and (not _HEX64.fullmatch(path.name) or path.parent.name != path.name[:2]):
                        continue
                    total += path.stat().st_size
                    count += 1
            return total, count

        encrypted_bytes, objects = count_files(self.cas / "objects" / "sha256", objects_only=True)
        metadata_bytes, metadata_files = count_files(self.tracks_dir)
        for name in ("playlists.json", "history.json"):
            path = self.root / name
            if path.is_file() and not path.is_symlink():
                metadata_bytes += path.stat().st_size
                metadata_files += 1
        return {
            "encrypted_bytes": encrypted_bytes,
            "encrypted_objects": objects,
            "library_metadata_bytes": metadata_bytes,
            "metadata_files": metadata_files,
            "accounted_bytes": encrypted_bytes + metadata_bytes,
        }

    def remove_offline_copy(self, file_id: str) -> dict:
        """Remove only this track's exclusive encrypted CAS objects.

        All manifests are checked before unlinking anything. Shared CAS objects,
        signed grants, keys, manifests, playlists and exports are NEVER removed.
        The caller must independently prevent active playback/download races.
        """
        file_id = file_key(file_id)
        with self._lock:
            meta = self.meta(file_id)
            if meta is None or not self.has_manifest(file_id):
                raise LibraryError("no complete track record to remove locally")

            def authenticated_chunks(fid: str, record: dict) -> set[str]:
                package = self.manifest(fid)
                if record.get("manifest_sha256") != manifest_digest(package):
                    raise LibraryError("manifest changed; refusing to remove encrypted audio")
                try:
                    signed = _verify_signed(package, bytes.fromhex(record["artist_key_hex"]), "manifest")
                    _assert_manifest(signed)
                except (StorageError, ValueError, KeyError, TypeError) as exc:
                    raise LibraryError("manifest cannot be authenticated; no files removed") from exc
                if signed["file_id"] != fid:
                    raise LibraryError("manifest file ID mismatch; no files removed")
                return {chunk["sha256"] for chunk in signed["chunks"]}

            own_chunks = authenticated_chunks(file_id, meta)
            protected: set[str] = set()
            # Any other known manifest may reference the same encrypted object.
            # Fail closed on unknown/invalid directories or manifests rather than
            # over-estimating the number of exclusively owned objects.
            for directory in self.tracks_dir.iterdir():
                if directory.is_symlink():
                    raise LibraryError("unsafe library track directory; no files removed")
                if not directory.is_dir() or not _HEX64.fullmatch(directory.name):
                    continue
                if directory.name == file_id:
                    continue
                manifest_path = directory / "manifest.json"
                if manifest_path.is_symlink():
                    raise LibraryError("unsafe referenced manifest; no files removed")
                if not manifest_path.exists():
                    continue  # pending metadata with no audio references
                other_meta = self.meta(directory.name)
                if other_meta is None:
                    raise LibraryError("unknown referenced manifest; no files removed")
                protected.update(authenticated_chunks(directory.name, other_meta))

            unique = own_chunks - protected
            prepared: list[tuple[Path, int]] = []
            # Reject every unsafe path before changing the 'complete' flag.
            for digest in unique:
                path = object_path(self.cas, digest)
                for parent in (self.cas, self.cas / "objects", self.cas / "objects" / "sha256", path.parent):
                    if parent.is_symlink():
                        raise LibraryError("unsafe encrypted-object directory; no files removed")
                if path.is_symlink():
                    raise LibraryError("unsafe encrypted-object link; no files removed")
                if path.exists():
                    if not path.is_file():
                        raise LibraryError("unsafe encrypted-object type; no files removed")
                    prepared.append((path, path.stat().st_size))

            # If an unlink later fails, the track remains marked incomplete,
            # never falsely offline-ready. A user can retry after fixing disk
            # permissions; a grant and metadata remain untouched.
            self.update_meta(file_id, complete=False)
            removed_bytes, removed_objects = 0, 0
            for path, size in prepared:
                path.unlink()
                removed_bytes += size
                removed_objects += 1
            return {
                "removed_bytes": removed_bytes,
                "removed_objects": removed_objects,
                "shared_objects_preserved": len(own_chunks & protected),
                "message": "Only exclusive app-managed encrypted chunks were removed. Library entries, licences and exports remain.",
            }

    # ---- playlists & history -----------------------------------------
    def playlists(self) -> list[dict]:
        path = self.root / "playlists.json"
        return _read_json(path, 4 * 1024 * 1024) if path.is_file() else []

    def save_playlists(self, playlists: list[dict]) -> None:
        if not isinstance(playlists, list) or len(playlists) > MAX_PLAYLISTS:
            raise LibraryError("too many playlists")
        clean = []
        seen = set()
        for p in playlists:
            if not isinstance(p, dict) or set(p) != {"id", "name", "tracks"}:
                raise LibraryError("invalid playlist")
            name = p["name"]
            if (not isinstance(p["id"], str) or not re.fullmatch(r"[0-9a-f]{16}", p["id"]) or p["id"] in seen
                    or not isinstance(name, str) or not name.strip() or len(name) > 120
                    or any(ord(c) < 32 for c in name)):
                raise LibraryError("invalid playlist id or name")
            seen.add(p["id"])
            if not isinstance(p["tracks"], list) or len(p["tracks"]) > MAX_PLAYLIST_TRACKS:
                raise LibraryError("invalid playlist tracks")
            for t in p["tracks"]:
                if not isinstance(t, str) or not re.fullmatch(r"[0-9a-f]{64}|[A-Za-z0-9_-]{1,64}:[0-9a-f]{32}", t):
                    raise LibraryError("invalid playlist track key")
            clean.append({"id": p["id"], "name": name.strip(), "tracks": list(p["tracks"])})
        _atomic_json(self.root / "playlists.json", clean)

    def history(self) -> list[dict]:
        path = self.root / "history.json"
        return _read_json(path, 1024 * 1024) if path.is_file() else []

    def record_play(self, entry: dict) -> None:
        with self._lock:
            rows = [r for r in self.history() if r.get("key") != entry["key"]]
            rows.insert(0, {**entry, "played_at": int(time.time())})
            _atomic_json(self.root / "history.json", rows[:MAX_HISTORY])

    def write_manifest_copy(self, file_id: str) -> bytes:
        return canonical(self.manifest(file_id))
