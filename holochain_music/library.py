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
    StorageError, canonical, manifest_digest, object_path, verify_package,
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
