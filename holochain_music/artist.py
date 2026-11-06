"""Artist tools and self-hosting for this installation's agent.

Publishing a track:
  1. normalise a PCM16 WAV into the canonical 44-byte-header form the
     authenticated player accepts (temporary 0600 file, removed immediately);
  2. encrypt it into the host CAS with the artist's Ed25519 key (S1); the AES
     content key goes ONLY to the local key store (needed to issue grants);
  3. publish S2 key binding + file commitment and the S5 track entry;
  4. sign a host receipt with this machine's host key and publish the replica
     claim, then (re)start the MoQ host and publish its endpoint.

Rights: `rights_basis` is the artist's own declaration. Nothing here verifies
copyright ownership.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import threading
import time
import wave

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from holochain_storage.holochain_identity import HOST_PURPOSE, OWNER_PURPOSE, key_for_agent
from holochain_storage.package import (
    StorageError, canonical, create_package, manifest_digest, public_key_bytes,
    replicate_package, sha256,
)
from music_catalogue.content_grants import ContentGrantError, issue_content_grant, issue_personal_licence
from music_catalogue.moq_conductor import MOQ_ENDPOINT_SCHEMA

from .bridge import Bridge, BridgeError
from .keys import KeyStore, KeyStoreError
from .library import LibraryError, _atomic_json, _read_json, file_key
from .metadata import ARTWORK_SCHEMA, HEX64, artwork_bytes, genres_list, validate_artwork_record
from .outbox import OutboxError

RATES = (8000, 11025, 16000, 22050, 32000, 44100, 48000)
KEY_SCHEMA = "holochain-storage/key-binding/v1"
MAX_WAV_BYTES = 2 * 1024**3


class ArtistError(RuntimeError):
    pass


def normalise_wav(source: Path, destination: Path) -> dict:
    """Rewrite any PCM16 mono/stereo WAV as canonical RIFF/WAVE (44-byte header)."""
    try:
        with wave.open(str(source), "rb") as w:
            channels, width, rate, frames = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
            if w.getcomptype() != "NONE" or width != 2 or channels not in (1, 2) or rate not in RATES:
                raise ArtistError("only uncompressed 16-bit mono/stereo WAV at a standard sample rate is supported")
            data_len = frames * channels * 2
            if not 0 < data_len <= MAX_WAV_BYTES:
                raise ArtistError("WAV is empty or too large")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 36 + data_len, b"WAVE", b"fmt ", 16, 1,
                                      channels, rate, rate * channels * 2, channels * 2, 16, b"data", data_len))
                written = 0
                while True:
                    block = w.readframes(65536)
                    if not block:
                        break
                    out.write(block)
                    written += len(block)
            if written != data_len:
                raise ArtistError("WAV data is truncated")
    except (wave.Error, EOFError) as exc:
        raise ArtistError(f"not a readable WAV file: {exc}") from exc
    return {"channels": channels, "sample_rate": rate, "frames": frames,
            "duration_ms": max(1, frames * 1000 // rate)}


class ArtistService:
    def __init__(self, *, bridge: Bridge, keys: KeyStore, host_root: Path, deliver=None):
        self.bridge, self.keys = bridge, keys
        # Delivery may be queued by the app's outbox when the listener is offline.
        self.deliver = deliver or (lambda op, **kw: (bridge.call(op, **kw), {"delivered": True})[1])
        self._request_lock = threading.RLock()
        self.root = Path(host_root)
        self.cas = self.root / "cas"
        self.files = self.root / "files"
        for d in (self.root, self.cas, self.files):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)

    @property
    def me(self) -> str:
        return self.bridge.whoami["agent"]

    # ---- identity bindings --------------------------------------------
    def _ensure_key(self, purpose: str, public: bytes) -> None:
        bound = set()
        for record in self.bridge.records("get_signing_keys", agent=self.me):
            try:
                bound.add(key_for_agent(record, self.me, purpose))
            except StorageError:
                continue
        if bound == {public}:
            return
        if bound:
            # Key rotation is not modelled in v1; a second key would make every
            # listener's resolution ambiguous (and is refused by them).
            raise ArtistError(f"this agent already has a different {purpose} key registered")
        self.bridge.call("register_signing_key", entry={"schema": KEY_SCHEMA, "agent": self.me,
                                                        "purpose": purpose, "signing_key_hex": public.hex()})

    # ---- catalogue ----------------------------------------------------
    def save_profile(self, display_name: str, biography: str) -> dict:
        return self.bridge.call("publish_artist_profile", entry={
            "schema": "holochain-music/artist/v1", "artist_agent": self.me,
            "display_name": display_name.strip(), "biography": biography.strip(),
            "artwork_manifest_sha256": None})

    def publish_artwork(self, *, mime_type: str, data_base64: str) -> dict:
        """Small, explicitly public cover art stored separately from secret audio."""
        image = artwork_bytes(mime_type=mime_type, data_base64=data_base64)
        digest = hashlib.sha256(image).hexdigest()
        self.bridge.call("publish_artwork", entry={
            "schema": ARTWORK_SCHEMA, "artist_agent": self.me, "mime_type": mime_type,
            "sha256": digest, "data_base64": data_base64})
        return {"artwork_sha256": digest, "bytes": len(image)}

    def _require_artwork(self, digest: str | None) -> None:
        if digest is None:
            return
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise ArtistError("invalid artwork digest")
        row = self.bridge.record("get_artwork", artist=self.me, sha256=digest)
        if row is None or row.author != self.me:
            raise ArtistError("upload artwork as this artist first")
        try:
            validate_artwork_record(row.body, author=self.me, digest=digest)
        except ValueError as exc:
            raise ArtistError("invalid or unverified artwork") from exc

    def create_album(self, title: str, release_date: str | None,
                     genres: list[str] | None = None, artwork_sha256: str | None = None) -> dict:
        album_id = secrets.token_hex(16)
        self._album_revision(album_id=album_id, title=title, release_date=release_date,
                             genres=genres or [], artwork_sha256=artwork_sha256)
        return {"album_id": album_id}

    def _album_revision(self, *, album_id: str, title: str, release_date: str | None,
                        genres: list[str], artwork_sha256: str | None) -> None:
        if not isinstance(album_id, str) or len(album_id) != 32 or any(c not in "0123456789abcdef" for c in album_id):
            raise ArtistError("invalid album ID")
        self._require_artwork(artwork_sha256)
        self.bridge.call("publish_album", entry={
            "schema": "holochain-music/album/v1", "artist_agent": self.me, "album_id": album_id,
            "title": title.strip(), "release_date": release_date or None, "artwork_manifest_sha256": None,
            "artwork_sha256": artwork_sha256, "genres": genres_list(genres)})

    def update_album(self, *, album_id: str, title: str, release_date: str | None,
                     genres: list[str], artwork_sha256: str | None) -> dict:
        records = self.bridge.records("list_albums", artist=self.me)
        if not any(r.author == self.me and r.body.get("album_id") == album_id for r in records):
            raise ArtistError("album not found for this artist")
        self._album_revision(album_id=album_id, title=title, release_date=release_date,
                             genres=genres, artwork_sha256=artwork_sha256)
        return {"album_id": album_id, "updated": True}

    def update_track(self, *, file_id: str, album_id: str | None, track_number: int,
                     genres: list[str], artwork_sha256: str | None) -> dict:
        """Append artist-owned metadata revision; preserve immutable audio identifiers."""
        file_id = file_key(file_id)
        saved = self.files / file_id / "track.json"
        if not saved.is_file():
            raise ArtistError("only tracks published on this artist account can be edited")
        local = _read_json(saved, 64 * 1024)
        if type(track_number) is not int or not 1 <= track_number <= 999:
            raise ArtistError("invalid track number")
        self._require_artwork(artwork_sha256)
        row = self.bridge.record("get_track", artist=self.me, track_id=local["track_id"])
        if (row is None or row.author != self.me or row.body.get("file_id") != file_id
                or row.body.get("manifest_sha256") != local["manifest_sha256"]):
            raise ArtistError("published track does not match this encrypted audio")
        body = dict(row.body)
        body.update(album_id=album_id, track_number=track_number, genres=genres_list(genres),
                    artwork_sha256=artwork_sha256)
        self.bridge.call("publish_track", entry=body)
        _atomic_json(saved, {**local, "album_id": album_id, "track_number": track_number,
                             "genres": body["genres"], "artwork_sha256": artwork_sha256})
        return {"file_id": file_id, "track_id": local["track_id"], "album_id": album_id,
                "genres": body["genres"], "artwork_sha256": artwork_sha256, "track_number": track_number}

    def publish_track(self, *, wav: Path, title: str, album_id: str | None = None,
                      track_number: int = 1, disc_number: int = 1,
                      rights_basis: str = "original_owner", genres: list[str] | None = None,
                      artwork_sha256: str | None = None) -> dict:
        if rights_basis not in ("original_owner", "licensed_by_rights_holder"):
            raise ArtistError("invalid rights declaration")
        clean_genres = genres_list(genres or [])
        self._require_artwork(artwork_sha256)
        artist_key = self.keys.artist_ed25519()
        self._ensure_key(OWNER_PURPOSE, public_key_bytes(artist_key))
        tmpdir = self.root / "tmp"
        tmpdir.mkdir(exist_ok=True)
        tmpdir.chmod(0o700)
        canonical_wav = tmpdir / f"{secrets.token_hex(8)}.wav"
        try:
            info = normalise_wav(Path(wav), canonical_wav)
            manifest, content_key = create_package(canonical_wav, self.cas, artist_key)
        finally:
            canonical_wav.unlink(missing_ok=True)
        file_id = manifest["body"]["file_id"]
        digest = manifest_digest(manifest)
        self.keys.save_content_key(file_id, content_key)
        del content_key
        d = self.files / file_id
        d.mkdir(exist_ok=True)
        d.chmod(0o700)
        _atomic_json(d / "manifest.json", manifest)
        self.bridge.call("publish_file_commitment", entry={
            "schema": "holochain-storage/file-commitment/v1", "owner_agent": self.me,
            "file_id": file_id, "manifest_sha256": digest})
        track_id = secrets.token_hex(16)
        self.bridge.call("publish_track", entry={
            "schema": "holochain-music/track/v1", "artist_agent": self.me, "track_id": track_id,
            "album_id": album_id or None, "title": title.strip(), "duration_ms": info["duration_ms"],
            "disc_number": disc_number, "track_number": track_number, "audio_format": "audio/wav",
            "file_id": file_id, "manifest_sha256": digest, "rights_basis": rights_basis,
            "genres": clean_genres, "artwork_sha256": artwork_sha256})
        self.host_file(manifest, owner_agent=self.me, artist_key=public_key_bytes(artist_key))
        _atomic_json(d / "track.json", {"track_id": track_id, "title": title.strip(), "file_id": file_id,
                                        "manifest_sha256": digest, "owner_agent": self.me,
                                        "published_at": int(time.time()), "album_id": album_id,
                                        "track_number": track_number, "genres": clean_genres,
                                        "artwork_sha256": artwork_sha256, **info})
        return {"track_id": track_id, "file_id": file_id, "manifest_sha256": digest, **info}

    # ---- hosting --------------------------------------------------------
    def host_file(self, manifest: dict, *, owner_agent: str, artist_key: bytes) -> None:
        """Sign a receipt for ciphertext already in the host CAS and claim it."""
        host_key = self.keys.host_ed25519()
        self._ensure_key(HOST_PURPOSE, public_key_bytes(host_key))
        receipt = replicate_package(manifest, self.cas, self.cas, artist_key, host_key)
        file_id = file_key(manifest["body"]["file_id"])
        d = self.files / file_id
        d.mkdir(exist_ok=True)
        _atomic_json(d / "manifest.json", manifest)
        _atomic_json(d / "receipt.json", receipt)
        _atomic_json(d / "hosting.json", {"owner_agent": owner_agent, "artist_key_hex": artist_key.hex(),
                                          "manifest_sha256": manifest_digest(manifest)})
        self.bridge.call("publish_replica_claim", entry={
            "schema": "holochain-storage/replica-claim/v1", "node_agent": self.me,
            "owner_agent": owner_agent, "file_id": file_id,
            "manifest_sha256": manifest_digest(manifest), "receipt_sha256": sha256(canonical(receipt))})

    def hosted(self) -> list[dict]:
        out = []
        for d in sorted(self.files.iterdir()):
            if d.is_dir() and (d / "hosting.json").is_file() and (d / "receipt.json").is_file():
                h = _read_json(d / "hosting.json", 64 * 1024)
                out.append({"file_id": d.name, "manifest": d / "manifest.json", "receipt": d / "receipt.json",
                            "owner_agent": h["owner_agent"], "trusted_artist_hex": h["artist_key_hex"],
                            "manifest_sha256": h["manifest_sha256"]})
        return out

    def my_tracks(self) -> list[dict]:
        return [_read_json(d / "track.json", 64 * 1024) for d in sorted(self.files.iterdir())
                if (d / "track.json").is_file()]

    def publish_endpoints(self, url: str, fingerprint: str) -> int:
        existing = {(e.body.get("file_id"), e.body.get("url"), e.body.get("cert_fingerprint_hex"))
                    for e in self.bridge.records("get_moq_endpoints", host=self.me) if e.author == self.me}
        published = 0
        for f in self.hosted():
            if (f["file_id"], url, fingerprint) in existing:
                continue
            self.bridge.call("publish_moq_endpoint", entry={
                "schema": MOQ_ENDPOINT_SCHEMA, "node_agent": self.me, "owner_agent": f["owner_agent"],
                "file_id": f["file_id"], "manifest_sha256": f["manifest_sha256"], "url": url,
                "cert_fingerprint_hex": fingerprint})
            published += 1
        return published

    # ---- access requests and grants ---------------------------------------
    def _issued_log(self) -> Path:
        return self.root / "issued-grants.json"

    def issued(self) -> list[dict]:
        p = self._issued_log()
        return _read_json(p, 4 * 1024 * 1024) if p.is_file() else []

    def _decision_log(self) -> Path:
        # Local and private. Never publish request decisions or counterparties to the DHT.
        return self.root / "request-decisions.json"

    def _decisions(self) -> dict:
        p = self._decision_log()
        return _read_json(p, 16 * 1024 * 1024) if p.is_file() else {}

    def _save_decision(self, request_hash: str, *, status: str, kind: str | None = None) -> None:
        decisions = self._decisions()
        decisions[request_hash] = {"status": status, "kind": kind, "decided_at": int(time.time())}
        _atomic_json(self._decision_log(), decisions)

    def _inbox(self) -> list[dict]:
        """Private requests on this artist's own chain. `listener_agent` was
        set by this conductor from the remote call's verified provenance."""
        rows = []
        for row in self.bridge.call("get_inbox_access_requests") or []:
            b = row.get("body") if isinstance(row, dict) else None
            if (isinstance(b, dict) and b.get("schema") == "holochain-music/inbox-access-request/v1"
                    and isinstance(b.get("listener_agent"), str)):
                rows.append({**b, "request_hash": row.get("action_hash"),
                             "received_at": int(row.get("received_at_us", 0)) // 1_000_000})
        return rows

    def requests(self) -> list[dict]:
        """One actionable row per listener/track/manifest/access type/key.

        Legacy duplicate private entries remain on the artist source chain, but
        never become multiple offers or consume multiple bulk decisions.
        """
        with self._request_lock:
            mine = {t["file_id"]: t for t in self.my_tracks()}
            issued = {(g["listener_agent"], g["file_id"], g["kind"]) for g in self.issued()}
            decisions = self._decisions()
            grouped: dict[tuple, dict] = {}
            for b in self._inbox():
                track = mine.get(b.get("file_id"))
                if track is None or b.get("manifest_sha256") != track["manifest_sha256"]:
                    continue
                h = b.get("request_hash")
                if not isinstance(h, str) or not 0 < len(h) <= 80:
                    continue
                kind = b.get("kind")
                if kind not in ("stream", "perpetual-personal"):
                    continue
                key = (b["listener_agent"], b["file_id"], b["manifest_sha256"],
                       kind, b.get("x25519_public_hex"))
                decision = decisions.get(h, {})
                legacy_granted = (b["listener_agent"], b["file_id"], kind) in issued
                status = ("approved" if legacy_granted or decision.get("status") == "approved"
                          else "declined" if decision.get("status") == "declined" else "pending")
                if key not in grouped:
                    grouped[key] = {
                        "request_hash": h, "listener_agent": b["listener_agent"],
                        "file_id": b["file_id"], "manifest_sha256": b["manifest_sha256"],
                        "request_id": b.get("request_id"),
                        "track_title": track["title"], "kind": kind,
                        "note": str(b.get("note", ""))[:500],
                        "received_at": b["received_at"], "status": status,
                        "duplicate_count": 1,
                    }
                else:
                    row = grouped[key]
                    row["duplicate_count"] += 1
                    # Resolved decisions on an older duplicate apply to its
                    # entire group. A grant always takes precedence over a decline.
                    if status == "approved" or (status == "declined" and row["status"] == "pending"):
                        row["status"] = status
            out = list(grouped.values())
            for row in out:
                row["granted"] = row["status"] == "approved"
                row["declined"] = row["status"] == "declined"
            return out

    def _send_decline(self, row: dict) -> dict:
        return self.deliver("send_decision", listener=row["listener_agent"], decision={
            "file_id": row["file_id"], "manifest_sha256": row["manifest_sha256"],
            "kind": row["kind"], "request_id": row.get("request_id"),
            "decision": "declined",
        })

    def reject(self, *, request_hash: str) -> dict:
        """Record locally first; privately notify the verified requester.

        Remote delivery can be queued for seven days if the listener is offline.
        A notification failure must never erase a recorded decision.
        """
        with self._request_lock:
            row = next((r for r in self.requests() if r["request_hash"] == request_hash), None)
            if row is None:
                raise ArtistError("unknown access request")
            if row["status"] == "approved":
                raise ArtistError("an already granted licence or stream cannot be declined retroactively")
            if row["status"] == "declined":
                return {"declined": True, "already_decided": True}
            self._save_decision(request_hash, status="declined")
            try:
                outcome = self._send_decline(row)
            except (BridgeError, OutboxError, ValueError) as exc:
                return {"declined": True, "notification_error": str(exc)[:160]}
            return {"declined": True, **outcome}

    def resend_decline(self, *, request_hash: str) -> dict:
        """Explicit repair for decisions saved before notifications existed."""
        with self._request_lock:
            row = next((r for r in self.requests() if r["request_hash"] == request_hash), None)
            if row is None or row["status"] != "declined":
                raise ArtistError("no declined request found")
            return self._send_decline(row)

    def decide_batch(self, *, request_hashes: list[str], action: str) -> dict:
        """Apply explicit snapshot IDs only; never run an unbounded server-side 'all'.
        Each result is independent so a failed delivery cannot silently skip others."""
        if action not in ("approve", "decline"):
            raise ArtistError("invalid decision")
        if (not isinstance(request_hashes, list) or not 1 <= len(request_hashes) <= 25
                or any(not isinstance(h, str) or not 0 < len(h) <= 80 for h in request_hashes)
                or len(set(request_hashes)) != len(request_hashes)):
            raise ArtistError("provide 1–25 distinct request hashes")
        outcomes = []
        for h in request_hashes:
            try:
                with self._request_lock:
                    row = next((r for r in self.requests() if r["request_hash"] == h), None)
                    if row is None:
                        raise ArtistError("unknown access request")
                    if row["status"] != "pending":
                        raise ArtistError("request is already resolved")
                    result = (self.grant(request_hash=h, kind=row["kind"]) if action == "approve"
                              else self.reject(request_hash=h))
                outcomes.append({"request_hash": h, "ok": True, "queued": bool(result.get("queued")),
                                 "notification_error": result.get("notification_error")})
            except (ArtistError, BridgeError, KeyStoreError, LibraryError, OutboxError,
                    ContentGrantError, StorageError, ValueError, KeyError, TypeError) as exc:
                outcomes.append({"request_hash": h, "ok": False, "error": str(exc)[:160]})
        return {"action": action, "processed": len(outcomes),
                "succeeded": sum(o["ok"] for o in outcomes), "results": outcomes}

    def grant(self, *, request_hash: str, kind: str) -> dict:
        """Approve one private request: wrap the content key to the X25519 key
        the listener sent in that authenticated request and deliver privately."""
        with self._request_lock:
            return self._grant_locked(request_hash=request_hash, kind=kind)

    def _grant_locked(self, *, request_hash: str, kind: str) -> dict:
        if kind not in ("stream", "perpetual-personal"):
            raise ArtistError("unknown grant kind")
        current = next((r for r in self.requests() if r["request_hash"] == request_hash), None)
        if current is None:
            raise ArtistError("unknown access request")
        if current["status"] != "pending":
            raise ArtistError("request is already approved or declined")
        if current["kind"] != kind:
            raise ArtistError("grant type must match the access requested")
        request = next((r for r in self._inbox() if r["request_hash"] == request_hash), None)
        if request is None:
            raise ArtistError("unknown access request")
        file_id = file_key(request["file_id"])
        d = self.files / file_id
        if not (d / "track.json").is_file():
            raise ArtistError("you can only grant access to tracks you published")
        manifest = _read_json(d / "manifest.json")
        if request["manifest_sha256"] != manifest_digest(manifest):
            raise ArtistError("request refers to a different version of this track")
        recipient = bytes.fromhex(request["x25519_public_hex"])
        X25519PublicKey.from_public_bytes(recipient)
        listener_agent = request["listener_agent"]
        common = dict(owner_signer=self.keys.artist_ed25519(), owner_agent=self.me, listener_agent=listener_agent,
                      recipient_public=recipient, signed_manifest=manifest,
                      content_key=self.keys.content_key(file_id))
        grant = issue_personal_licence(**common) if kind == "perpetual-personal" else \
            issue_content_grant(**common, lifetime_seconds=86400)
        outcome = self.deliver("send_grant", listener=listener_agent, grant={
            "file_id": file_id, "manifest_sha256": manifest_digest(manifest), "kind": kind,
            "grant_json": canonical(grant).decode()})
        log = self.issued()
        log.append({"listener_agent": listener_agent, "file_id": file_id, "kind": kind,
                    "request_hash": request_hash, "issued_at": int(time.time())})
        _atomic_json(self._issued_log(), log[-5000:])
        self._save_decision(request_hash, status="approved", kind=kind)
        return {"granted": True, "kind": kind, **outcome}
