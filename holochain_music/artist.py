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

import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import time
import wave

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from holochain_storage.holochain_identity import HOST_PURPOSE, OWNER_PURPOSE, key_for_agent
from holochain_storage.package import (
    StorageError, canonical, create_package, manifest_digest, public_key_bytes,
    replicate_package, sha256,
)
from music_catalogue.content_grants import issue_content_grant, issue_personal_licence
from music_catalogue.moq_conductor import MOQ_ENDPOINT_SCHEMA

from .artwork import AlbumArtworkStore, load_cover
from .artwork_transport import publish_public_artwork
from .bridge import Bridge
from .keys import KeyStore
from .library import _atomic_json, _read_json, file_key

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
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
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
        self.root = Path(host_root)
        self.cas = self.root / "cas"
        self.files = self.root / "files"
        self.album_art = AlbumArtworkStore(self.root / 'artwork')
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

    def create_album(self, title: str, release_date: str | None, *,
                     artwork_path: Path | None = None) -> dict:
        """Create a v1 album with an optional immutable, publicly retrievable
        artist-signed artwork package pinned to this first album record."""
        cover = load_cover(artwork_path) if artwork_path is not None else None
        album_id = secrets.token_hex(16)
        digest = None
        if cover is not None:
            signer = self.keys.artist_ed25519()
            artist_key = public_key_bytes(signer)
            self._ensure_key(OWNER_PURPOSE, artist_key)
            manifest = publish_public_artwork(
                cover, artist_agent=self.me, album_id=album_id,
                signer=signer, store=self.cas)
            digest = manifest_digest(manifest)
            # Use existing, Holochain-authenticated storage commitments and
            # claims. MoQ serves the exact signed S1 artwork as a public file.
            self.bridge.call("publish_file_commitment", entry={
                "schema": "holochain-storage/file-commitment/v1", "owner_agent": self.me,
                "file_id": manifest["body"]["file_id"], "manifest_sha256": digest})
            self.host_file(manifest, owner_agent=self.me, artist_key=artist_key)
            self.album_art.save(album_id, cover)
        try:
            self.bridge.call("publish_album", entry={
                "schema": "holochain-music/album/v1", "artist_agent": self.me, "album_id": album_id,
                "title": title.strip(), "release_date": release_date or None,
                "artwork_manifest_sha256": digest})
        except BaseException:
            # The published file commitment/claim is append-only: an orphan
            # can remain in the DHT, but it cannot be associated with an album
            # without this artist-authored album pin.
            if cover is not None:
                self.album_art.delete(album_id)
            raise
        return {"album_id": album_id, "local_artwork": cover is not None,
                "artwork_manifest_sha256": digest}

    def my_albums(self) -> list[dict]:
        """Verified authored album records with a local-only art availability flag."""
        seen: set[str] = set()
        albums = []
        for record in self.bridge.records("list_albums", artist=self.me):
            body = record.body
            album_id = body.get("album_id")
            if (record.author != self.me or body.get("artist_agent") != self.me
                    or body.get("schema") != "holochain-music/album/v1"
                    or not isinstance(album_id, str) or len(album_id) != 32
                    or any(c not in "0123456789abcdef" for c in album_id)
                    or album_id in seen):
                continue
            seen.add(album_id)
            albums.append({"album_id": album_id, "title": str(body.get("title", ""))[:200],
                           "local_artwork": self.album_art.has(album_id),
                           "artwork_manifest_sha256": body.get("artwork_manifest_sha256")})
        return albums

    def publish_track(self, *, wav: Path, title: str, album_id: str | None = None,
                      track_number: int = 1, disc_number: int = 1,
                      rights_basis: str = "original_owner") -> dict:
        if rights_basis not in ("original_owner", "licensed_by_rights_holder"):
            raise ArtistError("invalid rights declaration")
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
            "file_id": file_id, "manifest_sha256": digest, "rights_basis": rights_basis})
        self.host_file(manifest, owner_agent=self.me, artist_key=public_key_bytes(artist_key))
        _atomic_json(d / "track.json", {"track_id": track_id, "title": title.strip(), "file_id": file_id,
                                        "album_id": album_id or None, "track_number": track_number,
                                        "manifest_sha256": digest, "owner_agent": self.me,
                                        "published_at": int(time.time()), **info})
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
        mine = {t["file_id"]: t for t in self.my_tracks()}
        issued = {(g["listener_agent"], g["file_id"], g["kind"]) for g in self.issued()}
        out = []
        for b in self._inbox():
            track = mine.get(b.get("file_id"))
            if track is None or b.get("manifest_sha256") != track["manifest_sha256"]:
                continue
            out.append({"request_hash": b["request_hash"], "listener_agent": b["listener_agent"],
                        "file_id": b["file_id"], "track_title": track["title"], "kind": b.get("kind"),
                        "note": str(b.get("note", ""))[:500], "received_at": b["received_at"],
                        "granted": (b["listener_agent"], b["file_id"], b.get("kind")) in issued})
        return out

    def grant(self, *, request_hash: str, kind: str) -> dict:
        """Approve one private request: wrap the content key to the X25519 key
        the listener sent in that authenticated request and deliver privately."""
        if kind not in ("stream", "perpetual-personal"):
            raise ArtistError("unknown grant kind")
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
        log.append({"listener_agent": listener_agent, "file_id": file_id, "kind": kind, "issued_at": int(time.time())})
        _atomic_json(self._issued_log(), log[-5000:])
        return {"granted": True, "kind": kind, **outcome}
