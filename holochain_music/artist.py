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

from holochain_storage.holochain_identity import (
    ASSURANCE_POP_V2, HOST_PURPOSE, OWNER_PURPOSE, key_for_agent, make_key_binding_v2,
    resolve_signing_key,
)
from holochain_storage import key_lifecycle as kl
from holochain_storage.package import (
    StorageError, b64, canonical, create_package, manifest_digest, public_key_bytes,
    replicate_package, sha256,
)
from music_catalogue.content_grants import issue_content_grant, issue_personal_licence
from music_catalogue.moq_conductor import MOQ_ENDPOINT_SCHEMA

from .artwork import AlbumArtworkStore, load_cover
from .bridge import Bridge
from .keys import KeyStore
from .library import _atomic_json, _read_json, file_key

RATES = (8000, 11025, 16000, 22050, 32000, 44100, 48000)
KEY_SCHEMA = "holochain-storage/key-binding/v1"
MAX_WAV_BYTES = 2 * 1024**3


class ArtistError(RuntimeError):
    pass


_ROLE = {OWNER_PURPOSE: "artist", HOST_PURPOSE: "host"}


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
    def __init__(self, *, bridge: Bridge, keys: KeyStore, host_root: Path, deliver=None,
                 key_binding: str = "v1"):
        """`key_binding="v2"` is an explicit opt-in for the separate v2 storage
        DNA (dna-v2/, proof-of-possession bindings); `"v2.1"` for the separate
        v2.1 DNA (dna-v21/, key lifecycle with rotation/revocation and
        host-attributed receipts). The default keeps the existing v1
        behaviour; no existing identity is migrated."""
        if key_binding not in ("v1", "v2", "v2.1"):
            raise ArtistError("key_binding must be 'v1', 'v2' or 'v2.1'")
        self.key_binding = key_binding
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
    def _signer(self, purpose: str):
        """The key that signs NEW operations for `purpose`. v1/v2: the fixed
        key-store key (unchanged). v2.1: the active lifecycle generation's key
        (an inception with the existing key is published if none exists)."""
        if self.key_binding != "v2.1":
            return {OWNER_PURPOSE: self.keys.artist_ed25519, HOST_PURPOSE: self.keys.host_ed25519}[purpose]()
        generation = self._active_v21(purpose)
        signer = self.keys.lifecycle_ed25519(_ROLE[purpose], generation.generation)
        if public_key_bytes(signer) != generation.key:
            raise ArtistError("active lifecycle key does not match this installation's key store")
        return signer

    def _ensure_key(self, purpose: str, public: bytes) -> None:
        if self.key_binding == "v2.1":
            if self._active_v21(purpose).key != public:
                raise ArtistError(f"{purpose} key is not this agent's active lifecycle key")
            return
        if self.key_binding == "v2":
            signer = {OWNER_PURPOSE: self.keys.artist_ed25519, HOST_PURPOSE: self.keys.host_ed25519}[purpose]()
            if public_key_bytes(signer) != public:
                raise ArtistError("signing key does not match this installation's key store")
            self._ensure_key_v2(purpose, signer)
            return
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

    def _ensure_key_v2(self, purpose: str, signer) -> None:
        """Opt-in v2 registration: sign the proof of possession locally, publish
        only public material, then re-read and verify what the DHT returns."""
        public = public_key_bytes(signer)
        context = self.bridge.call("key_binding_v2_context")
        if not isinstance(context, dict) or context.get("agent") != self.me:
            raise ArtistError("storage cell agent differs from this installation's agent")
        dna_hash = context.get("dna_hash")

        def current():
            records = self.bridge.records("get_signing_keys_v2", agent=self.me)
            if not any(r.body.get("purpose") == purpose for r in records if isinstance(r.body, dict)):
                return None
            try:
                key, _ = resolve_signing_key(records, self.me, purpose,
                                             require=ASSURANCE_POP_V2, dna_hash=dna_hash)
            except StorageError as exc:
                raise ArtistError(f"existing {purpose} key bindings are invalid or ambiguous: {exc}") from exc
            return key

        existing = current()
        if existing == public:
            return
        if existing is not None:
            raise ArtistError(f"this agent already has a different {purpose} key registered")
        entry = make_key_binding_v2(signer, dna_hash=dna_hash, agent=self.me, purpose=purpose)
        self.bridge.call("register_signing_key_v2", entry=entry)
        if current() != public:
            raise ArtistError("registered key binding could not be confirmed")

    # ---- S2 key lifecycle v2.1 (opt-in, dna-v21/) -------------------------
    def _context_v21(self, purpose: str) -> dict:
        context = self.bridge.call("key_lifecycle_v21_context", purpose=purpose)
        if not isinstance(context, dict) or context.get("agent") != self.me or context.get("purpose") != purpose:
            raise ArtistError("storage cell agent differs from this installation's agent")
        return context

    def lifecycle_v21(self, purpose: str, agent: str | None = None) -> kl.KeyLifecycle:
        """Resolve and verify `agent`'s lifecycle from the conductor (DHT view)."""
        dna_hash = self._context_v21(purpose)["dna_hash"]
        rows = self.bridge.call("get_key_lifecycle_v21", agent=agent or self.me)
        if not isinstance(rows, list):
            raise ArtistError("expected lifecycle records")
        records = [kl.SequencedRecord(r["author"], r["action_hash"], r["action_seq"], r["body"]) for r in rows]
        try:
            return kl.resolve_key_lifecycle(records, agent or self.me, purpose, dna_hash)
        except StorageError as exc:
            raise ArtistError(f"key lifecycle unavailable: {exc}") from exc

    def _active_v21(self, purpose: str) -> kl.KeyGeneration:
        context = self._context_v21(purpose)
        if context["next_generation"] == "1":
            entry = kl.make_inception(self.keys.lifecycle_ed25519(_ROLE[purpose], 1),
                                      dna_hash=context["dna_hash"], agent=self.me, purpose=purpose)
            self.bridge.call("publish_key_transition_v21", entry=entry)
        try:
            return self.lifecycle_v21(purpose).active()
        except StorageError as exc:
            raise ArtistError(f"no active {purpose} key: {exc}") from exc

    def _grant_signer(self, manifest: dict):
        """S10 grants are signed by the key that signed the manifest. Under
        v2.1 issuing a grant is a NEW operation, so that key must still be the
        ACTIVE owner key; a rotated or revoked key never signs new grants.
        (A different issuer than the manifest signer needs a new, versioned
        grant format; see docs/s2-key-lifecycle-v21.md.)"""
        signer = self._signer(OWNER_PURPOSE)
        if self.key_binding == "v2.1" and manifest.get("signer") != b64(public_key_bytes(signer)):
            raise ArtistError("this track was signed by an owner key that is no longer active; "
                              "new grants need the track re-published under the active key")
        return signer

    def rotate_key_v21(self, purpose: str) -> dict:
        """Normal rotation: a NEW key (stored locally first) proves possession,
        the current key signs continuity, the agent authors the transition."""
        if self.key_binding != "v2.1":
            raise ArtistError("key rotation requires the v2.1 storage DNA")
        current = self._active_v21(purpose)
        context = self._context_v21(purpose)
        if context["predecessor_action"] != current.action_hash or context["predecessor_revoked"]:
            raise ArtistError("local chain and resolved lifecycle disagree; refusing to rotate")
        old = self.keys.lifecycle_ed25519(_ROLE[purpose], current.generation)
        new = self.keys.lifecycle_ed25519(_ROLE[purpose], current.generation + 1, create=True)
        entry = kl.make_rotation(new, old, dna_hash=context["dna_hash"], agent=self.me, purpose=purpose,
                                 predecessor_action=current.action_hash,
                                 predecessor_generation=str(current.generation))
        self.bridge.call("publish_key_transition_v21", entry=entry)
        if self._active_v21(purpose).key != public_key_bytes(new):
            raise ArtistError("rotation could not be confirmed")
        return {"purpose": purpose, "generation": current.generation + 1, "signing_key_hex": entry["signing_key_hex"]}

    def revoke_key_v21(self, purpose: str, generation: int, scope: str) -> dict:
        """Agent-authorised revocation of one exact generation."""
        if self.key_binding != "v2.1":
            raise ArtistError("key revocation requires the v2.1 storage DNA")
        lifecycle = self.lifecycle_v21(purpose)
        target = next((g for g in lifecycle.generations if g.generation == generation), None)
        if target is None:
            raise ArtistError("no such key generation")
        entry = kl.make_revocation(dna_hash=lifecycle.dna_hash, agent=self.me, purpose=purpose,
                                   generation=str(generation), signing_key_hex=target.key.hex(),
                                   target_action=target.action_hash, scope=scope)
        self.bridge.call("publish_key_revocation_v21", entry=entry)
        return {"purpose": purpose, "generation": generation, "scope": scope}

    # ---- catalogue ----------------------------------------------------
    def save_profile(self, display_name: str, biography: str) -> dict:
        return self.bridge.call("publish_artist_profile", entry={
            "schema": "holochain-music/artist/v1", "artist_agent": self.me,
            "display_name": display_name.strip(), "biography": biography.strip(),
            "artwork_manifest_sha256": None})

    def create_album(self, title: str, release_date: str | None, *,
                     artwork_path: Path | None = None) -> dict:
        """Create a public album entry; cover stays local until a verified
        cross-peer artwork distribution protocol is available."""
        cover = load_cover(artwork_path) if artwork_path is not None else None
        album_id = secrets.token_hex(16)
        if cover is not None:
            self.album_art.save(album_id, cover)
        try:
            # Do not put a bare PNG digest in artwork_manifest_sha256: that
            # catalogue field expects a signed artwork manifest, not file bytes.
            self.bridge.call("publish_album", entry={
                "schema": "holochain-music/album/v1", "artist_agent": self.me, "album_id": album_id,
                "title": title.strip(), "release_date": release_date or None, "artwork_manifest_sha256": None})
        except BaseException:
            if cover is not None:
                self.album_art.delete(album_id)
            raise
        return {"album_id": album_id, "local_artwork": cover is not None}

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
                           "local_artwork": self.album_art.has(album_id)})
        return albums

    def publish_track(self, *, wav: Path, title: str, album_id: str | None = None,
                      track_number: int = 1, disc_number: int = 1,
                      rights_basis: str = "original_owner") -> dict:
        if rights_basis not in ("original_owner", "licensed_by_rights_holder"):
            raise ArtistError("invalid rights declaration")
        artist_key = self._signer(OWNER_PURPOSE)
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
        host_key = self._signer(HOST_PURPOSE)
        self._ensure_key(HOST_PURPOSE, public_key_bytes(host_key))
        if self.key_binding == "v2.1":
            # Host-attributed replica-receipt/v2 (S1 receipt format unchanged).
            active = self.lifecycle_v21(HOST_PURPOSE).active()
            receipt = kl.replicate_package_v2(
                manifest, self.cas, self.cas, artist_key, host_key, dna_hash=self.lifecycle_v21(HOST_PURPOSE).dna_hash,
                host_agent=self.me, host_key_generation=str(active.generation),
                host_key_action=active.action_hash, owner_agent=owner_agent)
            receipt_sha256 = kl.receipt_v2_digest(receipt)
        else:
            receipt = replicate_package(manifest, self.cas, self.cas, artist_key, host_key)
            receipt_sha256 = sha256(canonical(receipt))
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
            "manifest_sha256": manifest_digest(manifest), "receipt_sha256": receipt_sha256})

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
        common = dict(owner_signer=self._grant_signer(manifest), owner_agent=self.me, listener_agent=listener_agent,
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
