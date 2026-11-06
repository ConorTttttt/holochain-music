"""Catalogue discovery and host/manifest trust resolution for one track.

Trust chain, unchanged from S2/S5/S9 but driven by discovery instead of
pre-supplied agent IDs:

1. Track, artist key binding and file commitment are authored by the artist
   agent (validated by this machine's conductor).
2. Replica claims, host key bindings and MoQ endpoints are authored by each
   host agent.
3. The signed S1 manifest and host receipt are fetched from the host over the
   pinned MoQ endpoint and accepted only if the manifest digest equals the
   artist's Holochain pin and both Ed25519 signatures verify.

A host that fails any check is skipped; the next one is tried.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import time

from holochain_storage.holochain_identity import (
    AuthoredRecord, HOST_PURPOSE, OWNER_PURPOSE, key_for_agent,
    verify_owned_manifest, verify_replica_claim,
)
from holochain_storage.package import StorageError, manifest_digest
from music_catalogue.contract import CatalogueError, validate_track, verify_track_manifest
from .metadata import HEX64, genres_list, validate_artwork_record
from music_catalogue.moq_conductor import MOQ_ENDPOINT_SCHEMA, _bound_local_url
from music_catalogue.moq_host import MoqFetchError, fetch_document

from .bridge import Bridge, BridgeError

ARTIST_SCHEMA = "holochain-music/artist/v1"
ALBUM_SCHEMA = "holochain-music/album/v1"
MAX_HOSTS_TRIED = 8


class ResolveError(RuntimeError):
    """No authenticated, reachable host could be established for a track."""


@dataclass
class HostCandidate:
    node_agent: str
    node_key: bytes
    url: str
    fingerprint: str


@dataclass
class TrustedTrack:
    artist_agent: str
    track: dict
    artist_key: bytes
    manifest: dict
    digest: str
    hosts: list[HostCandidate] = field(default_factory=list)


def _unique_key(records: list[AuthoredRecord], agent: str, purpose: str) -> bytes:
    """All matching bindings must agree on one key; otherwise it is ambiguous."""
    keys = set()
    for record in records:
        try:
            keys.add(key_for_agent(record, agent, purpose))
        except StorageError:
            continue
    if len(keys) != 1:
        raise ResolveError(f"{'no' if not keys else 'ambiguous'} {purpose} key binding for agent")
    return keys.pop()


def _binding_record(records: list[AuthoredRecord], agent: str, purpose: str, key: bytes) -> AuthoredRecord:
    for record in records:
        try:
            if key_for_agent(record, agent, purpose) == key:
                return record
        except StorageError:
            continue
    raise ResolveError("key binding disappeared")


class Catalogue:
    def __init__(self, bridge: Bridge, *, moq_binary, allow_lan: bool = False):
        self.bridge = bridge
        self.moq_binary = moq_binary
        self.allow_lan = allow_lan
        self._profiles: dict[str, tuple[float, dict | None]] = {}

    # ---- browsing (display data only; nothing here authorises playback) --
    def _clean_track(self, record: AuthoredRecord) -> dict | None:
        try:
            validate_track(record.body, author=record.author)
        except CatalogueError:
            return None
        body = record.body
        return {"key": f"{record.author}:{body['track_id']}", "artist_agent": record.author,
                "track_id": body["track_id"], "album_id": body["album_id"], "title": body["title"],
                "duration_ms": body["duration_ms"], "disc_number": body["disc_number"],
                "track_number": body["track_number"], "audio_format": body["audio_format"],
                "file_id": body["file_id"], "manifest_sha256": body["manifest_sha256"],
                "rights_basis": body["rights_basis"],
                "genres": body.get("genres", []), "artwork_sha256": body.get("artwork_sha256")}

    def profile(self, agent: str) -> dict | None:
        cached = self._profiles.get(agent)
        if cached and time.monotonic() - cached[0] < 60:
            return cached[1]
        record = self.bridge.record("get_artist_profile", artist=agent)
        result = None
        if record and record.author == agent and record.body.get("artist_agent") == agent \
                and record.body.get("schema") == ARTIST_SCHEMA:
            result = {"agent": agent, "display_name": str(record.body.get("display_name", ""))[:120],
                      "biography": str(record.body.get("biography", ""))[:2048]}
        if result is not None:  # never cache absence: DHT data may still be arriving
            self._profiles[agent] = (time.monotonic(), result)
        return result

    def artists(self) -> list[dict]:
        out = []
        for r in self.bridge.records("list_artists"):
            if r.body.get("artist_agent") == r.author and r.body.get("schema") == ARTIST_SCHEMA:
                out.append({"agent": r.author, "display_name": str(r.body.get("display_name", ""))[:120],
                            "biography": str(r.body.get("biography", ""))[:2048]})
                self._profiles[r.author] = (time.monotonic(), out[-1])
        return out

    def _decorate(self, tracks: list[dict]) -> list[dict]:
        for t in tracks:
            p = self.profile(t["artist_agent"])
            t["artist_name"] = p["display_name"] if p else "Unknown artist"
        return tracks

    def browse(self, limit: int = 100) -> list[dict]:
        rows = [self._clean_track(r) for r in self.bridge.records("browse_tracks", limit=limit)]
        return self._decorate([r for r in rows if r])

    def search(self, query: str, limit: int = 50) -> list[dict]:
        rows = [self._clean_track(r) for r in self.bridge.records("search_tracks", query=query, limit=limit)]
        return self._decorate([r for r in rows if r])

    def artist_tracks(self, agent: str) -> list[dict]:
        rows = [self._clean_track(r) for r in self.bridge.records("list_tracks", artist=agent)]
        return self._decorate([r for r in rows if r and r["artist_agent"] == agent])

    def albums(self, agent: str) -> list[dict]:
        out = []
        for r in self.bridge.records("list_albums", artist=agent):
            b = r.body
            if r.author == agent and b.get("artist_agent") == agent and b.get("schema") == ALBUM_SCHEMA:
                try:
                    genres = genres_list(b.get("genres", []))
                    cover = b.get("artwork_sha256")
                    if cover is not None and (not isinstance(cover, str) or not HEX64.fullmatch(cover)):
                        continue
                except ValueError:
                    continue
                out.append({"album_id": b.get("album_id"), "title": str(b.get("title", ""))[:200],
                            "release_date": b.get("release_date"), "artist_agent": agent,
                            "artwork_sha256": cover, "genres": genres})
        return out

    def artwork(self, agent: str, digest: str) -> dict:
        """Public art is verified against author + digest before it reaches the UI."""
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise CatalogueError("invalid artwork digest")
        record = self.bridge.record("get_artwork", artist=agent, sha256=digest)
        if record is None or record.author != agent:
            raise CatalogueError("artwork is not available from this artist")
        validate_artwork_record(record.body, author=agent, digest=digest)
        return {"mime_type": record.body["mime_type"], "data_base64": record.body["data_base64"]}

    # ---- trust resolution for playback --------------------------------
    def resolve(self, artist_agent: str, track_id: str) -> TrustedTrack:
        track = self.bridge.record("get_track", artist=artist_agent, track_id=track_id)
        if track is None or track.author != artist_agent:
            raise ResolveError("track not found in the authenticated catalogue")
        validate_track(track.body, author=artist_agent)
        owner_bindings = self.bridge.records("get_signing_keys", agent=artist_agent)
        artist_key = _unique_key(owner_bindings, artist_agent, OWNER_PURPOSE)
        owner_binding = _binding_record(owner_bindings, artist_agent, OWNER_PURPOSE, artist_key)
        file_id, digest = track.body["file_id"], track.body["manifest_sha256"]
        commitments = [c for c in self.bridge.records("get_file_commitments", agent=artist_agent)
                       if c.body.get("file_id") == file_id and c.body.get("manifest_sha256") == digest]
        if not commitments:
            raise ResolveError("artist has not committed to this encrypted file")
        commitment = commitments[0]
        claims = self.bridge.records("get_replica_claims", owner_agent=artist_agent, file_id=file_id)
        trusted: TrustedTrack | None = None
        errors = []
        tried = 0
        # Newest claims first; each host is tried with its newest endpoint first.
        for claim in reversed(claims):
            node = claim.author
            if claim.body.get("node_agent") != node or claim.body.get("manifest_sha256") != digest:
                continue
            if tried >= MAX_HOSTS_TRIED:
                break
            tried += 1
            try:
                host_bindings = self.bridge.records("get_signing_keys", agent=node)
                node_key = _unique_key(host_bindings, node, HOST_PURPOSE)
                node_binding = _binding_record(host_bindings, node, HOST_PURPOSE, node_key)
                endpoints = []
                for e in reversed(self.bridge.records("get_moq_endpoints", host=node)):
                    b = e.body
                    if (e.author == node and b.get("schema") == MOQ_ENDPOINT_SCHEMA and b.get("node_agent") == node
                            and b.get("owner_agent") == artist_agent and b.get("file_id") == file_id
                            and b.get("manifest_sha256") == digest):
                        try:
                            url = _bound_local_url(b.get("url"), allow_lan=self.allow_lan)
                        except ValueError:
                            continue
                        fp = b.get("cert_fingerprint_hex")
                        if (url, fp) not in [(c.url, c.fingerprint) for c in endpoints]:
                            endpoints.append(HostCandidate(node, node_key, url, fp))
                for candidate in endpoints[:3]:
                    try:
                        if trusted is None:
                            manifest = fetch_document(moq_binary=self.moq_binary, url=candidate.url,
                                                      cert_fingerprint_hex=candidate.fingerprint,
                                                      file_id=file_id, document="manifest",
                                                      allow_lan=self.allow_lan)
                            if manifest_digest(manifest) != digest:
                                raise ResolveError("host served a manifest that does not match the artist's pin")
                            verify_track_manifest(track.body, manifest, author=artist_agent, trusted_signer=artist_key)
                            verify_owned_manifest(manifest, artist_agent, owner_binding, commitment)
                        else:
                            manifest = trusted.manifest
                        receipt = fetch_document(moq_binary=self.moq_binary, url=candidate.url,
                                                 cert_fingerprint_hex=candidate.fingerprint,
                                                 file_id=file_id, document="receipt", allow_lan=self.allow_lan)
                        verify_replica_claim(receipt, manifest, artist_agent, node, owner_binding,
                                             node_binding, commitment, claim)
                        if trusted is None:
                            trusted = TrustedTrack(artist_agent, track.body, artist_key, manifest, digest)
                        trusted.hosts.append(candidate)
                        break
                    except (MoqFetchError, StorageError, CatalogueError, ResolveError) as exc:
                        errors.append(f"{type(exc).__name__}: {exc}")
            except (BridgeError, ResolveError, StorageError) as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
        if trusted is None or not trusted.hosts:
            detail = errors[-1] if errors else "no host has published this track"
            raise ResolveError(f"track unavailable: {detail}"[:240])
        return trusted

