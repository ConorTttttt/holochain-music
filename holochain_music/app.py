"""Holochain Music application core: one object the UI and CLI talk to."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import socket
import threading
import time

from holochain_storage.package import (
    StorageError, decrypt_package, manifest_digest, public_key_bytes, replicate_package,
)
from music_catalogue.content_grants import (
    ContentGrantError, grant_kind, issue_personal_licence, unwrap_content_grant,
)
from music_catalogue.contract import CatalogueError, validate_track
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.moq_host import MoqHost

from . import binaries
from .artist import ArtistError, ArtistService
from .bridge import Bridge, BridgeError
from .catalogue import Catalogue, ResolveError
from .conductor import APP_ID, BootstrapServer, Conductor, ConductorError
from .keys import KeyStore
from .library import Library, LibraryError, _atomic_json, file_key
from .paths import AppPaths
from .outbox import Outbox
from .player import Player, SessionSpec
from .streaming import Download

DEFAULT_BOOTSTRAP = "127.0.0.1:47011"
DEFAULTS = {
    "bootstrap_url": f"http://{DEFAULT_BOOTSTRAP}",
    "relay_url": f"http://{DEFAULT_BOOTSTRAP}",
    "run_local_bootstrap": True,
    "bootstrap_poll_max_ms": 30_000,
    "allow_lan": False,
    "host_enabled": True,
    "host_bind": "127.0.0.1:0",
    "host_advertise_ip": None,
    "host_max_rate": 8 * 1024 * 1024,
    "audio_backend": "alsa",
    "audio_device": "default",
}
USER_ERRORS = (PlaybackError, StorageError, CatalogueError, ResolveError, ArtistError, LibraryError,
               BridgeError, ConductorError, ContentGrantError, ValueError)


class AppError(RuntimeError):
    pass


class AlreadyRunning(AppError):
    pass


class MusicApp:
    def __init__(self, paths: AppPaths | None = None):
        self.paths = paths or AppPaths.default()
        self.paths.ensure()
        self.settings = self._load_settings()
        self.keys = KeyStore(self.paths.keys)
        self.library = Library(self.paths.library)
        self.conductor: Conductor | None = None
        self.bootstrap: BootstrapServer | None = None
        self.bridge: Bridge | None = None
        self.catalogue: Catalogue | None = None
        self.artist: ArtistService | None = None
        self.host: MoqHost | None = None
        self.downloads: dict[str, Download] = {}
        self.outbox: Outbox | None = None
        self.queue: list[str] = []
        self.status_message = "starting"
        self.online = False
        self._lock_fd = None
        self._sync_lock = threading.Lock()
        self.player = Player(backend=self.settings["audio_backend"], device=self.settings["audio_device"],
                             resolve=self._session_for, on_finished=self._advance,
                             on_started=self._record_play)

    # ---- settings -----------------------------------------------------
    def _load_settings(self) -> dict:
        path = self.paths.settings_file
        stored = {}
        if path.is_file():
            try:
                stored = json.loads(path.read_text())
            except ValueError:
                stored = {}
        settings = {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS or k == "pins"}}
        return settings

    def save_settings(self, **changes) -> dict:
        for key, value in changes.items():
            if key not in DEFAULTS:
                raise AppError(f"unknown setting {key}")
            if key in ("bootstrap_url", "relay_url"):
                if not isinstance(value, str) or not value.startswith(("http://", "https://")) or len(value) > 200:
                    raise AppError("network URLs must be http(s) URLs")
            if key == "host_advertise_ip" and value is not None:
                import ipaddress
                try:
                    ip = ipaddress.IPv4Address(value)
                except ValueError as exc:
                    raise AppError("host_advertise_ip must be an IPv4 address") from exc
                rfc1918 = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
                if not any(ip in n for n in rfc1918):  # same rule as the DNA and MoQ validators
                    raise AppError("host_advertise_ip must be a private-LAN (RFC1918) address")
            if key == "host_bind" and (not isinstance(value, str) or value.count(":") != 1
                                       or not value.rsplit(":", 1)[1].isdecimal()):
                raise AppError("host_bind must look like 0.0.0.0:47100 or 127.0.0.1:47100")
            if key == "audio_device" and (not isinstance(value, str) or not value or len(value) > 128):
                raise AppError("invalid ALSA device name")
            if key in ("allow_lan", "host_enabled", "run_local_bootstrap") and not isinstance(value, bool):
                raise AppError(f"{key} must be true or false")
            if key == "host_max_rate" and (type(value) is not int or not 64 * 1024 <= value <= 1024**3):
                raise AppError("host rate must be between 64 KiB/s and 1 GiB/s")
            if key == "bootstrap_poll_max_ms" and (type(value) is not int or not 5_000 <= value <= 300_000):
                raise AppError("bootstrap poll interval must be 5000–300000 ms")
            if key == "audio_backend" and value not in ("alsa", "null"):
                raise AppError("audio backend must be alsa or null")
            self.settings[key] = value
        _atomic_json(self.paths.settings_file, self.settings)
        return self.settings

    # ---- lifecycle ----------------------------------------------------
    def lock(self) -> None:
        fd = os.open(self.paths.lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise AlreadyRunning("Holochain Music is already running for this user/data directory") from exc
        self._lock_fd = fd

    def start(self, *, offline: bool = False) -> None:
        """Start network services. Offline mode needs none of them."""
        self.lock()
        if offline:
            self.status_message = "offline mode: playing your downloaded library only"
            return
        try:
            self._start_network()
        except (ConductorError, BridgeError, binaries.MissingBinary, OSError) as exc:
            # The library stays fully usable offline; report clearly.
            self.online = False
            self.status_message = f"offline: {exc}"[:240]

    def _start_network(self) -> None:
        logs = self.paths.logs
        url = self.settings["bootstrap_url"]
        if self.settings["run_local_bootstrap"] and url.startswith("http://127.0.0.1:"):
            # Single-machine use: run (or reuse) a loopback bootstrap+relay.
            address = url[len("http://"):].rstrip("/")
            host, port = address.split(":")
            with socket.socket() as s:
                in_use = s.connect_ex((host, int(port))) == 0
            if not in_use:
                self.bootstrap = BootstrapServer(address, logs / "bootstrap.log")
                self.bootstrap.start()
        self.conductor = Conductor(self.paths.conductor, self.keys.conductor_passphrase(),
                                   bootstrap_url=self.settings["bootstrap_url"],
                                   relay_url=self.settings["relay_url"], log_path=logs / "conductor.log",
                                   bootstrap_poll_max_ms=self.settings["bootstrap_poll_max_ms"])
        self.status_message = "installing Holochain app (first run)" if not self.conductor.installed() else "starting Holochain"
        self.conductor.install(binaries.find_happ())
        port = self.conductor.start()
        self.bridge = Bridge(port, app_id=APP_ID, log_path=logs / "bridge.log", pins=self.settings.get("pins"))
        who = self.bridge.start()
        if not self.settings.get("pins"):
            # Trust on first install: pin the DNA hashes of the bundled hApp.
            self.settings["pins"] = {"catalogue_dna": who["catalogue_dna"], "storage_dna": who["storage_dna"],
                                     "agent": who["agent"]}
            _atomic_json(self.paths.settings_file, self.settings)
        elif self.settings["pins"].get("agent") not in (None, who["agent"]):
            raise BridgeError("conductor agent changed unexpectedly; refusing to continue")
        moq = binaries.find("holochain-music-moq")
        self.catalogue = Catalogue(self.bridge, moq_binary=moq, allow_lan=self.settings["allow_lan"])
        self.outbox = Outbox(self.paths.data / "outbox.json", self.bridge.call)
        self.outbox.start()
        self.artist = ArtistService(bridge=self.bridge, keys=self.keys, host_root=self.paths.host,
                                    deliver=self.outbox.deliver)
        self.online = True
        self.status_message = "online"
        if self.settings["host_enabled"]:
            self.restart_host()

    def restart_host(self) -> dict | None:
        files = self.artist.hosted() if self.artist else []
        if not files:
            return None
        if self.host is None:
            bind = self.settings["host_bind"]
            if bind.endswith(":0"):
                # Persist a concrete port so the published URL survives restarts.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.bind(("127.0.0.1", 0))
                    bind = f"{bind.rsplit(':', 1)[0]}:{s.getsockname()[1]}"
                self.save_settings(host_bind=bind)
            self.host = MoqHost(moq_binary=binaries.find("holochain-music-moq"), store=self.paths.host / "cas",
                                cert_dir=self.paths.keys / "moq-host", state_dir=self.paths.host / "state",
                                bind=bind, advertise_ip=self.settings["host_advertise_ip"],
                                bytes_per_second=self.settings["host_max_rate"])
        self.host.set_files(files)
        ready = self.host.start()
        self.artist.publish_endpoints(ready["url"], ready["cert_fingerprint_hex"])
        return ready

    def stop(self) -> None:
        self.player.shutdown()
        for d in list(self.downloads.values()):
            d.stop()
        for part in (self.outbox, self.host, self.bridge, self.conductor, self.bootstrap):
            if part is not None:
                try:
                    part.stop()
                except Exception:
                    pass
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def require_online(self):
        if not self.online or self.catalogue is None:
            raise AppError("this needs the Holochain network; the app is offline")

    # ---- identity -----------------------------------------------------
    @property
    def agent(self) -> str | None:
        if self.bridge and self.bridge.whoami:
            return self.bridge.whoami["agent"]
        return (self.settings.get("pins") or {}).get("agent")

    def identity(self) -> dict:
        return {"agent": self.agent, "online": self.online, "status": self.status_message,
                "listener_x25519": self.keys.listener_public_hex(),
                "artist_ed25519": public_key_bytes(self.keys.artist_ed25519()).hex(),
                "host": {"url": self.host.url, "fingerprint": self.host.fingerprint}
                if self.host and self.host.ready else None,
                "settings": {k: v for k, v in self.settings.items() if k != "pins"}}

    # ---- library + grants -----------------------------------------------
    def _meta_from_trusted(self, trusted) -> dict:
        t = trusted.track
        profile = self.catalogue.profile(trusted.artist_agent) if self.catalogue else None
        album = None
        if t["album_id"]:
            album = next((a["title"] for a in self.catalogue.albums(trusted.artist_agent)
                          if a["album_id"] == t["album_id"]), None)
        return {"track_key": f"{trusted.artist_agent}:{t['track_id']}", "track_id": t["track_id"],
                "title": t["title"], "artist_agent": trusted.artist_agent,
                "artist_name": profile["display_name"] if profile else "Unknown artist",
                "album_id": t["album_id"], "album_title": album, "duration_ms": t["duration_ms"],
                "track_number": t["track_number"], "manifest_sha256": trusted.digest,
                "artist_key_hex": trusted.artist_key.hex(), "listener_agent": self.agent,
                "hosts": [{"node_agent": h.node_agent, "url": h.url, "fingerprint": h.fingerprint}
                          for h in trusted.hosts]}

    def sync_grants(self) -> int:
        """Import grants delivered privately to my own chain; keep only ones
        whose artist signature, listener binding and file binding verify."""
        self.require_online()
        added = 0
        with self._sync_lock:
            for row in self.bridge.call("get_inbox_grants") or []:
                b = row.get("body") if isinstance(row, dict) else None
                try:
                    owner = b["owner_agent"]
                    file_id = file_key(b["file_id"])
                    grant = json.loads(b["grant_json"])
                    meta = self.library.meta(file_id)
                    if meta is None or not self.library.has_manifest(file_id):
                        track = next((t for t in self.catalogue.artist_tracks(owner) if t["file_id"] == file_id), None)
                        if track is None:
                            continue
                        trusted = self.catalogue.resolve(owner, track["track_id"])
                        self.library.add(manifest=trusted.manifest, meta=self._meta_from_trusted(trusted))
                        meta = self.library.meta(file_id)
                    if meta["artist_agent"] != owner:
                        continue
                    kind = grant_kind(grant)
                    unwrap_content_grant(grant, trusted_artist=bytes.fromhex(meta["artist_key_hex"]),
                                         owner_agent=owner, listener_agent=self.agent,
                                         recipient_private=self.keys.listener_x25519(),
                                         signed_manifest=self.library.manifest(file_id))
                    if self.library.grant(file_id) != grant:
                        self.library.set_grant(file_id, grant, kind)  # never downgrades a licence
                        added += self.library.grant(file_id) == grant
                except (KeyError, TypeError, ValueError, *USER_ERRORS):
                    continue
        return added

    def request_access(self, track_key: str, kind: str, note: str = "") -> dict:
        """Send a private request to the artist's cell (artist must be online)."""
        self.require_online()
        if kind not in ("stream", "perpetual-personal"):
            raise AppError("invalid access kind")
        artist, track_id = self._split_key(track_key)
        if artist == self.agent:
            raise AppError("this is your own track; it is already in your library")
        # Only the DHT track record is needed to ask: the artist's host may be
        # offline. Hosts, manifest and signatures are verified when the grant
        # arrives (sync_grants) and again before any playback.
        record = self.bridge.record("get_track", artist=artist, track_id=track_id)
        if record is None or record.author != artist:
            raise AppError("track not found in the catalogue")
        validate_track(record.body, author=artist)
        file_id, digest = record.body["file_id"], record.body["manifest_sha256"]
        if self.library.meta(file_id) is None:
            profile = self.catalogue.profile(artist)
            self.library.add_pending(file_id, {
                "track_key": track_key, "track_id": track_id, "title": record.body["title"],
                "artist_agent": artist, "artist_name": profile["display_name"] if profile else "Unknown artist",
                "album_id": record.body["album_id"], "duration_ms": record.body["duration_ms"],
                "manifest_sha256": digest, "listener_agent": self.agent})
        outcome = self.outbox.deliver("send_access_request", owner=artist, request={
            "file_id": file_id, "manifest_sha256": digest,
            "x25519_public_hex": self.keys.listener_public_hex(), "kind": kind, "note": note[:500]})
        self.library.update_meta(file_id, requested=kind, requested_at=int(time.time()),
                                 request_queued=bool(outcome.get("queued")))
        return {"requested": True, "file_id": file_id, **outcome}

    @staticmethod
    def _split_key(track_key: str) -> tuple[str, str]:
        if not isinstance(track_key, str) or track_key.count(":") != 1:
            raise AppError("invalid track")
        artist, track_id = track_key.split(":")
        if len(track_id) != 32 or any(c not in "0123456789abcdef" for c in track_id) or not 1 <= len(artist) <= 80:
            raise AppError("invalid track")
        return artist, track_id

    def library_view(self) -> list[dict]:
        out = []
        for m in self.library.all():
            fid = m["file_id"]
            d = self.downloads.get(fid)
            grant = self.library.grant(fid)
            playable = grant is not None
            expires = grant["body"].get("expires_at") if grant else None
            if expires is not None and expires <= time.time():
                playable = False
            out.append({k: m.get(k) for k in ("file_id", "track_key", "title", "artist_name", "artist_agent",
                                              "album_title", "album_id", "duration_ms", "track_number",
                                              "grant_kind", "requested", "request_queued", "complete")}
                       | {"playable": playable, "grant_expires_at": expires,
                          "offline_ready": bool(m.get("complete")) and m.get("grant_kind") == "perpetual-personal",
                          "download": d.progress() if d else None})
        return out

    # ---- playback -----------------------------------------------------
    def _ensure_download(self, file_id: str, *, start: bool = True) -> Download | None:
        if self.library.verify_complete(file_id):
            return None
        d = self.downloads.get(file_id)
        if d is None:
            self.require_online()
            meta = self.library.meta(file_id)
            artist, track_id = self._split_key(meta["track_key"])
            trusted = self.catalogue.resolve(artist, track_id)
            if trusted.digest != meta["manifest_sha256"]:
                raise AppError("catalogue changed this track's encrypted file; re-add it")
            d = Download(trusted=trusted, store=self.library.cas, moq_binary=binaries.find("holochain-music-moq"),
                         allow_lan=self.settings["allow_lan"], present=self.library.present_chunks(trusted.manifest),
                         on_complete=lambda: self.library.verify_complete(file_id))
            self.downloads[file_id] = d
        elif d.state == "unavailable":
            # User retry after an outage: hosts may have moved; re-resolve them.
            self.require_online()
            meta = self.library.meta(file_id)
            artist, track_id = self._split_key(meta["track_key"])
            d.replace_hosts(self.catalogue.resolve(artist, track_id).hosts)
        if start:
            d.start()
        return d

    def download(self, file_id: str) -> dict:
        file_key(file_id)
        if self.library.grant(file_id) is None:
            raise AppError("you need access from the artist before downloading")
        d = self._ensure_download(file_id)
        return d.progress() if d else {"state": "complete"}

    def _session_for(self, file_id: str) -> SessionSpec:
        file_key(file_id)
        meta = self.library.meta(file_id)
        grant = self.library.grant(file_id)
        if meta is None:
            raise AppError("track is not in your library")
        if grant is None:
            raise AppError("you do not have access to this track yet; request it from the artist")
        download = self._ensure_download(file_id)
        return SessionSpec(key=file_id, manifest=self.library.manifest(file_id), grant=grant,
                           artist_key=bytes.fromhex(meta["artist_key_hex"]), owner_agent=meta["artist_agent"],
                           listener_agent=meta["listener_agent"], recipient=self.keys.listener_x25519(),
                           store=self.library.cas, download=download,
                           source="streaming" if download else "offline")

    def _record_play(self, file_id: str) -> None:
        meta = self.library.meta(file_id) or {}
        self.library.record_play({"key": file_id, "title": meta.get("title"), "artist_name": meta.get("artist_name")})

    def _advance(self, file_id: str) -> None:
        if self.queue:
            nxt = self.queue.pop(0)
            threading.Thread(target=lambda: self._try_play(nxt), daemon=True).start()

    def _try_play(self, file_id: str) -> None:
        try:
            self.player.play(file_id)
        except USER_ERRORS + (AppError,):
            self._advance(file_id)

    def set_queue(self, items: list[str]) -> list[str]:
        if not isinstance(items, list) or len(items) > 1000:
            raise AppError("invalid queue")
        self.queue = [file_key(i) for i in items]
        return self.queue

    def next_track(self) -> dict:
        if not self.queue:
            raise AppError("the queue is empty")
        return self.player.play(self.queue.pop(0))

    # ---- export (licence permitting) ------------------------------------
    def export_wav(self, file_id: str, destination: Path) -> Path:
        """Write a playable WAV for a perpetual personal-use licence only.

        The exported file is plaintext by design and cannot be revoked."""
        meta = self.library.meta(file_id)
        grant = self.library.grant(file_id)
        if not meta or not grant or grant_kind(grant) != "perpetual-personal":
            raise AppError("export requires a perpetual personal-use licence")
        if not self.library.verify_complete(file_id):
            raise AppError("download the track completely before exporting")
        key = unwrap_content_grant(grant, trusted_artist=bytes.fromhex(meta["artist_key_hex"]),
                                   owner_agent=meta["artist_agent"], listener_agent=meta["listener_agent"],
                                   recipient_private=self.keys.listener_x25519(),
                                   signed_manifest=self.library.manifest(file_id))
        destination = Path(destination).expanduser()
        if destination.exists():
            raise AppError("destination already exists")
        return decrypt_package(self.library.manifest(file_id), self.library.cas, destination, key,
                               bytes.fromhex(meta["artist_key_hex"]))

    # ---- artist conveniences -------------------------------------------
    def publish_track(self, **kwargs) -> dict:
        self.require_online()
        result = self.artist.publish_track(**kwargs)
        self._self_licence(result["file_id"], result["track_id"])
        if self.settings["host_enabled"]:
            self.restart_host()
        return result

    def _self_licence(self, file_id: str, track_id: str) -> None:
        """Artists can always play their own tracks offline."""
        manifest = json.loads((self.paths.host / "files" / file_id / "manifest.json").read_text())
        artist_key = public_key_bytes(self.keys.artist_ed25519())
        replicate_package(manifest, self.paths.host / "cas", self.library.cas, artist_key, self.keys.host_ed25519())
        licence = issue_personal_licence(owner_signer=self.keys.artist_ed25519(), owner_agent=self.agent,
                                         listener_agent=self.agent,
                                         recipient_public=bytes.fromhex(self.keys.listener_public_hex()),
                                         signed_manifest=manifest, content_key=self.keys.content_key(file_id))
        track = json.loads((self.paths.host / "files" / file_id / "track.json").read_text())
        profile = self.catalogue.profile(self.agent) if self.catalogue else None
        self.library.add(manifest=manifest, meta={
            "track_key": f"{self.agent}:{track_id}", "track_id": track_id, "title": track["title"],
            "artist_agent": self.agent, "artist_name": profile["display_name"] if profile else "You",
            "album_id": None, "album_title": None, "duration_ms": track["duration_ms"], "track_number": 1,
            "manifest_sha256": manifest_digest(manifest), "artist_key_hex": artist_key.hex(),
            "listener_agent": self.agent, "hosts": []})
        self.library.set_grant(file_id, licence, "perpetual-personal")
        self.library.verify_complete(file_id)
