"""S18 opt-in loopback-only music player for already-authorised local S1 tracks.

The web UI controls *local ALSA playback* in the listener process. Browsers
never receive PCM, ciphertext, grant, X25519 key, or Holochain admin secrets.
Local library labels are user-provided and NOT independently verified rights.
The S10 artist binding / S4/S9 metadata must come from an authenticated
Holochain workflow before a track is added to the local library config.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import tempfile
import threading
from typing import Any, Callable
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .buffered_playback import BufferedPcmPlayer, PlaybackStopped
from .granted_audio import PlaybackError
from .seekable_recovery import VerifiedWavSeeker

TRACK_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_LIBRARY_BYTES = 1024 * 1024
MAX_JSON_BYTES = 4096
MAX_SIGNED_JSON_BYTES = 8 * 1024 * 1024
_FIELDS = frozenset({"id", "title", "artist", "album", "manifest", "ciphertext_store",
                     "grant", "trusted_artist_hex", "owner_agent", "listener_agent",
                     "recipient_private_file"})


@dataclass(frozen=True)
class LocalTrack:
    id: str
    title: str
    artist: str
    album: str
    manifest: Path
    ciphertext_store: Path
    grant: Path
    trusted_artist_hex: str
    owner_agent: str
    listener_agent: str
    recipient_private_file: Path

    def display(self) -> dict:
        return {"id": self.id, "title": self.title, "artist": self.artist, "album": self.album}


def _as_string(name: str, value: Any, *, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise PlaybackError(f"invalid library {name}")
    return value


def _local_file(base: Path, label: str, value: Any, *, folder: bool = False) -> Path:
    text = _as_string(label, value, limit=1024)
    candidate = Path(text).expanduser()
    path = candidate if candidate.is_absolute() else base / candidate
    # Canonicalise only the *parent*: rejecting a symlink final component
    # prevents silently following a substituted grant/key/manifest file.
    path = path.parent.resolve() / path.name
    if path.is_symlink() or (not path.is_dir() if folder else not path.is_file()):
        raise PlaybackError(f"missing or unsafe local {label}")
    return path


def _read_json_file(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SIGNED_JSON_BYTES:
        raise PlaybackError("missing/unsafe/oversized signed JSON input")
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PlaybackError("invalid signed JSON input") from exc
    if not isinstance(result, dict):
        raise PlaybackError("signed local input must be a JSON object")
    return result


def load_library(path: Path) -> list[LocalTrack]:
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_LIBRARY_BYTES):
        raise PlaybackError("missing/unsafe/oversized local music library")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PlaybackError("invalid local music library JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"tracks"} or not isinstance(payload["tracks"], list):
        raise PlaybackError("library must contain exactly a tracks array")
    if not 1 <= len(payload["tracks"]) <= 100:
        raise PlaybackError("library must have between 1 and 100 tracks")
    tracks: list[LocalTrack] = []
    seen: set[str] = set()
    for raw in payload["tracks"]:
        if not isinstance(raw, dict) or set(raw) != _FIELDS:
            raise PlaybackError("unexpected or missing local track field")
        name = _as_string("id", raw["id"], limit=64)
        if not TRACK_ID.fullmatch(name) or name in seen:
            raise PlaybackError("duplicate or invalid local track ID")
        seen.add(name)
        key_hex = _as_string("trusted artist key", raw["trusted_artist_hex"], limit=64)
        if not HEX.fullmatch(key_hex):
            raise PlaybackError("invalid pinned artist Ed25519 key")
        tracks.append(LocalTrack(
            id=name,
            title=_as_string("title", raw["title"], limit=150),
            artist=_as_string("artist label", raw["artist"], limit=150),
            album=_as_string("album label", raw["album"], limit=150),
            manifest=_local_file(path.parent, "manifest", raw["manifest"]),
            ciphertext_store=_local_file(path.parent, "ciphertext store", raw["ciphertext_store"], folder=True),
            grant=_local_file(path.parent, "grant", raw["grant"]),
            trusted_artist_hex=key_hex,
            owner_agent=_as_string("owner agent", raw["owner_agent"], limit=200),
            listener_agent=_as_string("listener agent", raw["listener_agent"], limit=200),
            recipient_private_file=_local_file(path.parent, "recipient private key", raw["recipient_private_file"]),
        ))
    return tracks


def _open_seeker(track: LocalTrack) -> VerifiedWavSeeker:
    key = track.recipient_private_file
    if key.is_symlink() or key.stat().st_size != 32:
        raise PlaybackError("invalid local X25519 private key file")
    # The key stays solely inside the listener process and never crosses HTTP.
    recipient = X25519PrivateKey.from_private_bytes(key.read_bytes())
    return VerifiedWavSeeker(
        signed_manifest=_read_json_file(track.manifest),
        ciphertext_store=track.ciphertext_store,
        grant=_read_json_file(track.grant),
        trusted_artist=bytes.fromhex(track.trusted_artist_hex),
        owner_agent=track.owner_agent,
        listener_agent=track.listener_agent,
        recipient_private=recipient,
    )


class LocalPlayerController:
    """Serialised commands and generation-fenced, revocable playback workers."""

    def __init__(self, tracks: list[LocalTrack], *, backend: str = "null",
                 device: str = "default",
                 player_factory: Callable[[], BufferedPcmPlayer] | None = None):
        if backend not in ("null", "alsa"):
            raise PlaybackError("invalid local audio backend")
        if not tracks or len({t.id for t in tracks}) != len(tracks):
            raise PlaybackError("unique local library track IDs required")
        self.tracks = {t.id: t for t in tracks}
        self.backend, self.device = backend, device
        self._make_player = player_factory or (lambda: BufferedPcmPlayer(backend=backend, device=device))
        self._commands = threading.RLock()
        self._state_lock = threading.RLock()
        self._generation = 0
        self._cancel: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._player: BufferedPcmPlayer | None = None
        self._track_id: str | None = None
        self._state = "idle"
        self._start_frame = self._position = self._total_frames = self._sample_rate = 0
        self._result: dict | None = None
        self._error: str | None = None

    def library(self) -> list[dict]:
        return [t.display() for t in self.tracks.values()]

    def status(self) -> dict:
        with self._state_lock:
            position = self._position
            player = self._player
            if player is not None and self._state in ("playing", "paused"):
                progress = player.progress()
                position = min(self._total_frames, self._start_frame + progress["output_frames"])
            return {
                "state": self._state, "track_id": self._track_id,
                "position_frames": position, "total_frames": self._total_frames,
                "sample_rate": self._sample_rate, "audio_backend": self.backend,
                "error": self._error, "result": self._result,
            }

    def _stop_existing(self) -> None:
        with self._state_lock:
            if self._cancel:
                self._cancel.set()
            player, thread = self._player, self._thread
            self._generation += 1
            self._player = None
            self._thread = None
        if player is not None:
            player.stop()
        # A grant/manifest verifier may still be working. Its cancelled worker
        # can never open a device or overwrite newer state (generation check).
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)

    def play(self, track_id: str, start_frame: int = 0) -> dict:
        if type(start_frame) is not int or start_frame < 0:
            raise PlaybackError("invalid start frame")
        with self._commands:
            if not isinstance(track_id, str) or track_id not in self.tracks:
                raise PlaybackError("unknown local track")
            with self._state_lock:
                known_frames = self._total_frames if self._track_id == track_id else 0
            if known_frames and start_frame >= known_frames:
                raise PlaybackError("start frame is outside the track")
            self._stop_existing()
            with self._state_lock:
                generation = self._generation
                cancel = threading.Event()
                self._cancel = cancel
                self._track_id = track_id
                self._state = "loading"
                self._start_frame = self._position = start_frame
                self._total_frames = self._sample_rate = 0
                self._result = self._error = None
            thread = threading.Thread(target=self._run, args=(self.tracks[track_id], start_frame, generation, cancel),
                                      name="s18-local-authorised-player", daemon=True)
            with self._state_lock:
                self._thread = thread
            thread.start()
            return self.status()

    def _is_current(self, generation: int, cancel: threading.Event) -> bool:
        return not cancel.is_set() and self._generation == generation

    def _run(self, track: LocalTrack, start_frame: int, generation: int, cancel: threading.Event) -> None:
        player: BufferedPcmPlayer | None = None
        try:
            seeker = _open_seeker(track)  # full signature, grant and CAS check
            if start_frame >= seeker.frames:
                raise PlaybackError("requested frame is beyond the authenticated track")
            with self._state_lock:
                if not self._is_current(generation, cancel):
                    return
                player = self._make_player()
                self._player = player
                self._total_frames = seeker.frames
                self._sample_rate = seeker.fmt.sample_rate
                player.start({"sample_rate": seeker.fmt.sample_rate,
                              "channels": seeker.fmt.channels,
                              "bits_per_sample": seeker.fmt.bits_per_sample})
                self._state = "playing"
            digest = hashlib.sha256()
            supplied = 0
            for block in seeker.iter_frames(start_frame):
                if cancel.is_set():
                    raise PlaybackStopped("listener changed/ended playback")
                player.feed(block)
                digest.update(block)
                supplied += len(block)
            result = player.finish(timeout=7200)
            expected = (seeker.frames - start_frame) * seeker.fmt.frame_size
            if (supplied != expected or result["output_pcm_bytes"] != expected or
                    result["output_pcm_sha256"] != digest.hexdigest()):
                raise PlaybackError("output differs from authenticated WAV PCM")
            with self._state_lock:
                if self._is_current(generation, cancel):
                    self._position = seeker.frames
                    self._result = {**result, "seek_start_frame": start_frame, "seek_complete": True}
                    self._player = None
                    self._state = "finished"
        except PlaybackStopped:
            with self._state_lock:
                if self._is_current(generation, cancel):
                    self._state = "stopped"
        except BaseException as exc:
            if player is not None:
                try:
                    player.stop()
                except BaseException:
                    pass
            with self._state_lock:
                if self._is_current(generation, cancel):
                    self._state = "error"
                    # No exception detail includes private keys, grants or PCM.
                    self._error = f"{type(exc).__name__}: {str(exc)[:160]}"
                    self._player = None

    def pause(self) -> dict:
        with self._commands, self._state_lock:
            if self._state != "playing" or self._player is None:
                raise PlaybackError("no active track to pause")
            self._player.pause()
            self._state = "paused"
            return self.status()

    def resume(self) -> dict:
        with self._commands, self._state_lock:
            if self._state != "paused" or self._player is None:
                raise PlaybackError("no paused track to resume")
            self._player.resume()
            self._state = "playing"
            return self.status()

    def stop(self) -> dict:
        with self._commands:
            with self._state_lock:
                self._position = self.status()["position_frames"]
            self._stop_existing()
            with self._state_lock:
                self._state = "stopped" if self._track_id is not None else "idle"
                self._result = self._error = None
                return self.status()

    def seek(self, frame: int) -> dict:
        with self._commands:
            with self._state_lock:
                if self._track_id is None or self._state in ("loading", "error", "idle"):
                    raise PlaybackError("no authenticated current track to seek")
                if type(frame) is not int or not 0 <= frame < self._total_frames:
                    raise PlaybackError("seek outside current track")
                track_id = self._track_id
            return self.play(track_id, frame)


def make_handler(controller: LocalPlayerController, token: str, *, port: int):
    """No CORS, session bearer required, no plaintext/audio/key HTTP routes."""
    ui = Path(__file__).with_name("ui")
    static = {"/": ("index.html", "text/html; charset=utf-8"),
              "/app.js": ("app.js", "text/javascript; charset=utf-8"),
              "/app.css": ("app.css", "text/css; charset=utf-8")}

    class Handler(BaseHTTPRequestHandler):
        server_version = "HolochainMusicS18/0.1"

        def _headers(self, status: int, kind: str, length: int):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()

        def _send(self, obj: dict | list, status: int = 200):
            data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
            self._headers(status, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)

        def _allowed_host(self) -> bool:
            return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _authorized(self) -> bool:
            secret = self.headers.get("Authorization", "")
            return secrets.compare_digest(secret, f"Bearer {token}")

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            return origin in (None, f"http://127.0.0.1:{port}", f"http://localhost:{port}")

        def do_GET(self):
            if not self._allowed_host():
                self._send({"error": "invalid host header"}, 403)
                return
            path = urlsplit(self.path)
            if path.query or path.fragment:
                self._send({"error": "unexpected query"}, 400)
                return
            if path.path in static:
                name, kind = static[path.path]
                content = (ui / name).read_bytes()
                self._headers(200, kind, len(content))
                self.wfile.write(content)
            elif path.path.startswith("/api/"):
                if not self._authorized():
                    self._send({"error": "authorisation required"}, 401)
                elif path.path == "/api/library":
                    self._send({"tracks": controller.library()})
                elif path.path == "/api/state":
                    self._send(controller.status())
                else:
                    self._send({"error": "unknown endpoint"}, 404)
            else:
                self._send({"error": "not found"}, 404)

        def do_POST(self):
            if not self._allowed_host() or not self._same_origin():
                self._send({"error": "local browser origin required"}, 403)
                return
            if not self._authorized():
                self._send({"error": "authorisation required"}, 401)
                return
            path = urlsplit(self.path)
            if path.query or path.fragment or path.path not in (
                "/api/play", "/api/pause", "/api/resume", "/api/stop", "/api/seek"
            ):
                self._send({"error": "unknown playback command"}, 404)
                return
            try:
                size_text = self.headers.get("Content-Length")
                if size_text is None or not size_text.isdecimal() or not 0 <= int(size_text) <= MAX_JSON_BYTES:
                    raise PlaybackError("invalid playback command length")
                data = json.loads(self.rfile.read(int(size_text)))
                if not isinstance(data, dict):
                    raise PlaybackError("playback command must be JSON object")
                if path.path == "/api/play":
                    if set(data) not in ({"track_id"}, {"track_id", "start_frame"}):
                        raise PlaybackError("invalid play command")
                    result = controller.play(data["track_id"], data.get("start_frame", 0))
                elif path.path == "/api/seek":
                    if set(data) != {"frame"}:
                        raise PlaybackError("invalid seek command")
                    result = controller.seek(data["frame"])
                else:
                    if data:
                        raise PlaybackError("unexpected playback parameters")
                    result = {"/api/pause": controller.pause,
                              "/api/resume": controller.resume,
                              "/api/stop": controller.stop}[path.path]()
                self._send(result)
            except (PlaybackError, ValueError, TypeError, KeyError, UnicodeError) as exc:
                self._send({"error": str(exc)[:160]}, 400)
            except BaseException:
                self._send({"error": "local audio operation failed"}, 500)

        def do_OPTIONS(self):
            self._send({"error": "cross-origin requests refused"}, 403)

        def log_message(self, format, *args):
            # Never print session token or potentially sensitive query strings.
            return

    return Handler


def _demo_track(directory: Path) -> LocalTrack:
    from .playback_cli import _demo_inputs
    from holochain_storage.package import public_key_bytes  # noqa: F401

    inputs = _demo_inputs(directory, 7.0)
    manifest = directory / "manifest.json"
    grant = directory / "grant.json"
    key = directory / "recipient-private.bin"
    manifest.write_text(json.dumps(inputs["signed_manifest"]))
    grant.write_text(json.dumps(inputs["grant"]))
    key.write_bytes(inputs["recipient_private"].private_bytes_raw())
    key.chmod(0o600)
    return LocalTrack("s18-demo-tone", "Local test tone · 440 Hz", "S18 Demo", "Offline verification",
                      manifest, directory / "cas", grant, inputs["trusted_artist"].hex(),
                      "s11-demo-artist", "s11-demo-listener", key)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="S18 loopback music player for already-granted encrypted WAV")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="local disposable sound test, not Holochain licensing")
    mode.add_argument("--library", type=Path, help="local signed-package/grant library JSON")
    p.add_argument("--backend", choices=("null", "alsa"), default="null")
    p.add_argument("--device", default="default")
    p.add_argument("--port", type=int, default=0, help="127.0.0.1 listener, 0 for a random local port")
    p.add_argument("--open", action="store_true", help="open the local UI in a browser")
    args = p.parse_args(argv)
    if not 0 <= args.port <= 65535:
        p.error("invalid loopback port")
    with tempfile.TemporaryDirectory(prefix="holochain-music-s18-") as demo_dir:
        tracks = [_demo_track(Path(demo_dir))] if args.demo else load_library(args.library)
        controller = LocalPlayerController(tracks, backend=args.backend, device=args.device)
        token = secrets.token_urlsafe(32)
        server = ThreadingHTTPServer(("127.0.0.1", args.port), BaseHTTPRequestHandler)
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(controller, token, port=port)
        url = f"http://127.0.0.1:{port}/#token={token}"
        print("S18 private browser player (loopback only; token is a local capability):", flush=True)
        print(url, flush=True)
        print("Close with Ctrl+C. Private keys, decrypted PCM and grants never leave this process.", flush=True)
        try:
            if args.open:
                import webbrowser
                webbrowser.open(url)
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            controller.stop()
            server.server_close()


if __name__ == "__main__":
    main()
