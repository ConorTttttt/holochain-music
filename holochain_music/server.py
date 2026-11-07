"""Loopback-only, token-protected HTTP API + static UI (S18 security model).

* Binds 127.0.0.1 only. No CORS. Every /api route needs the per-launch
  256-bit bearer token; POSTs additionally require a loopback Host/Origin.
* The browser receives labels, state and progress — never PCM, ciphertext,
  grants, content keys or private keys.
* Query strings are refused; inputs are small JSON bodies with exact keys.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from .app import AppError, MusicApp, USER_ERRORS
from .artwork import ALBUM_ID, ArtworkError

MAX_BODY = 16 * 1024
UI = Path(__file__).with_name("ui")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/icon.svg": ("icon.svg", "image/svg+xml"),
          "/fonts/inter-latin-400-normal.woff2": ("fonts/inter-latin-400-normal.woff2", "font/woff2"),
          "/fonts/inter-latin-500-normal.woff2": ("fonts/inter-latin-500-normal.woff2", "font/woff2"),
          "/fonts/inter-latin-600-normal.woff2": ("fonts/inter-latin-600-normal.woff2", "font/woff2"),
          "/fonts/inter-latin-700-normal.woff2": ("fonts/inter-latin-700-normal.woff2", "font/woff2")}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' blob:; connect-src 'self'; "
       "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


def _keys(data: dict, required: set, optional: set = frozenset()) -> dict:
    if not isinstance(data, dict) or not required <= set(data) <= required | optional:
        raise AppError("unexpected request fields")
    return data


def _text(value, limit: int, *, empty_ok: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or "\x00" in value or (not empty_ok and not value.strip()):
        raise AppError("invalid text field")
    return value


def routes(app: MusicApp) -> dict:
    p = app.player

    def catalogue_artist(d):
        _keys(d, {"agent"})
        app.require_online()
        agent = _text(d["agent"], 80)
        return {"profile": app.catalogue.profile(agent), "albums": app.catalogue.albums(agent),
                "tracks": app.catalogue.artist_tracks(agent)}

    def export(d):
        _keys(d, {"file_id", "path"})
        target = Path(_text(d["path"], 1024)).expanduser()
        home = Path.home().resolve()
        parent = target.parent.resolve()
        if not target.is_absolute() or (parent != home and home not in parent.parents):
            raise AppError("choose a destination inside your home directory")
        if target.suffix.lower() != ".wav":
            raise AppError("the export file name must end in .wav")
        return {"exported": str(app.export_wav(d["file_id"], target))}

    def publish(d):
        _keys(d, {"path", "title"}, {"album_id", "track_number", "rights_basis"})
        path = Path(_text(d["path"], 1024)).expanduser()
        if not path.is_absolute() or not path.is_file():
            raise AppError("WAV file not found (use an absolute path)")
        tn = d.get("track_number", 1)
        if type(tn) is not int or not 1 <= tn <= 999:
            raise AppError("invalid track number")
        return app.publish_track(wav=path, title=_text(d["title"], 200), album_id=d.get("album_id") or None,
                                 track_number=tn, rights_basis=d.get("rights_basis", "original_owner"))

    def settings(d):
        allowed = {"bootstrap_url", "relay_url", "allow_lan", "host_enabled", "host_advertise_ip",
                   "audio_backend", "run_local_bootstrap", "host_bind"}
        _keys(d, set(), allowed)
        return {"settings": app.save_settings(**d), "restart_required": True}

    def noargs(fn):
        def wrapped(d):
            _keys(d, set())
            return fn()
        return wrapped

    def access_request(d):
        _keys(d, {"track_key", "kind"}, {"note"})
        if d["kind"] not in ("stream", "perpetual-personal"):
            raise AppError("invalid access kind")
        return app.request_access(_text(d["track_key"], 120), d["kind"], _text(d.get("note", ""), 500, empty_ok=True))

    def online(fn):
        def wrapped(d):
            app.require_online()
            return fn(d)
        return wrapped

    return {
        ("GET", "/api/state"): lambda _: {"player": p.status(), "queue": app.queue, "online": app.online,
                                          "status": app.status_message, "agent": app.agent},
        ("GET", "/api/identity"): lambda _: app.identity(),
        ("GET", "/api/library"): lambda _: {"tracks": app.library_view()},
        ("GET", "/api/playlists"): lambda _: {"playlists": app.library.playlists()},
        ("GET", "/api/history"): lambda _: {"history": app.library.history()},
        ("POST", "/api/catalogue/browse"): online(noargs(lambda: {"tracks": app.catalogue.browse(100)})),
        ("POST", "/api/catalogue/search"): online(lambda d: {"tracks": app.catalogue.search(
            _text(_keys(d, {"query"})["query"], 80), 50)}),
        ("POST", "/api/catalogue/artists"): online(noargs(lambda: {"artists": app.catalogue.artists()})),
        ("POST", "/api/catalogue/artist"): catalogue_artist,
        ("POST", "/api/access/request"): access_request,
        ("POST", "/api/grants/sync"): noargs(lambda: {"new_grants": app.sync_grants()}),
        ("POST", "/api/download"): lambda d: app.download(_keys(d, {"file_id"})["file_id"]),
        ("POST", "/api/offline/verify"): lambda d: app.offline_readiness(_keys(d, {"file_id"})["file_id"]),
        ("POST", "/api/play"): lambda d: p.play(_keys(d, {"file_id"}, {"start_frame"})["file_id"], d.get("start_frame", 0)),
        ("POST", "/api/pause"): noargs(p.pause),
        ("POST", "/api/resume"): noargs(p.resume),
        ("POST", "/api/stop"): noargs(p.stop),
        ("POST", "/api/seek"): lambda d: p.seek(_keys(d, {"frame"})["frame"]),
        ("POST", "/api/volume"): lambda d: p.set_volume(_keys(d, {"volume"})["volume"]),
        ("POST", "/api/queue"): lambda d: {"queue": app.set_queue(_keys(d, {"items"})["items"])},
        ("POST", "/api/next"): noargs(app.next_track),
        ("POST", "/api/playlists"): lambda d: (app.library.save_playlists(_keys(d, {"playlists"})["playlists"]),
                                               {"playlists": app.library.playlists()})[1],
        ("POST", "/api/export"): export,
        ("POST", "/api/artist/profile"): online(lambda d: app.artist.save_profile(
            _text(_keys(d, {"display_name"}, {"biography"})["display_name"], 120),
            _text(d.get("biography", ""), 2048, empty_ok=True))),
        ("POST", "/api/artist/album"): online(lambda d: app.artist.create_album(
            _text(_keys(d, {"title"}, {"release_date", "artwork_path"})["title"], 200),
            d.get("release_date") or None,
            artwork_path=Path(_text(d["artwork_path"], 1024)).expanduser()
            if d.get("artwork_path") else None)),
        ("POST", "/api/artist/albums"): online(noargs(lambda: {"albums": app.artist.my_albums()})),
        ("POST", "/api/artist/publish"): publish,
        ("POST", "/api/artist/tracks"): online(noargs(lambda: {"tracks": app.artist.my_tracks()})),
        ("POST", "/api/artist/requests"): online(noargs(lambda: {"requests": app.artist.requests()})),
        ("POST", "/api/artist/grant"): online(lambda d: app.artist.grant(
            request_hash=_text(_keys(d, {"request_hash", "kind"})["request_hash"], 80), kind=d["kind"])),
        ("POST", "/api/settings"): settings,
        # Lets the Start-menu "Quit" entry (and the UI) end a console-less app.
        ("POST", "/api/shutdown"): noargs(lambda: (app.shutdown_requested.set(), {"stopping": True})[1]),
    }


def make_handler(app: MusicApp, token: str, *, port: int):
    table = routes(app)
    hosts = (f"127.0.0.1:{port}", f"localhost:{port}")
    origins = (None, f"http://127.0.0.1:{port}", f"http://localhost:{port}")

    class Handler(BaseHTTPRequestHandler):
        server_version = "HolochainMusic/1"

        def _headers(self, status: int, kind: str, length: int):
            self.send_response(status)
            for k, v in (("Content-Type", kind), ("Content-Length", str(length)), ("Cache-Control", "no-store"),
                         ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                         ("Cross-Origin-Resource-Policy", "same-origin"), ("Content-Security-Policy", CSP)):
                self.send_header(k, v)
            self.end_headers()

        def _send(self, obj, status: int = 200):
            data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
            self._headers(status, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)

        def _dispatch(self, method: str):
            if self.headers.get("Host") not in hosts:
                return self._send({"error": "invalid host header"}, 403)
            if method == "POST" and self.headers.get("Origin") not in origins:
                return self._send({"error": "local browser origin required"}, 403)
            path = urlsplit(self.path)
            if path.query or path.fragment:
                return self._send({"error": "unexpected query"}, 400)
            if method == "GET" and path.path in STATIC:
                name, kind = STATIC[path.path]
                content = (UI / name).read_bytes()
                self._headers(200, kind, len(content))
                return self.wfile.write(content)
            if not path.path.startswith("/api/"):
                return self._send({"error": "not found"}, 404)
            if not secrets.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}"):
                return self._send({"error": "authorisation required"}, 401)
            # A session-authorised binary image response. No token in URL, no
            # arbitrary file path, and never a direct reference to a source file.
            if method == "GET" and path.path.startswith("/api/artwork/"):
                album_id = path.path.removeprefix("/api/artwork/")
                if not ALBUM_ID.fullmatch(album_id):
                    return self._send({"error": "not found"}, 404)
                try:
                    image = app.album_art.read(album_id)
                except (ArtworkError, OSError):
                    image = None
                if image is None:
                    return self._send({"error": "not found"}, 404)
                self._headers(200, "image/png", len(image))
                return self.wfile.write(image)
            handler = table.get((method, path.path))
            if handler is None:
                return self._send({"error": "unknown endpoint"}, 404)
            try:
                data = {}
                if method == "POST":
                    size = self.headers.get("Content-Length")
                    if size is None or not size.isdecimal() or int(size) > MAX_BODY:
                        raise AppError("invalid request length")
                    raw = self.rfile.read(int(size))
                    data = json.loads(raw) if raw else {}
                self._send(handler(data))
            except USER_ERRORS + (AppError, KeyError, TypeError) as exc:
                self._send({"error": str(exc)[:240] or type(exc).__name__}, 400)
            except Exception:
                self._send({"error": "internal error (see logs)"}, 500)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_OPTIONS(self):
            self._send({"error": "cross-origin requests refused"}, 403)

        def log_message(self, format, *args):
            return  # never log tokens or request bodies

    return Handler


def serve(app: MusicApp, *, port: int = 0):
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, token, port=actual)
    server.daemon_threads = True
    return server, f"http://127.0.0.1:{actual}/#token={token}"
