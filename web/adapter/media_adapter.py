#!/usr/bin/env python3
"""Holochain Music web media adapter: pinned MoQ/QUIC -> HTTP, ciphertext only.

Browsers cannot speak the native Music transport (raw QUIC MoQT draft-14 to
a self-signed, fingerprint-pinned host advertised as a private IPv4 literal).
This *separate* service bridges that gap and nothing else:

* it connects to an existing, unchanged `holochain-music-moq serve` host
  using the host URL and certificate fingerprint the BROWSER read from the
  host's own Holochain `MoqEndpoint` record;
* it forwards the host's public signed manifest/receipt and the AES-GCM
  ciphertext objects, re-verifying each object's SHA-256 against the signed
  manifest before serving it (defence in depth only);
* it never receives a content key, grant, listener key or plaintext, and it
  cannot decrypt. The browser independently verifies the artist signature,
  the Holochain manifest pin, every chunk hash and every AES-GCM tag.

It reuses the desktop player's own transfer worker (holochain_music.streaming
.Download): seek-prioritised restarts, bounded gap repair, host rotation and
a SHA-256-verified ciphertext CAS.

This is NOT the desktop app's loopback API (holochain_music/server.py) and
shares no state with it. By default it binds 127.0.0.1. Exposing it beyond
loopback is an operator decision that needs TLS in front of it and an
explicit --allow-origin list; see docs/web/media-transport.md.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import threading
import time
from collections import OrderedDict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from holochain_music.catalogue import HostCandidate, TrustedTrack  # noqa: E402
from holochain_music.streaming import Download, TrackUnavailable  # noqa: E402
from holochain_storage.package import (  # noqa: E402
    StorageError, _assert_manifest, _read_verified_chunk, _verify_signed, canonical, manifest_digest,
)
from music_catalogue.granted_audio import PlaybackError  # noqa: E402
from music_catalogue.moq_conductor import _bound_local_url  # noqa: E402
from music_catalogue.moq_host import MoqFetchError, fetch_document  # noqa: E402

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CHUNK_PATH = re.compile(r"/v1/files/([0-9a-f]{64})/chunks/(0|[1-9][0-9]{0,4})\Z")
DOC_PATH = re.compile(r"/v1/files/([0-9a-f]{64})/(manifest|receipt)\Z")
MAX_QUERY_BYTES = 1024
SERVICE = "holochain-music-web-media-adapter/v1"


class AdapterError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status


def _hex64(value: str | None, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise AdapterError(HTTPStatus.BAD_REQUEST, f"invalid {label}")
    return value


class Transfers:
    """One verified ciphertext transfer per (host, fingerprint, manifest pin)."""

    def __init__(self, *, moq_binary: Path, cache: Path, allow_lan: bool, max_files: int,
                 chunk_wait: float, stall_timeout: float):
        self.moq_binary, self.cache, self.allow_lan = moq_binary, cache, allow_lan
        self.max_files, self.chunk_wait, self.stall_timeout = max_files, chunk_wait, stall_timeout
        self._lock = threading.Lock()
        self._docs: dict[tuple, tuple[float, bytes]] = {}
        self._active: OrderedDict[tuple, Download] = OrderedDict()

    def host(self, url: str | None, fp: str | None) -> tuple[str, str]:
        try:
            url = _bound_local_url(url, allow_lan=self.allow_lan)
        except (ValueError, TypeError) as exc:
            raise AdapterError(HTTPStatus.FORBIDDEN, f"host URL not permitted: {exc}") from exc
        return url, _hex64(fp, "certificate fingerprint")

    def document(self, url: str, fp: str, file_id: str, kind: str) -> bytes:
        """Untrusted public document, re-encoded canonically (the browser re-hashes it)."""
        key = (url, fp, file_id, kind)
        with self._lock:
            hit = self._docs.get(key)
            if hit and time.monotonic() - hit[0] < 30:
                return hit[1]
        try:
            value = fetch_document(moq_binary=self.moq_binary, url=url, cert_fingerprint_hex=fp,
                                   file_id=file_id, document=kind, allow_lan=self.allow_lan)
        except MoqFetchError as exc:
            raise AdapterError(HTTPStatus.BAD_GATEWAY, str(exc)) from exc
        data = canonical(value)
        with self._lock:
            self._docs[key] = (time.monotonic(), data)
            while len(self._docs) > 4 * self.max_files:
                self._docs.pop(next(iter(self._docs)))
        return data

    def _download(self, url: str, fp: str, file_id: str, digest: str, artist: bytes) -> Download:
        key = (url, fp, digest)
        with self._lock:
            existing = self._active.get(key)
            if existing is not None:
                self._active.move_to_end(key)
                return existing
        manifest = json.loads(self.document(url, fp, file_id, "manifest"))
        try:
            body = _verify_signed(manifest, artist, "manifest")
            _assert_manifest(body)
        except StorageError as exc:
            raise AdapterError(HTTPStatus.BAD_GATEWAY, "host manifest fails the supplied artist pin") from exc
        if manifest_digest(manifest) != digest or body["file_id"] != file_id:
            raise AdapterError(HTTPStatus.BAD_GATEWAY, "host manifest does not match the Holochain pin")
        store = self.cache / digest / fp
        trusted = TrustedTrack(artist_agent="", track={}, artist_key=artist, manifest=manifest, digest=digest,
                               hosts=[HostCandidate(node_agent="", node_key=b"", url=url, fingerprint=fp)])
        present = set()
        for chunk in body["chunks"]:
            try:
                _read_verified_chunk(store, chunk)
                present.add(chunk["index"])
            except StorageError:
                pass
        download = Download(trusted=trusted, store=store, moq_binary=self.moq_binary, allow_lan=self.allow_lan,
                            present=present, stall_timeout=self.stall_timeout)
        evicted = []
        with self._lock:
            current = self._active.setdefault(key, download)
            self._active.move_to_end(key)
            while len(self._active) > self.max_files:
                old_key, old = self._active.popitem(last=False)
                evicted.append((old_key, old))
        for old_key, old in evicted:
            old.stop()
            shutil.rmtree(self.cache / old_key[2] / old_key[1], ignore_errors=True)
        return current

    def chunk(self, url: str, fp: str, file_id: str, digest: str, artist: bytes, index: int) -> bytes:
        download = self._download(url, fp, file_id, digest, artist)
        if index >= download.total:
            raise AdapterError(HTTPStatus.NOT_FOUND, "index outside signed manifest")
        chunk = download.chunks[index]
        if download.state == "unavailable":
            download.state, download.failures = "idle", 0  # an explicit new request may retry
        try:
            download.wait_for(chunk, timeout=self.chunk_wait)
            return _read_verified_chunk(download.store, chunk)
        except TrackUnavailable as exc:
            raise AdapterError(HTTPStatus.GATEWAY_TIMEOUT, str(exc)) from exc
        except (PlaybackError, StorageError) as exc:
            raise AdapterError(HTTPStatus.BAD_GATEWAY, str(exc)) from exc

    def status(self) -> dict:
        with self._lock:
            return {"service": SERVICE, "active_transfers": len(self._active),
                    "transfers": [d.progress() for d in self._active.values()]}

    def close(self) -> None:
        with self._lock:
            active = list(self._active.values())
            self._active.clear()
        for d in active:
            d.stop()


def make_handler(transfers: Transfers, allowed_origins: frozenset[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "hm-media-adapter"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # no request logging: URLs reveal listening history
            pass

        def _cors(self) -> None:
            origin = self.headers.get("Origin")
            if origin and origin in allowed_origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")

        def _send(self, status: HTTPStatus, body: bytes, ctype: str, cache: str = "no-store") -> None:
            self.send_response(status)
            self._cors()
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: HTTPStatus, message: str) -> None:
            self._send(status, json.dumps({"error": message[:200]}).encode(), "application/json")

        def do_OPTIONS(self):  # noqa: N802 - simple GETs need no preflight; refuse others
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "only GET is supported")

        def do_GET(self):  # noqa: N802
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                return self._error(HTTPStatus.FORBIDDEN, "origin not allowed")
            parts = urlsplit(self.path)
            if len(parts.query) > MAX_QUERY_BYTES:
                return self._error(HTTPStatus.REQUEST_URI_TOO_LONG, "query too long")
            try:
                if parts.path == "/healthz":
                    return self._send(HTTPStatus.OK, json.dumps(transfers.status()).encode(), "application/json")
                q = {k: v[0] for k, v in parse_qs(parts.query, strict_parsing=False).items() if len(v) == 1}
                url, fp = transfers.host(q.get("host"), q.get("fp"))
                if m := DOC_PATH.fullmatch(parts.path):
                    data = transfers.document(url, fp, m.group(1), m.group(2))
                    return self._send(HTTPStatus.OK, data, "application/json")
                if m := CHUNK_PATH.fullmatch(parts.path):
                    digest = _hex64(q.get("manifest_sha256"), "manifest digest")
                    artist = bytes.fromhex(_hex64(q.get("artist_key"), "artist key"))
                    data = transfers.chunk(url, fp, m.group(1), digest, artist, int(m.group(2)))
                    return self._send(HTTPStatus.OK, data, "application/octet-stream",
                                      "private, max-age=86400, immutable")
                return self._error(HTTPStatus.NOT_FOUND, "unknown route")
            except AdapterError as exc:
                return self._error(exc.status, str(exc))
            except Exception:  # never leak internals
                return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "adapter error")

        do_POST = do_PUT = do_DELETE = do_PATCH = (
            lambda self: self._error(HTTPStatus.METHOD_NOT_ALLOWED, "only GET is supported"))

    return Handler


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--allow-origin", action="append", default=[], required=True,
                   help="exact web app origin permitted to read responses (repeatable)")
    p.add_argument("--cache", type=Path, required=True, help="ciphertext-only cache directory")
    p.add_argument("--moq-binary", type=Path, default=os.environ.get("HOLOCHAIN_MOQ_BIN"))
    p.add_argument("--allow-lan", action="store_true", help="permit RFC1918 MoQ hosts (S17 rules)")
    p.add_argument("--max-files", type=int, default=16)
    p.add_argument("--chunk-wait", type=float, default=45.0)
    p.add_argument("--stall-timeout", type=float, default=20.0)
    p.add_argument("--ready-file", type=Path)
    args = p.parse_args(argv)
    if args.moq_binary is None or not Path(args.moq_binary).is_absolute() or not Path(args.moq_binary).is_file():
        p.error("--moq-binary (or HOLOCHAIN_MOQ_BIN) must be an existing absolute path")
    for origin in args.allow_origin:
        u = urlsplit(origin)
        if u.scheme not in ("https", "http") or u.path or u.query or origin != f"{u.scheme}://{u.netloc}":
            p.error(f"--allow-origin must be an exact origin: {origin}")
        if u.scheme == "http" and u.hostname not in ("localhost", "127.0.0.1"):
            p.error("plain-HTTP origins are only accepted for localhost development")
    if not 1 <= args.max_files <= 256:
        p.error("--max-files must be 1..256")
    args.cache.mkdir(parents=True, exist_ok=True)
    os.chmod(args.cache, 0o700)
    transfers = Transfers(moq_binary=Path(args.moq_binary), cache=args.cache, allow_lan=args.allow_lan,
                          max_files=args.max_files, chunk_wait=args.chunk_wait, stall_timeout=args.stall_timeout)
    server = ThreadingHTTPServer((args.bind, args.port), make_handler(transfers, frozenset(args.allow_origin)))
    server.daemon_threads = True
    address = f"http://{args.bind}:{server.server_address[1]}"
    if args.ready_file:
        args.ready_file.write_text(json.dumps({"url": address, "service": SERVICE}))
    print(json.dumps({"listening": address, "service": SERVICE}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        transfers.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
