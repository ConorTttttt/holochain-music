"""v1 long-running MoQ/QUIC ciphertext host and subscriber-driven fetch client.

The host (`holochain-music-moq serve`) serves many signed S1 packages from an
S4-style ciphertext CAS with one *stable* self-signed certificate, so the
URL + SHA-256 fingerprint it publishes in Holochain remain valid across
restarts. Subscribers choose the start index (initial play, seek-prioritised
restart, resumption) or an explicit bounded object set (listener-driven
repair). Nothing here sees a content key, listener key or plaintext.

The fetch client trusts **nothing** in the child's stdout: every progress
line must name the exact next expected manifest index and hash, and the CAS
object is re-read and SHA-256-verified before `on_chunk` is called.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import threading
import time
from typing import Callable, Iterable

from holochain_storage.package import (
    _assert_manifest, _read_verified_chunk, _verify_signed, canonical, manifest_digest,
)
from .granted_audio import PlaybackError
from .moq_conductor import _bound_local_url

MAX_FETCH_OBJECTS = 256
MAX_EVENT_BYTES = 4096


class MoqFetchError(PlaybackError):
    """A fetch failed, stalled, was cancelled, or reported something untrue."""


class MoqFetchCancelled(MoqFetchError):
    """The caller cancelled the fetch (track change, stop, seek restart)."""


def _hex64(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise MoqFetchError(f"invalid {label}")
    return value


class MoqHost:
    """Supervise one `serve` process. Restarting keeps the same certificate."""

    def __init__(self, *, moq_binary: str | Path, store: str | Path, cert_dir: str | Path,
                 state_dir: str | Path, bind: str = "127.0.0.1:0",
                 advertise_ip: str | None = None, max_sessions: int = 16,
                 bytes_per_second: int = 8 * 1024 * 1024):
        self.binary = Path(moq_binary)
        if not self.binary.is_absolute() or not self.binary.is_file():
            raise MoqFetchError("MoQ binary must be an existing absolute path")
        self.store, self.cert_dir, self.state_dir = Path(store), Path(cert_dir), Path(state_dir)
        self.bind, self.advertise_ip, self.max_sessions = bind, advertise_ip, max_sessions
        if type(bytes_per_second) is not int or not 64 * 1024 <= bytes_per_second <= 1024**3:
            raise MoqFetchError("host rate limit must be between 64 KiB/s and 1 GiB/s")
        self.bytes_per_second = bytes_per_second
        self.files: list[dict] = []
        self.proc: subprocess.Popen | None = None
        self.ready: dict | None = None

    def set_files(self, files: Iterable[dict]) -> None:
        """Entries: {"manifest", "trusted_artist_hex", "manifest_sha256"[, "receipt"]}."""
        out = []
        for f in files:
            entry = {"manifest": str(f["manifest"]),
                     "trusted_artist_hex": _hex64(f["trusted_artist_hex"], "artist key"),
                     "manifest_sha256": _hex64(f["manifest_sha256"], "manifest digest")}
            if f.get("receipt"):
                entry["receipt"] = str(f["receipt"])
            out.append(entry)
        self.files = out

    def start(self, timeout: float = 30) -> dict:
        self.stop()
        if not self.files:
            raise MoqFetchError("nothing to host")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        served = self.state_dir / "served.json"
        served.write_text(json.dumps({"files": self.files}))
        ready = self.state_dir / "ready.json"
        ready.unlink(missing_ok=True)
        argv = [str(self.binary), "serve", "--served-list", str(served), "--store", str(self.store),
                "--cert-dir", str(self.cert_dir), "--ready-file", str(ready), "--bind", self.bind,
                "--max-sessions", str(self.max_sessions), "--bytes-per-second", str(self.bytes_per_second)]
        if self.advertise_ip:
            argv += ["--allow-lan", "--advertise-ip", self.advertise_ip]
        log = open(self.state_dir / "moq-host.log", "ab")
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        finally:
            log.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise MoqFetchError("MoQ host exited during start-up (see moq-host.log)")
            if ready.is_file():
                try:
                    self.ready = json.loads(ready.read_text())
                    break
                except ValueError:
                    pass
            time.sleep(0.05)
        else:
            self.stop()
            raise MoqFetchError("MoQ host did not become ready")
        _hex64(self.ready.get("cert_fingerprint_hex"), "host certificate fingerprint")
        return self.ready

    @property
    def url(self) -> str:
        if not self.ready:
            raise MoqFetchError("MoQ host is not running")
        return self.ready["url"]

    @property
    def fingerprint(self) -> str:
        if not self.ready:
            raise MoqFetchError("MoQ host is not running")
        return self.ready["cert_fingerprint_hex"]

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc, self.proc, self.ready = self.proc, None, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def fetch_ciphertext(
    *, moq_binary: str | Path, signed_manifest: dict, trusted_artist: bytes,
    expected_manifest_sha256: str, store: str | Path, url: str, cert_fingerprint_hex: str,
    start_index: int = 0, objects: list[int] | None = None, allow_lan: bool = False,
    on_chunk: Callable[[int], None] | None = None, cancel: threading.Event | None = None,
    stall_timeout: float = 30.0, total_timeout: float = 3600.0,
) -> dict:
    """Receive ciphertext from a v1 host into a listener CAS (no key needed).

    Returns {"received_chunks", "indices"}. Raises MoqFetchCancelled when
    `cancel` is set and MoqFetchError for any failure; the CAS then holds only
    objects that were individually verified, so a caller can safely resume.
    """
    body = _verify_signed(signed_manifest, trusted_artist, "manifest")
    _assert_manifest(body)
    digest = manifest_digest(signed_manifest)
    if digest != expected_manifest_sha256:
        raise MoqFetchError("signed manifest does not match the Holochain pin")
    try:
        _bound_local_url(url, allow_lan=allow_lan)
    except ValueError as exc:
        raise MoqFetchError(str(exc)) from exc
    _hex64(cert_fingerprint_hex, "certificate fingerprint")
    chunks = body["chunks"]
    if objects is not None:
        if (not isinstance(objects, list) or not 1 <= len(objects) <= MAX_FETCH_OBJECTS
                or len(set(objects)) != len(objects)
                or any(type(i) is not int or not 0 <= i < len(chunks) for i in objects)):
            raise MoqFetchError("invalid bounded object list")
        expected_order = list(objects)
    else:
        if type(start_index) is not int or not 0 <= start_index < len(chunks):
            raise MoqFetchError("start index outside signed manifest")
        expected_order = list(range(start_index, len(chunks)))
    store = Path(store)
    store.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hm-fetch-") as tmp:
        manifest_path = Path(tmp) / "manifest.json"
        manifest_path.write_bytes(canonical(signed_manifest))
        argv = [str(moq_binary), "fetch", "--manifest", str(manifest_path), "--store", str(store),
                "--trusted-artist-hex", trusted_artist.hex(), "--expected-manifest-sha256", digest,
                "--url", url, "--cert-fingerprint-hex", cert_fingerprint_hex,
                "--object-timeout-secs", str(max(1, min(300, int(stall_timeout))))]
        if objects is not None:
            argv += ["--objects", ",".join(str(i) for i in objects)]
        else:
            argv += ["--start-index", str(start_index)]
        if allow_lan and not url.startswith("https://127.0.0.1:"):
            argv.append("--allow-lan")
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, bufsize=0)
        except OSError as exc:
            raise MoqFetchError("cannot start MoQ fetch") from exc
        position = 0
        pending = bytearray()
        total_out = 0
        deadline = time.monotonic() + total_timeout
        done = False
        try:
            assert proc.stdout is not None
            while not done:
                if cancel is not None and cancel.is_set():
                    raise MoqFetchCancelled("fetch cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MoqFetchError("MoQ fetch exceeded its total time budget")
                wait = min(0.2, remaining)
                readable, _, _ = select.select([proc.stdout], [], [], wait)
                if not readable:
                    if proc.poll() is not None and not pending:
                        raise MoqFetchError("MoQ fetch ended before completion")
                    continue
                data = os.read(proc.stdout.fileno(), 4096)
                if not data:
                    raise MoqFetchError("MoQ fetch ended before completion")
                total_out += len(data)
                if total_out > len(expected_order) * 512 + 4096:
                    raise MoqFetchError("oversized MoQ progress output")
                pending.extend(data)
                if len(pending) > MAX_EVENT_BYTES * 2 and b"\n" not in pending:
                    raise MoqFetchError("oversized MoQ event")
                while b"\n" in pending and not done:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    try:
                        event = json.loads(line)
                    except ValueError as exc:
                        raise MoqFetchError("non-JSON MoQ progress") from exc
                    kind = event.get("kind") if isinstance(event, dict) else None
                    if kind == "chunk_verified":
                        if position >= len(expected_order) or set(event) != {"kind", "index", "sha256", "cipher_bytes"}:
                            raise MoqFetchError("unexpected MoQ chunk report")
                        index = expected_order[position]
                        chunk = chunks[index]
                        if (event["index"] != index or event["sha256"] != chunk["sha256"]
                                or event["cipher_bytes"] != chunk["cipher_bytes"]):
                            raise MoqFetchError("out-of-order or forged MoQ chunk report")
                        _read_verified_chunk(store, chunk)  # independent re-verification
                        position += 1
                        if on_chunk is not None:
                            on_chunk(index)
                    elif kind == "fetch_complete":
                        if (position != len(expected_order) or event.get("received_chunks") != position
                                or event.get("manifest_sha256") != digest
                                or event.get("file_id") != body["file_id"]):
                            raise MoqFetchError("MoQ fetch claimed completion early")
                        done = True
                    else:
                        raise MoqFetchError("unknown MoQ progress event")
            if pending.strip():
                raise MoqFetchError("MoQ emitted output after completion")
            if proc.wait(timeout=max(1.0, deadline - time.monotonic())) != 0:
                raise MoqFetchError("MoQ fetch exited with an error")
            return {"received_chunks": position, "indices": expected_order,
                    "transport": "pinned-moq-quic-host-v1"}
        except subprocess.TimeoutExpired as exc:
            raise MoqFetchError("MoQ fetch did not exit") from exc
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout:
                proc.stdout.close()


MAX_DOCUMENT_BYTES = {"manifest": 8 * 1024 * 1024, "receipt": 16 * 1024}


def fetch_document(*, moq_binary: str | Path, url: str, cert_fingerprint_hex: str, file_id: str,
                   document: str, allow_lan: bool = False, timeout: float = 60) -> dict:
    """Fetch a host's public manifest/receipt JSON. UNTRUSTED: callers must
    check the manifest digest against the Holochain pin and verify the
    artist/host signatures before using it for anything."""
    if document not in MAX_DOCUMENT_BYTES:
        raise MoqFetchError("unknown document kind")
    _hex64(file_id, "file ID")
    _hex64(cert_fingerprint_hex, "certificate fingerprint")
    try:
        _bound_local_url(url, allow_lan=allow_lan)
    except ValueError as exc:
        raise MoqFetchError(str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix="hm-doc-") as tmp:
        out = Path(tmp) / "document.json"
        argv = [str(moq_binary), "fetch-document", "--url", url, "--cert-fingerprint-hex",
                cert_fingerprint_hex, "--file-id", file_id, "--document", document, "--out", str(out)]
        if allow_lan and not url.startswith("https://127.0.0.1:"):
            argv.append("--allow-lan")
        try:
            done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MoqFetchError(f"cannot fetch {document} from host") from exc
        if done.returncode != 0 or not out.is_file():
            raise MoqFetchError(f"host refused or failed to send the {document}")
        data = out.read_bytes()
        if len(data) > MAX_DOCUMENT_BYTES[document]:
            raise MoqFetchError(f"oversized {document}")
        try:
            value = json.loads(data)
        except ValueError as exc:
            raise MoqFetchError(f"host sent invalid {document} JSON") from exc
        if not isinstance(value, dict):
            raise MoqFetchError(f"host sent invalid {document}")
        return value
