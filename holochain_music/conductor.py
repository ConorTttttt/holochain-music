"""Supervise this installation's own Holochain conductor.

First run: ``hc sandbox generate`` creates the conductor config, an
in-process lair keystore (passphrase from the local key store) and installs
the packaged hApp under one agent. Every run: the admin interface is pinned
to a loopback port, the bootstrap/relay URLs are rewritten from settings,
and ``holochain`` is started with the passphrase piped on stdin.
"""
from __future__ import annotations

import re
import socket
import subprocess
import threading
import time
from pathlib import Path

from . import binaries

APP_ID = "holochain-music"
ADMIN_ORIGIN = "holochain-music-app"  # must match music_app_bridge ORIGIN
_ADMIN_RE = re.compile(r"###ADMIN_PORT:(\d+)###")


class ConductorError(RuntimeError):
    pass


def free_loopback_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _set_yaml_scalar(text: str, key: str, value: str) -> str:
    """Replace one top-level-ish `key: value` line written by hc sandbox."""
    pattern = re.compile(rf"^(\s*){re.escape(key)}:.*$", re.MULTILINE)
    if not pattern.search(text):
        raise ConductorError(f"conductor config lacks {key}")
    return pattern.sub(lambda m: f"{m.group(1)}{key}: {value}", text, count=1)


_BACKOFF_BLOCK = re.compile(r"^    coreBootstrap:\n      backoffMaxMs: \d+\n", re.MULTILINE)


def _set_bootstrap_backoff(text: str, max_ms: int) -> str:
    """kitsune2 polls the bootstrap server with a doubling interval capped at
    5 minutes by default and never resets it, so a peer that registered just
    after an early poll can stay invisible for up to ~5 minutes. Cap it."""
    text = _BACKOFF_BLOCK.sub("", text)
    if "\n  advanced:\n" not in text:
        raise ConductorError("conductor config lacks network.advanced")
    return text.replace("\n  advanced:\n",
                        f"\n  advanced:\n    coreBootstrap:\n      backoffMaxMs: {max_ms}\n", 1)


class Conductor:
    def __init__(self, root: Path, passphrase: bytes, *, bootstrap_url: str, relay_url: str,
                 log_path: Path, bootstrap_poll_max_ms: int = 30_000):
        self.root = Path(root)
        self.dir = self.root / "conductor"
        self.passphrase = passphrase
        self.bootstrap_url, self.relay_url = bootstrap_url, relay_url
        if type(bootstrap_poll_max_ms) is not int or not 5_000 <= bootstrap_poll_max_ms <= 300_000:
            raise ConductorError("bootstrap poll interval must be 5–300 s")
        self.bootstrap_poll_max_ms = bootstrap_poll_max_ms
        self.log_path = Path(log_path)
        self.proc: subprocess.Popen | None = None
        self.admin_port: int | None = None

    @property
    def config_path(self) -> Path:
        return self.dir / "conductor-config.yaml"

    def installed(self) -> bool:
        return self.config_path.is_file()

    def install(self, happ: Path, timeout: float = 180) -> None:
        if self.installed():
            return
        hc = binaries.find("hc")
        holochain = binaries.find("holochain")
        argv = [str(hc), "sandbox", "--piped", "-H", str(holochain), "generate", "--in-process-lair",
                "--app-id", APP_ID, "--root", str(self.root), "-d", "conductor", str(happ),
                "network", "--bootstrap", self.bootstrap_url, "quic", self.relay_url]
        with open(self.log_path, "ab") as log:
            done = subprocess.run(argv, input=self.passphrase, stdout=log, stderr=log,
                                  cwd=self.root, timeout=timeout)
        if done.returncode != 0 or not self.installed():
            raise ConductorError("first-run conductor/hApp installation failed (see conductor log)")

    def _write_config(self, admin_port: int) -> None:
        text = self.config_path.read_text()
        text = re.sub(r"(admin_interfaces:\s*\n- driver:\s*\n\s+type: websocket\s*\n\s+port:) \d+",
                      rf"\1 {admin_port}", text, count=1)
        if f"port: {admin_port}" not in text:
            raise ConductorError("could not pin the admin port in conductor config")
        # Only this machine's processes may reach the admin API, and only with
        # the bridge's Origin: a web page in the user's browser cannot forge
        # Origin, so it cannot drive the admin WebSocket even on loopback.
        text = _set_yaml_scalar(text, "danger_bind_addr", "null")
        text = _set_yaml_scalar(text, "allowed_origins", ADMIN_ORIGIN)
        text = _set_yaml_scalar(text, "bootstrap_url", self.bootstrap_url)
        text = _set_yaml_scalar(text, "relay_url", self.relay_url)
        text = _set_bootstrap_backoff(text, self.bootstrap_poll_max_ms)
        self.config_path.write_text(text)

    def start(self, timeout: float = 90) -> int:
        if self.proc is not None and self.proc.poll() is None:
            return self.admin_port
        if not self.installed():
            raise ConductorError("conductor is not installed")
        port = free_loopback_port()
        self._write_config(port)
        holochain = binaries.find("holochain")
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen([str(holochain), "--piped", "-c", str(self.config_path)],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=log, cwd=self.dir)
        finally:
            log.close()
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(self.passphrase)
        self.proc.stdin.close()
        ready = threading.Event()
        found: dict = {}

        def pump():
            with open(self.log_path, "ab") as sink:
                for raw in self.proc.stdout:
                    sink.write(raw)
                    sink.flush()
                    line = raw.decode("utf-8", "replace")
                    m = _ADMIN_RE.search(line)
                    if m:
                        found["port"] = int(m.group(1))
                    if "Conductor ready." in line:
                        ready.set()
        threading.Thread(target=pump, name="holochain-log", daemon=True).start()
        deadline = time.monotonic() + timeout
        while not ready.wait(0.2):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.stop()
                raise ConductorError("Holochain conductor failed to start (see conductor log)")
        if found.get("port") != port:
            self.stop()
            raise ConductorError("conductor admin port mismatch")
        self.admin_port = port
        return port

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


class BootstrapServer:
    """Optional local kitsune2 bootstrap + relay for one machine or a LAN."""

    def __init__(self, listen: str, log_path: Path):
        self.listen, self.log_path = listen, Path(log_path)
        self.proc: subprocess.Popen | None = None

    def start(self, timeout: float = 20) -> None:
        binary = binaries.find("kitsune2-bootstrap-srv")
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen([str(binary), "--listen", self.listen],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log)
        finally:
            log.close()
        assert self.proc.stdout
        deadline = time.monotonic() + timeout
        for raw in self.proc.stdout:
            if b"#kitsune2_bootstrap_srv#listening#" in raw:
                threading.Thread(target=lambda: [None for _ in self.proc.stdout], daemon=True).start()
                return
            if time.monotonic() > deadline:
                break
        self.stop()
        raise ConductorError("bootstrap server failed to start")

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
