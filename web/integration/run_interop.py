#!/usr/bin/env python3
"""Native Music artist <-> Chromium/HWC listener interoperability test.

Starts, in one working directory:
  * kitsune2 bootstrap + iroh relay (Holochain 0.7.0 release binary);
  * a native Music ARTIST (unchanged MusicApp: own conductor, Lair, hApp,
    MoQ/QUIC host) that publishes a generated tone, and a second native Music
    PEER (kitsune2 only grows storage arcs by syncing with another full-arc
    peer, so the browser gateway needs two native authorities);
  * the accepted Imposter H2HC gateway in authenticated (admission) mode;
  * the ciphertext-only web media adapter;
  * the built web client on http://localhost:<port> with the production CSP;
then runs browser_listener.mjs in real Chromium with the HWC extension.

Required env: HOLOCHAIN_MOQ_BIN, HOLOCHAIN_MUSIC_BRIDGE_BIN, HOLOCHAIN_MUSIC_HAPP,
H2HC_GATEWAY_BIN, HWC_EXTENSION_DIR; holochain, hc, lair-keystore and
kitsune2-bootstrap-srv on PATH. Optional: HM_LD_PRELOAD (IPv4-only shim for
sandboxes without an IPv6 stack; see env/ipv4only.c).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

WEB = Path(__file__).resolve().parents[1]
REPO = WEB.parent
CHUNK = 256 * 1024


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(fn, what: str, timeout: float, interval: float = 1.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except Exception:
            pass
        time.sleep(interval)
    raise SystemExit(f"timed out waiting for {what}")


def http_ok(url: str) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def dna_hash(dna: Path) -> str:
    return subprocess.check_output(["hc", "dna", "hash", str(dna)], text=True).strip()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--seconds", type=float, default=12.0)
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--serve-only", action="store_true",
                   help="start the whole stack, print its URLs and wait (manual demo / debugging)")
    args = p.parse_args()
    work = args.work.resolve()
    if work.exists():
        shutil.rmtree(work)
    for d in ("logs", "grants", "profiles"):
        (work / d).mkdir(parents=True)
    env = dict(os.environ)
    if env.get("HM_LD_PRELOAD"):
        env["LD_PRELOAD"] = env["HM_LD_PRELOAD"]
    procs: list[subprocess.Popen] = []

    def spawn(name: str, argv: list[str], extra: dict | None = None) -> subprocess.Popen:
        log = open(work / "logs" / f"{name}.log", "wb")
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env={**env, **(extra or {})},
                                start_new_session=True)
        procs.append(proc)
        return proc

    try:
        boot_port = free_port()
        bootstrap = f"http://127.0.0.1:{boot_port}"
        spawn("bootstrap", ["kitsune2-bootstrap-srv", "--listen", f"127.0.0.1:{boot_port}"])
        wait(lambda: http_ok(f"{bootstrap}/health"), "bootstrap", 30, 0.5)

        native = [args.python, str(WEB / "integration" / "native_artist.py"), "--bootstrap", bootstrap]
        spawn("artist", native + ["--home", str(work / "artist"), "--status", str(work / "artist.json"),
                                  "--seconds", str(args.seconds), "--grant-dir", str(work / "grants")])
        spawn("peer", native + ["--peer-only", "--home", str(work / "peer"), "--status", str(work / "peer.json")])
        status = wait(lambda: (s := json.loads((work / "artist.json").read_text())).get("phase") == "published" and s,
                      "native artist publication", 600, 2)
        wait(lambda: (work / "peer.json").exists(), "native peer", 300, 2)

        secret_file = work / "gateway.secret"
        secret_file.write_text(secrets.token_hex(32))
        secret_file.chmod(0o600)
        gw_port = free_port()
        gateway = f"http://127.0.0.1:{gw_port}"
        spawn("gateway", [env["H2HC_GATEWAY_BIN"]], {
            "H2HC_LINKER_ADDRESS": "127.0.0.1", "H2HC_LINKER_PORT": str(gw_port),
            "H2HC_LINKER_KEY_FILE": str(work / "gateway.key"),
            "H2HC_LINKER_SESSION_STORE": f"sqlite://{work / 'gateway-sessions.db'}",
            "H2HC_LINKER_ADMIN_SECRET": secret_file.read_text(),
            "H2HC_LINKER_BOOTSTRAP_URL": bootstrap, "H2HC_LINKER_RELAY_URL": bootstrap,
            "H2HC_LINKER_ALLOW_INSECURE_DEV": "false", "H2HC_LINKER_LOCAL_AUTHORITY_FALLBACK": "false",
            "RUST_LOG": "h2hc_linker=info,kitsune2=warn,iroh=warn",
        })
        wait(lambda: http_ok(f"{gateway}/health"), "gateway", 30, 0.5)

        web_port = free_port()
        web_origin = f"http://localhost:{web_port}"
        ad_port = free_port()
        adapter = f"http://127.0.0.1:{ad_port}"
        spawn("adapter", [args.python, str(WEB / "adapter" / "media_adapter.py"), "--port", str(ad_port),
                          "--allow-origin", web_origin, "--cache", str(work / "adapter-cache")])
        wait(lambda: http_ok(f"{adapter}/healthz"), "media adapter", 30, 0.5)

        happ = Path(env["HOLOCHAIN_MUSIC_HAPP"])
        cat_dna = dna_hash(REPO / "integration" / "workdir" / "music_catalogue.dna")
        sto_dna = dna_hash(REPO / "integration" / "workdir" / "music_storage.dna")
        if (cat_dna, sto_dna) != (status["bridge_whoami"]["catalogue_dna"], status["bridge_whoami"]["storage_dna"]):
            raise SystemExit("built DNA hashes differ from the native artist's installed DNAs")
        subprocess.run(["node", str(WEB / "scripts" / "build.mjs"), "--out", str(work / "dist"), "--happ", str(happ),
                        "--catalogue-dna", cat_dna, "--storage-dna", sto_dna, "--gateway", gateway, "--adapter", adapter,
                        "--release", "interop-test", "--origin", web_origin], check=True)
        spawn("web", ["node", str(WEB / "scripts" / "serve.mjs"), str(work / "dist"), "--port", str(web_port)])
        wait(lambda: http_ok(f"http://127.0.0.1:{web_port}/"), "web server", 30, 0.5)

        # TEST-ONLY malicious gateway in front of the real one: it forges the
        # track title in record responses ("Browser" -> "FORGED!", same length).
        tamper_port, tamper_web_port = free_port(), free_port()
        tamper_gateway = f"http://127.0.0.1:{tamper_port}"
        tamper_origin = f"http://localhost:{tamper_web_port}"
        spawn("tamper-proxy", ["node", str(WEB / "integration" / "tamper_proxy.mjs"), "--target", gateway,
                               "--port", str(tamper_port), "--find", "Browser", "--replace", "FORGED!",
                               "--state", str(work / "tamper.json"), "--dump", str(work / "tamper-dump")])
        wait(lambda: http_ok(f"{tamper_gateway}/health"), "tamper proxy", 30, 0.5)
        subprocess.run(["node", str(WEB / "scripts" / "build.mjs"), "--out", str(work / "dist-tamper"), "--happ", str(happ),
                        "--catalogue-dna", cat_dna, "--storage-dna", sto_dna, "--gateway", tamper_gateway,
                        "--adapter", adapter, "--release", "interop-test-malicious-gateway", "--origin", tamper_origin], check=True)
        spawn("web-tamper", ["node", str(WEB / "scripts" / "serve.mjs"), str(work / "dist-tamper"), "--port", str(tamper_web_port)])
        wait(lambda: http_ok(f"http://127.0.0.1:{tamper_web_port}/"), "tamper web server", 30, 0.5)

        # Expected plaintext per encrypted chunk, from the artist's canonical WAV.
        wav = (work / "artist" / "expected.wav").read_bytes()
        assert hashlib.sha256(wav).hexdigest() == status["wav_sha256"]
        (work / "expected.json").write_text(json.dumps({"chunk_plain_sha256": [
            hashlib.sha256(wav[i:i + CHUNK]).hexdigest() for i in range(0, len(wav), CHUNK)]}))

        if args.serve_only:
            info = {"web": web_origin, "gateway": gateway, "gateway_secret_file": str(secret_file), "adapter": adapter,
                    "hwc_extension": env["HWC_EXTENSION_DIR"], "artist": status, "grants_dir": str(work / "grants")}
            (work / "stack.json").write_text(json.dumps(info, indent=2))
            print(json.dumps(info), flush=True)
            signal.sigwait({signal.SIGINT, signal.SIGTERM})
            return 0
        browser_env = {
            "HM_WEB_URL": web_origin, "HM_HWC_EXTENSION": env["HWC_EXTENSION_DIR"], "HM_GATEWAY_URL": gateway,
            "HM_GATEWAY_SECRET_FILE": str(secret_file), "HM_ARTIST_STATUS": str(work / "artist.json"),
            "HM_EXPECTED_DIGESTS": str(work / "expected.json"), "HM_GRANT_DIR": str(work / "grants"),
            "HM_PROFILES": str(work / "profiles"), "HM_EVIDENCE": str(work / "evidence.json"),
            "HM_TAMPER_WEB_URL": tamper_origin, "HM_TAMPER_STATE": str(work / "tamper.json"),
        }
        browser_env.pop("LD_PRELOAD", None)
        run_env = {k: v for k, v in env.items() if k != "LD_PRELOAD"} | browser_env
        cmd = ["node", str(WEB / "integration" / "browser_listener.mjs")]
        if not os.environ.get("DISPLAY"):
            cmd = ["xvfb-run", "-a"] + cmd
        result = subprocess.run(cmd, env=run_env)
        evidence = json.loads((work / "evidence.json").read_text())
        evidence["environment"] = {
            "artist_agent": status["agent"], "dnas": {"music_catalogue": cat_dna, "music_storage": sto_dna},
            "happ_sha256": hashlib.sha256(happ.read_bytes()).hexdigest(), "track_key": status["track_key"],
            "manifest_sha256": status["manifest_sha256"], "host": status["host"],
        }
        (work / "evidence.json").write_text(json.dumps(evidence, indent=2))
        counts = {}
        for c in evidence["checks"]:
            counts[c["result"]] = counts.get(c["result"], 0) + 1
        print(json.dumps({"summary": counts, "exit": result.returncode}))
        return 0 if result.returncode == 0 and not counts.get("FAIL") else 1
    finally:
        for proc in reversed(procs):
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for proc in procs:
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)


if __name__ == "__main__":
    raise SystemExit(main())
