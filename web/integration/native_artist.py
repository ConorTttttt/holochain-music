#!/usr/bin/env python3
"""Run a genuine native Holochain Music artist for browser interop tests.

Drives the unchanged desktop application object (holochain_music.app.MusicApp)
exactly as tests/test_v1_e2e_flow.py does: its own Holochain 0.7 conductor,
its own Lair keystore and identity, the packaged hApp, the real encrypt ->
host CAS -> catalogue/S2 records -> MoQ/QUIC host publication path.

Writes a status JSON (public values only: agent, track IDs, manifest pin, DNA
hashes) and keeps running until SIGTERM. With --approve, it also acts as the
artist's operator for *native* access requests: the decision is made through
the same MusicApp.artist.grant() API the desktop UI uses.

Generated tone audio only. No third-party audio, no private keys in output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import signal
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / "tests")]

from holochain_music.app import MusicApp  # noqa: E402
from holochain_music.artist import normalise_wav  # noqa: E402
from holochain_music.paths import AppPaths  # noqa: E402
from v1_fixtures import write_tone  # noqa: E402


def issue_pending_grants(app: MusicApp, grant_dir: Path, published: dict) -> None:
    """Issue real v1 grants (artist Ed25519 + listener X25519) for explicit operator requests."""
    from music_catalogue.content_grants import issue_content_grant, issue_personal_licence
    for request_path in sorted(grant_dir.glob("*.request.json")):
        out = request_path.with_name(request_path.name.replace(".request.json", ".grant.json"))
        if out.exists():
            continue
        req = json.loads(request_path.read_text())
        file_id = published["file_id"]
        manifest = json.loads((app.paths.host / "files" / file_id / "manifest.json").read_text(encoding="utf-8"))
        common = dict(owner_signer=app.keys.artist_ed25519(), owner_agent=app.agent,
                      listener_agent=req["listener_agent"], recipient_public=bytes.fromhex(req["recipient_public_hex"]),
                      signed_manifest=manifest, content_key=app.keys.content_key(file_id))
        grant = (issue_personal_licence(**common) if req.get("kind") == "perpetual-personal"
                 else issue_content_grant(**common, lifetime_seconds=3600))
        out.write_text(json.dumps(grant))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--home", type=Path, required=True)
    p.add_argument("--bootstrap", required=True)
    p.add_argument("--status", type=Path, required=True)
    p.add_argument("--seconds", type=float, default=12.0)
    p.add_argument("--title", default="Browser Interop Tone")
    p.add_argument("--artist-name", default="Native Test Artist")
    p.add_argument("--host-rate", type=int, default=1024 * 1024)
    p.add_argument("--grant-dir", type=Path,
                   help="OPERATOR-ASSISTED, OUT-OF-BAND test grants: for each <name>.request.json "
                        "({listener_agent, recipient_public_hex, kind}) the artist issues a genuine v1 grant "
                        "with its own keys into <name>.grant.json. This is NOT the private Holochain "
                        "request/approval workflow (blocked for browsers; see docs/web/grants.md).")
    p.add_argument("--peer-only", action="store_true",
                   help="second native participant: join the network, publish nothing. kitsune2 grows a "
                        "node's storage arc only by syncing with another full-arc peer, so a lone artist "
                        "plus zero-arc browser gateways would never become a DHT authority.")
    args = p.parse_args()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    paths = AppPaths(data=args.home / "data", config=args.home / "config")
    app = MusicApp(paths)
    app.save_settings(bootstrap_url=args.bootstrap, relay_url=args.bootstrap, audio_backend="null",
                      host_max_rate=args.host_rate)
    app.player.backend = "null"
    t0 = time.monotonic()
    app.start()
    if not app.online:
        raise SystemExit(f"artist did not come online: {app.status_message}")
    try:
        status = {"phase": "online", "agent": app.agent, "online_s": round(time.monotonic() - t0, 1)}
        whoami = app.bridge.whoami if app.bridge else {}
        status["bridge_whoami"] = whoami
        args.status.write_text(json.dumps(status))
        if args.peer_only:
            while not stop.wait(3):
                status["heartbeat"] = int(time.time())
                args.status.write_text(json.dumps(status))
            return 0

        app.artist.save_profile(args.artist_name, "Generated test audio for browser interoperability.")
        wav = args.home / "tone.wav"
        write_tone(wav, seconds=args.seconds, rate=44100, channels=2)
        expected = args.home / "expected.wav"
        normalise_wav(wav, expected)
        canonical_wav = expected.read_bytes()
        t0 = time.monotonic()
        published = app.publish_track(wav=wav, title=args.title)
        status.update({
            "phase": "published", "publish_s": round(time.monotonic() - t0, 1),
            "track_id": published["track_id"], "file_id": published["file_id"],
            "manifest_sha256": published["manifest_sha256"],
            "track_key": f"{app.agent}:{published['track_id']}",
            "host": app.host.ready if app.host else None,
            # The listener must reproduce exactly these bytes after decrypting.
            "wav_sha256": hashlib.sha256(canonical_wav).hexdigest(),
            "pcm_sha256": hashlib.sha256(canonical_wav[44:]).hexdigest(),
            "wav_bytes": len(canonical_wav),
        })
        args.status.write_text(json.dumps(status))
        print(json.dumps(status), flush=True)
        while not stop.wait(3):
            if args.grant_dir:
                issue_pending_grants(app, args.grant_dir, published)
            requests = []
            try:
                requests = app.artist.requests()
            except Exception as exc:  # network flap: keep serving
                status["requests_error"] = str(exc)[:200]
            status["requests"] = [{k: r.get(k) for k in ("request_hash", "listener_agent", "file_id", "kind", "status")}
                                  for r in requests]
            status["heartbeat"] = int(time.time())
            args.status.write_text(json.dumps(status))
    finally:
        app.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
