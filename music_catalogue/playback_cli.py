"""S11 optional local ALSA speaker check / already-granted PCM player.

`demo` is a LOCAL sound-card check that makes a fresh disposable owner grant;
it is not a Holochain entitlement or live MoQ fixture. For actual music use
`play` with the authenticated S10 S1 manifest, owner signing key binding,
listener identity, ciphertext CAS, and owner-signed grant. No CLI flags are
read from peer-provided metadata automatically; use the S10/S11 bridge first.
"""
from __future__ import annotations

import argparse
import json
import math
import select
from pathlib import Path
import struct
import sys
import tempfile
import threading
import wave

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import create_package, public_key_bytes
from .buffered_playback import BufferedPcmPlayer, PlaybackStopped, play_granted_wav_realtime
from .content_grants import issue_content_grant
from .granted_audio import PlaybackError


def _read_json(path: Path):
    if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise PlaybackError("missing/oversized local input file")
    return json.loads(path.read_text())


def _demo_inputs(directory: Path, seconds: float):
    """Synthesise a 440Hz tone, issue a *test-only* signed grant, then unlink source."""
    rate = 16000
    frames = int(rate * seconds)
    source = directory / "tone.wav"
    artist = Ed25519PrivateKey.generate()
    listener = X25519PrivateKey.generate()
    with wave.open(str(source), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        # Avoid holding the entire demonstration audio file in memory.
        for begin in range(0, frames, 1024):
            samples = min(1024, frames - begin)
            pcm = b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / rate)))
                           for i in range(begin, begin + samples))
            wav.writeframesraw(pcm)
    manifest, aes_key = create_package(source, directory / "cas", artist, chunk_size=2048)
    source.unlink()  # never persist demo plaintext after encryption
    grant = issue_content_grant(
        owner_signer=artist, owner_agent="s11-demo-artist", listener_agent="s11-demo-listener",
        recipient_public=listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        signed_manifest=manifest, content_key=aes_key,
    )
    return dict(signed_manifest=manifest, ciphertext_store=directory / "cas",
                grant=grant, trusted_artist=public_key_bytes(artist),
                owner_agent="s11-demo-artist", listener_agent="s11-demo-listener",
                recipient_private=listener)


def _run_with_controls(kwargs: dict, backend: str, device: str, controls: bool) -> dict:
    engine = BufferedPcmPlayer(backend=backend, device=device)
    outcome: dict = {}
    error: list[BaseException] = []
    stop_requested = False

    def task():
        try:
            outcome.update(play_granted_wav_realtime(**kwargs, player=engine))
        except BaseException as exc:
            error.append(exc)

    thread = threading.Thread(target=task, name="s11-player", daemon=True)
    thread.start()
    if controls:
        print("Playback controls: p = pause, r = resume, s = stop; press Enter after each command.",
              file=sys.stderr)
        while thread.is_alive():
            # select() avoids getting stuck in input() after the track ends.
            ready, _, _ = select.select([sys.stdin], [], [], 0.15)
            if not ready:
                continue
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip().lower()
            try:
                if line in ("p", "pause"):
                    engine.pause()
                elif line in ("r", "resume"):
                    engine.resume()
                elif line in ("s", "stop"):
                    engine.stop()
                    stop_requested = True
                    break
            except PlaybackError as exc:
                print(f"Playback control unavailable: {exc}", file=sys.stderr)
    thread.join()
    if error:
        if stop_requested and isinstance(error[0], PlaybackStopped):
            return engine.stopped_report()
        raise error[0]
    if not outcome:
        raise PlaybackError("playback stopped or incomplete")
    return outcome


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="S11 local grant-verified PCM player")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="locally generated sine tone (not Holochain music)")
    demo.add_argument("--seconds", type=float, default=3.0)
    play = commands.add_parser("play", help="play trusted S1 manifest/grant/CAS from local files")
    play.add_argument("--manifest", type=Path, required=True)
    play.add_argument("--store", type=Path, required=True)
    play.add_argument("--grant", type=Path, required=True)
    play.add_argument("--trusted-artist-hex", required=True)
    play.add_argument("--owner-agent", required=True)
    play.add_argument("--listener-agent", required=True)
    play.add_argument("--recipient-private-file", type=Path, required=True)
    for command in (demo, play):
        command.add_argument("--backend", choices=("alsa", "null"), default="alsa")
        command.add_argument("--device", default="default")
        command.add_argument("--controls", action="store_true", help="interactive play/pause/resume/stop")
    args = parser.parse_args(argv)
    if args.controls and not sys.stdin.isatty():
        parser.error("--controls requires an interactive terminal")
    if args.command == "demo":
        if not math.isfinite(args.seconds) or not 0.1 <= args.seconds <= 15.0:
            parser.error("--seconds must be within 0.1..15")
        with tempfile.TemporaryDirectory(prefix="s11-speaker-demo-") as d:
            kwargs = _demo_inputs(Path(d), args.seconds)
            result = _run_with_controls(kwargs, args.backend, args.device, args.controls)
    else:
        key_file = args.recipient_private_file
        if not key_file.is_file() or key_file.stat().st_size != 32:
            parser.error("recipient private key file must be 32 bytes")
        # A local X25519 keystore integration replaces file loading later.
        try:
            artist = bytes.fromhex(args.trusted_artist_hex)
            if len(artist) != 32:
                raise ValueError("not 32 bytes")
            recipient = X25519PrivateKey.from_private_bytes(key_file.read_bytes())
        except ValueError:
            parser.error("invalid trusted artist key or listener X25519 key")
        kwargs = dict(signed_manifest=_read_json(args.manifest),
                      ciphertext_store=args.store, grant=_read_json(args.grant),
                      trusted_artist=artist, owner_agent=args.owner_agent,
                      listener_agent=args.listener_agent, recipient_private=recipient)
        result = _run_with_controls(kwargs, args.backend, args.device, args.controls)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
