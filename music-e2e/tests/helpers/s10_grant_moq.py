"""S10 Sweettest helper: owner grant issued before real Holochain/MoQ listen.

`issue` is Alice's explicit grant decision in the **trusted test runner**.
It encrypts the AES content key to Bob's independent X25519 public key,
signs the grant with Alice's existing owner-manifest Ed25519 key, then removes
the raw test content key and artist private key from the fixture workspace.
`receive` sees only the signed grant, Bob's X25519 private key, public S1/S2
metadata and the actual local conductor/MoQ flow. PCM goes to a hash sink,
never a plaintext file. A speaker device is intentionally not involved.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.package import canonical, manifest_digest
from music_catalogue.content_grants import issue_content_grant
from music_catalogue.granted_audio import play_granted_wav
from music_catalogue.buffered_playback import play_granted_wav_realtime
from music_catalogue.moq_conductor import receive_moq_from_live_conductor


def _private(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)


def issue(root: Path, artist_agent: str, reader_agent: str) -> dict:
    manifest = json.loads((root / "manifest.json").read_text())
    signer = Ed25519PrivateKey.from_private_bytes((root / "artist.ed25519").read_bytes())
    content_key = (root / "content.key").read_bytes()
    listener = X25519PrivateKey.generate()
    listener_public = listener.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    grant = issue_content_grant(
        owner_signer=signer, owner_agent=artist_agent,
        listener_agent=reader_agent, recipient_public=listener_public,
        signed_manifest=manifest, content_key=content_key, lifetime_seconds=3600,
    )
    # In a deployment, the private X25519 key lives in the listener's own
    # keystore and the signed grant travels via an authenticated channel.
    _private(root / "listener.x25519", listener.private_bytes_raw())
    (root / "grant.json").write_bytes(canonical(grant))
    # Test invariant: the listener cannot recover the key by reading the old
    # fixture's plaintext content.key or signing the grant itself.
    (root / "content.key").unlink()
    (root / "artist.ed25519").unlink()
    return {"issued": True, "file_id": manifest["body"]["file_id"],
            "manifest_sha256": manifest_digest(manifest), "reader_agent": reader_agent}


def receive(args) -> dict:
    root = args.root
    fixture = json.loads((root / "fixture.json").read_text())
    if args.track_id != fixture["track_id"]:
        raise ValueError("wrong S10 track")
    if (root / "content.key").exists() or (root / "artist.ed25519").exists():
        raise ValueError("S10 listener fixture still exposes owner secrets")
    report = receive_moq_from_live_conductor(
        bridge_binary=args.bridge_binary, moq_binary=args.moq_binary,
        admin_port=args.admin_port, app_id=args.app_id,
        catalogue_dna=args.catalogue_dna, storage_dna=args.storage_dna,
        reader_agent=args.reader_agent, artist_agent=args.artist_agent,
        node_agent=args.node_agent, track_id=args.track_id,
        storage_url=args.node_url, target_store=root / "bob-moq-store",
        catalogue_role=args.catalogue_role, storage_role=args.storage_role,
        include_trust_context=True,
    )
    # Reader identity was checked by the trusted S9 authenticated WebSocket
    # bridge before the QUIC receive. This grant independently checks it again.
    manifest = json.loads((root / "manifest.json").read_text())
    if report["verified_reader_agent"] != args.reader_agent or \
            report["verified_owner_agent"] != args.artist_agent:
        raise ValueError("trusted Holochain listener/artist binding mismatch")
    if report["manifest_sha256"] != fixture["manifest_sha256"]:
        raise ValueError("trusted Holochain manifest digest mismatch")
    artist_public = bytes.fromhex(report["verified_owner_key_hex"])
    if artist_public.hex() != fixture["artist_public_hex"]:
        raise ValueError("trusted Holochain artist key mismatch")
    listener_private = X25519PrivateKey.from_private_bytes((root / "listener.x25519").read_bytes())
    grant = json.loads((root / "grant.json").read_text())
    # Sink receives PCM blocks only after per-chunk S1 verification, grant
    # signature+recipient checks and AES-GCM authentication. No WAV file here.
    common = dict(
        signed_manifest=manifest, ciphertext_store=root / "bob-moq-store",
        grant=grant, trusted_artist=artist_public,
        owner_agent=args.artist_agent, listener_agent=args.reader_agent,
        recipient_private=listener_private,
    )
    if args.audio_mode == "paced-null":
        # S11: real-time paced, bounded audio FIFO, null hardware device.
        # This still uses all conductor-authenticated S10 grant/manifest pins.
        playable = play_granted_wav_realtime(**common, backend="null")
        if not playable["playback_complete"] or \
                playable["output_pcm_sha256"] != fixture["sample_pcm_sha256"]:
            raise ValueError("S11 timed PCM sink differs from original WAV")
    elif args.audio_mode == "alsa":
        # Explicit local hardware smoke test only: never used in headless CI.
        playable = play_granted_wav_realtime(**common, backend="alsa",
                                             device=args.audio_device)
    else:
        # Existing S10 default remains unchanged.
        playable = play_granted_wav(**common, pcm_sink=lambda _pcm: None)
    if playable["pcm_sha256"] != fixture["sample_pcm_sha256"]:
        raise ValueError("S10 PCM output differs from the authentic WAV fixture")
    if playable["frames"] != fixture["pcm_frames"]:
        raise ValueError("S10 PCM frame count differs from original WAV")
    return {"verified": True, "ciphertext_chunks": report["received_chunks"], **playable}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("issue", "receive"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--artist-agent", required=True)
    parser.add_argument("--reader-agent", required=True)
    parser.add_argument("--audio-mode", choices=("hash", "paced-null", "alsa"), default="hash")
    parser.add_argument("--audio-device", default="default")
    for name in ("bridge_binary", "moq_binary"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path)
    parser.add_argument("--node-url")
    parser.add_argument("--admin-port", type=int)
    for name in ("app_id", "catalogue_dna", "storage_dna", "node_agent",
                 "track_id", "catalogue_role", "storage_role"):
        parser.add_argument("--" + name.replace("_", "-"))
    args = parser.parse_args()
    if args.stage == "issue":
        result = issue(args.root, args.artist_agent, args.reader_agent)
    else:
        required = ("bridge_binary", "moq_binary", "node_url", "admin_port",
                    "app_id", "catalogue_dna", "storage_dna", "node_agent", "track_id",
                    "catalogue_role", "storage_role")
        if any(getattr(args, name) is None for name in required):
            parser.error("receive requires all S9 local conductor/MoQ parameters")
        result = receive(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
