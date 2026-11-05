"""S13 live conductor + true MoQ progress -> locally granted PCM before EOF.

TEST ONLY: Alice's grant was issued in an earlier separate stage; Bob has only
his X25519 secret, public owner grant, S1 manifest and authenticated conductor.
The host's local readiness JSON and artist private signer are never read here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from music_catalogue.streaming_playback import stream_granted_moq_from_live_conductor


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("stage", choices=("receive",))
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--bridge-binary", type=Path, required=True)
    p.add_argument("--moq-binary", type=Path, required=True)
    p.add_argument("--node-url", required=True)
    p.add_argument("--audio-backend", choices=("null", "alsa"), default="null")
    p.add_argument("--audio-device", default="default")
    p.add_argument("--admin-port", type=int, required=True)
    for name in ("app_id", "catalogue_dna", "storage_dna", "reader_agent", "artist_agent",
                 "node_agent", "track_id", "catalogue_role", "storage_role"):
        p.add_argument("--" + name.replace("_", "-"), required=True)
    args = p.parse_args()
    root = args.root
    fixture = json.loads((root / "fixture.json").read_text())
    if args.track_id != fixture["track_id"]:
        raise ValueError("S13 test track identity mismatch")
    if (root / "content.key").exists() or (root / "artist.ed25519").exists() or \
            (root / "sample.wav").exists():
        raise ValueError("S13 reader must not access owner signing/content keys or original WAV")
    listener_key = X25519PrivateKey.from_private_bytes((root / "listener.x25519").read_bytes())
    grant = json.loads((root / "grant.json").read_text())
    report = stream_granted_moq_from_live_conductor(
        grant=grant, recipient_private=listener_key,
        bridge_binary=args.bridge_binary, moq_binary=args.moq_binary,
        admin_port=args.admin_port, app_id=args.app_id,
        catalogue_dna=args.catalogue_dna, storage_dna=args.storage_dna,
        reader_agent=args.reader_agent, artist_agent=args.artist_agent,
        node_agent=args.node_agent, track_id=args.track_id,
        storage_url=args.node_url, target_store=root / "bob-s13-moq-store",
        catalogue_role=args.catalogue_role, storage_role=args.storage_role,
        backend=args.audio_backend, device=args.audio_device, timeout=150,
        adaptive_buffer=True,
    )
    if not report["first_pcm_before_last_chunk"] or not report["playback_complete"]:
        diagnostics = {k: report.get(k) for k in (
            "first_pcm_before_last_chunk", "first_pcm_after_verified_chunks",
            "ciphertext_chunks", "last_chunk_minus_first_pcm_ms", "playback_complete"
        )}
        raise ValueError(f"S13 PCM did not overlap authenticated MoQ transfer: {diagnostics}")
    if report.get("adaptive_buffer") is not True:
        raise ValueError("S13 verified PCM did not use adaptive buffering")
    if report["adaptive_final_target_blocks"] > report["adaptive_ceiling_blocks"] or \
            report["max_buffered_pcm_bytes"] > 65536:
        raise ValueError("S13 adaptive buffer exceeded its hard capacity")
    if report["rebuffer_events"] != report["buffer_underruns"]:
        raise ValueError("S13 underflow/rebuffer reporting inconsistent")
    if report["manifest_sha256"] != fixture["manifest_sha256"]:
        raise ValueError("S13 Holochain signed manifest digest mismatch")
    if report["pcm_sha256"] != fixture["sample_pcm_sha256"] or \
            report["output_pcm_sha256"] != fixture["sample_pcm_sha256"]:
        raise ValueError("S13 streaming PCM differs from signed fixture")
    if report["frames"] != fixture["pcm_frames"]:
        raise ValueError("S13 expected PCM frames not played")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
