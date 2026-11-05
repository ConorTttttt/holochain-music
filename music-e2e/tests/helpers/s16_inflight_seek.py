"""S16: seek forward then backward during genuine live S9 Holochain/MoQ transfer.

The Rust Sweettest operates actual Alice/Bob/Carol conductors, real signed S1
hosted ciphertext and pinned QUIC. This Python listener only receives the
artist's signed per-listener grant and public S9 trust material: no owner
private key, plaintext WAV, or AES content key is available here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from holochain_storage.package import manifest_digest
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.inflight_seek import stream_seek_granted_moq_from_live_conductor


SEEK_RANGES = ((24_007, 4096), (7001, 4096))


def _reference_pcm(start: int, frames: int) -> bytes:
    # Independent *test fixture* reference, never read from a decrypted file.
    return b"".join(struct.pack("<h", int(10000 * math.sin(2 * math.pi * 440 * i / 16000)))
                    for i in range(start, start + frames))


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
    for name in ("app_id", "catalogue_dna", "storage_dna", "reader_agent",
                 "artist_agent", "node_agent", "track_id", "catalogue_role", "storage_role"):
        p.add_argument("--" + name.replace("_", "-"), required=True)
    args = p.parse_args()
    root = args.root
    fixture = json.loads((root / "fixture.json").read_text())
    if args.track_id != fixture["track_id"]:
        raise PlaybackError("S16 Holochain catalogue track does not match fixture")
    if any((root / n).exists() for n in ("content.key", "artist.ed25519", "sample.wav")):
        raise PlaybackError("S16 listener fixture includes forbidden owner plaintext/keys")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest_digest(manifest) != fixture["manifest_sha256"]:
        raise PlaybackError("S16 fixture manifest mismatch")
    grant = json.loads((root / "grant.json").read_text())
    recipient = X25519PrivateKey.from_private_bytes((root / "listener.x25519").read_bytes())
    report = stream_seek_granted_moq_from_live_conductor(
        grant=grant, recipient_private=recipient,
        bridge_binary=args.bridge_binary, moq_binary=args.moq_binary,
        admin_port=args.admin_port, app_id=args.app_id,
        catalogue_dna=args.catalogue_dna, storage_dna=args.storage_dna,
        reader_agent=args.reader_agent, artist_agent=args.artist_agent,
        node_agent=args.node_agent, track_id=args.track_id,
        storage_url=args.node_url, target_store=root / "bob-s16-inflight-store",
        catalogue_role=args.catalogue_role, storage_role=args.storage_role,
        seek_ranges=SEEK_RANGES, backend=args.audio_backend, device=args.audio_device,
        timeout=150,
    )
    if (not report["verified"] or not report["inflight_seek"] or
            report["manifest_sha256"] != fixture["manifest_sha256"] or
            report["received_chunks"] != report["verified_ciphertext_chunks"] or
            not report["all_seeks_before_last_chunk"] or
            report["total_frames"] != fixture["pcm_frames"]):
        raise PlaybackError("S16 conductor/crypto/overlap verification failed")
    for (start, frames), entry in zip(SEEK_RANGES, report["seek_ranges"], strict=True):
        expected_hash = hashlib.sha256(_reference_pcm(start, frames)).hexdigest()
        if (entry["seek_start_frame"] != start or entry["output_frames"] != frames or
                not entry["playback_complete"] or entry["output_pcm_sha256"] != expected_hash or
                entry["seek_pcm_sha256"] != expected_hash or
                entry["first_pcm_after_verified_chunks"] >= report["received_chunks"] or
                entry["max_buffered_pcm_bytes"] > 65_536):
            raise PlaybackError(f"S16 selected seek failed exact PCM/overlap: {entry}")
    print(json.dumps({**report, "forward_seek_verified": True,
                      "backward_seek_verified": True,
                      "seek_transport": "ordered-pinned-moq-quic",
                      "seek_test_ranges": [list(p) for p in SEEK_RANGES]}, sort_keys=True))


if __name__ == "__main__":
    main()
