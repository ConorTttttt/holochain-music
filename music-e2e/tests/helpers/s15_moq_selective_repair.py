"""S15 real-conductor fixture: MoQ stream, lose one CAS object, pinned MoQ repair,
then owner-granted frame-exact seek/replay on Bob's bounded PCM output.

The missing chunk is a deliberately deleted listener CAS object AFTER
successful MoQ streaming. A second QUIC/MoQ connection to the SAME previously
Holochain-pinned endpoint restores exactly that requested S1 chunk. Host test
launch opts into the single preselected index. No HTTP ciphertext repair.
This is not transport-level packet loss retransmission or automatic retry.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from holochain_storage.package import StorageError, manifest_digest, object_path, verify_package
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.seekable_recovery import VerifiedWavSeeker
from music_catalogue.moq_repair import repair_missing_ciphertext_over_moq
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
        raise PlaybackError("S15 Holochain requested wrong catalogue track")
    if any((root / secret).exists() for secret in ("content.key", "artist.ed25519", "sample.wav")):
        raise PlaybackError("S15 listener fixture must not expose original WAV or owner secrets")
    listener_key = X25519PrivateKey.from_private_bytes((root / "listener.x25519").read_bytes())
    grant = json.loads((root / "grant.json").read_text())
    store = root / "bob-s15-moq-store"
    report = stream_granted_moq_from_live_conductor(
        grant=grant, recipient_private=listener_key,
        bridge_binary=args.bridge_binary, moq_binary=args.moq_binary,
        admin_port=args.admin_port, app_id=args.app_id,
        catalogue_dna=args.catalogue_dna, storage_dna=args.storage_dna,
        reader_agent=args.reader_agent, artist_agent=args.artist_agent,
        node_agent=args.node_agent, track_id=args.track_id,
        storage_url=args.node_url, target_store=store,
        catalogue_role=args.catalogue_role, storage_role=args.storage_role,
        backend=args.audio_backend, device=args.audio_device, timeout=150,
        adaptive_buffer=True, include_trust_context=True,
    )
    if not report["first_pcm_before_last_chunk"] or not report["playback_complete"]:
        raise PlaybackError("S15 prerequisite S13 MoQ playback was incomplete")
    if report["verified_reader_agent"] != args.reader_agent or \
            report["verified_owner_agent"] != args.artist_agent or \
            report["verified_node_agent"] != args.node_agent:
        raise PlaybackError("S15 Holochain agent trust context does not match")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest_digest(manifest) != report["manifest_sha256"] or \
            report["manifest_sha256"] != fixture["manifest_sha256"]:
        raise PlaybackError("S15 signed manifest differs from verified S9 conductor")
    artist_key = bytes.fromhex(report["verified_owner_key_hex"])
    node_key = bytes.fromhex(report["verified_node_key_hex"])
    if artist_key.hex() != fixture["artist_public_hex"]:
        raise PlaybackError("S15 artist key does not match signed fixture")
    chunks = manifest["body"]["chunks"]
    if len(chunks) < 8:
        raise PlaybackError("S15 fixture needs multiple authentic MoQ objects")
    verify_package(manifest, store, artist_key)
    lost = chunks[3]
    lost_path = object_path(store, lost["sha256"])
    lost_path.unlink()
    try:
        VerifiedWavSeeker(
            signed_manifest=manifest, ciphertext_store=store, grant=grant,
            trusted_artist=artist_key, owner_agent=args.artist_agent,
            listener_agent=args.reader_agent, recipient_private=listener_key)
    except StorageError:
        pass
    else:
        raise PlaybackError("S15 unexpectedly accepted missing ciphertext")
    # The endpoint URL and TLS SHA-256 pin come exclusively from S9's
    # independently validated Bob conductor context, NOT Carol's ready JSON.
    # This route MUST NOT call ReadOnlyStorageNodeClient._get(chunk).
    restored = repair_missing_ciphertext_over_moq(
        signed_manifest=manifest, ciphertext_store=store,
        trusted_artist=artist_key,
        expected_manifest_sha256=report["manifest_sha256"],
        moq_binary=args.moq_binary,
        moq_url=report["verified_moq_url"],
        moq_cert_fingerprint_hex=report["verified_moq_cert_fingerprint_hex"],
        timeout=90,
    )
    if not restored["repair_complete"] or restored["recovered_objects"] != 1:
        raise PlaybackError("S15 did not repair exactly one pinned MoQ object")
    seeker = VerifiedWavSeeker(
        signed_manifest=manifest, ciphertext_store=store, grant=grant,
        trusted_artist=artist_key, owner_agent=args.artist_agent,
        listener_agent=args.reader_agent, recipient_private=listener_key)
    start, frames = 8_000, 4_000
    if seeker.frames != fixture["pcm_frames"]:
        raise PlaybackError("S15 seek timeline not bound to S1 WAV metadata")
    # Reference data is generated independently from the S7 fixture's test-only
    # published formula, not read from an owner secret or from Bob's CAS.
    expected_slice = b"".join(struct.pack("<h", int(10000 * math.sin(2 * math.pi * 440 * i / 16000)))
                              for i in range(start, start + frames))
    expected_hash = hashlib.sha256(expected_slice).hexdigest()
    first = seeker.play(start_frame=start, frame_count=frames,
                        backend=args.audio_backend, device=args.audio_device)
    again = seeker.play(start_frame=start, frame_count=frames,
                        backend=args.audio_backend, device=args.audio_device)
    if (first["output_pcm_sha256"] != expected_hash or
            again["output_pcm_sha256"] != expected_hash or
            first["output_frames"] != frames or again["output_frames"] != frames):
        raise PlaybackError("S15 seeks/replays differ from fixture's exact PCM samples")
    if max(first["max_buffered_pcm_bytes"], again["max_buffered_pcm_bytes"]) > 65_536:
        raise PlaybackError("S15 bounded seek buffer exceeded")
    print(json.dumps({**report, **restored,
        "seek_verified": True, "seek_start_frame": start,
        "seek_frames": frames, "seek_pcm_sha256": first["output_pcm_sha256"],
        "replay_verified": True, "replay_pcm_sha256": again["output_pcm_sha256"],
        "repair_missing_index": lost["index"],
        "seek_max_buffered_pcm_bytes": max(first["max_buffered_pcm_bytes"],
                                            again["max_buffered_pcm_bytes"])}, sort_keys=True))


if __name__ == "__main__":
    main()
