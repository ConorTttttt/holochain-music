"""S14 real-conductor fixture: MoQ stream, lose one CAS object, pinned S4 repair,
then owner-granted frame-exact seek/replay on Bob's bounded PCM output.

The missing chunk is a deliberately deleted *listener CAS object* after
successful MoQ transport. Repair uses a separately signed S4 HTTP receipt;
it is NOT QUIC retransmission, adaptive bit-rate or an untrusted HTTP fallback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from holochain_storage.network_client import ReadOnlyStorageNodeClient
from holochain_storage.package import StorageError, manifest_digest, object_path, verify_package
from music_catalogue.granted_audio import PlaybackError
from music_catalogue.seekable_recovery import VerifiedWavSeeker, repair_missing_ciphertext
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
        raise PlaybackError("S14 Holochain requested wrong catalogue track")
    if any((root / secret).exists() for secret in ("content.key", "artist.ed25519", "sample.wav")):
        raise PlaybackError("S14 listener fixture must not expose original WAV or owner secrets")
    listener_key = X25519PrivateKey.from_private_bytes((root / "listener.x25519").read_bytes())
    grant = json.loads((root / "grant.json").read_text())
    store = root / "bob-s14-moq-store"
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
        raise PlaybackError("S14 prerequisite S13 MoQ playback was incomplete")
    if report["verified_reader_agent"] != args.reader_agent or \
            report["verified_owner_agent"] != args.artist_agent or \
            report["verified_node_agent"] != args.node_agent:
        raise PlaybackError("S14 Holochain agent trust context does not match")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest_digest(manifest) != report["manifest_sha256"] or \
            report["manifest_sha256"] != fixture["manifest_sha256"]:
        raise PlaybackError("S14 signed manifest differs from verified S9 conductor")
    artist_key = bytes.fromhex(report["verified_owner_key_hex"])
    node_key = bytes.fromhex(report["verified_node_key_hex"])
    if artist_key.hex() != fixture["artist_public_hex"]:
        raise PlaybackError("S14 artist key does not match signed fixture")
    chunks = manifest["body"]["chunks"]
    if len(chunks) < 8:
        raise PlaybackError("S14 fixture needs multiple authentic MoQ objects")
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
        raise PlaybackError("S14 unexpectedly accepted missing ciphertext")
    restored = repair_missing_ciphertext(
        signed_manifest=manifest, ciphertext_store=store,
        trusted_artist=artist_key, trusted_node=node_key,
        expected_manifest_sha256=report["manifest_sha256"],
        reader=ReadOnlyStorageNodeClient(args.node_url), max_objects=2)
    if not restored["repair_complete"] or restored["recovered_objects"] != 1:
        raise PlaybackError("S14 did not repair exactly one verified S4 object")
    seeker = VerifiedWavSeeker(
        signed_manifest=manifest, ciphertext_store=store, grant=grant,
        trusted_artist=artist_key, owner_agent=args.artist_agent,
        listener_agent=args.reader_agent, recipient_private=listener_key)
    start, frames = 8_000, 4_000
    if seeker.frames != fixture["pcm_frames"]:
        raise PlaybackError("S14 seek timeline not bound to S1 WAV metadata")
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
        raise PlaybackError("S14 seeks/replays differ from fixture's exact PCM samples")
    if max(first["max_buffered_pcm_bytes"], again["max_buffered_pcm_bytes"]) > 65_536:
        raise PlaybackError("S14 bounded seek buffer exceeded")
    print(json.dumps({**report, **restored,
        "seek_verified": True, "seek_start_frame": start,
        "seek_frames": frames, "seek_pcm_sha256": first["output_pcm_sha256"],
        "replay_verified": True, "replay_pcm_sha256": again["output_pcm_sha256"],
        "repair_missing_index": lost["index"],
        "seek_max_buffered_pcm_bytes": max(first["max_buffered_pcm_bytes"],
                                            again["max_buffered_pcm_bytes"])}, sort_keys=True))


if __name__ == "__main__":
    main()
