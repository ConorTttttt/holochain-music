"""Verify S5 catalogue -> S2 identity -> S1 signature -> S4 ciphertext.

IMPORTANT: `AuthoredRecord`s MUST originate from an authenticated, validating
Holochain conductor. A dict received from an untrusted peer is not proof of
Holochain action authorship. The conductor-to-Python websocket bridge is a
future integration gate; this function cannot authenticate it by itself.
"""
from __future__ import annotations

from pathlib import Path

from holochain_storage.holochain_identity import (
    AuthoredRecord, HOST_PURPOSE, OWNER_PURPOSE, key_for_agent,
    verify_owned_manifest, verify_replica_claim,
)
from holochain_storage.network_client import ReadOnlyStorageNodeClient
from holochain_storage.package import StorageError

from .contract import CatalogueError, verify_track_manifest


def fetch_verified_track(
    *,
    track_record: AuthoredRecord,
    signed_manifest: dict,
    owner_key_binding: AuthoredRecord,
    owner_commitment: AuthoredRecord,
    node_agent: str,
    node_key_binding: AuthoredRecord,
    replica_claim: AuthoredRecord,
    reader: ReadOnlyStorageNodeClient,
    target_store: str | Path,
) -> dict:
    """Fetch only after all catalogue, owner and host claims authenticate.

    Returns the verified manifest body. Downloads *encrypted chunks only*, not
    playable plaintext. No private key is given to the listener/reader.

    Key selection/rotation policy must be resolved by the caller; never select
    the first key in an untrusted registry. A signed receipt represents one
    successful past acceptance, not guaranteed current custody.
    """
    if not isinstance(track_record, AuthoredRecord) or not track_record.action_hash:
        raise CatalogueError("missing conductor-authenticated track record")
    owner_agent = track_record.author
    if not isinstance(owner_agent, str) or not owner_agent:
        raise CatalogueError("missing trusted artist identity")

    artist_key = key_for_agent(owner_key_binding, owner_agent, OWNER_PURPOSE)
    node_key = key_for_agent(node_key_binding, node_agent, HOST_PURPOSE)

    # All checks precede network payload transfer. A forged track, changed
    # manifest, forged owner commitment or wrong signing key fails closed.
    track_body = verify_track_manifest(
        track_record.body, signed_manifest, author=owner_agent, trusted_signer=artist_key,
    )
    owned_body = verify_owned_manifest(
        signed_manifest, owner_agent, owner_key_binding, owner_commitment,
    )
    if owned_body != track_body:
        raise StorageError("catalogue and storage commitment mismatch")

    receipt = reader.receipt(signed_manifest)
    verify_replica_claim(
        receipt, signed_manifest, owner_agent, node_agent,
        owner_key_binding, node_key_binding, owner_commitment, replica_claim,
    )
    reader.fetch(
        signed_manifest, Path(target_store), trusted_artist=artist_key, trusted_node=node_key,
    )
    return track_body
