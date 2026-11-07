"""Music track -> generic S1 encrypted-package commitment verification.

No audio payload, decryption key, or full signed manifest is published to the DHT.
The trusted_signer MUST be authenticated separately through Holochain S2.
The `author` MUST come from a validating conductor, not a caller's field.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from holochain_storage.package import (
    StorageError, _assert_manifest, _verify_signed, manifest_digest,
)

TRACK_SCHEMA = "holochain-music/track/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[0-9a-f]{32}$")
_FORMATS = {"audio/mpeg", "audio/flac", "audio/ogg", "audio/mp4", "audio/wav"}
_RIGHTS = {"original_owner", "licensed_by_rights_holder"}
_KEYS = {
    "schema", "artist_agent", "track_id", "album_id", "title", "duration_ms",
    "disc_number", "track_number", "audio_format", "file_id", "manifest_sha256", "rights_basis",
}


class CatalogueError(ValueError):
    """Invalid or mismatched public music catalogue metadata."""


def validate_track(track: Mapping[str, Any], *, author: str) -> None:
    """Validate a track with an authenticated conductor-provided action author.

    Do NOT use caller-reported JSON `author` values as independent authentication.
    """
    if not isinstance(track, dict) or set(track) != _KEYS:
        raise CatalogueError("invalid track fields")
    if not isinstance(author, str) or not author or track["artist_agent"] != author:
        raise CatalogueError("track publisher does not match authenticated author")
    if track["schema"] != TRACK_SCHEMA or not isinstance(track["track_id"], str) or not _ID.fullmatch(track["track_id"]):
        raise CatalogueError("invalid track schema/id")
    album = track["album_id"]
    if album is not None and (not isinstance(album, str) or not _ID.fullmatch(album)):
        raise CatalogueError("invalid album id")
    title = track["title"]
    if not isinstance(title, str) or not title or title.strip() != title or len(title.encode("utf-8")) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in title):
        raise CatalogueError("invalid title")
    for key, minimum, maximum in (("duration_ms", 1, 86_400_000), ("disc_number", 1, 99), ("track_number", 1, 999)):
        value = track[key]
        if type(value) is not int or not minimum <= value <= maximum:
            raise CatalogueError(f"invalid {key}")
    if track["audio_format"] not in _FORMATS or track["rights_basis"] not in _RIGHTS:
        raise CatalogueError("invalid audio format or rights declaration")
    for name in ("file_id", "manifest_sha256"):
        value = track[name]
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise CatalogueError(f"invalid {name}")


def verify_track_manifest(track: dict[str, Any], signed_manifest: dict[str, Any], *,
                          author: str, trusted_signer: bytes) -> dict[str, Any]:
    """Verify that an S1 signed manifest is exactly the package a track references.

    `author` must be from a validating Holochain conductor. `trusted_signer`
    must be obtained from an S2 agent-authored signing-key binding and validated
    against that author. This function cannot authenticate either one itself.
    """
    validate_track(track, author=author)
    try:
        body = _verify_signed(signed_manifest, trusted_signer, "manifest")
        _assert_manifest(body)
        digest = manifest_digest(signed_manifest)
    except (StorageError, TypeError, KeyError, ValueError) as exc:
        raise CatalogueError("signed encrypted manifest verification failed") from exc
    if body["file_id"] != track["file_id"] or digest != track["manifest_sha256"]:
        raise CatalogueError("track references a different signed encrypted manifest")
    return body
