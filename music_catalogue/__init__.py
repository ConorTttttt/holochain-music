"""Client-side checks for public Holochain music catalogue metadata.

A dict returned by a remote peer does not authenticate its own Holochain author.
Use a validating conductor and S2 to authenticate the claimed artist signing key.
"""

from .contract import CatalogueError, validate_track, verify_track_manifest

__all__ = ["CatalogueError", "validate_track", "verify_track_manifest"]
