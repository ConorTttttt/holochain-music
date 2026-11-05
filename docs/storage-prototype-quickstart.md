# S1 local protocol prototype — run and verify

This is the **generic file storage** prototype, deliberately separate from music-only ingestion. It is not a Holochain conductor, networked storage-node process, payment service, or MoQ file transfer. It exercises local full-copy replication on separate directories and issues assertions signed by independent node keys.

## Requirements

- Python 3.10 or newer
- The Python `cryptography` package (`pip install -e .` installs it)
- No Holochain / MoQ dependency for S1

## First run

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m holochain_storage.demo path/to/any/file
```

The demo encrypts an arbitrary input file, creates **two complete encrypted replicas**, verifies each host's signed acceptance receipt, creates an artist-signed perpetual buyer key grant, then reconstructs the exact original bytes. It reports success only after matching SHA-256 of the exported file against the input. The demo works with music, archives, images, text and even empty files.

The demo uses temporary directories and keys in memory; it cleans up temporary files on normal exit, but does **not** securely overwrite data from disk or memory. Do not test with sensitive documents on an untrusted workstation or assume this demo safely stores purchase secrets.

## Generic API

```python
from holochain_storage import (
    create_package, verify_package, replicate_package,
    verify_receipt, decrypt_package, create_perpetual_grant, open_perpetual_grant,
)
```

The package has **no** dependency on Holochain, MoQ or music formats. See `holochain_storage/package.py` for the v1 storage API and `holochain_storage/grant.py` for the offline buyer grant example. Use externally authenticated 32-byte raw Ed25519 public keys as `trusted_artist` and `trusted_node`; do **not** trust the signer key embedded in a received receipt or manifest by itself.

## Version 1 protocol limits

- AES-256-GCM with 96-bit independently generated random nonce per chunk, and package-ID/index AAD.
- Owner-signed canonical JSON manifest enumerating every ciphertext chunk SHA-256 digest; **no Merkle root yet**.
- 256 KiB default chunks, maximum 4 MiB chunks.
- Up to 16,384 chunks and 64 GiB plaintext in one v1 package (default 256 KiB chunks imply about 4 GiB at the chunk limit).
- Signed JSON body limit: 8 MiB. The limit may need revisiting for general-purpose very large files.
- Empty files are valid packages with zero chunks.
- File content keys are returned in memory and are **never** embedded in public manifests or receipts.

## What the tests establish

- Files can be verified and replicated without plaintext keys.
- Tampered, missing, malformed and symlinked encrypted objects are rejected, as are incorrect signers and wrong package receipts.
- A buyer with a valid grant and a full replica can export original bytes after the author's copy is gone.
- Wrong keys do not replace existing output files.

The tests do **not** establish malicious-host resistance in an untrusted OS, continuing custody, guaranteed retrievability, multi-host independence, or payment/rights verification. Run `python -m unittest discover -s tests -v` to see the current cases.
