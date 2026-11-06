# Artist access request management

On **Artist studio → Access requests** you can resolve individual requests and process
explicit groups of pending requests. All decisions require the running, locally
authenticated artist application. Only requests on this artist's private inbox
for a currently published matching track/manifest are displayed or actionable.

## Inbox and folder filters

- **Track folder** groups requests by the track's immutable file ID (with the
  track title shown for convenience). Pick one track to operate on its folder.
- **Request type** filters 24-hour streaming vs permanent personal-use licence.
- **Status** filters Pending (default), Approved, Declined, or all statuses.
- **Search** matches track title, listener agent, note, or file ID.
- Changing filters works on the fetched snapshot without requesting a new grant
  or changing any request. Leave and reopen the page to refresh the inbox.

## Individual and bulk decisions

- **Accept** grants exactly the access type that the listener requested.
  A streaming request does not silently become a permanent licence.
- **Decline** records the rejection without issuing any access grant.
- **Accept all pending** acts on all pending requests in the fetched inbox
  snapshot, ignoring the current folder and filters. The confirmation shows the
  exact count and warns about any permanent licences.
- **Accept all filtered** acts only on pending items matching all active filters.
  With a track folder selected, its label becomes **Accept all in this folder**
  and remains subject to the other filters.
- **Decline all filtered** declines only pending requests in the currently
  filtered view. Already-approved grants are never declined retroactively.

Every bulk action requires confirmation. The browser sends *explicit immutable
request hashes*, not a server-side command such as `all`. Batches are limited
to 25 hashes per call; each result identifies success, failure, or queued grant
delivery. If an operation is interrupted, refresh and inspect the status before
trying it again. Some grants may already have been signed and queued.

## Privacy, persistence and limitations

The artist's approvals and declines are saved in
`<artist-host-root>/request-decisions.json` via atomic writes with mode 0600.
This file is **local**, not a new public Holochain entry; only the artist's
existing conductor-authenticated request inbox supplies the request records.
The existing `issued-grants.json` ledger remains compatible with older
approvals. The listener and track association is not posted to the public DHT.

A declined request is **not yet notified** to the listener; it simply becomes
Declined in the artist's UI and cannot be approved later under the same request
hash. A listener may submit a new request. Rejected requests do not revoke
already-issued keys, streaming access, or exported copies. A permanent personal
licence is irrevocable once delivered or queued; read the confirmation carefully.

Grant signing and delivery retains the existing signed-manifest, per-recipient
X25519, source-chain and session-security checks. The new API endpoints remain
bound to loopback, bearer-token authenticated and same-origin protected:
`POST /api/artist/reject` and `POST /api/artist/requests/bulk`.
Both require online artist state. The bulk endpoint rejects empty, duplicate,
oversized and invalid ID sets. It returns independent results for each ID.
