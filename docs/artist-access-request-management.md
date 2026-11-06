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

Repeated submissions for the same artist, listener identity, encrypted file, manifest,\nrequest type and recipient key are shown as one combined row. The listener app\nalso refuses to transmit a second pending request of the same type, including\nacross restarts. Previous private entries stay on the artist's source chain;\nthey are grouped in the UI rather than deleted. Different licence types\nremain separate offers.\n\nThe artist's approvals and declines are saved in
`<artist-host-root>/request-decisions.json` via atomic writes with mode 0600.
This file is **local**, not a new public Holochain entry; only the artist's
existing conductor-authenticated request inbox supplies the request records.
The existing `issued-grants.json` ledger remains compatible with older
approvals. The listener and track association is not posted to the public DHT.

A declined request is also **delivered privately to the listener** by a\nconductor-authenticated remote call. If the listener is offline, the artist's\noutbox queues the message and retries while the artist app runs (up to seven\ndays). On the listener's next status sync, a decline is applied only if the\nsending agent, file, manifest, access type and per-request random correlation\nID match the listener's current pending request. Existing licences and grants\nare never revoked by this status. The UI shows **Access declined by artist**\nand suppresses another request for that same type.\n\nFor decisions made before notifications existed, the artist can choose\n**Resend decline notice** on a declined row. A previously declined request\ncannot be approved under its original request hash; a future explicit new\nrequest/reconsideration flow remains separate work. A permanent personal
licence is irrevocable once delivered or queued; read the confirmation carefully.

Grant signing and delivery retains the existing signed-manifest, per-recipient
X25519, source-chain and session-security checks. The new API endpoints remain
bound to loopback, bearer-token authenticated and same-origin protected:
`POST /api/artist/reject`, `POST /api/artist/reject/notify`,\n`POST /api/artist/requests/bulk` and `POST /api/decisions/sync`.
Both require online artist state. The bulk endpoint rejects empty, duplicate,
oversized and invalid ID sets. It returns independent results for each ID.

## Test and migration notes

This update adds a new private InboxDecision entry to the storage DNA and\nan allow-listed `receive_decision` remote zome call. **Rebuild and reinstall\nthe new storage DNA, full hApp and native bridge on both artist and listener**\nfor end-to-end tests. An existing conductor with the older DNA is not\nautomatically upgraded by restarting the Python UI; use isolated test profiles\nand a deliberate DNA migration plan before production. No private identity\nlinks or public decision contents are added to the DHT.\n