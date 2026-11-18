# Roadmap and follow-up work

Ordered by dependency. Priorities 1–4 of the brief are working with real
components; priority 5 (private grants) is blocked on transport; 6 depends on 5.

1. **H2HC/HWC `call_remote` relay** (unblocks Checkpoints E and F) — [grants.md](grants.md#interoperability-proposal-narrow-separately-reviewable).
2. **HWC verification of DHT reads** — close the gateway read-integrity gap ([security.md](security.md#remaining-vulnerabilities-and-limits-be-explicit) item 1).
3. **Deployment rehearsal** — HTTPS site, TLS gateway and adapter, two native authorities, operator admission, two physical machines.
4. **Experience** — albums view polish, artwork over the adapter (`artwork_manifest_sha256` is already in records), queue persistence, playlists, offline encrypted storage (OPFS) with a tested disconnected-playback gate, service worker for static assets only.
5. **Guest mode** — read-only discovery without HWC, once a gateway read API with verifiable records exists; must not invent a second catalogue.

## Prompts for follow-up agents

### Agent 1 — call_remote over H2HC (HWC + h2hc-linker)
> Implement standard Holochain `call_remote` for HWC browser agents through the
> authenticated h2hc-linker, as specified in `holochain-music/docs/web/grants.md`
> ("Interoperability proposal"). Base: HWC `0c391226…` with Imposter's
> browser-alpha patches and `holochain-music/web/hwc/apply_multi_cell_routing.py`;
> gateway source `9f5eb04b…` (Imposter archive). Outgoing: HWC signs
> `ZomeCallParams` with Lair; the gateway sends `CallRemoteReq` and returns the
> response. Incoming: the gateway forwards `CallRemoteReq` for registered
> browser agents; HWC verifies signature, nonce/expiry (replay store), local
> target cell and an existing `Listed` capability grant before running the zome
> with the caller's provenance. Add admission capabilities `call_remote_send` /
> `call_remote_receive`. Do not change any Music DNA, schema or grant format.
> Acceptance: `holochain-music/web/integration/run_interop.py` check E1 turns
> PASS, plus a new check where the native artist approves via
> `MusicApp.artist.grant()` and the browser imports the grant with
> "Check for grants"; forged/replayed/expired/ungranted calls refused; Imposter
> role-delivery CI unchanged.

### Agent 2 — record verification in HWC
> In Holo Web Conductor, verify every record/link returned by the gateway for
> `get`, `get_details`, `get_links`, `must_get_*` before handing it to WASM:
> action signature by its author, action hash, entry hash, and link-create
> action signature. Reject and log mismatches. Add tests with a deliberately
> malicious linker response. Then add a Music interop check that a tampered
> gateway response does not reach the catalogue view.

### Agent 3 — end-to-end private grant (after Agent 1)
> In `holochain-music/web`, wire the access-request button and "Check for
> grants" to the now-working transport, add periodic inbox sync, show request
> states (sent / approved / declined-unknown), and extend
> `browser_listener.mjs` with: request → native approval → grant delivered on
> the listener's chain → verify → play; a second browser identity cannot use
> it; duplicate delivery is idempotent. Remove the out-of-band import from the
> default UI (keep it behind diagnostics). Record Checkpoint E and attempt F
> from the documented setup only.

### Agent 4 — deployment rehearsal (operator, no public release)
> Following `holochain-music/docs/web/setup.md`, stand up a private HTTPS
> deployment on two machines: static site, TLS gateway with admission, TLS
> media adapter on the hosts' LAN, two native Music authorities. Record the
> preflight, a fresh-profile listener run and revocation. Do not publish
> publicly; do not commit operator secrets.

### Agent 5 — experience and PWA
> Improve the web UI without changing trust logic: album pages, artwork via the
> adapter with manifest verification, queue persistence in IndexedDB (no key
> material), keyboard and screen-reader pass, responsive checks at 360/768/1280
> px with Playwright screenshots, a static-asset-only service worker. Do not
> cache audio, grants or keys in Cache Storage.
