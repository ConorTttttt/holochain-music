# Roadmap and follow-up work

Ordered by dependency. Priorities 1–4 of the brief are working with real
components; priority 5 (private grants) is blocked on transport; 6 depends on 5.

1. **H2HC/HWC `call_remote` relay** (unblocks Checkpoints E and F) — design, native semantics and the tested HWC-side authoriser in [call-remote.md](call-remote.md). **This is the next dependency.**
2. **Signed links from the gateway** — record verification is done in HWC ([patch](../../web/hwc/record-verification/README.md)); link authorship still needs h2hc-linker to return signed `CreateLink` actions.
3. **Deployment rehearsal** — HTTPS site, TLS gateway and adapter, two native authorities, operator admission, two physical machines.
4. **Experience** — albums view polish, artwork over the adapter (`artwork_manifest_sha256` is already in records), queue persistence, playlists, offline encrypted storage (OPFS) with a tested disconnected-playback gate, service worker for static assets only.
5. **Guest mode** — read-only discovery without HWC, once a gateway read API with verifiable records exists; must not invent a second catalogue.

## Prompts for follow-up agents

### Agent 1 — call_remote over H2HC (h2hc-linker + HWC runtime)
> Implement standard Holochain `call_remote` for HWC browser agents exactly as
> specified in `holochain-music/docs/web/call-remote.md` ("Remaining work",
> steps 1–5). Start from the accepted gateway source (`9f5eb04b…`, built by
> Imposter's recipe at `293563649f…`) and HWC `0c391226…` with Imposter's
> patches plus `holochain-music/web/hwc/*` patches. Reuse
> `web/hwc/remote-call/remote-call-auth.ts` (native-vector tested) for the
> incoming path with a persistent nonce witness; fix HWC's ZomeCallParams
> signing to SHA-512. Gateway: `call_remote_send` / `call_remote_receive`
> admission capabilities, provenance must equal the authenticated session
> agent, `CallRemoteReq`/`CallRemoteRes` correlation with timeouts and bounds.
> Do not change any Music DNA, schema or grant format; keep Imposter's
> role-delivery and security tests passing. Acceptance: interop check E1
> PASS plus the native-approval → browser-grant → playback checks listed in
> step 6.

### Agent 2 — signed links from the gateway
> In h2hc-linker, return the signed `CreateLink` actions (or the `WireLinkOps`
> they come from) for `/dht/{dna}/links`, keeping the current `Vec<Link>`
> response available for old clients. In HWC, the record-verification patch
> already authenticates links that carry `signature`, `prev_action` and
> `action_seq`; switch the worker to the signed format and make unsigned
> links fail closed. Extend interop check M1 with an injected-link attack.

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
