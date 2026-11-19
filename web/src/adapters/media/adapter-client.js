// Client for the ciphertext-only web media adapter (web/adapter/media_adapter.py).
//
// The adapter is UNTRUSTED for integrity: everything it returns is verified
// by the caller (manifest digest + artist signature, chunk SHA-256 + AES-GCM).
// It never receives grants, keys or plaintext; requests carry only public
// values the browser read from Holochain (host URL, TLS pin, manifest pin,
// artist public key).

import { parseJson } from '../../security/canonical.js';
import { MAX_MANIFEST_BYTES, MAX_RECEIPT_BYTES } from '../../security/v1.js';

export class MediaUnavailable extends Error {
  constructor(message, { retryable = true, status = 0 } = {}) {
    super(message);
    this.retryable = retryable;
    this.status = status;
  }
}

const delay = (ms, signal) => new Promise((resolve, reject) => {
  const t = setTimeout(resolve, ms);
  signal?.addEventListener('abort', () => { clearTimeout(t); reject(signal.reason ?? new Error('aborted')); }, { once: true });
});

export class MediaAdapterClient {
  constructor(baseUrl, { fetchImpl = globalThis.fetch.bind(globalThis), attempts = 4 } = {}) {
    const u = new URL(baseUrl);
    if (u.pathname !== '/' || u.search || u.hash) throw new Error('media adapter URL must be an origin');
    this.base = u.origin;
    this.fetch = fetchImpl;
    this.attempts = attempts;
  }

  async _get(path, params, { signal, maxBytes } = {}) {
    const url = `${this.base}${path}?${new URLSearchParams(params)}`;
    let last;
    for (let attempt = 0; attempt < this.attempts; attempt++) {
      try {
        const res = await this.fetch(url, { signal, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
        if (res.ok) {
          const len = Number(res.headers.get('content-length') ?? 0);
          if (maxBytes && len > maxBytes) throw new MediaUnavailable('adapter response too large', { retryable: false });
          const body = new Uint8Array(await res.arrayBuffer());
          if (maxBytes && body.length > maxBytes) throw new MediaUnavailable('adapter response too large', { retryable: false });
          return body;
        }
        let message = `media adapter HTTP ${res.status}`;
        try { message = (await res.json()).error || message; } catch { /* not JSON */ }
        const retryable = res.status >= 500 || res.status === 429;
        last = new MediaUnavailable(message, { retryable, status: res.status });
        if (!retryable) throw last;
      } catch (e) {
        if (signal?.aborted) throw e;
        if (e instanceof MediaUnavailable && !e.retryable) throw e;
        last = e instanceof MediaUnavailable ? e : new MediaUnavailable(`media adapter unreachable: ${e.message}`);
      }
      await delay(Math.min(8000, 500 * 2 ** attempt), signal);
    }
    throw last;
  }

  /** UNTRUSTED public document from the host (verify before use). */
  async document(host, fileId, kind, { signal } = {}) {
    const max = kind === 'manifest' ? MAX_MANIFEST_BYTES : MAX_RECEIPT_BYTES;
    const bytes = await this._get(`/v1/files/${fileId}/${kind}`, { host: host.url, fp: host.fingerprint }, { signal, maxBytes: max });
    return parseJson(bytes, max);
  }

  /** UNTRUSTED ciphertext object (verify against the signed manifest). */
  async chunk(host, fileId, manifestSha256, artistKeyHex, index, { signal } = {}) {
    return this._get(`/v1/files/${fileId}/chunks/${index}`,
      { host: host.url, fp: host.fingerprint, manifest_sha256: manifestSha256, artist_key: artistKeyHex },
      { signal, maxBytes: 4 * 1024 * 1024 + 16 });
  }

  async health() {
    const res = await this.fetch(`${this.base}/healthz`, { cache: 'no-store', credentials: 'omit' });
    return res.ok ? res.json() : null;
  }
}
