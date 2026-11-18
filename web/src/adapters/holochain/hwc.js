// Holo Web Conductor (HWC) connection for Holochain Music.
//
// The browser's Holochain identity, source chain, WASM execution and signing
// live in the HWC extension (Lair keys never reach this page). This module
// only drives HWC's page API (`window.holochain`) and reports *checked* states:
// it never shows "ready" unless every check below has actually passed.

import { holoHashB64, holoHashBytes } from '../../security/bytes.js';

export const State = Object.freeze({
  CHECKING: 'checking',
  EXTENSION_UNAVAILABLE: 'extension-unavailable',
  AUTHORISATION_REQUIRED: 'authorisation-required',
  NOT_INSTALLED: 'not-installed',
  INSTALLING: 'installing',
  WRONG_DNA: 'wrong-dna',
  GATEWAY_DISCONNECTED: 'gateway-disconnected',
  ADMISSION_PENDING: 'admission-pending',
  SYNCHRONISING: 'synchronising',
  READY: 'ready',
  ERROR: 'error',
});

export const STATE_TEXT = {
  [State.CHECKING]: 'Checking for Holo Web Conductor…',
  [State.EXTENSION_UNAVAILABLE]: 'Holo Web Conductor is not available in this browser profile.',
  [State.AUTHORISATION_REQUIRED]: 'Approve this site in the Holo Web Conductor window to continue.',
  [State.NOT_INSTALLED]: 'Holochain Music is not installed in this browser yet.',
  [State.INSTALLING]: 'Verifying and installing Holochain Music…',
  [State.WRONG_DNA]: 'This browser has a different Holochain Music installation. It will not be used.',
  [State.GATEWAY_DISCONNECTED]: 'Not connected to the Holochain gateway.',
  [State.ADMISSION_PENDING]: 'Connected to the gateway, but this identity has not been admitted yet.',
  [State.SYNCHRONISING]: 'Connected and authenticated. Reaching the Music network…',
  [State.READY]: 'Connected to the Holochain Music network.',
  [State.ERROR]: 'Something went wrong.',
};

const delay = ms => new Promise(r => setTimeout(r, ms));

export class HolochainUnavailable extends Error {}

export class MusicHolochain extends EventTarget {
  /** @param {object} config validated deployment config (see config.js) */
  constructor(config, { hc = () => globalThis.window?.holochain } = {}) {
    super();
    this.config = config;
    this._hc = hc;
    this.state = State.CHECKING;
    this.detail = '';
    this.agent = null;
    this.cells = null; // { role: { dna, agent, cellId } }
    this.gateway = null;
    this._watch = null;
  }

  get hc() { return this._hc(); }

  _set(state, detail = '') {
    const changed = state !== this.state || detail !== this.detail;
    this.state = state;
    this.detail = detail;
    if (changed) this.dispatchEvent(new CustomEvent('state', { detail: { state, detail } }));
  }

  /** Wait briefly for the extension's injected API (document_start content script). */
  async detect(timeoutMs = 4000) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      if (this.hc?.isWebConductor) return true;
      await delay(100);
    }
    this._set(State.EXTENSION_UNAVAILABLE);
    return false;
  }

  /** Full connection sequence. Safe to call again for "Reconnect". */
  async connect({ install = true } = {}) {
    try {
      this._set(State.CHECKING);
      if (!globalThis.isSecureContext) throw new HolochainUnavailable('Open Holochain Music from an HTTPS (or localhost) address.');
      if (!await this.detect()) return this.state;
      await this.authorise();
      if (!await this.ensureInstalled(install)) return this.state;
      this.verifyCells(await this.hc.appInfo(this.config.app_id));
      await this.connectGateway();
      if (this.state === State.SYNCHRONISING) await this.probeNetwork();
      this.watch();
    } catch (e) {
      if (this.state === State.CHECKING || this.state === State.INSTALLING) this._set(State.ERROR, e.message);
      else if (![State.WRONG_DNA, State.AUTHORISATION_REQUIRED, State.ADMISSION_PENDING, State.GATEWAY_DISCONNECTED].includes(this.state)) {
        this._set(State.ERROR, e.message);
      }
    }
    return this.state;
  }

  async authorise() {
    this._set(State.AUTHORISATION_REQUIRED);
    try {
      await this.hc.connect(); // opens HWC's own approval window for a new origin
    } catch (e) {
      throw new HolochainUnavailable(`Holo Web Conductor did not authorise this site: ${e.message}`);
    }
    const key = this.hc.myPubKey;
    if (!key) throw new HolochainUnavailable('Holo Web Conductor returned no identity.');
    this.agent = holoHashB64(key);
    this._set(State.CHECKING);
  }

  async appInfo() {
    try {
      return await this.hc.appInfo(this.config.app_id);
    } catch (e) {
      if (/No hApp installed/i.test(e.message)) return null;
      throw e;
    }
  }

  /** Install the exact configured hApp bytes (SHA-256 checked) if absent. */
  async ensureInstalled(install) {
    const info = await this.appInfo();
    if (info) return true;
    if (!install) {
      this._set(State.NOT_INSTALLED);
      return false;
    }
    this._set(State.INSTALLING);
    const response = await fetch(this.config.happ_url, { cache: 'no-store', redirect: 'error' });
    if (!response.ok) throw new HolochainUnavailable('The Holochain Music hApp could not be downloaded.');
    const bundle = new Uint8Array(await response.arrayBuffer());
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bundle)), b => b.toString(16).padStart(2, '0')).join('');
    if (digest !== this.config.happ_sha256) throw new HolochainUnavailable('The downloaded hApp does not match this release (SHA-256 mismatch).');
    await this.hc.installApp({ bundle, installedAppId: this.config.app_id });
    return true;
  }

  /** Every configured role must exist with the exact DNA hash and our agent. */
  verifyCells(info) {
    if (!info || info.status !== 'enabled' && info.enabled !== true) {
      this._set(State.WRONG_DNA, 'The installed hApp is disabled.');
      throw new HolochainUnavailable('hApp disabled');
    }
    const expected = this.config.roles;
    const cells = {};
    const seen = (info.cells || []).map(([dna, agent]) => ({ dna: holoHashB64(dna), agent: holoHashB64(agent) }));
    for (const [role, dna] of Object.entries(expected)) {
      const match = seen.filter(c => c.dna === dna);
      if (match.length !== 1) {
        this._set(State.WRONG_DNA, `Missing or unexpected DNA for role ${role}.`);
        throw new HolochainUnavailable('wrong DNA');
      }
      if (match[0].agent !== this.agent) {
        this._set(State.WRONG_DNA, `Cell for role ${role} belongs to a different identity.`);
        throw new HolochainUnavailable('wrong agent');
      }
      cells[role] = { dna, agent: match[0].agent, cellId: [holoHashBytes(dna), holoHashBytes(match[0].agent)] };
    }
    if (seen.length !== Object.keys(expected).length) {
      this._set(State.WRONG_DNA, 'The installed hApp has unexpected extra cells.');
      throw new HolochainUnavailable('extra cells');
    }
    this.cells = cells;
  }

  async connectGateway(timeoutMs = 20000) {
    const url = this.config.gateway_url;
    this._set(State.GATEWAY_DISCONNECTED, 'Connecting…');
    await this.hc.configureNetwork({ linkerUrl: url });
    const end = Date.now() + timeoutMs;
    let reachable = false;
    while (Date.now() < end) {
      const status = await this.gatewayStatus();
      reachable ||= status.reachable;
      if (status.authenticated) {
        this._set(State.SYNCHRONISING);
        return;
      }
      await delay(300);
    }
    if (reachable) this._set(State.ADMISSION_PENDING, 'Ask the operator to admit your public identity, then reconnect.');
    else this._set(State.GATEWAY_DISCONNECTED, 'The gateway is unreachable.');
  }

  async gatewayStatus() {
    const url = this.config.gateway_url;
    const c = await this.hc.getConnectionStatus();
    const n = await this.hc.getNetworkStatus();
    const expected = c?.linkerUrl === url && n?.linkerUrl === url;
    this.gateway = { url, ...c, hasSession: Boolean(n?.hasSession) };
    return {
      reachable: expected && Boolean(c.httpHealthy || c.wsHealthy),
      authenticated: expected && Boolean(c.authenticated && c.wsHealthy && n.hasSession),
    };
  }

  /** A real round trip through HWC -> gateway -> DHT authorities. */
  async probeNetwork() {
    try {
      await this.call('music_catalogue', 'list_artists', null);
      this._set(State.READY);
    } catch (e) {
      this._set(State.SYNCHRONISING, e.message);
    }
  }

  /** Keep the displayed state honest; recover from ordinary disconnects. */
  watch(intervalMs = 5000) {
    clearInterval(this._watch);
    this._watch = setInterval(async () => {
      try {
        const s = await this.gatewayStatus();
        if (!s.authenticated && (this.state === State.READY || this.state === State.SYNCHRONISING)) {
          this._set(State.GATEWAY_DISCONNECTED, 'Connection lost; reconnecting…');
          await this.connectGateway(15000).catch(() => {});
          if (this.state === State.SYNCHRONISING) await this.probeNetwork();
        } else if (s.authenticated && this.state === State.SYNCHRONISING) {
          await this.probeNetwork();
        }
      } catch {
        // Extension restarting; next tick retries.
      }
    }, intervalMs);
  }

  stop() { clearInterval(this._watch); }

  /** Zome call routed to the named role's verified cell. */
  async call(role, fn, payload) {
    const cell = this.cells?.[role];
    if (!cell) throw new HolochainUnavailable(`role ${role} is not verified`);
    return this.hc.callZome({ role_name: role, cell_id: cell.cellId, zome_name: role, fn_name: fn, payload });
  }
}
