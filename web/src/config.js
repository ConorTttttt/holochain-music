// Deployment configuration (public values only). Served as /web-config.json
// by the operator; validated strictly so a typo cannot silently weaken the
// expected DNA identity, the hApp digest or the endpoints the page talks to.

const HASH = /^uhC0k[A-Za-z0-9_-]{48}$/;
const SHA = /^[0-9a-f]{64}$/;

export class ConfigError extends Error {}

function origin(value, label, { allowHttpLoopback }) {
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new ConfigError(`${label} must be a URL`);
  }
  const loopback = ['localhost', '127.0.0.1'].includes(u.hostname);
  if (u.origin !== value || !(u.protocol === 'https:' || (allowHttpLoopback && loopback && u.protocol === 'http:'))) {
    throw new ConfigError(`${label} must be an https origin (http only for localhost development)`);
  }
  return value;
}

export function validateConfig(raw, { pageOrigin = globalThis.location?.origin } = {}) {
  if (!raw || typeof raw !== 'object') throw new ConfigError('missing web-config.json');
  const allowHttpLoopback = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(pageOrigin ?? '');
  const roles = raw.roles ?? {};
  if (!HASH.test(roles.music_catalogue ?? '') || !HASH.test(roles.music_storage ?? '') || Object.keys(roles).length !== 2) {
    throw new ConfigError('roles must pin exactly music_catalogue and music_storage DNA hashes');
  }
  if (!SHA.test(raw.happ_sha256 ?? '')) throw new ConfigError('happ_sha256 must be a SHA-256 hex digest');
  if (typeof raw.app_id !== 'string' || !/^[a-z0-9-]{3,64}$/.test(raw.app_id)) throw new ConfigError('invalid app_id');
  if (typeof raw.happ_url !== 'string' || !raw.happ_url.startsWith('/')) throw new ConfigError('happ_url must be same-origin');
  return Object.freeze({
    app_id: raw.app_id,
    happ_url: raw.happ_url,
    happ_sha256: raw.happ_sha256,
    roles: Object.freeze({ music_catalogue: roles.music_catalogue, music_storage: roles.music_storage }),
    gateway_url: origin(raw.gateway_url, 'gateway_url', { allowHttpLoopback }),
    media_adapter_url: origin(raw.media_adapter_url, 'media_adapter_url', { allowHttpLoopback }),
    allow_lan_hosts: raw.allow_lan_hosts === true,
    release: typeof raw.release === 'string' ? raw.release.slice(0, 80) : 'development',
  });
}

export async function loadConfig(url = '/web-config.json') {
  const res = await fetch(url, { cache: 'no-store', redirect: 'error' });
  if (!res.ok) throw new ConfigError('web-config.json could not be loaded');
  return validateConfig(await res.json());
}
