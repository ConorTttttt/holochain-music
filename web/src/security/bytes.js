// Strict encoders matching the Python v1 helpers (holochain_storage.package).

export class EncodingError extends Error {}

const HEX = /^[0-9a-f]*$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function toHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Lowercase hex only, like the DNA's `is_hex32` and Python's _HEX checks. */
export function fromHex(text, size) {
  if (typeof text !== 'string' || text.length % 2 !== 0 || !HEX.test(text)) throw new EncodingError('invalid hex field');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  if (size !== undefined && out.length !== size) throw new EncodingError('invalid hex field length');
  return out;
}

export function isHex(text, digits) {
  return typeof text === 'string' && text.length === digits && HEX.test(text);
}

/** base64.b64decode(text, validate=True) with an optional exact length. */
export function fromB64(text, size) {
  if (typeof text !== 'string' || !B64.test(text)) throw new EncodingError('invalid base64 field');
  let binary;
  try {
    binary = atob(text);
  } catch {
    throw new EncodingError('invalid base64 field');
  }
  const out = Uint8Array.from(binary, c => c.charCodeAt(0));
  if (size !== undefined && out.length !== size) throw new EncodingError('invalid encoded field length');
  return out;
}

export function toB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function u64be(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new EncodingError('invalid u64');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

/** Holochain HoloHash (39 bytes) -> "u" + URL-safe base64 without padding. */
export function holoHashB64(value) {
  const bytes = value instanceof Uint8Array ? value
    : Array.isArray(value) ? Uint8Array.from(value)
      : value && typeof value === 'object' ? Uint8Array.from(Object.values(value)) : null;
  if (!bytes || bytes.length !== 39) throw new EncodingError('invalid Holochain hash');
  return 'u' + toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function holoHashBytes(text) {
  if (typeof text !== 'string' || !/^u[A-Za-z0-9_-]{52}$/.test(text)) throw new EncodingError('invalid Holochain hash');
  const b64 = text.slice(1).replace(/-/g, '+').replace(/_/g, '/');
  const out = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  if (out.length !== 39) throw new EncodingError('invalid Holochain hash');
  return out;
}
