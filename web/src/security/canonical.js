// Byte-exact port of holochain_storage.package.canonical():
//   json.dumps(obj, sort_keys=True, separators=(",", ":"),
//              ensure_ascii=False, allow_nan=False).encode("utf-8")
//
// Only the value shapes used by the Music v1 schemas are accepted: objects,
// arrays, strings, safe integers, booleans and null. Anything else (floats,
// lone surrogates, non-plain objects) fails closed rather than risking a
// serialisation that differs from Python.

const encoder = new TextEncoder();

export class CanonicalError extends Error {}

function compareCodePoints(a, b) {
  // Python sorts str keys by Unicode code point; JS sorts by UTF-16 unit.
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done === y.done ? 0 : x.done ? -1 : 1;
    const cx = x.value.codePointAt(0);
    const cy = y.value.codePointAt(0);
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

function assertWellFormed(text) {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new CanonicalError('lone surrogate');
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new CanonicalError('lone surrogate');
    }
  }
}

function encodeString(text) {
  assertWellFormed(text);
  // For well-formed strings JSON.stringify escapes exactly the set Python
  // escapes with ensure_ascii=False: '"', '\\', \b \f \n \r \t and other
  // C0 controls as lowercase \u00xx. Neither escapes '/', DEL or U+2028.
  return JSON.stringify(text);
}

function encode(value, depth) {
  if (depth > 64) throw new CanonicalError('nesting too deep');
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return encodeString(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CanonicalError('only safe integers are canonical');
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (Array.isArray(value)) return '[' + value.map(v => encode(v, depth + 1)).join(',') + ']';
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort(compareCodePoints);
    return '{' + keys.map(k => encodeString(k) + ':' + encode(value[k], depth + 1)).join(',') + '}';
  }
  throw new CanonicalError(`unsupported canonical value: ${typeof value}`);
}

export function canonicalString(value) {
  return encode(value, 0);
}

export function canonical(value) {
  return encoder.encode(canonicalString(value));
}

/** JSON.parse that rejects duplicate keys is not available natively; Music
 * documents are produced by Python json.dumps, which never emits them. We
 * re-canonicalise every parsed document before hashing, so a duplicate key
 * can only change the digest (and therefore fail the Holochain pin). */
export function parseJson(bytesOrText, maxBytes) {
  const text = typeof bytesOrText === 'string' ? bytesOrText : new TextDecoder('utf-8', { fatal: true }).decode(bytesOrText);
  if (maxBytes !== undefined && encoder.encode(text).length > maxBytes) throw new CanonicalError('document too large');
  return JSON.parse(text);
}
