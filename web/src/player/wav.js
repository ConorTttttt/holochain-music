// Canonical RIFF/WAVE PCM16 header, exactly the rules of
// music_catalogue/granted_audio.py (the only format Music v1 publishes).

export const WAV_HEADER_BYTES = 44;
const RATES = new Set([8000, 11025, 16000, 22050, 32000, 44100, 48000]);

export class WavError extends Error {}

export function parseWavHeader(bytes, totalPlainBytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < WAV_HEADER_BYTES) throw new WavError('truncated WAV header');
  const v = new DataView(bytes.buffer, bytes.byteOffset, WAV_HEADER_BYTES);
  const tag = o => String.fromCharCode(bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]);
  const riffLen = v.getUint32(4, true);
  const fmtLen = v.getUint32(16, true);
  const format = v.getUint16(20, true);
  const channels = v.getUint16(22, true);
  const rate = v.getUint32(24, true);
  const byteRate = v.getUint32(28, true);
  const blockAlign = v.getUint16(32, true);
  const bits = v.getUint16(34, true);
  const dataLen = v.getUint32(40, true);
  if (tag(0) !== 'RIFF' || tag(8) !== 'WAVE' || tag(12) !== 'fmt ' || fmtLen !== 16 || format !== 1
      || (channels !== 1 && channels !== 2) || bits !== 16 || !RATES.has(rate)
      || byteRate !== rate * channels * 2 || blockAlign !== channels * 2 || tag(36) !== 'data'
      || riffLen + 8 !== totalPlainBytes || dataLen + WAV_HEADER_BYTES !== totalPlainBytes || dataLen % blockAlign !== 0) {
    throw new WavError('only canonical bounded RIFF/WAVE PCM16 audio is supported');
  }
  return { sampleRate: rate, channels, blockAlign, dataBytes: dataLen, frames: dataLen / blockAlign };
}

/** Interleaved little-endian PCM16 -> planar Float32 (one array per channel). */
export function pcm16ToPlanar(bytes, channels) {
  const frames = Math.floor(bytes.length / (2 * channels));
  const view = new DataView(bytes.buffer, bytes.byteOffset, frames * 2 * channels);
  const out = Array.from({ length: channels }, () => new Float32Array(frames));
  for (let f = 0; f < frames; f++) {
    for (let c = 0; c < channels; c++) out[c][f] = view.getInt16((f * channels + c) * 2, true) / 32768;
  }
  return out;
}
