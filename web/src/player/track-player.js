// Streaming player for one authorised Music track.
//
// For each chunk: fetch ciphertext (untrusted adapter) -> verify length and
// SHA-256 against the artist-signed manifest -> AES-GCM decrypt with the
// file/index-bound AAD -> PCM16 -> Float32 -> AudioWorklet. No PCM is
// produced before the manifest, grant and that chunk's tag all verify.
// Memory is bounded: decoding pauses while more than `aheadSeconds` of audio
// is queued, and at most `prefetch` ciphertext chunks are in flight.

import { decryptChunk } from '../security/v1.js';
import { WAV_HEADER_BYTES, parseWavHeader, pcm16ToPlanar } from './wav.js';

export const PlayerState = Object.freeze({
  IDLE: 'idle', LOADING: 'loading', PLAYING: 'playing', PAUSED: 'paused', BUFFERING: 'buffering',
  ENDED: 'ended', STOPPED: 'stopped', ERROR: 'error',
});

const delay = ms => new Promise(r => setTimeout(r, ms));

export class TrackPlayer extends EventTarget {
  /**
   * @param {object} opts
   * @param {object} opts.trusted   catalogue.resolve() result
   * @param {CryptoKey} opts.contentKey non-extractable AES-GCM key from a verified grant
   * @param {object} opts.media     MediaAdapterClient
   * @param {string} opts.workletUrl URL of pcm-worklet.js
   */
  constructor({ trusted, contentKey, media, workletUrl, aheadSeconds = 6, prefetch = 2, maxRetries = 8, onChunk = null }) {
    super();
    Object.assign(this, { trusted, contentKey, media, workletUrl, aheadSeconds, prefetch, maxRetries, onChunk });
    this.body = trusted.manifestBody;
    this.state = PlayerState.IDLE;
    this.format = null;
    this.generation = 0;
    this.startFrame = 0;
    this.playedFrames = 0;
    this.queuedFrames = 0;
    this.volume = 1;
    this.stats = { chunks_verified: 0, underruns: 0, retries: 0, seeks: 0, frames_sent: 0, frames_played: 0 };
    this._abort = null;
    this._cache = new Map(); // index -> Promise<Uint8Array ciphertext>
  }

  _set(state, error = null) {
    this.state = state;
    this.error = error;
    this.dispatchEvent(new CustomEvent('state', { detail: { state, error } }));
  }

  get positionFrames() { return this.startFrame + this.playedFrames; }
  get durationFrames() { return this.format?.frames ?? 0; }

  /** Must be called from a user gesture (browser autoplay policy). */
  async start(startFrame = 0) {
    this._set(PlayerState.LOADING);
    try {
      const head = await this._plain(0);
      this.format = parseWavHeader(head.subarray(0, WAV_HEADER_BYTES), this.body.total_plain_bytes);
      if (!this.ctx || this.ctx.sampleRate !== this.format.sampleRate) {
        await this.ctx?.close();
        this.ctx = new AudioContext({ sampleRate: this.format.sampleRate, latencyHint: 'playback' });
        await this.ctx.audioWorklet.addModule(this.workletUrl);
        this.node = new AudioWorkletNode(this.ctx, 'music-pcm', { numberOfInputs: 0, outputChannelCount: [this.format.channels] });
        this.gain = new GainNode(this.ctx, { gain: this.volume });
        this.node.connect(this.gain).connect(this.ctx.destination);
        this.node.port.onmessage = ({ data }) => this._onWorklet(data);
      }
      await this.ctx.resume();
      this._run(Math.max(0, Math.min(startFrame, this.format.frames - 1)));
    } catch (e) {
      this._set(PlayerState.ERROR, e.message);
      throw e;
    }
  }

  _onWorklet(data) {
    if (data.generation !== this.generation) return;
    if (data.type === 'position') {
      this.playedFrames = data.played;
      this.queuedFrames = data.queued;
      this.stats.frames_played = this.positionFrames;
      this.dispatchEvent(new CustomEvent('position', { detail: { frame: this.positionFrames } }));
    } else if (data.type === 'underrun' && this.state === PlayerState.PLAYING) {
      this.stats.underruns++;
      this._set(PlayerState.BUFFERING);
    } else if (data.type === 'resumed' && this.state === PlayerState.BUFFERING) {
      this._set(PlayerState.PLAYING);
    } else if (data.type === 'drained') {
      this.playedFrames = data.played;
      this.stats.frames_played = this.positionFrames;
      this._set(PlayerState.ENDED);
    }
  }

  /** Ciphertext with bounded retry; verification happens in _plain(). */
  _ciphertext(index, signal) {
    if (!this._cache.has(index)) {
      const host = this.trusted.hosts[0];
      const p = (async () => {
        for (let attempt = 0; ; attempt++) {
          try {
            return await this.media.chunk(host, this.body.file_id, this.trusted.digest, this.trusted.artistKeyHex, index, { signal });
          } catch (e) {
            if (signal?.aborted || attempt >= this.maxRetries || e.retryable === false) throw e;
            this.stats.retries++;
            if (this.state === PlayerState.PLAYING) this._set(PlayerState.BUFFERING);
            await delay(Math.min(5000, 400 * 2 ** attempt));
          }
        }
      })();
      p.catch(() => this._cache.delete(index));
      this._cache.set(index, p);
    }
    return this._cache.get(index);
  }

  async _plain(index, signal) {
    const data = await this._ciphertext(index, signal);
    const plain = await decryptChunk(this.contentKey, this.body, index, data);
    this._cache.delete(index); // ciphertext no longer needed
    this.stats.chunks_verified++;
    if (this.onChunk) await this.onChunk(index, plain);
    return plain;
  }

  async _run(startFrame) {
    this._abort?.abort();
    const abort = new AbortController();
    this._abort = abort;
    const generation = ++this.generation;
    this.startFrame = startFrame;
    this.playedFrames = 0;
    this.queuedFrames = 0;
    this.node.port.postMessage({ type: 'reset', generation });
    this.node.port.postMessage({ type: 'pause', paused: false });
    this._set(PlayerState.BUFFERING);
    const { blockAlign, channels, sampleRate } = this.format;
    const size = this.body.chunk_size;
    let byte = WAV_HEADER_BYTES + startFrame * blockAlign;
    const last = this.body.chunks.length - 1;
    let carry = new Uint8Array(0);
    let sent = 0; // frames posted in this generation
    try {
      for (let index = Math.floor(byte / size); index <= last; index++) {
        if (abort.signal.aborted) return;
        for (let k = 1; k <= this.prefetch && index + k <= last; k++) this._ciphertext(index + k, abort.signal).catch(() => {});
        let plain = await this._plain(index, abort.signal);
        if (abort.signal.aborted) return;
        const from = Math.max(0, byte - index * size);
        plain = plain.subarray(index === 0 ? Math.max(from, WAV_HEADER_BYTES) : from);
        byte = (index + 1) * size;
        let pcm = carry.length ? concat(carry, plain) : plain;
        const usable = pcm.length - (pcm.length % blockAlign);
        carry = pcm.slice(usable);
        const planar = pcm16ToPlanar(pcm.subarray(0, usable), channels);
        if (pcm !== plain) pcm.fill(0); // minimise plaintext lifetime
        this.node.port.postMessage({ type: 'pcm', generation, channels: planar }, planar.map(a => a.buffer));
        sent += usable / blockAlign;
        this.stats.frames_sent += usable / blockAlign;
        if (this.state === PlayerState.BUFFERING) this._set(PlayerState.PLAYING);
        // Bounded look-ahead: never hold more than `aheadSeconds` of plaintext.
        while (!abort.signal.aborted && sent - this.playedFrames > this.aheadSeconds * sampleRate) await delay(100);
      }
      if (!abort.signal.aborted) this.node.port.postMessage({ type: 'end', generation });
    } catch (e) {
      if (!abort.signal.aborted) this._set(PlayerState.ERROR, e.message);
    }
  }

  pause() {
    if (this.state !== PlayerState.PLAYING && this.state !== PlayerState.BUFFERING) return;
    this.node?.port.postMessage({ type: 'pause', paused: true });
    this.ctx?.suspend();
    this._set(PlayerState.PAUSED);
  }

  async resume() {
    if (this.state !== PlayerState.PAUSED) return;
    await this.ctx?.resume();
    this.node?.port.postMessage({ type: 'pause', paused: false });
    this._set(PlayerState.PLAYING);
  }

  async seek(frame) {
    if (!this.format) return;
    this.stats.seeks++;
    await this.ctx?.resume();
    this._run(Math.max(0, Math.min(Math.floor(frame), this.format.frames - 1)));
  }

  setVolume(v) {
    this.volume = Math.max(0, Math.min(1, v));
    if (this.gain) this.gain.gain.value = this.volume;
  }

  async stop() {
    this._abort?.abort();
    this.generation++;
    this.node?.port.postMessage({ type: 'reset', generation: this.generation });
    this._cache.clear();
    await this.ctx?.close().catch(() => {});
    this.ctx = null;
    this.node = null;
    this._set(PlayerState.STOPPED);
  }
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
