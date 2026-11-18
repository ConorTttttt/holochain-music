// AudioWorklet: bounded queue of authenticated, decrypted PCM blocks.
// Receives planar Float32 blocks (transferred, not copied), plays them in
// order, and reports position, underruns and end-of-track. A `generation`
// number lets seek/stop discard any block queued for an older position.

class MusicPcmProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.queue = [];
    this.offset = 0;
    this.generation = 0;
    this.played = 0; // frames rendered in this generation
    this.queued = 0; // frames waiting
    this.ended = false;
    this.paused = false;
    this.starved = false;
    this.lastReport = 0;
    this.port.onmessage = ({ data }) => {
      if (data.type === 'pcm') {
        if (data.generation !== this.generation) return;
        this.queue.push(data.channels);
        this.queued += data.channels[0].length;
      } else if (data.type === 'reset') {
        this.generation = data.generation;
        this.queue = [];
        this.offset = 0;
        this.played = 0;
        this.queued = 0;
        this.ended = false;
        this.starved = false;
      } else if (data.type === 'end') {
        if (data.generation === this.generation) this.ended = true;
      } else if (data.type === 'pause') {
        this.paused = data.paused;
      }
    };
  }

  process(_inputs, outputs) {
    const out = outputs[0];
    const frames = out[0].length;
    let written = 0;
    if (!this.paused) {
      while (written < frames && this.queue.length) {
        const block = this.queue[0];
        const n = Math.min(frames - written, block[0].length - this.offset);
        for (let c = 0; c < out.length; c++) {
          const src = block[Math.min(c, block.length - 1)];
          out[c].set(src.subarray(this.offset, this.offset + n), written);
        }
        written += n;
        this.offset += n;
        if (this.offset >= block[0].length) {
          this.queue.shift();
          this.offset = 0;
        }
      }
      this.played += written;
      this.queued -= written;
      if (written < frames && !this.ended && !this.starved) {
        this.starved = true;
        this.port.postMessage({ type: 'underrun', generation: this.generation, played: this.played });
      } else if (written === frames && this.starved) {
        this.starved = false;
        this.port.postMessage({ type: 'resumed', generation: this.generation });
      }
      if (this.ended && !this.queue.length) {
        this.ended = false;
        this.port.postMessage({ type: 'drained', generation: this.generation, played: this.played });
      }
    }
    for (let c = 0; c < out.length; c++) out[c].fill(0, written);
    if (currentTime - this.lastReport > 0.1) {
      this.lastReport = currentTime;
      this.port.postMessage({ type: 'position', generation: this.generation, played: this.played, queued: this.queued });
    }
    return true;
  }
}

registerProcessor('music-pcm', MusicPcmProcessor);
