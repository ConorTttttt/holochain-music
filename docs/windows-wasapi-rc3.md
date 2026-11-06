# Windows rc3 WASAPI audio quality investigation — 2026-11-06

Private candidate; physical Windows speaker verification is PENDING. The user
verified rc2 discovery, requests/grants, audible Realtek output and reliable
seeking/track switching, but reported crackling even with a fully downloaded
track offline. This rules out network delivery as a necessary cause. No user
identity, downloaded music or Ubuntu release candidate was modified.

## Evidence and limits of the diagnosis

The saved pre-edit rc2 pipeline is in `dist/rc3-validation/rc2-*.py` with raw
measurements alongside it. rc2's stream-owner/COM changes preserved the same
PCM dtype, channel count, sample rate, shared conversion, 200 ms ring and
40 ms latency request as rc1. The software pacing defect and callback hashing
also existed in rc1. Consequently we cannot attribute the hardware regression
to one rc2 change, or prove that the measured starvation explains every crackle.

The concrete defect reproduced here is two independent clocks. After a 250 ms
start burst, S11 wrote 4096 bytes and waited for that block's duration (23.220 ms
at 44.1 kHz stereo), including scheduling overhead, while the output callback
consumed according to the device clock. Every excess wait accumulated; the
initial ring was only temporary protection. Verification and software gain
also take time before the next write. For example, a 2 ms excess per block
reduces production to roughly 92% of device consumption, even with all data
already local and authenticated. No network change is needed to reproduce it.

`packaging/bench-wasapi-buffer.py` uses absolute 10 ms device deadlines and
adds 2 ms ONLY to the worker's software pacing wait. It is a Linux/Python
scheduling model, not PortAudio, Windows timer measurement or speaker evidence.

| 12 seconds of identical 44.1 kHz stereo PCM | Saved rc2 | rc3 |
|---|---:|---:|
| Queue underruns / callbacks padded during playback | 228 | 0 |
| Elapsed playback time | 12.902 s | 12.002 s |
| Callback maximum, measured around callback | 0.069 ms | 0.101 ms |
| Observed occupancy low / high | 0 / 35,280 B | 0 / 70,560 B |
| Ring capacity | 35,280 B | 70,560 B |
| Delivered PCM bytes | 2,116,800 | 2,116,800 |
| Delivered PCM SHA-256 matches source | yes | yes |

The unchanged digest in rc2 matters: hashing only delivered PCM did not reveal
silence inserted BETWEEN valid blocks. Both inserted silence and callback host
underflows must be measured. The low occupancy above includes startup/EOF.

A separate 180-second real-time model soak delivered 31,752,000 bytes with an
exact digest, zero queue underruns, zero starvation frames, zero rebuffer
silence frames and one stream start. It observed 18,002 callbacks, a maximum
callback duration of 0.089 ms and maximum interval of 18.662 ms. This also is a
modeled clock; host-underflow flags cannot be established without a real host.

## PCM format at every boundary

| Boundary | Format and operation |
|---|---|
| Signed/encrypted package -> WAV reader | Signed manifest, licence/recipient gate, ciphertext SHA-256 and AES-GCM authentication precede emission; canonical RIFF/WAVE PCM format 1 only |
| WAV reader -> FIFO | Signed 16-bit LITTLE-ENDIAN, mono or stereo, interleaved LRLR for stereo, declared 8–48 kHz rate; validates byte rate, block alignment, payload length and whole frames |
| Reader -> S11 worker | Up to 16 KiB split into <=4096-byte whole-frame blocks; no sample-rate or channel change |
| Volume -> output ring | Optional scalar signed-int16 gain outside callback; explicit little-endian handling, preserving channel order, byte count and sample rate |
| Ring -> RawOutputStream | Same interleaved PCM16 bytes; `dtype=int16`, track rate and channels; little-endian GIL-enabled CPython required (bundled Windows x64 runtime meets this) |
| PortAudio -> WASAPI shared engine | `exclusive=False, auto_convert=True`; Windows performs required rate conversion/channel mixing, including 44.1 kHz source into 48 kHz mix; PortAudio selects a supported working sample format |
| Shared engine -> Realtek | Actual mix/stream sample format and host buffer size require native logs and physical retest; no assumed 48 kHz or float format is reported as measured |

The exact 44.1/48 kHz tests compare signed stereo sentinel bytes through ring
wraps and arbitrary callback sizes; they verify the source-rate request and
shared conversion flag, not the signal fidelity of Windows' resampler.
The pinned sounddevice 0.5.6 DLL exports `PaWasapi_GetFramesPerHostBuffer`,
`PaWasapi_GetDeviceCurrentFormat` and `PaWasapi_GetDeviceMixFormat` (verified
with PE export inspection). Owner-thread read-only queries now log these
values, PortAudio version, actual stream latency/sample rate/blocksize and
callback minimum/maximum frame counts. Query absence is explicit and does not
prevent playback. Native values remain pending Windows execution.

Contracts checked against primary sources:
[sounddevice WASAPI shared conversion](https://python-sounddevice.readthedocs.io/en/0.5.6/api/platform-specific-settings.html),
[callback, latency and variable block size](https://python-sounddevice.readthedocs.io/en/0.5.6/api/streams.html),
[PortAudio WASAPI extensions](https://github.com/PortAudio/portaudio/blob/master/include/pa_win_wasapi.h).

## Buffering and lifecycle changes

- WASAPI alone uses device backpressure instead of S11 wall-clock sleeps.
  Linux ALSA and null retain their existing pacing and seek behavior.
- Fixed-size 400 ms ring: 70,560 bytes at 44.1 kHz stereo, 76,800 at 48 kHz.
  S11's separate FIFO remains <=16 x 4096 bytes. Memory stays bounded.
- Hold PCM until at least 150 ms is authenticated and in the output ring
  (26,460 bytes at 44.1 kHz stereo). A short EOF drains below this threshold.
  The native stream starts early for synchronous startup-error handling, but
  its callback emits intentional silence until this prebuffer is ready.
- Request 100 ms shared latency and `blocksize=0` for host-selected callback
  sizes. Actual latency and host maximum frames are logged; requested latency
  is not presented as actual device buffering. The extra buffering prioritizes
  uninterrupted music; abort still discards rather than drains on a seek.
- Single producer/single consumer ring with monotonic published cursors on
  GIL-enabled CPython. Copy precedes cursor publication; a producer never
  overwrites unread slots. No lock, hash, logging, disk I/O, decrypt, allocation
  proportional to the queue, resampling or native lifecycle call in callback.
  Small Python view/scalar allocations remain; this is not a hard-real-time
  native ring or support for free-threaded Python.
- Initialize every callback buffer with preallocated silence, then copy at
  most two ring spans. EOF/abort/pause/rebuffer tails are deterministic silence.
  Consumed-byte SHA-256 moves to producer/owner before consumed slots are reused.
- A starvation counts an event, partial buffer and missing frames; recovery
  accumulates a fresh prebuffer rather than repeatedly alternating tiny PCM
  fragments with silence. Native host underflows are separate counters.
- Pause freezes ring consumption with intentional silence; resume continues
  the same frames. Already submitted device audio may sound for its latency.
- rc2 owner-thread MTA and process-MTA pin, immediate cancellation, abort before
  worker join, tracked teardown, device-loss/error propagation and replacement
  refusal on uncertain close remain. Reset ring cursors only after callbacks
  stop. No old ring can supply a new session. No automatic restart hides errors.

Every five seconds the owner records callback timing, occupancy/high/low,
partial callback buffers, split ring writes, queue starvation, host underflows,
writer waits and starts.
Increasing underruns produce WARNING logs; the status API includes
`audio_output.healthy=false` after an interruption and the GUI shows an amber
`Audio interruptions` badge. Successful PCM byte delivery does not imply clean
sound. Status positions use callback-consumed frames for WASAPI instead of
counting all ring-buffered bytes as already output. Position still precedes
physical DAC output by device latency. Seek metrics named `first_output` remain
first producer-write times; `first_pcm_ms` separately measures callback delivery
relative to output construction, neither is an acoustic latency measurement.

## Regression coverage and known risks

`test_wasapi_quality.py` adds exact 44.1/48 kHz stereo, arbitrary callbacks
(including larger than the ring), wraps, partial fills, short EOF, startup
silence, underrun/rebuffer recovery, host flags, pause/resume/abort silence,
producer-lock independence, WAVEFORMATEX decoding and optional native queries.
A real signed/licensed/encrypted three-minute stereo WAV is deleted after
packaging and played from ciphertext alone through the authenticated reader,
FIFO and ring with an accelerated manual clock. Both captured PCM and delivered
digest match all 31,752,000 source bytes. This is continuity testing; the separate
real-time soak measures scheduling.

Existing rc2 lifecycle tests still cover rapid forward/backward seeks,
concurrent seeks, repeated switches, stop/play, startup and callback failures,
device loss/reopen, drain cancellation, native stop/abort/close errors, delayed
teardown and COM ownership. Native smoke now writes several seconds at 44.1
and 48 kHz and rejects reported interruptions where a Windows device exists.
Linux execution skips it; no CI run was pushed.

Remaining risks: Realtek/Windows driver timing, DPC delays, effects/enhancements,
real shared-mode conversion fidelity and actual host-buffer settings are
unverified here. Python callbacks require GIL scheduling; large unrelated CPU
loads can still underrun. Shared conversion retains the existing explicit MME
fallback if WASAPI cannot open, with the used API logged. A permanently hung
native driver or uncertain failed close still requires application restart.
Normal source/seek-boundary discontinuities can click; starvation and signal
content must be distinguished during listening. The standard-Windows-player
comparison below is PENDING, not claimed as completed.

## Physical Windows speaker retest

1. Quit the app and install the private rc3 candidate over the existing program.
   Keep `%LOCALAPPDATA%\HolochainMusic`, all identities, settings, grants and
   downloaded music; keep Ubuntu rc1. Verify installer SHA-256 against
   `windows-rc-checksums.md`, then `holochain-music.exe --version` = `1.0.0rc3`.
2. Start `holochain-music.exe start --offline --audio wasapi`, select the existing
   `Speakers (Realtek(R) Audio)` setting and play a licensed downloaded track
   uninterrupted for at least five minutes. Record exact crackle times, CPU
   load/context, and any amber interruption badge. Repeat with a second track.
3. Export that SAME perpetual-licensed track using the existing Export action
   to a NEW WAV filename, then play the exported WAV through Windows Media
   Player on the SAME speakers/volume. This export passes the existing licence,
   hash and authentication checks. Compare the same timestamps and record
   whether the crackle occurs in either path. Do not compare a different encode.
   CLI alternative after quitting the app:
   `holochain-music.exe export <file_id> "C:\Users\<you>\Music\rc3-comparison.wav"`.
4. Repeat offline with Windows speaker format set to 44.1 kHz, then 48 kHz
   where offered. Preserve original settings and restore them afterwards.
   Record the selected Windows format, actual logs and audible result.
5. Seek forward 20 times and backward 20 times; drag rapidly in both directions,
   then let the final target play for a minute. Listen for old audio, repeated
   fragments, gaps and continuing crackle before/after each seek.
6. Switch between two tracks at least 20 times, including differing rates if
   available. Pause/resume ten times; seek/Stop/Play ten times. Verify immediate
   cancellation, intended final position and continued clean sound.
7. Where practical invalidate/restore the output device, then retry Play;
   record the visible error, recovery and any need to restart. Quit/relaunch
   and confirm existing identity and offline library persist.
8. Reconnect and repeat streaming from Ubuntu, keeping network and audio
   failures separate. Do not infer a protocol defect from an audio underrun.

Retain `%LOCALAPPDATA%\HolochainMusic\data\logs\audio.log` and rotations,
version, operation sequence, speaker/driver name and Windows format. Logs
contain audio metadata/counters only, never PCM, keys or grants. Compare
`host_underflows`, `underruns`, `starved_frames`, `rebuffer_silence_frames`,
`queue_high_bytes`, callback gaps/durations, `native` formats/host maximum
frames, actual latency and `stream_starts` per session. A zero counter alone
cannot establish absence of audible corruption. Only a human physical-speaker
retest can establish that the reported crackling is resolved.

Full automated results, reproduction commands and installer identity are in
`windows-wasapi-rc3-validation.md` and `windows-rc-checksums.md`.
