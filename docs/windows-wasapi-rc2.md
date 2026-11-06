# Windows WASAPI seeking and recovery — private rc2

Status: code and automated checks only; awaiting a Windows physical-speaker
retest. This does not establish the exact native error on the original machine.

## Evidence and lifecycle defects

The first Windows 11 ↔ Ubuntu LAN test confirmed track discovery, licence
request/approval/grant receipt and audible Realtek playback. Seeking failed
with WASAPI, and later playback could fail to start. The same seeks and track
changes worked with null output. A separate catalogue Websocket timeout is not
evidence of an audio cause.

Inspection of the previous code found:

- `BufferedPcmPlayer.stop()` joined its worker before aborting the output. A
  worker blocked on the PortAudio ring, or draining it at EOF, could outlive
  that wait. `Player._stop_worker()` discarded its references and suppressed
  teardown errors, allowing another output to open while the old one remained.
- `PortAudioOutput.close()` set `_closed` before native stop/close. Concurrent
  abort could return early while teardown was still running. Drain waits did
  not observe abort, and native lifecycle operations had no common owner.
- sounddevice was lazily imported on the first short-lived `hm-player` thread.
  Its import initializes PortAudio, including Windows COM setup. Later seeks
  created new threads without explicit COM initialization. Stream creation and
  start occurred on `hm-player`; stop/abort/close occurred on the PCM worker.
  This is a concrete COM lifetime/threading hazard and a plausible contributor
  to first-play success followed by startup failure. The user's original native
  exception was hidden, so causation on that hardware remains unconfirmed.
- Startup errors hid the underlying PortAudio exception. Teardown calls used
  sounddevice's default `ignore_errors=True`, and abort discarded exceptions.

Relevant upstream contracts:
[PortAudio stream lifecycle](https://portaudio.com/docs/v19-doxydocs/portaudio_8h.html)
(stop drains, abort discards, close releases),
[sounddevice streams](https://python-sounddevice.readthedocs.io/en/0.5.6/api/streams.html),
[WASAPI startup COM marshalling](https://github.com/PortAudio/portaudio/blob/master/src/hostapi/wasapi/pa_win_wasapi.c),
[PortAudio COM initialization](https://github.com/PortAudio/portaudio/blob/master/src/os/win/pa_win_coinitialize.c),
and [Microsoft MTA lifetime semantics](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coincrementmtausage).
These document the native contracts; they are not a Windows hardware test.

## Resulting behavior

Each output has one owner thread with an explicit MTA COM scope. It loads
sounddevice and creates, starts, checks, aborts/stops and closes its stream in
that scope. A shared MTA usage reference keeps PortAudio's cached device
objects alive between streams without leaving a Python worker running. Its
cleanup is registered before sounddevice imports, so PortAudio terminates
before that reference is released during normal interpreter exit. Failed
imports release a newly acquired reference and remain retryable. Device
enumeration also uses this loader to avoid initializing a separate STA.
Native teardown completes before the owner exits. The callback
only transfers PCM and records errors; it never invokes PortAudio or logs PCM.

Seek/stop/switch cancel the old generation, clear the bounded S11 FIFO, signal
the output to discard its 200 ms ring, wake blocked writers/drainers, and wait
for teardown before opening a replacement. EOF alone drains and stops. Abort
interrupts an EOF ring drain. Native stop and close cannot race on different
threads. A stream that fails startup is aborted/closed before failure returns.

Unexpected inactivity, callback failure, native exceptions and drain failures
reach the controller; `output_active` becomes false. Play retries after cleanup.
If native teardown outlives a bounded wait, its owner remains tracked and
replacement is refused until a retry observes completion. If native close
itself fails, ownership is uncertain and the error remains visible; restart the
app before retrying. The code cannot guarantee recovery from a hung driver.
Canceled package verification owns no output and remains tracked until it
returns; generation checks prevent it from opening a superseded device.
Application shutdown still releases network services and its instance lock if
audio teardown reports failure.

The signed manifest, ciphertext SHA-256, AES-GCM, recipient/licence gates and
per-chunk checks are unchanged. Seeks reuse the verified reader and perform the
same checks on every emitted chunk. Linux retains worker-owned aplay kill/pipe
teardown and the existing seek path; no native PortAudio worker is used there.

## Diagnostics

The GUI and CLI write native audio diagnostics to
`%LOCALAPPDATA%\HolochainMusic\data\logs\audio.log`, rotating at 1,000,000 bytes
with two backups. It records selected/requested device, host API, sample rate,
channels, latency/ring limit, creation/start/teardown and the original exception
chain. It never records PCM, content keys, grants, API tokens or identities.
The player error also includes the underlying device exception where available.

For a failure, retain `audio.log` and its rotated files, exact UI error, app
version, selected device and the operation sequence. Inspect audio and bridge
logs separately; a bridge timeout alone cannot diagnose an output failure.

## Required Windows retest

Use `HolochainMusic-1.0.0-rc2-windows-x64.exe` and the checksum in
`windows-rc-checksums.md`. Quit the old application before upgrading in place.
Keep `%LOCALAPPDATA%\HolochainMusic`, the existing identities/settings/library,
and the existing Ubuntu rc1 installation. No reset or new identity is needed.
Verify `holochain-music.exe --version` reports `1.0.0rc2`.

Start with `holochain-music.exe start --audio wasapi` and listen through the
physical Realtek speakers. Use a licensed downloaded track to isolate output
behavior, then repeat while streaming from Ubuntu.

1. Play; seek forward at least 20 times; confirm the requested position plays.
2. Seek backward at least 20 times; confirm audio follows each final position.
3. Drag rapidly/repeatedly across the seek bar, then let the final target play.
4. Switch between at least two licensed tracks at least 20 times during play.
5. Seek, immediately Stop, then Play again; repeat at least 10 times.
6. Where practical, change/remove an available output device during playback,
   restore/select it, and try Play again. Record any error and recovery. This
   step is simulated in automation; recovery on physical devices is unverified.
7. Quit/relaunch and repeat; confirm identity and existing library persist.

Record observed audio, stale audio/clicks, delay, errors and recovery, plus the
log and version. Null audio is a diagnostic comparison only. A headless CI
pass does not validate sound from speakers. The fix is hardware-verified only
after the user completes repeated seeks, track changes and playback recovery
through physical Windows speakers.

## Automated evidence

Final commands, results, installer checksum and artefact preservation are
recorded in `windows-wasapi-rc2-validation.md` alongside this report.
