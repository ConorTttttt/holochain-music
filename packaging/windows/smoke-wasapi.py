#!/usr/bin/env python3
"""Create real WASAPI streams if the runner exposes an output device.

Zero-valued PCM only. Headless runners may skip; this never validates speakers.
Initialization/start/close failures with an advertised output device fail CI.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main():
    if sys.platform != 'win32':
        print('SKIP real WASAPI: Windows host required')
        return
    import logging
    logging.basicConfig(level=logging.INFO)
    from music_catalogue.audio_output import PortAudioOutput, WASAPI, list_output_devices, _load_sounddevice
    from music_catalogue.buffered_playback import AudioFormat
    sd = _load_sounddevice()
    devices = list_output_devices(WASAPI)
    if not devices:
        print('SKIP real WASAPI: runner advertises no WASAPI output devices; speaker validation remains manual')
        return
    apis = sd.query_hostapis()
    api = next(a for a in apis if a['name'] == WASAPI)
    index = api['default_output_device']
    if index is None or index < 0:
        print('SKIP real WASAPI: no default output device; speaker validation remains manual')
        return
    info = sd.query_devices(index)
    channels = min(2, info['max_output_channels'])
    for rate in dict.fromkeys((int(info['default_samplerate']), 44100, 48000)):
        fmt = AudioFormat(rate, channels, 16)
        for i in range(6):
            out = PortAudioOutput(fmt, fallback_hostapi=None)
            try:
                if i < 2:
                    # Several seconds under actual device backpressure, at both
                    # 44.1 and 48 kHz. Silence only; never speaker validation.
                    for _ in range(150):
                        out.write(bytes((rate // 50) * fmt.frame_size))
                    out.close()
                    print('WASAPI buffer measurements:', out.diagnostics())
                    assert out.underruns == 0, 'WASAPI stream reported interruptions'
                else:
                    out.write(bytes((rate // 50) * fmt.frame_size))
                if i % 2:
                    out.close()
            finally:
                out.abort()
            assert not out._owner.is_alive(), 'stream owner leaked'
    print('PASS real WASAPI creation/start/abort/drain/reopen; physical speakers NOT validated')


if __name__ == '__main__':
    main()
