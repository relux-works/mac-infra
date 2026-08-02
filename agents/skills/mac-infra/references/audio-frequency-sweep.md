# Audio Frequency Sweep

Use this when the user wants a local frequency/hearing/output-chain test without
YouTube or streaming-platform compression.

```bash
mac-audio-sweep device
mac-audio-sweep tui
mac-audio-sweep tui --rerender
mac-audio-sweep generate --out .temp/mac-audio-sweep/manual-sweep.wav
```

`mac-audio-sweep device` prints the current default output device sample rate,
whether the rate is settable, and whether the target rate is supported.

`mac-audio-sweep tui` reuses a cached PCM WAV when the current normalized sweep
parameters already have one under `.temp/mac-audio-sweep/cache/`; otherwise it
renders the WAV. Pass `--rerender` to force overwriting the cached WAV for the
same parameters, or `--no-cache` for a one-shot temporary WAV. Playback uses
`afplay` while a Bubble Tea TUI shows the current frequency, slope, elapsed time,
and sample-rate/Nyquist limits. Press `r` to restart from the beginning. Press
`q`, `esc`, or `ctrl+c` to stop playback and exit.

Defaults:

- `96 kHz`, stereo, 16-bit PCM WAV.
- `1 Hz -> 44 kHz` total sweep.
- `1 Hz -> 50 Hz` slow low ramp over `90s`, starting near `+1 Hz / 5s` and then
  accelerating smoothly.
- Low amplitude default (`0.20`) for safer startup.
- TUI output-rate policy `set`: switch the default output device to the WAV
  sample rate when supported, then restore the previous rate on stop/exit.

Important caveats:

- A true `44 kHz` signal requires sample rate above `88 kHz`; default `96 kHz`
  gives a `48 kHz` Nyquist limit.
- Use `--output-rate strict` to refuse playback unless the default output device
  is already at the WAV sample rate. Use `--output-rate off` only when explicit
  CoreAudio sample-rate management is not wanted.
- `0 Hz` is DC, not an audible tone; use `1 Hz` as the practical "0-ish" start.
- DACs, Bluetooth codecs, headphones, macOS output paths, or hearing protection
  can still resample/filter ultrasonic content. Keep volume low.
