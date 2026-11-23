#!/usr/bin/env python3
"""Analyze a song -> build/onsets.json (drum hits) + build/config.json (beat period, first-beat offset, end).
usage: analyze_song.py song.wav [--t0 SECONDS] [--end SECONDS]   (wav: mono or stereo; use ffmpeg to convert)"""
import sys, json, wave, pathlib, numpy as np
args = sys.argv[1:]
song = args[0]
def opt(name, default=None):
    return float(args[args.index(name) + 1]) if name in args else default
w = wave.open(song); sr = w.getframerate(); ch = w.getnchannels()
x = np.frombuffer(w.readframes(w.getnframes()), "<i2").astype(float) / 32768
if ch > 1: x = x.reshape(-1, ch).mean(1)
N, H = 1024, 256; win = np.hanning(N)
S = np.array([np.abs(np.fft.rfft(x[i:i + N] * win)) for i in range(0, len(x) - N, H)])
flux = np.maximum(0, np.diff(np.log1p(S * 50), axis=0)).sum(1); flux = (flux - flux.mean()) / flux.std()
t = np.arange(len(flux)) * H / sr
on = []
for i in range(2, len(flux) - 2):
    if flux[i] > 1.2 and flux[i] == flux[i - 2:i + 3].max() and (not on or t[i] - on[-1][0] > .1):
        on.append((float(t[i]), float(min(3, flux[i]))))
fps = sr / H; f = flux - flux.mean(); ac = np.correlate(f, f, "full")[len(f) - 1:]
lag = max(range(int(fps * .3), int(fps * .9)), key=lambda l: ac[l]); beat = lag / fps
ph = np.array([o[0] % beat for o in on]) / beat * 2 * np.pi
t0 = (np.angle(np.exp(1j * ph).mean()) / (2 * np.pi) * beat) % beat
t0 = opt("--t0", float(t0)); end = opt("--end", min(len(x) / sr, on[-1][0] + .35))
out = pathlib.Path(__file__).parent / "build"; out.mkdir(exist_ok=True)
(out / "onsets.json").write_text(json.dumps({"on": on}))
(out / "config.json").write_text(json.dumps({"beat": round(beat, 4), "t0": round(t0, 3), "end": round(end, 2)}))
print(f"bpm {60/beat:.1f}  beat {beat:.4f}s  t0 {t0:.3f}  end {end:.2f}  onsets {len(on)}")
