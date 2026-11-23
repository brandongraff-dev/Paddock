#!/usr/bin/env python3
"""Generate build/frames.js (Muybridge horse plates) and build/corpus.txt (code wall) from this repo."""
import re, pathlib
here = pathlib.Path(__file__).parent
root = here.parent.parent
out = here / "build"; out.mkdir(exist_ok=True)
ts = (root / "dashboard/src/brand/horseFrames.ts").read_text()
frames = re.findall(r'"([A-Za-z0-9+/=]{100,})"', ts)
(out / "frames.js").write_text("window.HORSE_FRAMES=" + repr(frames).replace("'", '"') + ";")
core = (root / "sdk/python/paddock_sdk/_core.py").read_text().splitlines()[:90]
(out / "corpus.txt").write_text("\n".join(l[:70] for l in core))
print("frames:", len(frames), "corpus lines:", len(core))
