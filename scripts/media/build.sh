#!/usr/bin/env bash
# Turn the captures from scripts/media/capture.cjs into the published media:
#   docs/screenshots/*.webp      (2000 px, from the 2x PNGs)
#   docs/media/paddock-demo.mp4  (captioned, 1.6x speed)
#   docs/media/paddock-demo.gif  (860 px, 10 fps, < 10 MB for the README)
# Needs ffmpeg and Python with Pillow.
set -euo pipefail
IN=${1:?usage: build.sh <capture-dir>}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FONT=${FONT:-/usr/share/fonts/opentype/inter/Inter-SemiBold.otf}

python3 - "$IN" "$ROOT/docs/screenshots" <<'PY'
import sys, pathlib
from PIL import Image
src, dst = map(pathlib.Path, sys.argv[1:])
for png in sorted(src.glob("*.png")):
    im = Image.open(png).convert("RGB")
    w, h = im.size
    im.resize((2000, round(h * 2000 / w)), Image.LANCZOS).save(dst / f"{png.stem}.webp", "WEBP", quality=88, method=6)
    print("wrote", dst / f"{png.stem}.webp")
PY

RAW=$(ls -t "$IN"/*.webm 2>/dev/null | head -1 || true)
[ -n "$RAW" ] || { echo "no .webm in $IN (run: capture.cjs video $IN)"; exit 0; }
cap() { echo "drawtext=fontfile=$FONT:text='$1':enable='between(t,$2,$3)':x=(w-text_w)/2:y=h-118:fontsize=34:fontcolor=0xF2EDE4:box=1:boxcolor=0x0B0A09@0.78:boxborderw=22"; }
VF="$(cap 'Defensive attack-surface intelligence' 0.6 8.6),$(cap 'See everything you expose' 8.9 12.5),$(cap 'Map the paths attackers would take' 12.8 17.2),$(cap 'Prove it is exploitable. Prove it is fixed.' 17.5 22.7),$(cap 'Correlate noise into one story' 23.0 24.9),$(cap 'Evidence your auditors accept' 25.2 28.7),$(cap 'Free passive exposure check' 29.0 32.8),setpts=PTS/1.6"
M="$ROOT/docs/media"; mkdir -p "$M"
ffmpeg -v error -y -i "$RAW" -vf "$VF" -an -c:v libx264 -preset slow -crf 22 -pix_fmt yuv420p -movflags +faststart "$M/paddock-demo.mp4"
ffmpeg -v error -y -i "$M/paddock-demo.mp4" -vf "fps=10,scale=860:-1:flags=lanczos,palettegen=max_colors=128:stats_mode=diff" "$IN/pal.png"
ffmpeg -v error -y -i "$M/paddock-demo.mp4" -i "$IN/pal.png" -lavfi "fps=10,scale=860:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" "$M/paddock-demo.gif"
ls -la "$M"
