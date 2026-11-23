#!/usr/bin/env bash
# Render the Paddock TikTok edit, locked to a song.
#   ./build.sh path/to/song.(mp3|wav|mp4) [seconds-of-video, default = song end]
# Needs: node + playwright, python3 + numpy, ffmpeg.  Inputs (not in git): inputs/memes/*.png, inputs/shots/*.png
set -euo pipefail
cd "$(dirname "$0")"
SONG="${1:?usage: build.sh song-file [seconds]}"
mkdir -p build out
ffmpeg -y -loglevel error -i "$SONG" -vn -ac 2 -ar 44100 -c:a pcm_s16le build/song.wav
python3 prepare.py
python3 analyze_song.py build/song.wav ${2:+--end "$2"}
END=$(python3 -c "import json;print(json.load(open('build/config.json'))['end'])")
FRAMES=$(python3 -c "print(int(round($END*30)))")
(python3 -m http.server 8767 >/dev/null 2>&1 & echo $! > build/server.pid); sleep 1
trap 'kill $(cat build/server.pid) 2>/dev/null || true' EXIT
PER=$(( (FRAMES + 3) / 4 ))
for k in 0 1 2 3; do node render.js $((k*PER)) $(( (k+1)*PER < FRAMES ? (k+1)*PER : FRAMES )) out/frames 8767 & done; wait
ffmpeg -y -loglevel error -framerate 30 -i out/frames/f%04d.jpg -i build/song.wav -af "atrim=0:$END,afade=t=out:st=$(python3 -c "print($END-.3)"):d=.3" \
  -c:v libx264 -preset slow -crf 19 -pix_fmt yuv420p -c:a aac -b:a 224k -movflags +faststart -t "$END" out/tiktok-with-song.mp4
ffmpeg -y -loglevel error -framerate 30 -i out/frames/f%04d.jpg -c:v libx264 -preset slow -crf 19 -pix_fmt yuv420p -an -movflags +faststart -t "$END" out/tiktok-NO-AUDIO.mp4
echo "done: out/tiktok-with-song.mp4  out/tiktok-NO-AUDIO.mp4  (post the NO-AUDIO one and add the sound in TikTok)"
