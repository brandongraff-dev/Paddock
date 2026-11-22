# Screenshots and demo video

The README's screenshots (`*.webp` here) and demo video (`docs/media/`) are
captured from a real stack with the demo data, so they never drift from the
product. To regenerate them after a UI change:

```bash
make quickstart                       # full stack + demo data (or: make lite && make lite-demo)
npm i -g playwright && npx playwright install chromium   # once
export PADDOCK_PASSWORD=...           # ADMIN_BOOTSTRAP_PASSWORD from .env
node scripts/media/capture.cjs shots /tmp/paddock-media   # 2x PNG screenshots
node scripts/media/capture.cjs video /tmp/paddock-media   # raw tour video
bash scripts/media/build.sh /tmp/paddock-media            # -> *.webp, demo.mp4, demo.gif
```

`build.sh` needs `ffmpeg` and Python with Pillow. The GIF is kept under 10 MB
(860 px, 10 fps) so GitHub renders it inline; the MP4 is the full-quality cut.
