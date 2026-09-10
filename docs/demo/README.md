# Live-path recording assets

`memtriage-live.mp4` is the full-resolution source and `memtriage-live.gif` is
its GitHub-README-compatible preview. Both show a live Docker run, not a mocked
UI. The README preview links to the MP4 so the detailed workbench text remains
readable.

## Stack

```bash
export MEMTRIAGE_SAMPLES_DIR="/absolute/path/to/Samples"
docker compose -f deploy/docker-compose.yml -f docs/demo/compose.samples.yml up --build
```

Open `http://127.0.0.1:5173`. Upload `2580_5.vmem` (SHA-256
`777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4`).
Leave **Prefer cache** selected for Volatility JSON sidecars. Cached plugin
artifacts sit next to the image as `<image>_<plugin>.json`. Scoring is always
recomputed from VolMemLyzer's bounded OverviewAnalysis (max 30); do not reuse a
stale `triage.json` that still carries the old unbounded catalog scores.

To seed those artifacts into an investigation without re-uploading 4 GiB, use
the **quick** plugin set (no psscan/psxview/netscan/hivescan):

```bash
docker compose -f deploy/docker-compose.yml -f docs/demo/compose.samples.yml \
  exec worker python -m memtriage.pipeline.fixture_seed \
  --dumps-dir /samples --image-name 2580_5.vmem --quick
```

The command prints an `investigation_id`. Open
`http://127.0.0.1:5173/?investigation=<id>` to resume that live investigation.

## Playwright

Viewport is 1280×800. Video is recorded, then converted.

```bash
cd docs/demo
npm install
npx playwright install chromium
MEMTRIAGE_INVESTIGATION=<id> npm run record
# or a first-time live upload:
# MEMTRIAGE_DUMP=/absolute/path/to/2580_5.vmem npm run record
```

Video lands under `docs/demo/test-results/`. Stills land under `docs/figures/`
at 1280×800: `triage-board.png`, `evidence-expansion.png`, `attention-overlay.png`.

## Publish the recording

Keep the MP4 as the canonical walkthrough, optimize it for web playback, and
derive a lower-frame-rate GIF for inline rendering on GitHub:

```bash
VIDEO=$(ls -t docs/demo/test-results/**/*.webm | head -1)
ffmpeg -y -i "$VIDEO" -c:v libx264 -pix_fmt yuv420p -movflags +faststart \
  docs/demo/memtriage-live.mp4
ffmpeg -y -i docs/demo/memtriage-live.mp4 -filter_complex \
  "fps=4,scale=900:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
  docs/demo/memtriage-live.gif
```

Social preview (1280×640) from the triage-board still. GitHub has no API for the
settings image; upload `docs/figures/social-preview.png` at
https://github.com/YaCnDehfuli/MemTriage/settings under Social preview.

```bash
ffmpeg -y -i docs/figures/triage-board.png \
  -vf "scale=1280:640:force_original_aspect_ratio=increase,crop=1280:640" \
  docs/figures/social-preview.png
```
