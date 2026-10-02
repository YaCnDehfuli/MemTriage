# Demo assets

The current README uses the original root recordings:
[analysis demo](../../demo.mov) and [report demo](../../report_demo.mp4).
Neither recording is re-encoded. Both are tracked with Git LFS.
The [project report](../index.html) includes current UI captures and the
[supplied PDF examples](../reports/README.md).

`memtriage-live.mp4`, `memtriage-live.gif`, the recording scripts, and
`docs/figures/` are retained as historical live-path assets. The instructions
below reproduce that older recording; they do not describe the current demos.

The separate [report-writing recording guide](report-writing-demo.md) follows
the completed `2580_5.vmem` experiment through evidence selection, harness
attribution, per-region notes, analyst assessment, and technical/executive
exports. Its [evidence extract](report-writing-evidence.json) records the saved
results used to prepare the script.

## Stack

```bash
git submodule update --init --recursive
git lfs pull --include="models/Multi_32_224_6f_3u.pt"
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
at 1280×800: `triage-board.png` and `evidence-expansion.png`.

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
