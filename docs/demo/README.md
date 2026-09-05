# Live-path recording

The README GIF is a live Docker run, not a mocked UI. Demo-mode documentation
was removed from the application and the first-screen README.

## Stack

```bash
export MEMTRIAGE_SAMPLES_DIR="/absolute/path/to/Samples"
docker compose -f deploy/docker-compose.yml -f docs/demo/compose.samples.yml up --build
```

Open `http://127.0.0.1:5173`. Upload `2580_5.vmem` (SHA-256
`777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4`).
Leave **Prefer cache** selected. Cached VolMemLyzer artifacts sit next to the
image as `<image>_<plugin>.json`.

To seed those artifacts into an investigation without re-uploading 4 GiB:

```bash
docker compose -f deploy/docker-compose.yml -f docs/demo/compose.samples.yml \
  exec worker python -m memtriage.pipeline.fixture_seed \
  --dumps-dir /samples --image-name 2580_5.vmem
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

## ffmpeg + gifski

Target: 20–25 s, under 6 MB. If the GIF is larger, drop to 12 fps and 1000 px
wide before cutting content.

```bash
VIDEO=$(ls -t docs/demo/test-results/**/*.webm | head -1)
ffmpeg -y -i "$VIDEO" -vf "fps=12,scale=1000:-1:flags=lanczos" /tmp/memtriage-frames/frame%04d.png
gifski -o docs/demo/memtriage-live.gif --fps 12 --width 1000 /tmp/memtriage-frames/frame*.png
```

Social preview (1280×640) from the triage-board still. GitHub has no API for the
settings image; upload `docs/figures/social-preview.png` at
https://github.com/YaCnDehfuli/MemTriage/settings under Social preview.

```bash
ffmpeg -y -i docs/figures/triage-board.png \
  -vf "scale=1280:640:force_original_aspect_ratio=increase,crop=1280:640" \
  docs/figures/social-preview.png
```
