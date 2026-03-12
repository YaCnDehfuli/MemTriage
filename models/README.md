# Model weights (bring your own)

MemTriage does not ship VADViT's trained weights. To enable real verdicts, place
two files here (this directory is mounted read-only into the worker at `/models`):

- `Multi_32_224_6f_3u.pt` — the VADViT `state_dict` (a `vit_base_patch32_224`
  classifier with 9 outputs: `Benign` + 8 malware families).
- `labels.json` — the class-index → name mapping, in the alphabetical order used
  at training time, e.g.:

  ```json
  ["Benign", "FamilyA", "FamilyB", "FamilyC", "FamilyD",
   "FamilyE", "FamilyF", "FamilyG", "FamilyH"]
  ```

Weight files are git-ignored and never committed. When the checkpoint is absent,
the pipeline still runs (extraction, candidate rendering, explainability
plumbing) and the verdict panel shows an explicit **"model not loaded"** state —
it never fabricates a classification.

## Placeholder model (development / demo)

Before the real weights are available you can generate a **structural
placeholder** — identical architecture, dims and I/O (`vit_base_patch32_224`, 9
classes) with random weights — so the full dump → consolidate → render → classify
flow is exercisable end to end:

```bash
python -m memtriage.pipeline.placeholder_model --out ./models
```

This writes `Multi_32_224_6f_3u.pt`, `labels.json`, and a `model_meta.json` marker
(`{"placeholder": true}`). Because the marker is present, every verdict is flagged
`placeholder: true` and labelled *"structural placeholder — not a real
detection,"* so a random-weight class is never mistaken for a finding. Swapping in
the trained checkpoint is a drop-in: overwrite the `.pt` and `labels.json` (and
remove `model_meta.json`) — **no code changes**. Requires `torch`/`timm` (present
in the worker image).
