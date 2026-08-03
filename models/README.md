# Model weights

MemTriage does **not** ship VADViT's trained weights. They were produced as part
of university research and are released on request by the author rather than
bundled with this repository.

## What runs without them

Nothing is disabled. When no trained checkpoint is present the pipeline builds a
**structural placeholder** — the identical architecture, dims and I/O
(`vit_base_patch32_224`, 9 classes) with untrained weights, generated once from a
fixed seed into `<MEMTRIAGE_DATA_DIR>/model_cache/`. Region dumping, grid
rendering, classification, the attention map, the patch-to-region attribution and
the whole low-level region deep-dive therefore all run end to end.

Every verdict produced this way is flagged `placeholder: true` with
`model_source: "placeholder"` and carries the note *"Untrained structural
placeholder — this family label is NOT a detection."* The class name is never
presented as a finding. Attention and the analysis that hangs off it are
architectural, so they still describe real memory.

Set `MEMTRIAGE_MODEL_AUTO_PLACEHOLDER=false` to turn the fallback off; verdicts
then read "model not loaded" as before.

## Requesting the trained weights

Use the **Request trained weights** form in the app (VADViT deep-dive panel), or
email **yasindeh@yorku.ca** directly with your name, organization, role and what
you intend to use the model for. See `docs/MODEL_ACCESS.md`.

## Installing them

Drop the two files into this directory (mounted read-only at `/models` in the
worker):

- `Multi_32_224_6f_3u.pt` — the VADViT `state_dict` (`vit_base_patch32_224` with
  9 outputs: `Benign` + 8 malware families).
- `labels.json` — the class-index to name mapping, in the alphabetical order used
  at training time:

  ```json
  ["Benign", "FamilyA", "FamilyB", "FamilyC", "FamilyD",
   "FamilyE", "FamilyF", "FamilyG", "FamilyH"]
  ```

Weight files are git-ignored and never committed. The swap is drop-in: trained
weights take precedence over the cached placeholder with no code change and no
restart flag. Requires `torch`/`timm`, which the worker image already has.

## Generating a placeholder by hand

```bash
python -m memtriage.pipeline.placeholder_model --out ./models
```

This is only needed if you want the placeholder in a specific directory; the
runtime otherwise creates and caches its own.
