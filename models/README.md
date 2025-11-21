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
