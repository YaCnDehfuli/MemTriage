# Bundled VADViT model

MemTriage includes the trained `models/Multi_32_224_6f_3u.pt` checkpoint.
It is loaded automatically during process analysis; users do not need to request
weights or upload a model.

## Checkpoint and architecture

- Architecture: `vit_base_patch32_224`, using VADViT's `ViTForImages` module layout.
- Head: nine outputs (`vit.head.weight` has shape `[9, 768]`).
- Input: 224 × 224 RGB process grid, arranged as 7 × 7 patches of 32 × 32 pixels.
- Evaluation: resize, tensor conversion, and ImageNet normalization.
- Loading: local tensor state dictionary, using `torch.load(weights_only=True)`.
- Inference runs in the worker on CPU by default, with no model download at runtime.

The other two recovered checkpoints had binary heads and were removed because
this workflow expects the multiclass model.

## Class names

`models/labels.json` supplies the output-index mapping derived from the VADViT
paper's labeled multiclass confusion matrix for **Patch32, Image224, 6 Frozen
layers (32-224-6)**, compared with the recovered experiment confusion matrix
for the bundled checkpoint:

| Output index | Class |
| --- | --- |
| 0 | Backdoor |
| 1 | Benign |
| 2 | Exploit |
| 3 | HackTool |
| 4 | Hoax |
| 5 | Rootkit |
| 6 | Trojan |
| 7 | Virus |
| 8 | Worm |

The paper's legend explicitly names both axes in this order. It also matches
`components/vadvit/dataset/dataset_loader.py`, which assigns multiclass indices
by sorting dataset folder names alphabetically. **Benign is index 1**, not 0;
the recovered plot's two visible "Negative"/"Positive" labels are binary plotting
labels and do not identify these multiclass outputs.

The matrices share the diagonal `[21, 25, 29, 18, 18, 18, 17, 22, 16]` and
the first eight rows. Their last (Worm) row differs: the recovered experiment
shows errors in Hoax and Trojan, while the paper shows errors in HackTool and
Rootkit. The mapping therefore uses the paper's axis legend and training order;
the two plots are not treated as identical evaluation results.

The classifier notices label-file changes on the next analysis. Cached verdicts
whose probability names no longer match the current mapping are recomputed when
the process is selected again.

## Deployment

The checkpoint is tracked with Git LFS. Install Git LFS before cloning:

```bash
git lfs install
git clone --recurse-submodules https://github.com/YaCnDehfuli/MemTriage.git
cd MemTriage
./deploy/up.sh
```

For an existing checkout, run `git lfs pull`. The launcher checks for a missing
checkpoint or an unresolved LFS pointer before starting Docker Compose.
API and worker both mount `models/` read-only at `/models`; the API reports the
same checkpoint the worker uses. `GET /api/model` reports `active_source: "trained"`
when the bundled checkpoint is present. Classification results report
`model_source: "trained"` and `placeholder: false` after successful inference.

Local Python runs resolve `models/` from the repository automatically. Set
`MEMTRIAGE_MODEL_CHECKPOINT_PATH` and `MEMTRIAGE_LABELS_PATH` only when using
another location. Set `MEMTRIAGE_DEVICE=cuda` for a compatible GPU environment.
A missing or invalid checkpoint produces an explicit unavailable verdict.

## Viewing results

Run triage, select a PID from the process inventory, and start process analysis.
The VADViT panel displays the top class and all nine probabilities. The attention
overlay links ranked grid patches to VAD addresses and region-analysis panels.
Selecting a process again replaces a cached untrained or unavailable verdict
with a new analysis using the bundled checkpoint. Completed trained results
are reused, and consolidated results include each PID once.
