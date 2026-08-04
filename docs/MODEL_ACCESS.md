# Trained VADViT weights

MemTriage does not ship the trained VADViT checkpoint. It is the output of
university research, and it is released by the author on request rather than
bundled with the application. This page explains what that means in practice and
how to ask for it.

## What the application does without it

Everything, minus a meaningful family label.

When no trained checkpoint is mounted, MemTriage builds an **untrained structural
placeholder** — the same `vit_base_patch32_224` backbone, the same 9-class head,
the same preprocessing — once, from a fixed seed, into
`<MEMTRIAGE_DATA_DIR>/model_cache/`. The pipeline then runs unchanged:

| Stage | With placeholder |
|---|---|
| VAD region dump and consolidation | real |
| Grid rendering (tag/entropy/Markov channels) | real |
| Classification | runs; label is **not** a detection |
| Attention map and overlay | real, architectural |
| Patch to VAD region attribution | real |
| Region deep-dive (disassembly, CFG, strings, patterns) | real |

Only the class name is meaningless. Attention is a property of the architecture
and the input, so where the model looks — and everything the region deep-dive
derives from the region it looks hardest at — describes actual memory.

Verdicts produced this way are marked in three places so it cannot be missed:
`placeholder: true`, `model_source: "placeholder"`, and a note reading *"Untrained
structural placeholder — this family label is NOT a detection."* The UI shows a
banner on the verdict panel and repeats the caveat in the report and the export.

To turn the fallback off and go back to an explicit "model not loaded" state, set
`MEMTRIAGE_MODEL_AUTO_PLACEHOLDER=false`.

## Requesting the trained weights

Either use the **Request trained weights** form in the app — it is on the VADViT
deep-dive panel, next to the placeholder banner — or email the author directly.

**Contact: yasindeh@yorku.ca**

The form asks for:

- name, email, organization, role, country
- intended use (research, education, thesis, evaluation, commercial, other)
- a short description of what the model would be used for
- whether results are expected to be published

It records the request locally and gives you a formatted message plus a `mailto:`
link. MemTriage never sends the mail itself: the API has no mail credentials, and
the analysis worker has no outbound network access at all by design. The request
is yours to send.

### Terms

Requests are granted for the stated use. Weights are not redistributed, and any
published result that relies on them cites the VADViT work.

## Installing the weights once you have them

Place both files in `models/` (mounted read-only at `/models` in the worker):

```
models/Multi_32_224_6f_3u.pt
models/labels.json
```

`labels.json` is the index-ordered class list used at training time:

```json
["Benign", "FamilyA", "FamilyB", "FamilyC", "FamilyD",
 "FamilyE", "FamilyF", "FamilyG", "FamilyH"]
```

Trained weights take precedence over the cached placeholder automatically — no
code change, no flag, no need to delete the cache. Restart the worker and the
verdict panel switches to `model_source: "trained"`.

Weight files are git-ignored and are never committed.
