"""Generate a structural placeholder VADViT checkpoint.

Until the real ``Multi_32_224_6f_3u.pt`` + ``labels.json`` are provided, this
writes a randomly-initialized checkpoint with the *exact* architecture, dims and
I/O of the real model (``vit_base_patch32_224``, 9 classes), plus a ``labels.json``
and a ``model_meta.json`` marker. The full pipeline — dump → consolidate → render →
classify → explain — is therefore exercisable end to end, while the verdict is
clearly flagged as a placeholder so it is never mistaken for a real detection.

Swapping in the real weights is a drop-in: replace the ``.pt`` and ``labels.json``
in the models directory (and remove or overwrite ``model_meta.json``); no code
changes are required.

Run as::

    python -m memtriage.pipeline.placeholder_model            # uses settings paths
    python -m memtriage.pipeline.placeholder_model --out /models
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..config import get_settings
from .vadvit_model import META_FILENAME, build_model

# Nine index-ordered placeholder class names (index 0 first), structurally
# mirroring the real "Benign + 8 families" head. Obviously synthetic on purpose.
PLACEHOLDER_LABELS: list[str] = [
    "Benign",
    "Placeholder_Backdoor",
    "Placeholder_Downloader",
    "Placeholder_Dropper",
    "Placeholder_Keylogger",
    "Placeholder_Ransomware",
    "Placeholder_Rootkit",
    "Placeholder_Trojan",
    "Placeholder_Worm",
]


def generate_placeholder(
    checkpoint_path,
    labels_path,
    *,
    model_name: str,
    num_classes: int,
    seed: int = 0,
) -> dict:
    """Build a random-weight checkpoint + labels + meta. Requires torch/timm.

    Returns a dict of the paths written.
    """
    import torch

    torch.manual_seed(seed)
    model = build_model(model_name, num_classes, pretrained=False)

    ckpt = Path(checkpoint_path)
    ckpt.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), str(ckpt))

    labels = PLACEHOLDER_LABELS[:num_classes]
    if len(labels) < num_classes:
        labels = labels + [f"class_{i}" for i in range(len(labels), num_classes)]
    Path(labels_path).write_text(json.dumps(labels, indent=2))

    meta_path = ckpt.parent / META_FILENAME
    meta_path.write_text(json.dumps({
        "placeholder": True,
        "model_name": model_name,
        "num_classes": num_classes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": ("Randomly-initialized structural placeholder. Verdicts are NOT "
                 "meaningful; replace with the trained checkpoint to enable real "
                 "classification."),
    }, indent=2))

    return {"checkpoint": str(ckpt), "labels": str(labels_path), "meta": str(meta_path)}


def _main(argv: list[str] | None = None) -> int:
    import argparse

    s = get_settings()
    parser = argparse.ArgumentParser(description="Generate a placeholder VADViT model")
    parser.add_argument("--out", default=None,
                        help="Directory for the checkpoint/labels/meta (default: settings paths)")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    if args.out:
        out = Path(args.out)
        ckpt = out / Path(s.model_checkpoint_path).name
        labels = out / Path(s.labels_path).name
    else:
        ckpt = Path(s.model_checkpoint_path)
        labels = Path(s.labels_path)

    written = generate_placeholder(
        ckpt, labels, model_name=s.model_name, num_classes=s.num_classes, seed=args.seed
    )
    print("Wrote placeholder VADViT artifacts:")
    for k, v in written.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
