"""Generate a structural placeholder VADViT checkpoint.

Legacy test utility for creating random weights with the same architecture and
I/O as VADViT. Normal MemTriage deployments use the bundled trained checkpoint
and never invoke this fallback automatically. Generated verdicts are marked as
untrained so test outputs cannot be mistaken for meaningful classifications.

Run as::

    python -m memtriage.pipeline.placeholder_model            # uses the test cache
    python -m memtriage.pipeline.placeholder_model --out /tmp/vadvit-test
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
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
    # Writing our own randomly-initialized state_dict, not loading untrusted input.
    torch.save(model.state_dict(), str(ckpt))  # nosec B614

    labels = PLACEHOLDER_LABELS[:num_classes]
    if len(labels) < num_classes:
        labels = labels + [f"class_{i}" for i in range(len(labels), num_classes)]
    Path(labels_path).write_text(json.dumps(labels, indent=2))

    meta_path = ckpt.parent / META_FILENAME
    meta_path.write_text(json.dumps({
        "placeholder": True,
        "model_name": model_name,
        "num_classes": num_classes,
        "generated_at": datetime.now(UTC).isoformat(),
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
                        help="Directory for checkpoint/labels/meta (default: model_cache_dir)")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    if args.out:
        out = Path(args.out)
        ckpt = out / Path(s.model_checkpoint_path).name
        labels = out / Path(s.labels_path).name
    else:
        ckpt = s.model_cache_dir / Path(s.model_checkpoint_path).name
        labels = s.model_cache_dir / Path(s.labels_path).name

    if ckpt.resolve() == Path(s.model_checkpoint_path).resolve():
        parser.error("Test weights must not overwrite the bundled trained checkpoint.")

    written = generate_placeholder(
        ckpt, labels, model_name=s.model_name, num_classes=s.num_classes, seed=args.seed
    )
    print("Wrote placeholder VADViT artifacts:")
    for k, v in written.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
