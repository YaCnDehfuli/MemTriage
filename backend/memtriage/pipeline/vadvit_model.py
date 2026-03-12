"""VADViT model adapter — classify a rendered process grid into a family verdict.

Design goals:

* **Zero-change swap-in.** :func:`build_model` reproduces VADViT's ``ViTForImages``
  module layout exactly (``self.vit = timm.create_model(name); self.vit.head =
  Linear(num_features, num_classes)``), so the real ``Multi_32_224_6f_3u.pt``
  state_dict loads with no code changes — the placeholder and the real model are
  structurally identical.
* **Never a fabricated verdict.** If the checkpoint is not mounted, or PyTorch/timm
  are unavailable, or anything fails, :meth:`VADViTClassifier.classify` returns a
  degraded ``Verdict(model_loaded=False)`` — it never invents a family.
* **Honest about placeholders.** A structural placeholder checkpoint carries a
  ``model_meta.json`` marker; the verdict is flagged ``placeholder`` so the UI can
  make clear the class is not a real detection.

Preprocessing matches VADViT's evaluation path (``dataset_loader`` → ``val_transform``):
Resize(224) → ToTensor → Normalize(ImageNet). torch/timm/torchvision are imported
lazily so the API, worker and test processes import this module without them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..config import get_settings

IMAGENET_MEAN = (0.485, 0.456, 0.406)
IMAGENET_STD = (0.229, 0.224, 0.225)
META_FILENAME = "model_meta.json"


@dataclass
class Verdict:
    """A VADViT classification result (or an honest 'no verdict' state)."""

    model_loaded: bool
    family: str | None = None
    confidence: float | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    placeholder: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "model_loaded": self.model_loaded,
            "family": self.family,
            "confidence": self.confidence,
            "probabilities": self.probabilities,
            "placeholder": self.placeholder,
            "note": self.note,
        }

    @classmethod
    def unavailable(cls, note: str) -> "Verdict":
        return cls(model_loaded=False, note=note)


def torch_available() -> bool:
    """True iff the inference stack (torch + timm + torchvision) can be imported."""
    try:
        import timm  # noqa: F401
        import torch  # noqa: F401
        import torchvision  # noqa: F401
        return True
    except Exception:
        return False


def build_model(model_name: str, num_classes: int, *, pretrained: bool = False):
    """Reproduce VADViT's ``ViTForImages`` (no config coupling).

    Same submodule layout as the published model, so a trained state_dict loads
    unchanged. ``pretrained=False`` by default: for the placeholder we want random
    init, and when loading a real checkpoint the state_dict overwrites the weights
    anyway (and avoids a network fetch of ImageNet weights). Frozen-layer
    bookkeeping is training-only and intentionally omitted.
    """
    import torch.nn as nn
    from timm import create_model

    class ViTForImages(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.vit = create_model(model_name, pretrained=pretrained)
            self.vit.head = nn.Linear(self.vit.num_features, num_classes)

        def forward(self, x):  # noqa: ANN001
            return self.vit(x)

    return ViTForImages()


def val_transform(image_size: int):
    """VADViT's evaluation transform: Resize → ToTensor → Normalize(ImageNet)."""
    import torchvision.transforms as T

    return T.Compose([
        T.Resize((image_size, image_size)),
        T.ToTensor(),
        T.Normalize(mean=list(IMAGENET_MEAN), std=list(IMAGENET_STD)),
    ])


def load_labels(labels_path, num_classes: int) -> list[str]:
    """Load the index→family label list; fall back to generic class names.

    Accepts a JSON list ``["Benign", ...]`` (index order, as VADViT's
    ``sorted(os.listdir(dataset_dir))`` produces) or a mapping ``{"0": "Benign"}``.
    """
    p = Path(labels_path)
    labels: list[str] = []
    if p.exists():
        try:
            data = json.loads(p.read_text())
            if isinstance(data, dict):
                data = data.get("labels") or [data[k] for k in sorted(data, key=str)]
            if isinstance(data, list):
                labels = [str(x) for x in data]
        except (ValueError, OSError):
            labels = []
    if len(labels) >= num_classes:
        return labels[:num_classes]
    return labels + [f"class_{i}" for i in range(len(labels), num_classes)]


class VADViTClassifier:
    """Lazily-loaded VADViT classifier with a clean ``classify(png) -> Verdict``."""

    def __init__(self, checkpoint_path, labels_path, model_name: str,
                 num_classes: int, image_size: int, device: str = "cpu") -> None:
        self.checkpoint_path = Path(checkpoint_path)
        self.labels_path = labels_path
        self.model_name = model_name
        self.num_classes = num_classes
        self.image_size = image_size
        self.device = device
        self._model = None
        self._labels: list[str] | None = None

    @property
    def checkpoint_present(self) -> bool:
        return self.checkpoint_path.exists()

    def available(self) -> bool:
        return self.checkpoint_present and torch_available()

    @property
    def labels(self) -> list[str]:
        if self._labels is None:
            self._labels = load_labels(self.labels_path, self.num_classes)
        return self._labels

    def _is_placeholder(self) -> bool:
        meta = self.checkpoint_path.parent / META_FILENAME
        if not meta.exists():
            return False
        try:
            return bool(json.loads(meta.read_text()).get("placeholder", False))
        except (ValueError, OSError):
            return False

    def _ensure_model(self):
        if self._model is not None:
            return self._model
        import torch

        model = build_model(self.model_name, self.num_classes, pretrained=False)
        state = torch.load(str(self.checkpoint_path), map_location=self.device)
        if isinstance(state, dict) and "state_dict" in state \
                and not any(str(k).startswith("vit.") for k in state):
            state = state["state_dict"]
        model.load_state_dict(state)
        model.to(self.device).eval()
        self._model = model
        return model

    def classify(self, grid_png_path) -> Verdict:
        """Classify a rendered grid PNG. Degrades honestly, never fabricates."""
        if not self.checkpoint_present:
            return Verdict.unavailable("VADViT checkpoint not mounted — verdict disabled.")
        if not torch_available():
            return Verdict.unavailable(
                "PyTorch/timm unavailable in this environment — verdict disabled."
            )
        png = Path(grid_png_path)
        if not png.exists():
            return Verdict.unavailable("No grid image available to classify.")
        try:
            import torch
            from PIL import Image

            model = self._ensure_model()
            transform = val_transform(self.image_size)
            image = Image.open(str(png)).convert("RGB")
            tensor = transform(image).unsqueeze(0).to(self.device)
            with torch.no_grad():
                logits = model(tensor)
                probs = torch.nn.functional.softmax(logits, dim=1).squeeze(0)
            probs_list = [float(v) for v in probs.detach().cpu().tolist()]
        except Exception as exc:  # noqa: BLE001 - degrade, never crash the pipeline
            return Verdict.unavailable(
                f"VADViT inference unavailable ({type(exc).__name__})."
            )

        labels = self.labels
        idx = max(range(len(probs_list)), key=lambda i: probs_list[i])
        prob_map = {
            (labels[i] if i < len(labels) else f"class_{i}"): round(probs_list[i], 6)
            for i in range(len(probs_list))
        }
        placeholder = self._is_placeholder()
        note = ("Structural placeholder model — the family label is NOT a real "
                "detection." if placeholder else "VADViT classification.")
        return Verdict(
            model_loaded=True,
            family=labels[idx] if idx < len(labels) else f"class_{idx}",
            confidence=round(probs_list[idx], 6),
            probabilities=prob_map,
            placeholder=placeholder,
            note=note,
        )


@lru_cache
def get_classifier() -> VADViTClassifier:
    """Process-wide classifier built from settings (weights loaded on first use)."""
    s = get_settings()
    return VADViTClassifier(
        checkpoint_path=s.model_checkpoint_path,
        labels_path=s.labels_path,
        model_name=s.model_name,
        num_classes=s.num_classes,
        image_size=s.image_size,
        device=s.device,
    )
