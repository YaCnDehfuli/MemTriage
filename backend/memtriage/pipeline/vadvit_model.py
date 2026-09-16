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
* **Always something to explain.** The trained weights are not distributed with
  the project. When they are absent, a seeded placeholder is generated once into
  ``model_cache_dir`` so rendering, classification, the attention map and the
  region deep-dive that hangs off it all still run — labelled, throughout, as a
  non-detection.

Preprocessing matches VADViT's evaluation path (``dataset_loader`` → ``val_transform``):
Resize(224) → ToTensor → Normalize(ImageNet). torch/timm/torchvision are imported
lazily so the API, worker and test processes import this module without them.
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from ..config import get_settings

logger = logging.getLogger(__name__)

IMAGENET_MEAN = (0.485, 0.456, 0.406)
IMAGENET_STD = (0.229, 0.224, 0.225)
META_FILENAME = "model_meta.json"
PLACEHOLDER_VERDICT_NOTE = (
    "Untrained structural placeholder — this family label is NOT a detection. "
    "The attention map and region analysis below are architectural and still "
    "describe real memory; the class name is not evidence of anything."
)


@dataclass
class Verdict:
    """A VADViT classification result (or an honest 'no verdict' state)."""

    model_loaded: bool
    family: str | None = None
    confidence: float | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    placeholder: bool = False
    note: str = ""
    model_source: str = "none"  # trained | placeholder | none

    def to_dict(self) -> dict:
        return {
            "model_loaded": self.model_loaded,
            "family": self.family,
            "confidence": self.confidence,
            "probabilities": self.probabilities,
            "placeholder": self.placeholder,
            "note": self.note,
            "model_source": self.model_source,
        }

    @classmethod
    def unavailable(cls, note: str) -> Verdict:
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

        def forward(self, x):
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
                 num_classes: int, image_size: int, device: str = "cpu",
                 *, cache_dir=None, auto_placeholder: bool = False,
                 placeholder_seed: int = 0, upload_dir=None) -> None:
        self.checkpoint_path = Path(checkpoint_path)
        self.labels_path = Path(labels_path)
        self.model_name = model_name
        self.num_classes = num_classes
        self.image_size = image_size
        self.device = device
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.upload_dir = Path(upload_dir) if upload_dir else None
        self.auto_placeholder = auto_placeholder
        self.placeholder_seed = placeholder_seed
        self._model = None
        self._labels: list[str] | None = None
        self._resolved: Path | None = None
        # Which file the loaded model came from, and the version of it. The
        # uploader is the API process and the loader is the worker, so an upload
        # is never an in-process event the cache could be told about — the only
        # thing both sides share is the file. See _stamp.
        self._model_stamp: tuple | None = None
        self._labels_stamp: tuple | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _stamp(path: Path | None) -> tuple | None:
        """Identity of a file's current contents, cheap enough to check per call.

        Path alone is not enough: replacing an upload keeps the name. Size and
        mtime move whenever the bytes do, which is what a cross-process cache
        needs to notice.
        """
        if path is None:
            return None
        try:
            st = path.stat()
        except OSError:
            return None
        return (str(path), st.st_mtime_ns, st.st_size)

    @property
    def trained_checkpoint_present(self) -> bool:
        return self.checkpoint_path.exists()

    @property
    def uploaded_checkpoint_path(self) -> Path | None:
        if self.upload_dir is None:
            return None
        return self.upload_dir / self.checkpoint_path.name

    @property
    def uploaded_checkpoint_present(self) -> bool:
        path = self.uploaded_checkpoint_path
        return bool(path and path.exists())

    @property
    def cached_placeholder_path(self) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / self.checkpoint_path.name

    def _checkpoint_obtainable(self) -> bool:
        """A checkpoint exists, or one can be generated once torch is importable."""
        if self.trained_checkpoint_present or self.uploaded_checkpoint_present:
            return True
        cached = self.cached_placeholder_path
        if cached is not None and cached.exists():
            return True
        return bool(self.auto_placeholder and self.cache_dir is not None)

    @property
    def checkpoint_present(self) -> bool:
        """True when a checkpoint is loadable right now."""
        return self._checkpoint_obtainable() and (
            self.trained_checkpoint_present
            or self.uploaded_checkpoint_present
            or (self.cached_placeholder_path or Path()).exists()
            or torch_available()
        )

    def available(self) -> bool:
        return self.checkpoint_present and torch_available()

    def resolve_labels_path(self) -> Path:
        """Labels beside the weights that are actually in use."""
        candidates = [self.labels_path]
        if self.upload_dir is not None:
            candidates.insert(0, self.upload_dir / self.labels_path.name)
        if self.cache_dir is not None:
            candidates.append(self.cache_dir / self.labels_path.name)
        # Uploaded labels only apply while uploaded weights are the ones loaded;
        # otherwise a stale upload would rename the placeholder's classes.
        if not self.uploaded_checkpoint_present and self.upload_dir is not None:
            candidates.pop(0)
        for path in candidates:
            if path.exists():
                return path
        return self.labels_path

    @property
    def labels(self) -> list[str]:
        path = self.resolve_labels_path()
        stamp = self._stamp(path)
        if self._labels is None or stamp != self._labels_stamp:
            self._labels = load_labels(path, self.num_classes)
            self._labels_stamp = stamp
        return self._labels

    def resolve_checkpoint(self) -> Path | None:
        """Mounted weights, else uploaded weights, else a placeholder.

        Recomputed on every call rather than memoized. The weights can change
        underneath a long-lived worker -- someone uploads a checkpoint through
        the UI, or deletes one -- and a cached answer would keep that worker
        classifying with the file it happened to see first, with nothing in the
        output saying so. The checks are a few stat() calls; only generating a
        placeholder is expensive, and that stays guarded.
        """
        # A deliberate read-only mount outranks a runtime upload: it is the
        # deployment's own configuration. model_status reports which one won, so
        # an upload can never be silently ignored.
        if self.trained_checkpoint_present:
            self._resolved = self.checkpoint_path
            return self._resolved
        uploaded = self.uploaded_checkpoint_path
        if uploaded is not None and uploaded.exists():
            self._resolved = uploaded
            return uploaded

        cached = self.cached_placeholder_path
        if cached is None:
            return None
        if cached.exists():
            self._resolved = cached
            return cached
        if not self.auto_placeholder or not torch_available():
            return None

        with self._lock:
            if cached.exists():
                self._resolved = cached
                return cached
            try:
                from .placeholder_model import generate_placeholder

                cached.parent.mkdir(parents=True, exist_ok=True)
                generate_placeholder(
                    cached, cached.parent / self.labels_path.name,
                    model_name=self.model_name, num_classes=self.num_classes,
                    seed=self.placeholder_seed,
                )
            except Exception:
                logger.exception("could not generate the placeholder checkpoint")
                return None
        self._labels = None
        self._resolved = cached
        return cached

    def _is_placeholder(self, checkpoint: Path) -> bool:
        meta = checkpoint.parent / META_FILENAME
        if not meta.exists():
            return False
        try:
            return bool(json.loads(meta.read_text()).get("placeholder", False))
        except (ValueError, OSError):
            return False

    def source_of(self, checkpoint: Path) -> str:
        """Where the weights behind a verdict came from: mounted, uploaded, or generated.

        "trained" is a claim about provenance, so an uploaded file does not get
        to borrow it. The operator supplied those weights; the report says so and
        lets the reader judge them.
        """
        if self._is_placeholder(checkpoint):
            return "placeholder"
        uploaded = self.uploaded_checkpoint_path
        if uploaded is not None and checkpoint == uploaded:
            return "uploaded"
        return "trained"

    def _ensure_model(self, checkpoint: Path):
        stamp = self._stamp(checkpoint)
        if self._model is not None and stamp == self._model_stamp:
            return self._model
        import torch

        model = build_model(self.model_name, self.num_classes, pretrained=False)
        # Local .pt we placed (research-facility or generated placeholder).
        # weights_only rejects pickled objects; Bandit still flags the API.
        state = torch.load(  # nosec B614
            str(checkpoint), map_location=self.device, weights_only=True,
        )
        if isinstance(state, dict) and "state_dict" in state \
                and not any(str(k).startswith("vit.") for k in state):
            state = state["state_dict"]
        model.load_state_dict(state)
        model.to(self.device).eval()
        self._model = model
        self._model_stamp = stamp
        return model

    def classify(self, grid_png_path) -> Verdict:
        """Classify a rendered grid PNG. Degrades honestly, never fabricates."""
        if not self._checkpoint_obtainable():
            return Verdict.unavailable("VADViT checkpoint not mounted — verdict disabled.")
        if not torch_available():
            return Verdict.unavailable(
                "PyTorch/timm unavailable in this environment — verdict disabled."
            )
        checkpoint = self.resolve_checkpoint()
        if checkpoint is None:
            return Verdict.unavailable(
                "VADViT checkpoint could not be prepared — verdict disabled."
            )
        png = Path(grid_png_path)
        if not png.exists():
            return Verdict.unavailable("No grid image available to classify.")
        try:
            import torch
            from PIL import Image

            model = self._ensure_model(checkpoint)
            transform = val_transform(self.image_size)
            image = Image.open(str(png)).convert("RGB")
            tensor = transform(image).unsqueeze(0).to(self.device)
            with torch.no_grad():
                logits = model(tensor)
                probs = torch.nn.functional.softmax(logits, dim=1).squeeze(0)
            probs_list = [float(v) for v in probs.detach().cpu().tolist()]
        except Exception as exc:
            return Verdict.unavailable(
                f"VADViT inference unavailable ({type(exc).__name__})."
            )

        labels = self.labels
        idx = max(range(len(probs_list)), key=lambda i: probs_list[i])
        prob_map = {
            (labels[i] if i < len(labels) else f"class_{i}"): round(probs_list[i], 6)
            for i in range(len(probs_list))
        }
        source = self.source_of(checkpoint)
        placeholder = source == "placeholder"
        notes = {
            "placeholder": PLACEHOLDER_VERDICT_NOTE,
            "uploaded": ("VADViT classification using operator-supplied weights "
                         "(uploaded through the UI, not the checkpoint shipped "
                         "with this deployment)."),
            "trained": "VADViT classification.",
        }
        return Verdict(
            model_loaded=True,
            family=labels[idx] if idx < len(labels) else f"class_{idx}",
            confidence=round(probs_list[idx], 6),
            probabilities=prob_map,
            placeholder=placeholder,
            note=notes[source],
            model_source=source,
        )

    def attention_map(self, grid_png_path) -> list[float] | None:
        """Flat CLS→patch attention from the last block (``grid_size**2`` values).

        Reproduces VADViT's hook (``blocks[-1].attn``: q·kᵀ/√d → softmax, take the
        CLS row's attention to patches). Returns ``None`` when unavailable — the
        overlay is architectural, so it works with the placeholder weights too.
        """
        if not self._checkpoint_obtainable() or not torch_available():
            return None
        checkpoint = self.resolve_checkpoint()
        if checkpoint is None or not Path(grid_png_path).exists():
            return None
        try:
            import torch
            from PIL import Image

            model = self._ensure_model(checkpoint)
            captured: dict = {}

            def _hook(module, inp, output):
                qkv = module.qkv(inp[0])
                q, k, _ = qkv.chunk(3, dim=-1)
                scores = (q @ k.transpose(-2, -1)) / (q.shape[-1] ** 0.5)
                captured["attn"] = scores.softmax(dim=-1).detach().cpu()
                return output

            handle = model.vit.blocks[-1].attn.register_forward_hook(_hook)
            try:
                transform = val_transform(self.image_size)
                image = Image.open(str(grid_png_path)).convert("RGB")
                tensor = transform(image).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    model(tensor)
            finally:
                handle.remove()

            attn = captured.get("attn")
            if attn is None:
                return None
            cls_attention = attn[:, 0, 1:].mean(dim=0)  # CLS → patches
            return [float(v) for v in cls_attention.tolist()]
        except Exception:
            return None


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
        cache_dir=s.model_cache_dir,
        auto_placeholder=s.model_auto_placeholder,
        placeholder_seed=s.placeholder_seed,
        upload_dir=s.model_upload_dir,
    )


def model_status() -> dict:
    """What the UI needs to explain which weights produced a verdict."""
    s = get_settings()
    clf = get_classifier()
    trained = clf.trained_checkpoint_present
    uploaded = clf.uploaded_checkpoint_present
    cached = clf.cached_placeholder_path
    active = "trained" if trained else ("uploaded" if uploaded else "placeholder")
    notes = {
        "trained": "Trained VADViT weights in use.",
        "uploaded": ("Operator-supplied weights in use. Provenance is the "
                     "uploader's to vouch for; this deployment did not train "
                     "or verify them."),
        "placeholder": PLACEHOLDER_VERDICT_NOTE,
    }
    uploaded_path = clf.uploaded_checkpoint_path
    detail = None
    if uploaded and uploaded_path is not None:
        stat = uploaded_path.stat()
        detail = {
            "filename": uploaded_path.name,
            "size_bytes": stat.st_size,
            "uploaded_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                                   .isoformat().replace("+00:00", "Z"),
            "labels_uploaded": (clf.upload_dir / clf.labels_path.name).exists(),
            # An upload that a mount outranks is still stored, and saying so is
            # the difference between "ignored" and "silently ignored".
            "superseded_by_mount": trained,
        }
    return {
        "active_source": active,
        "trained_weights_present": trained,
        "uploaded_weights_present": uploaded,
        "uploaded_weights": detail,
        "placeholder_active": active == "placeholder",
        "placeholder_cached": bool(cached and cached.exists()),
        "auto_placeholder": s.model_auto_placeholder,
        "runtime_available": torch_available(),
        "labels": clf.labels,
        "max_upload_bytes": s.max_model_upload_bytes,
        "expected_filename": clf.checkpoint_path.name,
        "contact": s.model_contact,
        "note": notes[active],
    }
