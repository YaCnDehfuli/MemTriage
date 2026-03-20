"""Explainability: attention heatmap overlay + patch → VAD attribution.

VADViT's last transformer block exposes how much the classification CLS token
attended to each image patch. Because the grid is rendered one VAD region per
patch in a known order (``grid_render.order_regions`` — exe-then-dll by address,
pasted row-major), each attended patch maps back to a concrete VAD region address
in the named process. This module:

* renders a magma attention heatmap over the grid PNG (``attention.png``); and
* builds an attribution table linking the most-attended patches to their VAD
  region address + category.

The overlay is reproduced with NumPy + Pillow only (VADViT's own version uses
matplotlib/cv2 with a GUI backend, unusable in a headless worker). The attention
values come from the model, but everything here is pure given those values, so it
is unit-testable without PyTorch and works identically with the placeholder model.
"""
from __future__ import annotations

import numpy as np
from PIL import Image

# Magma colormap anchor stops (t=0..1), transcribed from matplotlib's "magma".
_MAGMA_ANCHORS: list[tuple[float, tuple[int, int, int]]] = [
    (0.000, (0, 0, 4)),
    (0.125, (28, 16, 68)),
    (0.250, (79, 18, 123)),
    (0.375, (129, 37, 129)),
    (0.500, (181, 54, 122)),
    (0.625, (229, 80, 100)),
    (0.750, (251, 135, 97)),
    (0.875, (254, 194, 135)),
    (1.000, (252, 253, 191)),
]


def magma_lut() -> np.ndarray:
    """256×3 uint8 magma lookup table (linear interpolation of the anchors)."""
    xs = np.array([a for a, _ in _MAGMA_ANCHORS])
    cols = np.array([c for _, c in _MAGMA_ANCHORS], dtype=np.float32)
    t = np.linspace(0.0, 1.0, 256)
    lut = np.stack([np.interp(t, xs, cols[:, i]) for i in range(3)], axis=1)
    return lut.round().astype(np.uint8)


def _normalize(arr: np.ndarray) -> np.ndarray:
    lo, hi = float(arr.min()), float(arr.max())
    return (arr - lo) / (hi - lo + 1e-8)


def render_attention_overlay(grid_png_path, attention, grid_size: int, out_path,
                             alpha_gain: float = 1.0) -> str:
    """Composite a magma attention heatmap over the grid PNG and save it.

    ``attention`` is the flat CLS→patch attention (``grid_size**2`` values, row
    major). Returns the output path.
    """
    base = Image.open(str(grid_png_path)).convert("RGB")
    width, height = base.size

    n = grid_size * grid_size
    att = np.asarray(attention, dtype=np.float32).ravel()
    att = att[:n] if att.size >= n else np.pad(att, (0, n - att.size))
    grid = _normalize(att.reshape(grid_size, grid_size))

    # Upsample patch grid → full image with a smooth (bicubic) interpolation.
    heat = Image.fromarray((grid * 255).astype(np.uint8), mode="L").resize(
        (width, height), Image.BICUBIC
    )
    heat = np.asarray(heat, dtype=np.float32) / 255.0

    lut = magma_lut()
    heat_rgb = lut[(heat * 255).astype(np.uint8)].astype(np.float32)
    alpha = np.clip(heat * alpha_gain, 0.0, 1.0)[..., None]

    base_arr = np.asarray(base, dtype=np.float32)
    out = base_arr * (1.0 - alpha) + heat_rgb * alpha
    Image.fromarray(out.clip(0, 255).astype(np.uint8), mode="RGB").save(str(out_path))
    return str(out_path)


def attribution_table(attention, ordered_regions, grid_size: int,
                      top_k: int = 8) -> list[dict]:
    """Map the most-attended patches back to VAD regions.

    ``ordered_regions`` must be the same order the grid was rendered in
    (``grid_render.order_regions``), so patch ``i`` ↔ ``ordered_regions[i]``.
    Returns up to ``top_k`` rows sorted by attention (relative 0-1 share).
    """
    n = grid_size * grid_size
    att = np.asarray(attention, dtype=np.float32).ravel()
    att = att[:n] if att.size >= n else np.pad(att, (0, n - att.size))
    rel = _normalize(att)

    rows: list[dict] = []
    for i in range(min(n, len(ordered_regions))):
        r = ordered_regions[i]
        row, col = divmod(i, grid_size)
        addr = r.addr
        rows.append({
            "patch_index": i,
            "row": row,
            "col": col,
            "attention": round(float(rel[i]), 6),
            "region_addr": hex(addr) if isinstance(addr, int) else str(addr),
            "category": getattr(r, "category", ""),
        })
    rows.sort(key=lambda d: d["attention"], reverse=True)
    return rows[:top_k]
