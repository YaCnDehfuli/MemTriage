"""Reproduce VADViT's region → RGB grid rendering EXACTLY.

Each VAD region becomes one ``patch_size × patch_size × 3`` patch:

* **R** — feature image: constant ``TAG_MAPPING[tag] + PROTECTION_MAPPING[prot]``
* **G** — dynamic sliding-window Shannon entropy, min-max scaled to 0-255
* **B** — 256×256 Markov byte-transition table, log1p/normalize/sqrt, mean-pooled

Patches are ordered executable-regions-then-dll-regions, each sorted by VAD start
address, zero-padded/truncated to ``grid_size²``, and pasted row-major into the
grid. This is a faithful transcription of VADViT's
``Data Preprocessing/Consolidated_to_Grid/process2image.py`` (``ProcessVisulaizer``);
``tests/test_grid_render.py`` asserts byte-for-byte equality against that class,
so any drift is caught. Channel order (feature, entropy, markov) is load-bearing
because the model's ImageNet Normalize is per-channel.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from PIL import Image

# VADViT preprocessing mappings (Consolidated_to_Grid config).
TAG_MAPPING = {"Vad": 50, "VadS": 80, "VadF": 100}
PROTECTION_MAPPING = {"PAGE_EXECUTE_READWRITE": 45, "PAGE_EXECUTE_WRITECOPY": 0}


@dataclass
class Region:
    """One dumped VAD region ready to render."""

    addr: int                 # Start VPN (used for ordering)
    tag: str                  # Vad / VadS / VadF
    protection: str           # PAGE_EXECUTE_* etc.
    category: str             # "exe" | "dll" (grid uses these, in this order)
    data: np.ndarray          # uint8 byte array of the region


# --------------------------------------------------------------------------
# Per-channel math — transcribed from ProcessVisulaizer, verified byte-exact.
# --------------------------------------------------------------------------

def feature_image(patch_size: int, tag: str, protection: str) -> np.ndarray:
    value = TAG_MAPPING.get(tag, 0) + PROTECTION_MAPPING.get(protection, 0)
    return np.full((patch_size, patch_size), value, dtype=np.uint8)


def _entropy(data: np.ndarray) -> float:
    if len(data) == 0:
        return 0
    probabilities = np.bincount(data, minlength=256) / len(data)
    probabilities = probabilities[probabilities > 0]
    return -np.sum(probabilities * np.log2(probabilities))


def entropy_image(patch_size: int, data: np.ndarray) -> np.ndarray:
    n = patch_size * patch_size
    if len(data) == 0:
        return np.zeros((patch_size, patch_size), dtype=np.uint8)
    window = math.ceil(len(data) / n)  # DYNAMIC
    values = [_entropy(data[i:i + window]) for i in range(0, len(data), window)]
    values = (values + [0] * n)[:n]
    arr = np.array(values).reshape((patch_size, patch_size))
    normalized = ((arr - np.min(arr)) / (np.max(arr) - np.min(arr) + 1e-9)) * 255
    return normalized.astype(np.uint8)


def _byte_tables(data: np.ndarray) -> np.ndarray:
    freq = np.zeros((256, 256), dtype=np.int32)
    np.add.at(freq, (data[:-1], data[1:]), 1)
    log_freq = np.log1p(freq)
    max_per_row = log_freq.max(axis=1, keepdims=True)
    scaled = np.divide(log_freq, max_per_row, out=np.zeros_like(log_freq), where=max_per_row != 0)
    row_sums = scaled.sum(axis=1, keepdims=True)
    return np.divide(scaled, row_sums, out=np.zeros_like(scaled), where=row_sums != 0)


def _downsample_mean(image: np.ndarray, patch_size: int) -> np.ndarray:
    h, _ = image.shape
    factor = h // patch_size
    reshaped = image.reshape(patch_size, factor, patch_size, factor)
    return reshaped.mean(axis=(1, 3))


def markov_image(patch_size: int, data: np.ndarray) -> np.ndarray:
    table = _byte_tables(data)
    stretched = (table - table.min()) / (table.max() - table.min())
    enhanced = np.sqrt(stretched) * 255
    hist_eq = (enhanced - enhanced.min()) / (enhanced.max() - enhanced.min())
    color_map = (hist_eq * 255).astype(np.uint8)
    return _downsample_mean(color_map, patch_size).astype(np.uint8)


def region_to_patch(patch_size: int, region: Region) -> np.ndarray:
    f = feature_image(patch_size, region.tag, region.protection)
    e = entropy_image(patch_size, region.data)
    m = markov_image(patch_size, region.data)
    return np.stack([f, e, m], axis=-1)


# --------------------------------------------------------------------------
# Grid assembly (MemTriage owns ordering/padding; matches proc_to_img)
# --------------------------------------------------------------------------

def order_regions(regions: list[Region]) -> list[Region]:
    """Executable regions first, then dll regions; each sorted by start address."""
    exe = sorted((r for r in regions if r.category == "exe"), key=lambda r: r.addr)
    dll = sorted((r for r in regions if r.category == "dll"), key=lambda r: r.addr)
    return exe + dll


def render_grid(regions: list[Region], patch_size: int, grid_size: int) -> np.ndarray:
    """Return the (H, W, 3) uint8 grid image array."""
    num_patches = grid_size * grid_size
    ordered = order_regions(regions)
    patches = [region_to_patch(patch_size, r) for r in ordered]

    if len(patches) < num_patches:
        pad = np.zeros((patch_size, patch_size, 3), dtype=np.uint8)
        patches.extend([pad] * (num_patches - len(patches)))
    else:
        patches = patches[:num_patches]

    side = grid_size * patch_size
    grid = np.zeros((side, side, 3), dtype=np.uint8)
    for idx, patch in enumerate(patches):
        row, col = divmod(idx, grid_size)
        grid[row * patch_size:(row + 1) * patch_size,
             col * patch_size:(col + 1) * patch_size] = patch
    return grid


def render_grid_png(regions: list[Region], patch_size: int, grid_size: int, out_path) -> int:
    """Render the grid and save it as PNG. Returns the number of regions used."""
    grid = render_grid(regions, patch_size, grid_size)
    Image.fromarray(grid, mode="RGB").save(out_path)
    return min(len(regions), grid_size * grid_size)
