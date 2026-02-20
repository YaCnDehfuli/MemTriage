"""Grid rendering: byte-for-byte fidelity against VADViT + assembly correctness."""
import importlib.util
from pathlib import Path

import numpy as np
import pytest

from memtriage.pipeline import grid_render as gr
from memtriage.pipeline.grid_render import Region

_VADVIT_P2I = (
    Path(__file__).resolve().parents[2]
    / "components/vadvit/Data Preprocessing/Consolidated_to_Grid/process2image.py"
)
_HAS_VADVIT = _VADVIT_P2I.exists()


def _load_vadvit_visualizer():
    spec = importlib.util.spec_from_file_location("vadvit_p2i", _VADVIT_P2I)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ProcessVisulaizer(32, 224, gr.TAG_MAPPING, gr.PROTECTION_MAPPING, "DYNAMIC")


def _region(addr, category, data=None):
    return Region(addr=addr, tag="VadS", protection="PAGE_EXECUTE_READWRITE",
                  category=category, data=np.zeros(256, dtype=np.uint8) if data is None else data)


@pytest.mark.skipif(not _HAS_VADVIT, reason="VADViT submodule not initialized")
def test_channels_match_vadvit_byte_for_byte():
    """Our renderer must equal VADViT's ProcessVisulaizer exactly — else the
    model silently degrades below its published accuracy."""
    viz = _load_vadvit_visualizer()
    rng = np.random.default_rng(20260115)
    for size in (256, 1000, 4096, 70000):
        data = rng.integers(0, 256, size=size, dtype=np.uint8)
        assert np.array_equal(gr.entropy_image(32, data), viz.generate_entropy_image(data)), size
        assert np.array_equal(gr.markov_image(32, data), viz.generate_markov_image(data)), size
    for tag in ("Vad", "VadS", "VadF", "Unknown"):
        for prot in ("PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY", "PAGE_READONLY"):
            assert np.array_equal(gr.feature_image(32, tag, prot),
                                  viz.generate_feature_image(tag, prot)), (tag, prot)


def test_region_to_patch_shape_and_channel_order():
    data = np.frombuffer(b"MZ" + bytes(range(256)) * 4, dtype=np.uint8)
    patch = gr.region_to_patch(32, _region(0x1000, "exe", data))
    assert patch.shape == (32, 32, 3)
    assert patch.dtype == np.uint8
    # R channel is the constant feature value (VadS + RWX = 80 + 45 = 125)
    assert (patch[:, :, 0] == 125).all()


def test_order_regions_exe_then_dll_by_address():
    regs = [_region(0x30, "dll"), _region(0x10, "exe"), _region(0x20, "exe"), _region(0x05, "dll")]
    ordered = gr.order_regions(regs)
    assert [(r.category, r.addr) for r in ordered] == [
        ("exe", 0x10), ("exe", 0x20), ("dll", 0x05), ("dll", 0x30)]


def test_render_grid_geometry_and_zero_padding():
    grid = gr.render_grid([_region(0x1000, "exe")], patch_size=32, grid_size=7)
    assert grid.shape == (224, 224, 3) and grid.dtype == np.uint8
    # only the first patch is populated; the rest are zero-padded
    assert grid[0:32, 0:32].any()
    assert not grid[0:32, 32:224].any()


def test_render_grid_truncates_to_num_patches():
    regs = [_region(i, "exe", np.full(128, i % 256, dtype=np.uint8)) for i in range(60)]
    grid = gr.render_grid(regs, patch_size=32, grid_size=7)  # 49 max
    assert grid.shape == (224, 224, 3)


def test_render_grid_is_deterministic():
    regs = [_region(0x10, "exe", np.arange(300, dtype=np.uint8) % 256),
            _region(0x20, "dll", np.arange(500, dtype=np.uint8) % 256)]
    a = gr.render_grid(regs, 32, 7)
    b = gr.render_grid(regs, 32, 7)
    assert np.array_equal(a, b)
