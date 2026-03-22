"""Explainability: magma LUT, patch→VAD attribution, overlay rendering, and the
run_process_analysis explaining-stage wiring. All pure (no torch)."""
import json
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from memtriage.pipeline import explain as ex


def _write_png(path):  # noqa: ANN001
    Image.new("RGB", (224, 224), (10, 20, 30)).save(str(path))


@dataclass
class _Reg:
    addr: int
    category: str


# --------------------------------------------------------------------------
# colormap + overlay
# --------------------------------------------------------------------------

def test_magma_lut_shape_and_endpoints():
    lut = ex.magma_lut()
    assert lut.shape == (256, 3) and lut.dtype.name == "uint8"
    assert tuple(lut[0]) == (0, 0, 4)          # magma starts near-black
    assert tuple(lut[-1]) == (252, 253, 191)   # ends near-white


def test_render_attention_overlay_writes_same_size_png(tmp_path):
    base = tmp_path / "grid.png"
    Image.new("RGB", (224, 224), (10, 20, 30)).save(base)
    attention = [0.0] * 49
    attention[24] = 1.0  # center patch hot
    out = tmp_path / "attention.png"
    ex.render_attention_overlay(base, attention, grid_size=7, out_path=out)
    assert out.exists()
    with Image.open(out) as im:
        assert im.size == (224, 224) and im.mode == "RGB"


# --------------------------------------------------------------------------
# attribution
# --------------------------------------------------------------------------

def test_attribution_maps_top_patch_to_region():
    regions = [_Reg(0x1000, "exe"), _Reg(0x2000, "dll"), _Reg(0x3000, "dll")]
    attention = [0.1, 0.9, 0.3, 0.0]         # patch 1 dominates
    table = ex.attribution_table(attention, regions, grid_size=2, top_k=8)
    assert table[0]["patch_index"] == 1
    assert table[0]["region_addr"] == hex(0x2000)
    assert table[0]["category"] == "dll"
    assert table[0]["attention"] >= table[1]["attention"]     # sorted desc
    assert table[0]["attention"] == 1.0                       # relative-normalized


def test_attribution_respects_top_k_and_region_bound():
    regions = [_Reg(0x100 * i, "exe") for i in range(1, 4)]   # 3 regions
    attention = [0.5, 0.4, 0.3, 0.2]                          # grid has 4 patches
    table = ex.attribution_table(attention, regions, grid_size=2, top_k=2)
    assert len(table) == 2                                    # top_k
    # only patches with a backing region are attributed (3, not 4)
    full = ex.attribution_table(attention, regions, grid_size=2, top_k=99)
    assert len(full) == 3


# --------------------------------------------------------------------------
# task wiring
# --------------------------------------------------------------------------

def test_process_analysis_produces_attention_and_attributions(client, monkeypatch):
    from memtriage.pipeline import grid_render as gr
    from memtriage.pipeline import region_dump as rd
    from memtriage.pipeline import vadvit_model as vm
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_process_analysis, run_triage

    monkeypatch.setattr(vml, "run_triage", lambda *a, **k: {
        "features": {}, "vol_version": None, "processes": [],
        "dashboard": {"features": {}, "suspicious_processes": [], "injections": [],
                      "network": [], "persistence": [], "attack_techniques": []},
    })
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"RAWMEM",
                headers={"X-Filename": "m.raw"})
    run_triage.apply(args=[inv_id])

    regions = [_Reg(0x1000, "exe"), _Reg(0x2000, "dll")]
    monkeypatch.setattr(rd, "dump_snapshot", lambda *a, **k: list(regions))
    monkeypatch.setattr(gr, "render_grid_png",
                        lambda regs, ps, gs, path: _write_png(path))

    class _FakeClf:
        def classify(self, _png):  # noqa: ANN001
            return vm.Verdict(model_loaded=True, family="Placeholder_Trojan",
                              confidence=0.6, probabilities={"Placeholder_Trojan": 0.6},
                              placeholder=True, note="placeholder")

        def attention_map(self, _png):  # noqa: ANN001
            return [0.1, 0.9]  # patch 1 (the dll region) dominates

    monkeypatch.setattr(vm, "get_classifier", lambda: _FakeClf())

    aid = client.post(f"/api/investigations/{inv_id}/processes/analyze",
                      json={"pid": 1337}).json()["analysis_id"]
    run_process_analysis.apply(args=[aid])

    result = client.get(f"/api/investigations/{inv_id}/result").json()
    expl = result["process_analyses"][0]["explainability"]
    assert expl["attention_png"] == "attention"
    assert expl["attributions"], "attribution table should be populated"
    top = expl["attributions"][0]
    assert top["region_addr"] == hex(0x2000) and top["category"] == "dll"

    # the overlay artifact is on disk and served by the results API
    from memtriage.storage import ProcessPaths
    assert ProcessPaths(inv_id, 1337).attention.exists()
    r = client.get(f"/api/investigations/{inv_id}/processes/1337/artifacts/attention")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
