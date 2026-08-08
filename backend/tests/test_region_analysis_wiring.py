"""The phase-2 region artifacts: manifest, deep-dives, and the routes serving them."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from memtriage.pipeline import grid_render as gr
from memtriage.pipeline import region_dump as rd
from memtriage.pipeline import vadvit_model as vm
from memtriage.storage import ProcessPaths

_PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6360000002000100ffff03000006"
    "0005570bce0000000049454e44ae426082"
)

SHELLCODE = (
    b"\x90" * 24
    + bytes.fromhex("e8000000005b")
    + b"\x64\xa1\x30\x00\x00\x00"
    + b"http://c2.example/beacon\x00"
    + bytes.fromhex("554889e54883ec2085c0740583c001eb0383c8ffc9c3")
)


def _region(addr: int, data: bytes, protection="PAGE_EXECUTE_READWRITE", category="exe"):
    return gr.Region(
        addr=addr, tag="VadS", protection=protection, category=category,
        data=np.frombuffer(data, dtype=np.uint8), end_addr=addr + len(data),
        file_backing="", dmp_path=f"/tmp/{addr:x}.dmp", snapshot_ordinal=0, private=True,
    )


def _triaged(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"x" * 64,
                headers={"X-Filename": "mem.raw"})
    monkeypatch.setattr(vml, "run_triage", lambda *a, **k: {
        "features": {}, "dashboard": {}, "processes": [], "profile": {},
        "manifest": {}, "vol_version": "test",
    })
    run_triage.apply(args=[inv_id])
    return inv_id


@pytest.fixture
def analyzed(client, monkeypatch):
    inv_id = _triaged(client, monkeypatch)
    regions = [
        _region(0x400000, SHELLCODE),
        _region(0x500000, b"\x00" * 512, protection="PAGE_EXECUTE_READ", category="dll"),
    ]
    monkeypatch.setattr(rd, "dump_snapshot", lambda *a, **k: regions)
    monkeypatch.setattr(gr, "render_grid_png",
                        lambda regs, ps, gs, path: Path(path).write_bytes(_PNG_1x1))

    verdict = vm.Verdict(model_loaded=True, family="Placeholder_Trojan", confidence=0.61,
                         probabilities={"Benign": 0.39, "Placeholder_Trojan": 0.61},
                         placeholder=True, note=vm.PLACEHOLDER_VERDICT_NOTE,
                         model_source="placeholder")

    class _Clf:
        def classify(self, _png):
            return verdict

        def attention_map(self, _png):
            # Patch 0 is the shellcode region; give it the higher score.
            return [0.9, 0.2] + [0.0] * 47

    monkeypatch.setattr(vm, "get_classifier", lambda: _Clf())
    monkeypatch.setattr("memtriage.pipeline.explain.render_attention_overlay",
                        lambda *a, **k: str(a[3]) if len(a) > 3 else "")

    from memtriage.workers.tasks import run_process_analysis

    aid = client.post(f"/api/investigations/{inv_id}/processes/analyze",
                      json={"pid": 1337}).json()["analysis_id"]
    run_process_analysis.apply(args=[aid])
    return inv_id, 1337


def test_manifest_ranks_every_rendered_region(analyzed, client):
    inv_id, pid = analyzed
    manifest = client.get(f"/api/investigations/{inv_id}/processes/{pid}/regions").json()
    assert len(manifest) == 2
    assert [r["rank"] for r in manifest] == [1, 2]
    top = manifest[0]
    assert top["addr"] == "0x400000"
    assert top["attention"] > manifest[1]["attention"]
    assert "rwx" in top["flags"] and "private-executable" in top["flags"]
    assert top["sha256"] and top["size"] == len(SHELLCODE)


def test_lowlevel_analyzes_the_top_region(analyzed, client):
    inv_id, pid = analyzed
    body = client.get(f"/api/investigations/{inv_id}/processes/{pid}/lowlevel").json()
    assert body["ranked_regions"] == 2
    assert len(body["regions"]) == 2
    top = body["regions"][0]
    assert top["region"]["addr"] == "0x400000"
    assert top["structure"]["size"] == len(SHELLCODE)
    ids = {h["id"] for h in top["patterns"]["hits"]}
    assert {"rwx_region", "private_executable"} <= ids
    urls = [s["value"] for s in top["strings"]["interesting"]]
    assert any("c2.example" in u for u in urls)


def test_single_region_route_selects_by_patch_index(analyzed, client):
    inv_id, pid = analyzed
    body = client.get(f"/api/investigations/{inv_id}/processes/{pid}/lowlevel/0").json()
    assert body["region"]["patch_index"] == 0
    missing = client.get(f"/api/investigations/{inv_id}/processes/{pid}/lowlevel/44")
    assert missing.status_code == 404


def test_analysis_json_carries_the_manifest_and_caveats(analyzed, client):
    inv_id, pid = analyzed
    result = client.get(f"/api/investigations/{inv_id}/result").json()
    analysis = result["process_analyses"][0]
    assert analysis["explainability"]["region_count_ranked"] == 2
    assert analysis["explainability"]["regions_analyzed"] == 2
    assert len(analysis["regions"]) == 2
    assert analysis["region_analysis_summary"]["analyzed"] == 2
    notes = " ".join(analysis["notes"]).lower()
    assert "not a detection" in notes
    assert "not conclusions" in notes


def test_artifacts_are_written_to_the_process_directory(analyzed):
    inv_id, pid = analyzed
    paths = ProcessPaths(inv_id, pid)
    assert paths.region_manifest.exists()
    assert paths.lowlevel.exists()
    assert json.loads(paths.lowlevel.read_text())["grid_size"] == 7


def test_routes_404_before_an_analysis_has_run(client, monkeypatch):
    inv_id = _triaged(client, monkeypatch)
    assert client.get(f"/api/investigations/{inv_id}/processes/999/regions").status_code == 404
    assert client.get(f"/api/investigations/{inv_id}/processes/999/lowlevel").status_code == 404


def test_region_analysis_failure_does_not_fail_the_analysis(client, monkeypatch):
    inv_id = _triaged(client, monkeypatch)
    monkeypatch.setattr(rd, "dump_snapshot", lambda *a, **k: [_region(0x1000, SHELLCODE)])
    monkeypatch.setattr(gr, "render_grid_png",
                        lambda regs, ps, gs, path: Path(path).write_bytes(_PNG_1x1))
    monkeypatch.setattr("memtriage.lowlevel.build_manifest",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    from memtriage.workers.tasks import run_process_analysis

    aid = client.post(f"/api/investigations/{inv_id}/processes/analyze",
                      json={"pid": 4242}).json()["analysis_id"]
    assert run_process_analysis.apply(args=[aid]).result == "done"
    state = client.get(f"/api/investigations/{inv_id}/analyses/{aid}").json()
    assert state["status"] == "done"
