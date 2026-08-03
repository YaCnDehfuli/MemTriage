"""VADViT model adapter: honest degradation, label mapping, task wiring, and
(when torch/timm are present) placeholder generation + real inference.

torch/timm/torchvision are not installed in the unit environment, so the actual
inference tests importorskip and run in the Docker worker image; every degradation
and wiring path is covered without them."""
import json
from pathlib import Path

import pytest

from memtriage.pipeline import vadvit_model as vm

_PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6360000002000100ffff03000006"
    "0005570bce0000000049454e44ae426082"
)


# --------------------------------------------------------------------------
# Verdict + labels (no torch)
# --------------------------------------------------------------------------

def test_verdict_unavailable_never_fabricates():
    v = vm.Verdict.unavailable("no checkpoint")
    assert v.model_loaded is False and v.family is None and v.confidence is None
    d = v.to_dict()
    assert d["model_loaded"] is False and d["family"] is None


def test_load_labels_list_and_fallback(tmp_path):
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps(["Benign", "Trojan", "Worm"]))
    assert vm.load_labels(lp, 3) == ["Benign", "Trojan", "Worm"]
    # too few labels → padded with generic names; missing file → all generic
    assert vm.load_labels(lp, 5)[3:] == ["class_3", "class_4"]
    assert vm.load_labels(tmp_path / "nope.json", 2) == ["class_0", "class_1"]


def test_load_labels_accepts_mapping(tmp_path):
    lp = tmp_path / "labels.json"
    lp.write_text(json.dumps({"0": "Benign", "1": "Trojan"}))
    assert vm.load_labels(lp, 2) == ["Benign", "Trojan"]


# --------------------------------------------------------------------------
# graceful degradation (no torch / no checkpoint)
# --------------------------------------------------------------------------

def _clf(tmp_path, checkpoint_exists=False, placeholder=False):
    ckpt = tmp_path / "model.pt"
    if checkpoint_exists:
        ckpt.write_bytes(b"not-a-real-state-dict")
    if placeholder:
        (tmp_path / vm.META_FILENAME).write_text(json.dumps({"placeholder": True}))
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps(["Benign", "Trojan"]))
    return vm.VADViTClassifier(ckpt, labels, "vit_base_patch32_224", 2, 224, "cpu")


def test_classifier_degrades_without_checkpoint(tmp_path):
    clf = _clf(tmp_path, checkpoint_exists=False)
    assert clf.available() is False
    v = clf.classify(tmp_path / "grid.png")
    assert v.model_loaded is False and v.family is None
    assert "checkpoint" in v.note.lower()


def test_classifier_degrades_when_stack_or_checkpoint_invalid(tmp_path):
    # Checkpoint file exists but torch is absent (unit env) or the bytes are not a
    # valid state_dict (Docker) — either way: honest, non-fabricated degradation.
    png = tmp_path / "grid.png"
    png.write_bytes(_PNG_1x1)
    clf = _clf(tmp_path, checkpoint_exists=True)
    v = clf.classify(png)
    assert v.model_loaded is False and v.family is None


# --------------------------------------------------------------------------
# task wiring
# --------------------------------------------------------------------------

def _triaged(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage
    monkeypatch.setattr(vml, "run_triage", lambda *a, **k: {
        "features": {}, "vol_version": None, "processes": [],
        "dashboard": {"features": {}, "suspicious_processes": [], "injections": [],
                      "network": [], "persistence": [], "attack_techniques": []},
    })
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"RAWMEM",
                headers={"X-Filename": "m.raw"})
    run_triage.apply(args=[inv_id])
    return inv_id


def test_process_analysis_records_model_verdict(client, monkeypatch):
    inv_id = _triaged(client, monkeypatch)
    from memtriage.pipeline import grid_render as gr
    from memtriage.pipeline import region_dump as rd

    monkeypatch.setattr(rd, "dump_snapshot", lambda *a, **k: [object(), object()])
    monkeypatch.setattr(gr, "render_grid_png",
                        lambda regions, ps, gs, path: Path(path).write_bytes(_PNG_1x1))

    fake = vm.Verdict(model_loaded=True, family="Placeholder_Trojan", confidence=0.73,
                      probabilities={"Benign": 0.27, "Placeholder_Trojan": 0.73},
                      placeholder=True, note="placeholder")

    class _FakeClf:
        def classify(self, _png):  # noqa: ANN001
            return fake

    monkeypatch.setattr(vm, "get_classifier", lambda: _FakeClf())

    from memtriage.workers.tasks import run_process_analysis
    aid = client.post(f"/api/investigations/{inv_id}/processes/analyze",
                      json={"pid": 1337}).json()["analysis_id"]
    run_process_analysis.apply(args=[aid])

    state = client.get(f"/api/investigations/{inv_id}/analyses/{aid}").json()
    assert state["status"] == "done"
    assert state["model_loaded"] is True
    assert state["verdict_family"] == "Placeholder_Trojan"
    assert state["verdict_confidence"] == pytest.approx(0.73)

    result = client.get(f"/api/investigations/{inv_id}/result").json()
    verdict = result["process_analyses"][0]["verdict"]
    assert verdict["placeholder"] is True
    assert verdict["family"] == "Placeholder_Trojan"


def test_process_analysis_no_grid_is_honest(client, monkeypatch):
    inv_id = _triaged(client, monkeypatch)
    from memtriage.pipeline import region_dump as rd
    monkeypatch.setattr(rd, "dump_snapshot", lambda *a, **k: [])  # no regions → no grid

    from memtriage.workers.tasks import run_process_analysis
    aid = client.post(f"/api/investigations/{inv_id}/processes/analyze",
                      json={"pid": 1337}).json()["analysis_id"]
    run_process_analysis.apply(args=[aid])

    state = client.get(f"/api/investigations/{inv_id}/analyses/{aid}").json()
    assert state["status"] == "done"
    assert state["model_loaded"] is False and state["verdict_family"] is None


# --------------------------------------------------------------------------
# real model (torch/timm required) — runs in the Docker worker / CI
# --------------------------------------------------------------------------

def test_placeholder_generation_and_inference(tmp_path):
    pytest.importorskip("torch")
    pytest.importorskip("timm")
    pytest.importorskip("torchvision")
    from PIL import Image

    from memtriage.pipeline.placeholder_model import PLACEHOLDER_LABELS, generate_placeholder

    ckpt = tmp_path / "Multi_32_224_6f_3u.pt"
    labels = tmp_path / "labels.json"
    generate_placeholder(ckpt, labels, model_name="vit_base_patch32_224",
                         num_classes=9, seed=0)
    assert ckpt.exists() and labels.exists()
    assert (tmp_path / vm.META_FILENAME).exists()

    grid = tmp_path / "grid.png"
    Image.new("RGB", (224, 224), (123, 45, 200)).save(grid)

    clf = vm.VADViTClassifier(ckpt, labels, "vit_base_patch32_224", 9, 224, "cpu")
    assert clf.available() is True
    v = clf.classify(grid)
    assert v.model_loaded is True
    assert v.family in PLACEHOLDER_LABELS
    assert 0.0 <= v.confidence <= 1.0
    assert v.placeholder is True
    assert v.probabilities and abs(sum(v.probabilities.values()) - 1.0) < 1e-3


# --------------------------------------------------------------------------
# placeholder resolution (the trained checkpoint is not distributed)
# --------------------------------------------------------------------------

def _auto_clf(tmp_path, *, auto=True):
    return vm.VADViTClassifier(
        tmp_path / "models" / "Multi_32_224_6f_3u.pt",
        tmp_path / "models" / "labels.json",
        "vit_base_patch32_224", 2, 224, "cpu",
        cache_dir=tmp_path / "cache", auto_placeholder=auto, placeholder_seed=7,
    )


def test_trained_weights_win_over_the_cache(tmp_path):
    clf = _auto_clf(tmp_path)
    clf.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    clf.checkpoint_path.write_bytes(b"trained")
    cached = clf.cached_placeholder_path
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(b"placeholder")
    assert clf.resolve_checkpoint() == clf.checkpoint_path
    assert clf.trained_checkpoint_present is True


def test_cached_placeholder_is_reused_without_regenerating(tmp_path):
    clf = _auto_clf(tmp_path)
    cached = clf.cached_placeholder_path
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(b"placeholder")
    assert clf.resolve_checkpoint() == cached
    assert clf.trained_checkpoint_present is False


def test_labels_fall_back_to_the_cache_directory(tmp_path):
    clf = _auto_clf(tmp_path)
    cached = clf.cached_placeholder_path
    cached.parent.mkdir(parents=True, exist_ok=True)
    (cached.parent / "labels.json").write_text(json.dumps(["Benign", "Placeholder_Trojan"]))
    assert clf.labels == ["Benign", "Placeholder_Trojan"]


def test_auto_placeholder_disabled_leaves_no_checkpoint(tmp_path):
    clf = _auto_clf(tmp_path, auto=False)
    assert clf.resolve_checkpoint() is None
    assert "checkpoint" in clf.classify(tmp_path / "grid.png").note.lower()


def test_generation_failure_degrades_instead_of_raising(tmp_path, monkeypatch):
    clf = _auto_clf(tmp_path)
    monkeypatch.setattr(vm, "torch_available", lambda: True)
    monkeypatch.setattr(
        "memtriage.pipeline.placeholder_model.generate_placeholder",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no torch")),
    )
    assert clf.resolve_checkpoint() is None


def test_placeholder_checkpoints_are_detected_by_their_marker(tmp_path):
    clf = _auto_clf(tmp_path)
    cached = clf.cached_placeholder_path
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(b"placeholder")
    assert clf._is_placeholder(cached) is False
    (cached.parent / vm.META_FILENAME).write_text(json.dumps({"placeholder": True}))
    assert clf._is_placeholder(cached) is True
    (cached.parent / vm.META_FILENAME).write_text("{ not json")
    assert clf._is_placeholder(cached) is False


def test_placeholder_note_states_it_is_not_a_detection():
    assert "not a detection" in vm.PLACEHOLDER_VERDICT_NOTE.lower()
    verdict = vm.Verdict(model_loaded=True, family="Placeholder_Trojan", confidence=0.5,
                         placeholder=True, note=vm.PLACEHOLDER_VERDICT_NOTE,
                         model_source="placeholder")
    assert verdict.to_dict()["model_source"] == "placeholder"


def test_model_status_reports_the_contact_when_untrained(monkeypatch, tmp_path):
    monkeypatch.setattr(vm, "get_classifier", lambda: _auto_clf(tmp_path))
    status = vm.model_status()
    assert status["trained_weights_present"] is False
    assert status["placeholder_active"] is True
    assert "@" in status["contact"]


def test_placeholder_labels_cover_every_class():
    from memtriage.pipeline.placeholder_model import PLACEHOLDER_LABELS

    assert PLACEHOLDER_LABELS[0] == "Benign"
    assert len(PLACEHOLDER_LABELS) == 9
    assert all(name.startswith("Placeholder_") for name in PLACEHOLDER_LABELS[1:])
