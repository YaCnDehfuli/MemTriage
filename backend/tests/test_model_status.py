"""Bundled model configuration, provenance, and missing-checkpoint behavior."""
import json
import uuid
from pathlib import Path

import pytest

from memtriage.config import Settings
from memtriage.pipeline import vadvit_model as vm


def _classifier(tmp_path):
    return vm.VADViTClassifier(
        tmp_path / "mount" / "model.pt", tmp_path / "mount" / "labels.json",
        "vit_base_patch32_224", 9, 224,
        cache_dir=tmp_path / "cache", upload_dir=tmp_path / "uploads",
    )


def test_local_defaults_resolve_bundled_model():
    settings = Settings(_env_file=None)
    models = Path(__file__).resolve().parents[2] / "models"
    assert settings.model_checkpoint_path == models / "Multi_32_224_6f_3u.pt"
    assert settings.labels_path == models / "labels.json"
    assert settings.model_auto_placeholder is False


def test_bundled_labels_match_paper_legend_and_training_order():
    labels_path = Path(__file__).resolve().parents[2] / "models" / "labels.json"
    labels = vm.load_labels(labels_path, 9)
    assert labels == [
        "Backdoor", "Benign", "Exploit", "HackTool", "Hoax",
        "Rootkit", "Trojan", "Virus", "Worm",
    ]
    assert labels == sorted(labels)
    assert labels.index("Benign") == 1


def test_bundled_status_works_without_api_torch(monkeypatch, tmp_path):
    clf = _classifier(tmp_path)
    clf.checkpoint_path.parent.mkdir()
    clf.checkpoint_path.write_bytes(b"checkpoint")
    monkeypatch.setattr(vm, "get_classifier", lambda: clf)
    monkeypatch.setattr(vm, "torch_available", lambda: False)
    status = vm.model_status()
    assert status["active_source"] == "trained"
    assert status["placeholder_active"] is False
    assert status["runtime_available"] is False
    assert status["labels"] == [f"class_{i}" for i in range(9)]


def test_lfs_pointer_is_missing_weights(monkeypatch, tmp_path):
    clf = _classifier(tmp_path)
    clf.checkpoint_path.parent.mkdir()
    clf.checkpoint_path.write_text("version https://git-lfs.github.com/spec/v1\n")
    monkeypatch.setattr(vm, "get_classifier", lambda: clf)
    assert clf.resolve_checkpoint() is None
    assert vm.model_status()["active_source"] == "none"
    assert clf.classify(tmp_path / "grid.png").model_loaded is False


def test_default_does_not_reuse_old_random_checkpoint(tmp_path):
    clf = _classifier(tmp_path)
    clf.cache_dir.mkdir()
    clf.cached_placeholder_path.write_bytes(b"old random weights")
    assert clf.resolve_checkpoint() is None
    assert clf.checkpoint_present is False


def test_legacy_generator_defaults_to_cache_not_bundled_weights(monkeypatch, tmp_path):
    from memtriage.pipeline import placeholder_model as pm

    settings = Settings(data_dir=tmp_path, _env_file=None)
    monkeypatch.setattr(pm, "get_settings", lambda: settings)
    written = []

    def generate(checkpoint, labels, **kwargs):
        written.append((checkpoint, labels))
        return {}

    monkeypatch.setattr(pm, "generate_placeholder", generate)
    assert pm._main([]) == 0
    assert written == [(
        settings.model_cache_dir / settings.model_checkpoint_path.name,
        settings.model_cache_dir / settings.labels_path.name,
    )]
    with pytest.raises(SystemExit):
        pm._main(["--out", str(settings.model_checkpoint_path.parent)])
    assert len(written) == 1


def test_upload_cannot_rename_bundled_classes(tmp_path):
    clf = _classifier(tmp_path)
    clf.checkpoint_path.parent.mkdir()
    clf.checkpoint_path.write_bytes(b"bundled")
    clf.upload_dir.mkdir()
    clf.uploaded_checkpoint_path.write_bytes(b"uploaded")
    uploaded_labels = clf.upload_dir / "labels.json"
    uploaded_labels.write_text(json.dumps(["Wrong"] * 9))
    assert clf.resolve_labels_path() == clf.labels_path
    assert clf.labels == [f"class_{i}" for i in range(9)]
    clf.labels_path.write_text(json.dumps([f"Family{i}" for i in range(9)]))
    assert clf.labels == [f"Family{i}" for i in range(9)]


def test_retired_model_request_endpoints_are_unavailable(client):
    assert client.get("/api/model-access").status_code == 404
    assert client.post("/api/model-access-requests", json={}).status_code == 404


@pytest.mark.parametrize("source", [
    "placeholder", "none", "uploaded", "trained", "trained_indices",
])
def test_selecting_process_refreshes_old_verdicts(client, monkeypatch, tmp_path, source):
    from memtriage.db import SessionLocal
    from memtriage.models import (
        AnalysisStatus,
        Investigation,
        InvestigationStatus,
        ProcessAnalysis,
    )
    from memtriage.storage import ProcessPaths

    clf = _classifier(tmp_path)
    clf.checkpoint_path.parent.mkdir()
    clf.checkpoint_path.write_bytes(b"bundled")
    bundled_labels = Path(__file__).resolve().parents[2] / "models" / "labels.json"
    clf.labels_path.write_bytes(bundled_labels.read_bytes())
    monkeypatch.setattr(vm, "get_classifier", lambda: clf)
    inv_id, analysis_id = str(uuid.uuid4()), str(uuid.uuid4())
    paths = ProcessPaths(inv_id, 1337).ensure()
    cached_labels = [f"class_{i}" for i in range(9)] if source == "trained_indices" else clf.labels
    paths.result.write_text(json.dumps({"verdict": {
        "model_loaded": source != "none",
        "model_source": "trained" if source == "trained_indices" else source,
        "placeholder": source == "placeholder",
        "probabilities": {name: 1.0 if i == 0 else 0.0 for i, name in enumerate(cached_labels)},
    }}))
    with SessionLocal() as session:
        session.add(Investigation(id=inv_id, status=InvestigationStatus.TRIAGED))
        session.add(ProcessAnalysis(
            id=analysis_id, investigation_id=inv_id, pid=1337,
            status=AnalysisStatus.DONE, region_count=49,
            result_path=str(paths.result),
        ))
        session.commit()

    response = client.post(
        f"/api/investigations/{inv_id}/processes/analyze", json={"pid": 1337},
    )
    assert response.status_code == 200
    state = response.json()
    if source == "trained":
        assert state["analysis_id"] == analysis_id
        assert state["status"] == "done"
    else:
        assert state["analysis_id"] != analysis_id
        assert state["status"] == "queued"
        # Selecting again while queued must not enqueue a second job.
        repeated = client.post(
            f"/api/investigations/{inv_id}/processes/analyze", json={"pid": 1337},
        ).json()
        assert repeated["analysis_id"] == state["analysis_id"]


def test_consolidated_result_lists_reanalyzed_pid_once(client):
    from memtriage.db import SessionLocal
    from memtriage.models import AnalysisStatus, Investigation, ProcessAnalysis
    from memtriage.storage import InvestigationPaths, ProcessPaths
    from memtriage.workers.tasks import _write_consolidated

    inv_id = str(uuid.uuid4())
    current = {"pid": 1337, "verdict": {"model_source": "trained"}}
    ProcessPaths(inv_id, 1337).ensure().result.write_text(json.dumps(current))
    with SessionLocal() as session:
        inv = Investigation(id=inv_id)
        session.add(inv)
        for _ in range(2):
            session.add(ProcessAnalysis(
                id=str(uuid.uuid4()), investigation_id=inv_id,
                pid=1337, status=AnalysisStatus.DONE,
            ))
        session.commit()
        _write_consolidated(inv, session)
    report = json.loads(InvestigationPaths(inv_id).result.read_text())
    assert report["process_analyses"] == [current]
