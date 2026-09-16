"""Operator-supplied VADViT weights.

The trained checkpoint is released on request rather than shipped, so whoever
obtains it needs a way to load it into a running deployment without host shell
access. These pin the parts that are easy to get quietly wrong: what gets
accepted, which weights win when several exist, whether a long-lived worker
notices a change, and whether a verdict still says where its weights came from.
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from memtriage.config import get_settings
from memtriage.main import app
from memtriage.pipeline import vadvit_model


def _torch_shaped_pt(payload: bytes = b"x" * 64) -> bytes:
    """A zip archive, which is the shape torch.save writes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("archive/data.pkl", payload)
    return buf.getvalue()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMTRIAGE_DATA_DIR", str(tmp_path))
    # Point the mount somewhere empty so "no trained weights" is the start state.
    monkeypatch.setenv("MEMTRIAGE_MODEL_CHECKPOINT_PATH",
                       str(tmp_path / "mount" / "Multi_32_224_6f_3u.pt"))
    monkeypatch.setenv("MEMTRIAGE_LABELS_PATH", str(tmp_path / "mount" / "labels.json"))
    get_settings.cache_clear()
    vadvit_model.get_classifier.cache_clear()
    yield TestClient(app)
    get_settings.cache_clear()
    vadvit_model.get_classifier.cache_clear()


def _upload(client, *, checkpoint=None, name="weights.pt", labels=None):
    files = {"checkpoint": (name, checkpoint if checkpoint is not None else _torch_shaped_pt())}
    if labels is not None:
        files["labels"] = ("labels.json", labels)
    return client.post("/api/model/weights", files=files)


def test_without_an_upload_the_placeholder_is_the_active_source(client):
    body = client.get("/api/model").json()
    assert body["active_source"] == "placeholder"
    assert body["uploaded_weights_present"] is False
    assert body["uploaded_weights"] is None


def test_an_uploaded_checkpoint_becomes_the_active_source(client):
    assert _upload(client).status_code == 201
    body = client.get("/api/model").json()
    assert body["active_source"] == "uploaded"
    assert body["uploaded_weights"]["superseded_by_mount"] is False


def test_the_checkpoint_is_stored_under_the_configured_name(client):
    """The worker resolves a fixed path, so the uploaded filename cannot decide it."""
    _upload(client, name="my-run-3-epoch12.pt")
    settings = get_settings()
    stored = list(settings.model_upload_dir.iterdir())
    assert [p.name for p in stored] == [settings.model_checkpoint_path.name]


def test_re_uploading_replaces_rather_than_accumulates(client):
    _upload(client, checkpoint=_torch_shaped_pt(b"a" * 32))
    first = client.get("/api/model").json()["uploaded_weights"]["size_bytes"]
    _upload(client, checkpoint=_torch_shaped_pt(b"b" * 4096))
    second = client.get("/api/model").json()["uploaded_weights"]["size_bytes"]
    assert second != first
    assert len(list(get_settings().model_upload_dir.glob("*.pt"))) == 1


@pytest.mark.parametrize("name,blob,reason", [
    ("weights.bin", None, "extension"),
    ("weights.pt", b"plain text, not an archive", "not a zip"),
    ("weights.pt", b"", "empty"),
])
def test_a_file_that_cannot_be_a_checkpoint_is_refused(client, name, blob, reason):
    response = _upload(client, name=name,
                       checkpoint=blob if blob is not None else _torch_shaped_pt())
    assert response.status_code == 400, reason
    assert client.get("/api/model").json()["uploaded_weights_present"] is False


def test_an_oversized_checkpoint_is_refused(client, monkeypatch):
    monkeypatch.setenv("MEMTRIAGE_MAX_MODEL_UPLOAD_BYTES", "512")
    get_settings.cache_clear()
    vadvit_model.get_classifier.cache_clear()
    response = _upload(client, checkpoint=_torch_shaped_pt(b"x" * 8192))
    assert response.status_code == 413
    # Nothing half-written survives a rejected upload.
    assert not list(get_settings().model_upload_dir.glob("*.pt"))


def test_uploaded_labels_rename_the_classes(client):
    names = ["Benign"] + [f"Family{i}" for i in range(8)]
    assert _upload(client, labels=json.dumps(names).encode()).status_code == 201
    body = client.get("/api/model").json()
    assert body["labels"] == names
    assert body["uploaded_weights"]["labels_uploaded"] is True


@pytest.mark.parametrize("payload", [b"{not json}", b'{"a": 1}', b'["ok", 7]'])
def test_labels_that_are_not_a_list_of_names_are_refused(client, payload):
    assert _upload(client, labels=payload).status_code == 400


def test_deleting_an_upload_reverts_to_the_placeholder(client):
    _upload(client, labels=json.dumps(["A"] * 9).encode())
    assert client.get("/api/model").json()["active_source"] == "uploaded"
    removed = client.delete("/api/model/weights").json()
    assert removed["removed"] is True
    assert removed["model"]["active_source"] == "placeholder"
    assert not list(get_settings().model_upload_dir.iterdir())


def test_deleting_an_upload_never_removes_the_generated_placeholder(client):
    """The two live in different directories precisely so this cannot happen."""
    settings = get_settings()
    settings.model_cache_dir.mkdir(parents=True, exist_ok=True)
    placeholder = settings.model_cache_dir / settings.model_checkpoint_path.name
    placeholder.write_bytes(_torch_shaped_pt())
    _upload(client)
    client.delete("/api/model/weights")
    assert placeholder.exists()


def test_a_mounted_checkpoint_outranks_an_upload_and_says_so(client):
    """An upload that loses to a mount is stored, and reported as not in use."""
    settings = get_settings()
    settings.model_checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    settings.model_checkpoint_path.write_bytes(_torch_shaped_pt())
    _upload(client)
    body = client.get("/api/model").json()
    assert body["active_source"] == "trained"
    assert body["uploaded_weights_present"] is True
    assert body["uploaded_weights"]["superseded_by_mount"] is True


# --- the classifier's own resolution, without the HTTP layer ----------------

def _classifier(tmp_path, **over):
    kwargs = dict(
        checkpoint_path=tmp_path / "mount" / "m.pt",
        labels_path=tmp_path / "mount" / "labels.json",
        model_name="vit_base_patch32_224", num_classes=9, image_size=224,
        cache_dir=tmp_path / "cache", upload_dir=tmp_path / "uploads",
        auto_placeholder=False,
    )
    kwargs.update(over)
    return vadvit_model.VADViTClassifier(**kwargs)


def test_resolution_order_is_mount_then_upload_then_placeholder(tmp_path):
    clf = _classifier(tmp_path)
    for directory in ("mount", "cache", "uploads"):
        (tmp_path / directory).mkdir()
    assert clf.resolve_checkpoint() is None

    (tmp_path / "cache" / "m.pt").write_bytes(b"placeholder")
    assert clf.resolve_checkpoint() == tmp_path / "cache" / "m.pt"

    (tmp_path / "uploads" / "m.pt").write_bytes(b"uploaded")
    assert clf.resolve_checkpoint() == tmp_path / "uploads" / "m.pt"

    (tmp_path / "mount" / "m.pt").write_bytes(b"mounted")
    assert clf.resolve_checkpoint() == tmp_path / "mount" / "m.pt"


def test_resolution_is_not_memoized_across_a_deletion(tmp_path):
    """The worker is long-lived; weights can appear and vanish beneath it."""
    clf = _classifier(tmp_path)
    (tmp_path / "uploads").mkdir()
    (tmp_path / "cache").mkdir()
    uploaded = tmp_path / "uploads" / "m.pt"
    uploaded.write_bytes(b"uploaded")
    assert clf.resolve_checkpoint() == uploaded

    uploaded.unlink()
    (tmp_path / "cache" / "m.pt").write_bytes(b"placeholder")
    assert clf.resolve_checkpoint() == tmp_path / "cache" / "m.pt"


def test_replacing_the_file_changes_its_stamp(tmp_path):
    """What makes a cached model reload in a process that never saw the upload."""
    clf = _classifier(tmp_path)
    (tmp_path / "uploads").mkdir()
    target = tmp_path / "uploads" / "m.pt"
    target.write_bytes(b"one")
    first = clf._stamp(target)
    target.write_bytes(b"a much longer set of bytes")
    assert clf._stamp(target) != first
    assert clf._stamp(tmp_path / "missing.pt") is None


def test_uploaded_weights_are_never_reported_as_trained(tmp_path):
    """"trained" is a provenance claim an uploaded file does not get to borrow."""
    clf = _classifier(tmp_path)
    (tmp_path / "uploads").mkdir()
    uploaded = tmp_path / "uploads" / "m.pt"
    uploaded.write_bytes(b"uploaded")
    assert clf.source_of(uploaded) == "uploaded"
    (tmp_path / "mount").mkdir()
    mounted = tmp_path / "mount" / "m.pt"
    mounted.write_bytes(b"mounted")
    assert clf.source_of(mounted) == "trained"


def test_stale_uploaded_labels_do_not_rename_placeholder_classes(tmp_path):
    """Labels only apply while the weights they came with are the ones loaded."""
    clf = _classifier(tmp_path)
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "labels.json").write_text(json.dumps(["Zeta"] * 9))
    # No uploaded checkpoint, so the uploaded labels must not be used.
    assert clf.resolve_labels_path() != tmp_path / "uploads" / "labels.json"
    (tmp_path / "uploads" / "m.pt").write_bytes(b"uploaded")
    assert clf.resolve_labels_path() == tmp_path / "uploads" / "labels.json"
