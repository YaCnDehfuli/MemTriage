"""Precomputed example-dump cache: seed captured plugin JSON, never run Volatility."""
from __future__ import annotations

import hashlib

from memtriage.db import SessionLocal
from memtriage.models import Investigation, InvestigationStatus
from memtriage.storage import InvestigationPaths


def _new_investigation(client) -> str:
    response = client.post("/api/investigations")
    assert response.status_code == 201
    return response.json()["investigation_id"]


def _add_dump(client, inv_id: str, content: bytes, name: str = "mem.raw"):
    return client.post(
        f"/api/investigations/{inv_id}/dumps",
        content=content,
        headers={"X-Filename": name},
    )


def _patch_example_hash(monkeypatch, digest: str) -> None:
    monkeypatch.setattr(
        "memtriage.pipeline.example_cache.EXAMPLE_DUMP_SHA256", digest,
    )
    monkeypatch.setattr(
        "memtriage.api.routes_investigations.EXAMPLE_DUMP_SHA256", digest,
    )


def test_example_outputs_are_present():
    from memtriage.pipeline import example_cache

    directory = example_cache.example_outputs_dir()
    assert directory is not None
    assert "pslist" in example_cache.list_example_plugins(directory)


def test_unrelated_dump_cannot_load_precomputed_results(client):
    inv_id = _new_investigation(client)
    assert _add_dump(client, inv_id, b"RAWMEMORYIMAGE-not-a-deny-magic").status_code == 201
    response = client.post(f"/api/investigations/{inv_id}/example-cache")
    assert response.status_code == 409


def test_example_filename_with_the_wrong_hash_is_rejected(client):
    inv_id = _new_investigation(client)
    assert _add_dump(
        client, inv_id, b"RAWMEMORYIMAGE-not-a-deny-magic", name="2580_5.vmem",
    ).status_code == 201
    response = client.post(f"/api/investigations/{inv_id}/example-cache")
    assert response.status_code == 409
    assert "hash" in response.json()["error"]["message"].lower()


def test_verified_replacement_wins_over_earlier_same_name_upload(client, monkeypatch):
    content = b"RAWMEMORYIMAGE-restored-original"
    _patch_example_hash(monkeypatch, hashlib.sha256(content).hexdigest())
    inv_id = _new_investigation(client)
    assert _add_dump(client, inv_id, b"RAWMEMORYIMAGE-wrong-copy", "2580_5.vmem").status_code == 201
    assert _add_dump(client, inv_id, content, "2580_5.vmem").status_code == 201

    response = client.post(f"/api/investigations/{inv_id}/example-cache")
    assert response.status_code == 200, response.text
    paths = InvestigationPaths(inv_id)
    assert (paths.volmemlyzer / "dump_1_pslist.json").is_file()
    assert not (paths.volmemlyzer / "dump_0_pslist.json").exists()


def test_verified_example_can_be_renamed(client, monkeypatch):
    content = b"RAWMEMORYIMAGE-restored-original"
    _patch_example_hash(monkeypatch, hashlib.sha256(content).hexdigest())
    inv_id = _new_investigation(client)
    assert _add_dump(client, inv_id, content, "restored.vmem").status_code == 201
    response = client.post(f"/api/investigations/{inv_id}/example-cache")
    assert response.status_code == 200, response.text


def test_filename_without_a_recorded_hash_cannot_load_demo(client):
    inv_id = _new_investigation(client)
    assert _add_dump(client, inv_id, b"RAWMEMORYIMAGE", "2580_5.vmem").status_code == 201
    with SessionLocal() as session:
        inv = session.get(Investigation, inv_id)
        inv.dumps[0].sha256 = None
        session.commit()
    response = client.post(f"/api/investigations/{inv_id}/example-cache")
    assert response.status_code == 409


def test_matching_hash_copies_plugin_json_and_does_not_enqueue_triage(client, monkeypatch):
    content = b"RAWMEMORYIMAGE-not-a-deny-magic"
    digest = hashlib.sha256(content).hexdigest()
    _patch_example_hash(monkeypatch, digest)

    enqueued: list[object] = []
    from memtriage.workers import celery_app as ca
    monkeypatch.setattr(ca.celery_app, "send_task", lambda *a, **k: enqueued.append(a))

    inv_id = _new_investigation(client)
    uploaded = _add_dump(client, inv_id, content, name="2580_5.vmem")
    assert uploaded.status_code == 201
    assert uploaded.json()["sha256"] == digest

    response = client.post(f"/api/investigations/{inv_id}/example-cache")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["reused"] is False
    assert body["investigation_id"] == inv_id
    assert "pslist" in body["plugins"]
    assert body["artifacts"] == len(body["plugins"])
    assert enqueued == []

    cached = InvestigationPaths(inv_id).volmemlyzer / "dump_0_pslist.json"
    assert cached.is_file()
    assert cached.stat().st_size > 0


def test_completed_example_investigation_is_reopened(client, monkeypatch):
    content = b"RAWMEMORYIMAGE-not-a-deny-magic"
    digest = hashlib.sha256(content).hexdigest()
    _patch_example_hash(monkeypatch, digest)

    source = _new_investigation(client)
    assert _add_dump(client, source, content, name="2580_5.vmem").status_code == 201
    InvestigationPaths(source).result.write_text("{}")
    session = SessionLocal()
    try:
        inv = session.get(Investigation, source)
        assert inv is not None
        inv.status = InvestigationStatus.TRIAGED
        inv.requested_plugins = ["pslist", "malfind"]
        session.add(inv)
        session.commit()
    finally:
        session.close()

    target = _new_investigation(client)
    assert _add_dump(client, target, content, name="2580_5.vmem").status_code == 201
    response = client.post(f"/api/investigations/{target}/example-cache")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["reused"] is True
    assert body["investigation_id"] == source
    assert body["plugins"] == ["pslist", "malfind"]
    assert not (InvestigationPaths(target).volmemlyzer / "dump_0_pslist.json").is_file()


def test_seed_example_artifacts_renames_onto_dump_ordinal():
    from memtriage.pipeline import example_cache

    investigation_id = "00000000-0000-0000-0000-000000000001"
    copied = example_cache.seed_example_artifacts(investigation_id, dump_ordinal=0)
    assert "pslist" in copied
    target = InvestigationPaths(investigation_id).volmemlyzer / "dump_0_pslist.json"
    assert target.is_file()
    source = example_cache.example_outputs_dir()
    assert source is not None
    assert target.read_bytes() == (source / "2580_5.vmem_pslist.json").read_bytes()
