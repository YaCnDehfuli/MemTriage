"""Trained-model access requests: validation, persistence, and rate limiting."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from memtriage.api import routes_model_access as ma

VALID = {
    "full_name": "Ada Lovelace",
    "email": "ada@example.ac.uk",
    "organization": "Example University",
    "role": "PhD candidate",
    "country": "Canada",
    "intended_use": "research",
    "project_description": (
        "Reproducing the VADViT evaluation on our own memory image corpus as part "
        "of a comparison of process-memory classifiers."
    ),
    "expected_publication": "Workshop paper, 2027",
    "agrees_to_terms": True,
}


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    ma._recent.clear()
    yield
    ma._recent.clear()


def _post(client, **overrides):
    return client.post("/api/model-access-requests", json={**VALID, **overrides})


def test_policy_exposes_contact_and_options(client):
    body = client.get("/api/model-access").json()
    assert "@" in body["contact"]
    values = {opt["value"] for opt in body["intended_use_options"]}
    assert {"research", "education", "commercial"} <= values
    assert "not distributed" in body["policy"]
    assert body["model"]["placeholder_active"] in (True, False)


def test_valid_request_is_accepted_and_composed(client):
    res = _post(client)
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["request_id"]
    assert "Ada Lovelace" in body["email_subject"]
    assert "Example University" in body["email_body"]
    assert body["mailto"].startswith(f"mailto:{body['contact']}?subject=")
    assert "Reproducing the VADViT" in body["email_body"]


def test_request_is_persisted_as_jsonl(client):
    _post(client, full_name="Grace Hopper")
    lines = ma._requests_path().read_text().strip().splitlines()
    records = [json.loads(line) for line in lines]
    assert any(r["full_name"] == "Grace Hopper" for r in records)
    assert all("request_id" in r and "submitted_at" in r for r in records)


def test_terms_must_be_accepted(client):
    res = _post(client, agrees_to_terms=False)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", "not-an-address"),
        ("full_name", "A"),
        ("organization", ""),
        ("intended_use", "mining-crypto"),
        ("project_description", "too short"),
    ],
)
def test_invalid_fields_are_rejected(client, field, value):
    assert _post(client, **{field: value}).status_code == 422


def test_control_characters_are_stripped_from_free_text(client):
    body = _post(client, full_name="Ada\x00\x07 Lovelace").json()
    assert "\x00" not in body["email_body"] and "\x07" not in body["email_body"]


def test_rate_limit_returns_429_with_the_contact(client):
    for _ in range(ma._RATE_LIMIT):
        assert _post(client).status_code == 201
    res = _post(client)
    assert res.status_code == 429
    err = res.json()["error"]
    assert err["code"] == "rate_limited"
    assert "@" in err["message"]


def test_requests_directory_is_created_on_demand(client, monkeypatch, tmp_path):
    target = tmp_path / "nested" / "requests.jsonl"
    monkeypatch.setattr(ma, "_requests_path", lambda: target)
    assert _post(client).status_code == 201
    assert Path(target).exists()
