"""Error envelope, request ids, and the capability report."""
from __future__ import annotations

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from memtriage.errors import (
    Conflict,
    MemTriageError,
    NotFound,
    RateLimited,
    UpstreamError,
)
from memtriage.main import app

_probe = APIRouter(prefix="/api/_test")


@_probe.get("/boom")
def _boom() -> dict:
    raise RuntimeError("internal detail that must not leak")


@_probe.get("/known")
def _known() -> dict:
    raise NotFound("no such thing")


app.include_router(_probe)


@pytest.fixture
def raw_client():
    """A client that lets the 500 handler answer instead of re-raising."""
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def _envelope(response) -> dict:
    body = response.json()
    assert "error" in body, body
    return body["error"]


def test_unhandled_exception_returns_envelope_without_leaking(raw_client):
    res = raw_client.get("/api/_test/boom")
    assert res.status_code == 500
    err = _envelope(res)
    assert err["code"] == "internal_error"
    assert "internal detail" not in err["message"]
    assert err["request_id"]


def test_domain_error_maps_to_status_and_code(client):
    res = client.get("/api/_test/known")
    assert res.status_code == 404
    assert _envelope(res)["code"] == "not_found"


def test_http_exception_keeps_detail_text(client):
    res = client.get("/api/investigations/does-not-exist")
    assert res.status_code == 404
    err = _envelope(res)
    assert err["code"] == "not_found"
    assert "not found" in err["message"].lower()


def test_validation_error_lists_fields(client):
    res = client.get("/api/investigations?limit=not-a-number")
    assert res.status_code == 422
    err = _envelope(res)
    assert err["code"] == "validation_error"
    assert isinstance(err["details"], list)


def test_request_id_is_echoed_when_supplied(client):
    res = client.get("/api/health", headers={"X-Request-ID": "abc123"})
    assert res.headers["X-Request-ID"] == "abc123"


def test_request_id_is_generated_when_absent(client):
    assert client.get("/api/health").headers["X-Request-ID"]


@pytest.mark.parametrize(
    ("exc", "status"),
    [(NotFound, 404), (Conflict, 409), (RateLimited, 429), (UpstreamError, 502)],
)
def test_error_classes_carry_their_status(exc, status):
    assert exc("x").status_code == status
    assert isinstance(exc("x"), MemTriageError)


def test_deep_health_reports_every_check(client):
    body = client.get("/api/health/deep").json()
    assert body["status"] in {"ok", "degraded", "error"}
    names = {c["name"] for c in body["checks"]}
    assert "data directory" in names
    assert "VADViT checkpoint" in names
    for check in body["checks"]:
        assert check["status"] in {"ok", "degraded", "missing", "error"}
