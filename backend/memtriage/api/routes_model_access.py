"""Trained-model access requests.

The trained VADViT checkpoint is released by the author on request rather than
shipped with the project. This endpoint records a structured request, and hands
back a formatted subject/body the requester can send from their own mail client.
Nothing is emailed from here: the API has no mail credentials, and the analysis
worker deliberately has no egress at all.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator

from ..config import get_settings
from ..errors import RateLimited
from ..pipeline.vadvit_model import model_status
from ..security.sanitize import sanitize_text

router = APIRouter(prefix="/api", tags=["model-access"])

settings = get_settings()

INTENDED_USE = {
    "research": "Academic research",
    "education": "Teaching or coursework",
    "thesis": "Thesis or dissertation",
    "evaluation": "Evaluation / benchmarking",
    "commercial": "Commercial use",
    "other": "Other",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")

_RATE_LIMIT = 5
_RATE_WINDOW_S = 3600
_recent: dict[str, list[float]] = {}
_recent_lock = Lock()


class ModelAccessRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254)
    organization: str = Field(min_length=2, max_length=160)
    role: str = Field(min_length=2, max_length=120)
    country: str = Field(default="", max_length=80)
    intended_use: str = Field(default="research")
    project_description: str = Field(min_length=30, max_length=4000)
    expected_publication: str = Field(default="", max_length=500)
    agrees_to_terms: bool = False

    @field_validator("email")
    @classmethod
    def _looks_like_an_address(cls, value: str) -> str:
        value = value.strip()
        if not _EMAIL_RE.match(value):
            raise ValueError("must be a valid email address")
        return value

    @field_validator("intended_use")
    @classmethod
    def _known_use(cls, value: str) -> str:
        if value not in INTENDED_USE:
            raise ValueError(f"must be one of: {', '.join(sorted(INTENDED_USE))}")
        return value

    @field_validator("agrees_to_terms")
    @classmethod
    def _must_agree(cls, value: bool) -> bool:
        if not value:
            raise ValueError("the research-use terms must be accepted")
        return value


class ModelAccessResponse(BaseModel):
    request_id: str
    submitted_at: datetime
    contact: str
    email_subject: str
    email_body: str
    mailto: str
    note: str


def _rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    with _recent_lock:
        window = [t for t in _recent.get(client_ip, []) if now - t < _RATE_WINDOW_S]
        if len(window) >= _RATE_LIMIT:
            raise RateLimited(
                "Too many access requests from this address. Try again later, or "
                f"email {settings.model_contact} directly."
            )
        window.append(now)
        _recent[client_ip] = window
        if len(_recent) > 2048:
            _recent.clear()
            _recent[client_ip] = window


def _requests_path() -> Path:
    return Path(settings.data_dir) / "model_access_requests" / "requests.jsonl"


def _persist(record: dict) -> None:
    path = _requests_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _compose(body: ModelAccessRequest, request_id: str) -> tuple[str, str]:
    subject = f"VADViT trained-model access request — {body.full_name} ({body.organization})"
    lines = [
        f"Request id: {request_id}",
        "",
        f"Name:          {body.full_name}",
        f"Email:         {body.email}",
        f"Organization:  {body.organization}",
        f"Role:          {body.role}",
        f"Country:       {body.country or '-'}",
        f"Intended use:  {INTENDED_USE[body.intended_use]}",
        f"Publication:   {body.expected_publication or '-'}",
        "",
        "What the model would be used for:",
        body.project_description,
        "",
        "The requester accepted the research-use terms shown in MemTriage.",
    ]
    return subject, "\n".join(lines)


def _quote(text: str) -> str:
    from urllib.parse import quote

    return quote(text, safe="")


@router.get("/model-access")
def model_access_policy() -> dict:
    """Contact and policy text, plus which weights the app is currently running."""
    return {
        "contact": settings.model_contact,
        "intended_use_options": [{"value": k, "label": v} for k, v in INTENDED_USE.items()],
        "policy": (
            "The trained VADViT checkpoint is the output of university research and "
            "is not distributed with this application. MemTriage runs an untrained "
            "structural placeholder in its place, so every stage of the pipeline "
            "still works — but a placeholder family label is not a detection. To "
            "use the trained weights, send the author a short description of your "
            "intended use and they will follow up directly."
        ),
        "terms": (
            "Requested weights are for the stated use only, are not redistributed, "
            "and any published result that relies on them cites the VADViT work."
        ),
        "model": model_status(),
    }


@router.post("/model-access-requests", response_model=ModelAccessResponse, status_code=201)
def create_model_access_request(body: ModelAccessRequest, request: Request) -> ModelAccessResponse:
    client_ip = request.client.host if request.client else "unknown"
    _rate_limit(client_ip)

    request_id = uuid.uuid4().hex
    submitted_at = datetime.now(timezone.utc)
    clean = ModelAccessRequest(
        full_name=sanitize_text(body.full_name, max_len=120),
        email=body.email,
        organization=sanitize_text(body.organization, max_len=160),
        role=sanitize_text(body.role, max_len=120),
        country=sanitize_text(body.country, max_len=80),
        intended_use=body.intended_use,
        project_description=sanitize_text(body.project_description, max_len=4000,
                                          collapse_ws=False),
        expected_publication=sanitize_text(body.expected_publication, max_len=500),
        agrees_to_terms=True,
    )
    subject, email_body = _compose(clean, request_id)

    _persist({
        "request_id": request_id,
        "submitted_at": submitted_at.isoformat(),
        **clean.model_dump(mode="json"),
    })

    return ModelAccessResponse(
        request_id=request_id,
        submitted_at=submitted_at,
        contact=settings.model_contact,
        email_subject=subject,
        email_body=email_body,
        mailto=(f"mailto:{settings.model_contact}"
                f"?subject={_quote(subject)}&body={_quote(email_body)}"),
        note=("Recorded locally. MemTriage cannot send mail — copy the message "
              f"above, or use the mail link, to reach {settings.model_contact}."),
    )
