"""Trained-model access requests.

The trained VADViT checkpoint is released by the author on request rather than
shipped with the project. This endpoint records a structured request, and hands
back a formatted subject/body the requester can send from their own mail client.
Nothing is emailed from here: the API has no mail credentials, and the analysis
worker deliberately has no egress at all.
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator

from ..config import get_settings
from ..errors import RateLimited
from ..pipeline.vadvit_model import model_status
from ..security.sanitize import sanitize_text

router = APIRouter(prefix="/api", tags=["model-access"])

logger = logging.getLogger(__name__)
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


# --------------------------------------------------------------------------
# Bring-your-own weights
#
# Someone who obtained the trained checkpoint through the channel above needs a
# way to put it into a running deployment. Mounting a volume means restarting
# the stack and having shell access to the host, which the person evaluating
# this generally does not.
#
# The file is data, never code: it is loaded with torch.load(weights_only=True)
# into a fixed architecture, so a pickled payload is rejected by torch rather
# than executed. Everything below is about keeping an unusable file from being
# accepted quietly.
# --------------------------------------------------------------------------

# torch.save writes a zip archive; a mistyped file is usually the give-away.
_ZIP_MAGIC = b"PK\x03\x04"


def _upload_dir() -> Path:
    # get_settings() per call, not the module-level `settings`: that one is bound
    # at import, and these are filesystem paths rather than static policy text.
    path = Path(get_settings().model_upload_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


async def _store_upload(upload: UploadFile, target: Path, limit: int) -> int:
    """Stream to a temp file beside the target, then swap it in atomically.

    Streamed because a checkpoint is hundreds of megabytes and reading it into
    memory would let one upload take the API process out. Swapped atomically
    because the worker resolves this exact path on every classify: a half-written
    file must never be reachable under the real name.
    """
    temporary = target.parent / f".upload_{uuid.uuid4().hex}.part"
    total = 0
    try:
        with temporary.open("wb") as handle:
            while chunk := await upload.read(4 * 1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise HTTPException(
                        status_code=413,
                        detail=(f"Checkpoint exceeds the {limit // (1024 * 1024)} MB "
                                f"limit for an uploaded model."),
                    )
                handle.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return total


@router.get("/model")
def model_state() -> dict:
    """Which weights are active, and what an upload would need to look like."""
    return model_status()


@router.post("/model/weights", status_code=201)
async def upload_model_weights(
    checkpoint: UploadFile = File(..., description="VADViT .pt state_dict"),
    labels: UploadFile | None = File(None, description="Optional labels.json"),
) -> dict:
    """Install operator-supplied VADViT weights for this deployment."""
    current = get_settings()
    name = Path(checkpoint.filename or "").name
    if not name.endswith(".pt"):
        raise HTTPException(status_code=400,
                            detail="Expected a PyTorch checkpoint with a .pt extension.")

    head = await checkpoint.read(len(_ZIP_MAGIC))
    if head != _ZIP_MAGIC:
        raise HTTPException(
            status_code=400,
            detail=("That file is not a PyTorch checkpoint — torch.save writes a zip "
                    "archive and this does not start like one."),
        )
    await checkpoint.seek(0)

    directory = _upload_dir()
    # Stored under the configured checkpoint name, not the uploaded one, so the
    # worker resolves it without being told and a re-upload replaces rather than
    # accumulates.
    target = directory / Path(current.model_checkpoint_path).name
    size = await _store_upload(checkpoint, target, current.max_model_upload_bytes)

    labels_stored = False
    if labels is not None and (labels.filename or "").strip():
        raw = await labels.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400,
                                detail=f"labels.json is not valid JSON ({exc}).") from exc
        if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
            raise HTTPException(status_code=400,
                                detail="labels.json must be a JSON array of strings.")
        (directory / Path(current.labels_path).name).write_text(
            json.dumps(parsed, indent=2), encoding="utf-8")
        labels_stored = True

    logger.info("model weights uploaded (%d bytes, labels=%s)", size, labels_stored)
    status = model_status()
    # The weights are only loaded when something classifies, in the worker. This
    # says the file is in place, not that it produced a verdict.
    return {"stored": True, "size_bytes": size, "labels_stored": labels_stored,
            "model": status}


@router.delete("/model/weights")
def delete_model_weights() -> dict:
    """Remove uploaded weights and fall back to whatever ranks next."""
    current = get_settings()
    directory = Path(current.model_upload_dir)
    removed = False
    for name in (Path(current.model_checkpoint_path).name,
                 Path(current.labels_path).name):
        candidate = directory / name
        if candidate.exists():
            candidate.unlink()
            removed = True
    return {"removed": removed, "model": model_status()}


@router.post("/model-access-requests", response_model=ModelAccessResponse, status_code=201)
def create_model_access_request(body: ModelAccessRequest, request: Request) -> ModelAccessResponse:
    client_ip = request.client.host if request.client else "unknown"
    _rate_limit(client_ip)

    request_id = uuid.uuid4().hex
    submitted_at = datetime.now(UTC)
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
