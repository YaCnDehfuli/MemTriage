"""Phase 3: ask questions about an investigation.

The analyst brings their own key. It arrives in the request body, is used for
that one upstream call, and is never written to disk, never put in a log line,
and never echoed back — including inside an error message.

Egress happens here, in the API container. The analysis worker stays on the
internal network with no route out, which is why this lives in a route rather
than in a Celery task.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..assistant.context_pack import cached_pack
from ..assistant.errors import AssistantError
from ..assistant.providers import ProviderError, catalogue, custom_base_url_allowed
from ..assistant.scriptgen import generate
from ..assistant.service import SUGGESTED_QUESTIONS, chat
from ..db import get_session
from ..errors import MemTriageError, NotFound, UpstreamError, ValidationFailed
from ..models import Investigation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["assistant"])

CONSENT_NOTICE = (
    "Sending a question forwards the briefing — memory-derived metadata, region "
    "addresses, disassembly and extracted strings — to the provider you choose. "
    "Pick a local provider to keep it on this machine. Your API key is used for "
    "the request and is never stored or logged."
)


class ChatMessage(BaseModel):
    role: str
    content: str = Field(max_length=8000)


class ChatRequest(BaseModel):
    provider: str
    model: str = ""
    api_key: str = Field(default="", max_length=512, repr=False)
    base_url: str | None = Field(default=None, max_length=512)
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)
    refresh_context: bool = False


class ScriptRequest(BaseModel):
    provider: str
    model: str = ""
    base_url: str | None = Field(default=None, max_length=512)
    language: str = "python"


def _require(investigation_id: str, session: Session) -> Investigation:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise NotFound("Investigation not found")
    return inv


def _as_http(exc: AssistantError) -> MemTriageError:
    status = {
        "key_required": 400, "bad_request": 400, "auth_failed": 401,
        "forbidden": 403, "unknown_model": 404, "rate_limited": 429,
        "too_large": 413, "sdk_missing": 501,
    }.get(exc.code)
    if status is not None:
        return MemTriageError(exc.message, status_code=status, code=exc.code)
    return UpstreamError(exc.message, code=exc.code)


@router.get("/assistant/providers")
def list_providers() -> dict:
    """Where a question may be sent, and what each provider needs."""
    return {
        "providers": catalogue(),
        "custom_endpoints_enabled": custom_base_url_allowed(),
        "suggested_questions": list(SUGGESTED_QUESTIONS),
        "consent_notice": CONSENT_NOTICE,
    }


@router.get("/investigations/{investigation_id}/assistant/context")
def get_context(
    investigation_id: str,
    refresh: bool = False,
    include_markdown: bool = True,
    session: Session = Depends(get_session),
) -> dict:
    """The briefing itself, so the analyst can read exactly what would be sent."""
    _require(investigation_id, session)
    pack = cached_pack(investigation_id, refresh=refresh)
    payload = {
        "investigation_id": investigation_id,
        "sha256": pack.sha256,
        "approx_tokens": pack.approx_tokens,
        "sections": pack.sections,
        "truncated_sections": pack.truncated_sections,
        "consent_notice": CONSENT_NOTICE,
    }
    if include_markdown:
        payload["markdown"] = pack.markdown
    return payload


@router.post("/investigations/{investigation_id}/assistant/chat")
def assistant_chat(
    investigation_id: str,
    body: ChatRequest,
    session: Session = Depends(get_session),
) -> dict:
    _require(investigation_id, session)
    try:
        return chat(
            investigation_id=investigation_id,
            provider_id=body.provider,
            model=body.model,
            api_key=body.api_key,
            base_url=body.base_url,
            messages=[m.model_dump() for m in body.messages],
            refresh_pack=body.refresh_context,
        )
    except ProviderError as exc:
        raise ValidationFailed(str(exc)) from None
    except AssistantError as exc:
        # Deliberately logged without the exception object: SDK exception strings
        # can carry request context, and the key must never reach a log line.
        logger.warning("assistant call failed for %s: %s", investigation_id, exc.code)
        raise _as_http(exc) from None


@router.post("/investigations/{investigation_id}/assistant/script")
def assistant_script(
    investigation_id: str,
    body: ScriptRequest,
    session: Session = Depends(get_session),
) -> dict:
    """A runnable equivalent of the same call, for use outside MemTriage."""
    _require(investigation_id, session)
    if body.language not in {"python", "curl"}:
        raise ValidationFailed("Script language must be 'python' or 'curl'.")
    try:
        return generate(cached_pack(investigation_id), body.provider, body.model,
                        body.base_url, body.language)
    except ProviderError as exc:
        raise ValidationFailed(str(exc)) from None
