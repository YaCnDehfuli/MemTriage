"""Turning any provider failure into one shape the UI can act on.

Two rules. Every failure is classified into something the analyst can do
something about — a wrong key, a rate limit, an unknown model, an unreachable
host. And the key never appears in a message: the SDKs put request context into
exception strings, so the key is redacted out of anything that leaves here.
"""
from __future__ import annotations

import re

REDACTED = "[redacted]"

_KEY_SHAPES = re.compile(r"\b(sk-[A-Za-z0-9_\-]{8,}|gsk_[A-Za-z0-9_\-]{8,}"
                         r"|sk-ant-[A-Za-z0-9_\-]{8,})\b")


class AssistantError(Exception):
    """A provider call that failed, described in terms the analyst can act on."""

    def __init__(self, message: str, *, code: str = "provider_error",
                 status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "status": self.status}


def redact(text: str, api_key: str = "") -> str:
    """Strip anything key-shaped, and the actual key, out of a message."""
    cleaned = _KEY_SHAPES.sub(REDACTED, str(text))
    if api_key and len(api_key) >= 8:
        cleaned = cleaned.replace(api_key, REDACTED)
        cleaned = cleaned.replace(api_key[-8:], REDACTED)
    return cleaned


_BY_STATUS = {
    400: ("bad_request", "The provider rejected the request. Check the model name."),
    401: ("auth_failed", "The provider rejected that API key."),
    403: ("forbidden", "That key is not permitted to use this model."),
    404: ("unknown_model", "The provider does not recognize that model."),
    413: ("too_large", "The briefing plus your question exceeded the model's input limit."),
    422: ("bad_request", "The provider rejected the request shape."),
    429: ("rate_limited", "The provider is rate limiting this key. Wait and retry."),
    500: ("provider_error", "The provider returned a server error."),
    502: ("provider_error", "The provider returned a bad gateway."),
    503: ("provider_unavailable", "The provider is temporarily unavailable."),
    529: ("provider_unavailable", "The provider is overloaded."),
}


def classify_exception(exc: Exception, api_key: str = "") -> AssistantError:
    status = getattr(exc, "status_code", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)

    name = type(exc).__name__
    detail = redact(str(exc), api_key)[:400]

    if isinstance(status, int) and status in _BY_STATUS:
        code, message = _BY_STATUS[status]
        return AssistantError(f"{message} ({detail})" if detail else message,
                              code=code, status=status)
    if "Connection" in name or "Timeout" in name:
        return AssistantError(
            "Could not reach the provider. The API container needs outbound access to it; "
            "the analysis worker is deliberately offline. "
            f"({name})",
            code="unreachable",
        )
    if "Authentication" in name or "PermissionDenied" in name:
        return AssistantError("The provider rejected that API key.", code="auth_failed",
                              status=401)
    if "RateLimit" in name:
        return AssistantError("The provider is rate limiting this key. Wait and retry.",
                              code="rate_limited", status=429)
    return AssistantError(f"The provider call failed ({name}): {detail}",
                          code="provider_error",
                          status=status if isinstance(status, int) else None)
