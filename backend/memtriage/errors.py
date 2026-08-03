"""Uniform error envelope for the API.

Every failure — validation, explicit ``HTTPException``, or an unhandled bug —
leaves the process as the same JSON shape::

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

Unhandled exceptions log a traceback server-side and return a generic message,
so a malformed memory image can never turn a stack trace into a response body.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

_STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "unavailable",
}


class MemTriageError(Exception):
    """Base class for errors that carry an HTTP status and a stable code."""

    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, *, status_code: int | None = None,
                 code: str | None = None, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.details = details


class ValidationFailed(MemTriageError):
    status_code = 422
    code = "validation_error"


class NotFound(MemTriageError):
    status_code = 404
    code = "not_found"


class Conflict(MemTriageError):
    status_code = 409
    code = "conflict"


class RateLimited(MemTriageError):
    status_code = 429
    code = "rate_limited"


class UpstreamError(MemTriageError):
    """A dependency the app does not control failed (LLM provider, Volatility)."""

    status_code = 502
    code = "upstream_error"


def request_id(request: Request) -> str:
    existing = getattr(request.state, "request_id", None)
    if existing:
        return str(existing)
    incoming = request.headers.get(REQUEST_ID_HEADER, "")
    rid = incoming[:64] if incoming else uuid.uuid4().hex
    request.state.request_id = rid
    return rid


def error_response(request: Request, status_code: int, code: str, message: str,
                   details: Any = None) -> JSONResponse:
    rid = request_id(request)
    payload: dict[str, Any] = {"code": code, "message": message, "request_id": rid}
    if details is not None:
        payload["details"] = details
    return JSONResponse(
        {"error": payload},
        status_code=status_code,
        headers={REQUEST_ID_HEADER: rid},
    )


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(MemTriageError)
    async def _memtriage_error(request: Request, exc: MemTriageError) -> JSONResponse:
        return error_response(request, exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [
            {"field": ".".join(str(p) for p in err.get("loc", ())[1:]),
             "problem": str(err.get("msg", ""))}
            for err in exc.errors()[:20]
        ]
        return error_response(request, 422, "validation_error",
                              "Request body failed validation.", fields)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        response = error_response(request, exc.status_code, code, message)
        for key, value in (getattr(exc, "headers", None) or {}).items():
            response.headers[key] = value
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        rid = request_id(request)
        logger.exception("unhandled error on %s %s (request_id=%s)",
                         request.method, request.url.path, rid)
        return error_response(
            request, 500, "internal_error",
            "The server hit an unexpected error. The request id below is in the logs.",
        )


__all__ = [
    "Conflict",
    "MemTriageError",
    "NotFound",
    "RateLimited",
    "REQUEST_ID_HEADER",
    "UpstreamError",
    "ValidationFailed",
    "error_response",
    "register_error_handlers",
    "request_id",
]
