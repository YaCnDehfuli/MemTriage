"""FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .api import routes_events, routes_investigations, routes_processes, routes_results
from .config import get_settings
from .db import init_db
from .storage import ensure_base_dirs

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001
    ensure_base_dirs()
    init_db()
    yield


app = FastAPI(
    title="MemTriage",
    version=__version__,
    description=(
        "Upload a memory image → consolidated investigation report. VolMemLyzer "
        "triages the image and lists processes; the analyst selects one and "
        "VADViT classifies it with an explainability overlay."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # noqa: ANN001
    """Baseline hardening headers on every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers.setdefault(
        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/api/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": settings.app_name, "version": __version__})


app.include_router(routes_investigations.router)
app.include_router(routes_processes.router)
app.include_router(routes_events.router)
app.include_router(routes_results.router)
