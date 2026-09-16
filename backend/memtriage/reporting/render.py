"""Render an assembled document to standalone HTML.

``autoescape`` is the load-bearing control in this module. Everything
interpolated into these templates is either analyst text or metadata lifted out
of an attacker-controlled memory image, so nothing may ever be marked ``|safe``.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .assembly import EXECUTIVE, ReportDocument

TEMPLATES_DIR = Path(__file__).parent / "templates"

TEMPLATE_FOR_AUDIENCE = {
    "technical": "report_technical.html.j2",
    EXECUTIVE: "report_executive.html.j2",
}

_UNITS = ("B", "KB", "MB", "GB", "TB")

# Sections substantial enough to start their own printed page. Short ones flow,
# so a two-line overview never occupies a page by itself.
PAGE_BREAK_SECTIONS = frozenset({"findings", "attack", "deepdives"})


def _filesize(value: object) -> str:
    """Byte count as a short human string; never raises on odd input."""
    try:
        size = float(value)  # type: ignore[arg-type]
    except Exception:
        # Includes jinja2's UndefinedError: a document missing the key entirely
        # must render a dash, not fail the whole report over a cover field.
        return "—"
    if size < 0:
        return "—"
    unit = 0
    while size >= 1024 and unit < len(_UNITS) - 1:
        size /= 1024.0
        unit += 1
    return f"{size:.0f} {_UNITS[unit]}" if unit == 0 else f"{size:.1f} {_UNITS[unit]}"


def build_environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "j2", "html.j2"), default=True
        ),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["filesize"] = _filesize
    env.globals["PAGE_BREAK_SECTIONS"] = PAGE_BREAK_SECTIONS
    return env


_env: Environment | None = None


def environment() -> Environment:
    global _env
    if _env is None:
        _env = build_environment()
    return _env


def render(doc: ReportDocument) -> str:
    name = TEMPLATE_FOR_AUDIENCE.get(doc.audience, TEMPLATE_FOR_AUDIENCE["technical"])
    return environment().get_template(name).render(doc=doc)
