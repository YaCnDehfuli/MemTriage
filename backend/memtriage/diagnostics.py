"""Runtime capability probing.

Everything heavy in MemTriage is optional: Volatility, PyTorch, Capstone and the
VADViT checkpoint may all be absent, and the pipeline is written to degrade
rather than fail when they are. This module answers "what is actually available
right now" for ``GET /api/health/deep`` and for the ``preflight`` command, so a
user can tell a missing optional apart from a broken install.
"""
from __future__ import annotations

import importlib
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import get_settings

OK = "ok"
DEGRADED = "degraded"
MISSING = "missing"
ERROR = "error"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    remediation: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "remediation": self.remediation,
            **({"extra": self.extra} if self.extra else {}),
        }


def _module_version(name: str) -> str:
    try:
        module = importlib.import_module(name)
    except Exception:
        return ""
    return str(getattr(module, "__version__", "present"))


def _check_modules(label: str, names: list[str], remediation: str,
                   *, required: bool = False) -> Check:
    found = {n: _module_version(n) for n in names}
    missing = [n for n, v in found.items() if not v]
    if not missing:
        return Check(label, OK, ", ".join(f"{n} {v}" for n, v in found.items()))
    status = ERROR if required else MISSING
    return Check(label, status, f"not importable: {', '.join(missing)}", remediation,
                 extra={k: v for k, v in found.items() if v})


def check_inference() -> Check:
    return _check_modules(
        "inference (torch/timm/torchvision)",
        ["torch", "timm", "torchvision"],
        "Install the worker image, or `pip install torch timm torchvision`. "
        "Without it verdicts and attention maps are disabled, everything else still runs.",
    )


def check_disassembly() -> Check:
    return _check_modules(
        "disassembly (capstone)",
        ["capstone"],
        "`pip install capstone`. Without it the region deep-dive shows structure, "
        "strings and byte patterns but no instruction listing, CFG or call graph.",
    )


def check_pe_parser() -> Check:
    return _check_modules(
        "PE parsing (pefile)",
        ["pefile"],
        "`pip install pefile`. Without it a built-in minimal PE header reader is used.",
    )


def check_volatility() -> Check:
    settings = get_settings()
    candidate = settings.vol_path or shutil.which("vol") or shutil.which("vol.py")
    if not candidate:
        return Check("volatility3", MISSING, "no `vol` executable on PATH",
                     "Install VolMemLyzer's dependencies (`pip install -e components/volmemlyzer`) "
                     "or set MEMTRIAGE_VOL_PATH.")
    try:
        proc = subprocess.run([candidate, "--help"], capture_output=True, text=True,
                              timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return Check("volatility3", ERROR, f"{type(exc).__name__} running {candidate}",
                     "Check that the path is executable in this container.")
    if proc.returncode != 0:
        return Check("volatility3", DEGRADED, f"{candidate} exited {proc.returncode}",
                     "Run it manually to see the underlying error.")
    return Check("volatility3", OK, candidate)


def check_symbols() -> Check:
    """Windows images need a kernel symbol table, and the worker has no egress.

    Without one every windows.* plugin fails and triage completes empty, which is
    indistinguishable from a clean image unless someone says so here.
    """
    settings = get_settings()
    configured = list(settings.vol_symbol_dirs or [])
    if not configured:
        return Check("volatility symbols", MISSING, "no symbol directories configured",
                     "Set MEMTRIAGE_VOL_SYMBOL_DIRS, or give this host outbound access "
                     "to msdl.microsoft.com. See docs/SYMBOLS.md.")

    present, empty, absent = [], [], []
    for candidate in configured:
        path = Path(candidate)
        try:
            if not path.is_dir():
                absent.append(candidate)
            elif any(path.rglob("*.json*")):
                present.append(candidate)
            else:
                empty.append(candidate)
        except OSError:
            absent.append(candidate)

    if present:
        return Check("volatility symbols", OK, ", ".join(present),
                     extra={"empty": empty, "missing": absent})
    detail = f"configured but unusable: {', '.join(empty + absent)}"
    return Check("volatility symbols", MISSING, detail,
                 "Pre-fetch symbols on a networked machine and mount them here; "
                 "otherwise every Windows plugin fails and triage returns nothing. "
                 "See docs/SYMBOLS.md.")


def check_model() -> Check:
    settings = get_settings()
    checkpoint = Path(settings.model_checkpoint_path)
    if checkpoint.exists():
        return Check("VADViT checkpoint", OK, f"trained weights at {checkpoint}")
    cached = Path(settings.model_cache_dir) / checkpoint.name
    if cached.exists():
        return Check("VADViT checkpoint", DEGRADED,
                     "untrained structural placeholder in use",
                     f"Request the trained weights from {settings.model_contact}.")
    if settings.model_auto_placeholder:
        return Check("VADViT checkpoint", DEGRADED,
                     "no checkpoint yet; a structural placeholder is generated on first use",
                     f"Request the trained weights from {settings.model_contact}.")
    return Check("VADViT checkpoint", MISSING, f"nothing at {checkpoint}",
                 "Mount trained weights, or set MEMTRIAGE_MODEL_AUTO_PLACEHOLDER=true.")


def check_database() -> Check:
    from sqlalchemy import text

    from .db import engine

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return Check("database", ERROR, f"{type(exc).__name__}",
                     "Check MEMTRIAGE_DATABASE_URL and that Postgres is up.")
    return Check("database", OK, engine.url.render_as_string(hide_password=True))


def check_broker() -> Check:
    settings = get_settings()
    try:
        import redis
    except Exception:
        return Check("redis", MISSING, "redis client not importable",
                     "`pip install redis`.")
    try:
        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        client.ping()
        client.close()
    except Exception as exc:
        return Check("redis", ERROR, f"{type(exc).__name__}",
                     "Check MEMTRIAGE_REDIS_URL; progress streaming and job queueing need it.")
    return Check("redis", OK, "reachable")


def check_storage() -> Check:
    settings = get_settings()
    root = Path(settings.data_dir)
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".write-probe"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return Check("data directory", ERROR, f"{root}: {type(exc).__name__}",
                     "Mount a writable volume at MEMTRIAGE_DATA_DIR.")
    usage = shutil.disk_usage(root)
    return Check("data directory", OK, str(root),
                 extra={"free_bytes": usage.free, "total_bytes": usage.total})


CHECKS = (
    check_storage,
    check_database,
    check_broker,
    check_volatility,
    check_symbols,
    check_inference,
    check_disassembly,
    check_pe_parser,
    check_model,
)


def run_all() -> dict:
    checks = []
    for probe in CHECKS:
        try:
            checks.append(probe())
        except Exception as exc:
            checks.append(Check(getattr(probe, "__name__", "check"), ERROR,
                                f"probe raised {type(exc).__name__}"))
    worst = OK
    if any(c.status == ERROR for c in checks):
        worst = ERROR
    elif any(c.status in (DEGRADED, MISSING) for c in checks):
        worst = DEGRADED
    return {"status": worst, "checks": [c.to_dict() for c in checks]}
