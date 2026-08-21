"""Run an analyst-picked batch of Volatility plugins live, and mirror it.

The triage workbench exposes both preset/custom triage and analyst-triggered
manual runs. This module provides their shared catalog and live event capture,
plus the thin wrapper around a manual ``Pipeline.run_plugin_raw()`` call.

The catalog (:func:`plugin_catalog`) is hardcoded display metadata
(name/category/cost/deps), not read from a live ``volmemlyzer`` registry, and
this module never imports ``volmemlyzer`` at all: ``GET /api/plugins/catalog``
has no investigation and is served by the lightweight API image, which does
not install ``volmemlyzer``/``volatility3`` (only the worker image does — see
``deploy/Dockerfile.api`` vs ``Dockerfile.worker``). :func:`run_selected_plugins`
takes an already-built ``Pipeline`` (the caller — the Celery task — builds one
the same way triage does, via ``volmemlyzer_adapter.build_pipeline``) and only
calls duck-typed methods on it, so this module stays import-safe everywhere.

Event capture is a ``logging.Handler`` attached to the ``volmemlyzer`` logger
for the duration of one ``run_plugin_raw()`` call. VolMemLyzer's own log lines
are the only live signal that exists (there is no callback/event-stream hook
in that package); the recognized subset below is drawn from direct reading of
``volmemlyzer/pipeline.py`` and ``runner.py`` at the pinned commit — every
line is matched by *template* (``record.msg``/``record.args``), not by
formatted text, except the one line VolMemLyzer itself eagerly ``.format()``s
before logging (parsed by its distinctive ``<<...>>`` delimiters instead).
Two real behaviors this accounts for, both load-bearing for the UI:

* A cache hit never calls the runner at all — only a "Using the cached ..."
  line fires, no "Finished" line. That is its own terminal state
  (``plugin_cached``), not a failure to paper over.
* The pinned scheduler logs ``Running plugin`` when it submits work to its
  executor, not when a subprocess actually starts. MemTriage's runner wrapper
  adds ``Executing plugin`` from inside the worker, so queued/dispatched and
  genuinely active plugins remain distinct. Older layer lines remain supported.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

from .volmemlyzer_adapter import DEEP_TRIAGE_PLUGINS, LIGHT_TRIAGE_PLUGINS

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------

CATEGORY_PROCESS = "Process & object census"
CATEGORY_REGISTRY = "Registry & persistence"
CATEGORY_SCANNERS = "Physical-layer scanners"

# name -> (category, cost, deps). Mirrors volmemlyzer/src/volmemlyzer/plugins.py
# PLUGIN_SPECIFICS as of the pinned submodule commit (e60f260) — display
# metadata only; VolMemLyzer's own registry remains the runtime source of
# truth for what is actually runnable (an unknown/renamed plugin the analyst
# somehow requests just comes back in `failed_plugins`, same as any other).
_PLUGINS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "info": (CATEGORY_PROCESS, "fast", ()),
    "pslist": (CATEGORY_PROCESS, "fast", ()),
    "psscan": (CATEGORY_PROCESS, "scan", ("pslist",)),
    "threads": (CATEGORY_PROCESS, "scan", ()),
    "thrdscan": (CATEGORY_PROCESS, "scan", ("threads",)),
    "deskscan": (CATEGORY_PROCESS, "scan", ("pslist",)),
    "amcache": (CATEGORY_PROCESS, "fast", ("info",)),
    "bigpools": (CATEGORY_PROCESS, "scan", ()),
    "cmdline": (CATEGORY_PROCESS, "fast", ()),
    "cmdscan": (CATEGORY_PROCESS, "fast", ()),
    "consoles": (CATEGORY_PROCESS, "fast", ()),
    "dlllist": (CATEGORY_PROCESS, "scan", ()),
    "envars": (CATEGORY_PROCESS, "fast", ()),
    "getservicesids": (CATEGORY_PROCESS, "fast", ()),
    "getsids": (CATEGORY_PROCESS, "fast", ()),
    "handles": (CATEGORY_PROCESS, "heavy", ()),
    "iat": (CATEGORY_PROCESS, "heavy", ()),
    "joblinks": (CATEGORY_PROCESS, "fast", ()),
    "ldrmodules": (CATEGORY_PROCESS, "scan", ()),
    "malfind": (CATEGORY_PROCESS, "heavy", ()),
    "mbrscan": (CATEGORY_PROCESS, "scan", ()),
    "modules": (CATEGORY_PROCESS, "fast", ()),
    "netstat": (CATEGORY_PROCESS, "fast", ()),
    "privileges": (CATEGORY_PROCESS, "fast", ()),
    "pstree": (CATEGORY_PROCESS, "fast", ()),
    "registry.printkey": (CATEGORY_REGISTRY, "fast", ()),
    "registry.hivelist": (CATEGORY_REGISTRY, "fast", ()),
    "registry.hivescan": (CATEGORY_REGISTRY, "scan", ("registry.hivelist",)),
    "registry.certificates": (CATEGORY_REGISTRY, "fast", ()),
    "registry.userassist": (CATEGORY_REGISTRY, "fast", ()),
    "shimcache": (CATEGORY_REGISTRY, "scan", ()),
    "skeleton_key": (CATEGORY_REGISTRY, "fast", ()),
    "ssdt": (CATEGORY_PROCESS, "fast", ()),
    "statistics": (CATEGORY_PROCESS, "scan", ()),
    "svcscan": (CATEGORY_REGISTRY, "scan", ()),
    "svclist": (CATEGORY_REGISTRY, "fast", ()),
    "timers": (CATEGORY_REGISTRY, "fast", ()),
    "vadinfo": (CATEGORY_PROCESS, "heavy", ()),
    "vadwalk": (CATEGORY_PROCESS, "scan", ()),
    "verinfo": (CATEGORY_PROCESS, "heavy", ()),
    "virtmap": (CATEGORY_PROCESS, "scan", ()),
    "windows": (CATEGORY_PROCESS, "fast", ()),
    "windowstations": (CATEGORY_PROCESS, "fast", ()),
    "callbacks": (CATEGORY_SCANNERS, "fast", ()),
    "devicetree": (CATEGORY_SCANNERS, "scan", ()),
    "driverirp": (CATEGORY_SCANNERS, "fast", ()),
    "drivermodule": (CATEGORY_SCANNERS, "fast", ()),
    "driverscan": (CATEGORY_SCANNERS, "scan", ()),
    "filescan": (CATEGORY_SCANNERS, "heavy", ()),
    "modscan": (CATEGORY_SCANNERS, "scan", ()),
    "mutantscan": (CATEGORY_SCANNERS, "scan", ()),
    "netscan": (CATEGORY_SCANNERS, "scan", ()),
    "scheduled_tasks": (CATEGORY_SCANNERS, "fast", ()),
    "poolscanner": (CATEGORY_SCANNERS, "scan", ()),
    "symlinkscan": (CATEGORY_SCANNERS, "scan", ()),
    "psxview": (CATEGORY_SCANNERS, "heavy", ()),
}


def plugin_catalog() -> list[dict[str, Any]]:
    """Every known plugin, grouped for the picker UI. Pure data, no imports."""
    light_set = set(LIGHT_TRIAGE_PLUGINS)
    deep_set = set(DEEP_TRIAGE_PLUGINS)
    return [
        {"name": name, "category": category, "cost": cost, "deps": list(deps),
         "in_light_set": name in light_set, "in_deep_set": name in deep_set,
         # Kept for clients from the first plugin-console iteration.
         "in_triage_set": name in deep_set}
        for name, (category, cost, deps) in sorted(_PLUGINS.items())
    ]


# --------------------------------------------------------------------------
# Live event capture
# --------------------------------------------------------------------------

_LAYER_RE = re.compile(r"^Running plugins: <<(.*)>> in paralell$")


class PluginEventCapture(logging.Handler):
    """Normalizes VolMemLyzer's log records into structured run events.

    Attach immediately before one ``run_plugin_raw()`` call and remove in a
    ``finally`` right after (see :func:`run_selected_plugins`) — that scoping
    is enough on its own, with no extra thread-local bookkeeping, because only
    one plugin-run job executes at a time per worker process
    (``deploy/Dockerfile.worker`` runs Celery with ``--concurrency=1``), and
    Python logging handlers see every record regardless of which thread in the
    process emitted it.
    """

    def __init__(self, on_event: Callable[[dict[str, Any]], None]) -> None:
        super().__init__(level=logging.INFO)
        self._on_event = on_event
        self._state_lock = threading.Lock()
        self._active: set[str] = set()
        self._terminal: set[str] = set()

    @property
    def active_plugins(self) -> list[str]:
        with self._state_lock:
            return sorted(self._active)

    @property
    def terminal_plugins(self) -> set[str]:
        with self._state_lock:
            return set(self._terminal)

    def _send(self, event: dict[str, Any]) -> None:
        name = event.get("plugin")
        with self._state_lock:
            if name and event.get("type") == "plugin_started":
                self._active.add(str(name))
            if name and event.get("type") in {
                "plugin_finished", "plugin_cached", "plugin_converted",
                "plugin_unavailable", "plugin_failed",
            }:
                self._active.discard(str(name))
                self._terminal.add(str(name))
        self._on_event(event)

    def ensure_terminal(
        self, names: list[str] | set[str] | tuple[str, ...], *,
        failures: dict[str, str] | None = None, artifacts: dict[str, str] | None = None,
    ) -> None:
        """Close any status holes left by an unfamiliar VolMemLyzer log line."""
        failures = failures or {}
        artifacts = artifacts or {}
        for name in sorted(set(names) - self.terminal_plugins):
            if name in failures:
                event = {"type": "plugin_failed", "plugin": name,
                         "explanation": str(failures[name]), "synthetic": True}
            elif name in artifacts:
                event = {"type": "plugin_finished", "plugin": name, "rc": 0,
                         "ok": True, "synthetic": True}
            else:
                event = {"type": "plugin_failed", "plugin": name,
                         "explanation": "No usable output was produced", "synthetic": True}
            event["at"] = time.time()
            self._send(event)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._normalize(record)
        except Exception:
            # A malformed/unexpected log line must never take the run down.
            logger.exception("plugin event capture failed on a log record")

    def _normalize(self, record: logging.LogRecord) -> None:
        msg = record.msg
        args = record.args or ()
        now = time.time()
        event: dict[str, Any] | None = None
        extra_events: list[dict[str, Any]] = []

        if msg == "Running plugin %s" and len(args) == 1:
            event = {"type": "plugin_dispatched", "plugin": args[0]}
        elif msg == "Executing plugin %s" and len(args) == 1:
            event = {"type": "plugin_started", "plugin": args[0]}
        elif msg == "Finished %s rc=%s in %.2fs" and len(args) == 3:
            name, rc, dur = args
            event = {"type": "plugin_finished", "plugin": name, "rc": int(rc),
                     "duration_s": round(float(dur), 2), "ok": int(rc) == 0}
        elif msg == "Plugin %s failed (rc=%s). %s" and len(args) == 3:
            name, rc, explanation = args
            event = {"type": "plugin_failed_detail", "plugin": name, "rc": int(rc),
                     "explanation": str(explanation)}
        elif msg == "Plugin %s timed out after %ss" and len(args) == 2:
            name, timeout_s = args
            event = {"type": "plugin_timeout", "plugin": name, "timeout_s": timeout_s}
        elif (msg == "Using the cached %s plugin output in the %s directory. "
                     "Re-run avoided" and len(args) == 2):
            event = {"type": "plugin_cached", "plugin": args[0]}
        elif msg == "Converted %s: %s -> %s via %s. Re-run avoided" and len(args) == 4:
            name, src_format, want_ext, _used = args
            event = {"type": "plugin_converted", "plugin": name,
                     "from_format": src_format, "to_format": want_ext}
        elif isinstance(msg, str) and msg.startswith("%d of %d plugins produced no usable"):
            failed, attempted, names = args
            event = {"type": "run_summary", "failed": int(failed),
                     "attempted": int(attempted), "plugin_names": str(names)}
        elif msg == "Skipping %d plugin(s) this Volatility does not provide: %s" and len(args) == 2:
            for name in str(args[1]).split(","):
                if name.strip():
                    extra_events.append({"type": "plugin_unavailable",
                                         "plugin": name.strip()})
        elif msg == "Plugin %s raised" and len(args) == 1:
            event = {"type": "plugin_failed", "plugin": args[0],
                     "explanation": "VolMemLyzer raised while running this plugin"}
        elif isinstance(msg, str):
            # Built via eager str.format(), so `msg` is already the full text
            # and `args` is empty — parse the one distinctive delimited line.
            m = _LAYER_RE.match(msg)
            if m:
                names = [n.strip() for n in m.group(1).split(",") if n.strip()]
                event = {"type": "layer_dispatched", "plugins": names}

        if event is not None:
            event["at"] = now
            self._send(event)
        for extra in extra_events:
            extra["at"] = now
            self._send(extra)

        # Always also emit a raw line, even for records already turned into a
        # structured event above, so the console mirror is a complete, honest
        # transcript rather than only the parsed subset.
        try:
            line = record.getMessage()
        except Exception:
            line = str(record.msg)
        self._on_event({"type": "log", "at": now, "level": record.levelname,
                        "logger": record.name, "line": line})


@contextmanager
def capture_plugin_events(
    on_event: Callable[[dict[str, Any]], None], *, heartbeat_interval_s: float = 15.0,
):
    """Mirror VolMemLyzer logs and emit elapsed-time heartbeats during long scans."""
    handler = PluginEventCapture(on_event)
    vol_logger = logging.getLogger("volmemlyzer")
    prev_level = vol_logger.level
    stop = threading.Event()
    started = time.monotonic()

    def _heartbeat() -> None:
        while not stop.wait(max(1.0, heartbeat_interval_s)):
            try:
                on_event({
                    "type": "heartbeat", "at": time.time(),
                    "elapsed_s": round(time.monotonic() - started, 1),
                    "plugins": handler.active_plugins,
                    "message": "Volatility 3 is still working; large scans can take a long time.",
                })
            except Exception:
                logger.exception("plugin heartbeat delivery failed")

    thread = threading.Thread(target=_heartbeat, name="volatility-heartbeat", daemon=True)
    vol_logger.addHandler(handler)
    vol_logger.setLevel(logging.INFO)
    thread.start()
    try:
        yield handler
    finally:
        stop.set()
        thread.join(timeout=1.0)
        vol_logger.removeHandler(handler)
        vol_logger.setLevel(prev_level)


def run_selected_plugins(
    pipe: Any, image_path: str, outdir: str, names: list[str], concurrency: int,
    on_event: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Run one analyst-picked batch of plugins with live event capture.

    ``pipe`` is a ``volmemlyzer.pipeline.Pipeline``, built the same way triage
    builds one (``volmemlyzer_adapter.build_pipeline``) — never imported or
    constructed here. Returns ``{"plugins": {name: path}, "failed_plugins":
    {name: reason}}``, the same artifact shape ``run_triage`` uses.
    """
    selected = sorted({n for n in names if n})

    try:
        layers = pipe.registry.topo_layers(set(selected))
        plan = [sorted(layer) for layer in layers]
    except Exception:
        logger.exception("could not compute a layer plan; falling back to one batch")
        plan = [selected]
    on_event({"type": "plan", "at": time.time(), "layers": plan, "concurrency": concurrency})

    with capture_plugin_events(on_event) as handler:
        try:
            result = pipe.run_plugin_raw(
                image_path=image_path, enable=set(selected), outdir=outdir,
                concurrency=max(1, int(concurrency)), use_cache=True,
            )
        except Exception as exc:
            reason = f"Manual run stopped after {type(exc).__name__}"
            handler.ensure_terminal(
                selected, failures=dict.fromkeys(selected, reason)
            )
            raise

    artifacts = (result.artifacts if result and result.artifacts else {}) or {}
    handler.ensure_terminal(selected, failures=artifacts.get("failed_plugins") or {},
                            artifacts=artifacts.get("plugins") or {})
    return {
        "plugins": dict(artifacts.get("plugins", {}) or {}),
        "failed_plugins": dict(artifacts.get("failed_plugins", {}) or {}),
    }
