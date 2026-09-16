"""Timeline and correlation over cached triage records.

A memory image carries more sequence than a findings table shows: pslist,
pstree and psscan record when each process started and exited and who launched
it; netscan records when connections were created; the scheduled-task registry
records when tasks were created and last ran; UserAssist records when programs
were last launched. This module lays those out on one clock and links them.

Links are drawn only from identity, never guessed:

* **Lineage** — a process's parent is the process with its PPID that already
  existed when it started. psscan recovers parents that have exited, which
  pslist can no longer see, so a process that looks orphaned often is not.
* **Command line** — a scheduled task is linked to a process when the task's
  action arguments appear in that process's command line.
* **Findings** — events carry the report ref of every scored object that names
  the same process, task or program, so they can be pinned as evidence.

Everything here is derived from an untrusted memory image and describes what the
image records, not what was proven to have happened.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from ..reporting.assembly import evidence_ref
from ..reporting.narrative import RISK_ORDER, risk_rank

# Ancestors/descendants walked from a process; bounds a corrupted PPID cycle.
MAX_LINEAGE_DEPTH = 32
# Timestamps before this are placeholders (FILETIME zero, epoch), not events.
_EARLIEST_REAL_YEAR = 1990
# A task argument shorter than this matches too many command lines to mean
# anything ("-c", "/s").
_MIN_ARGUMENT_MATCH = 6

SOURCES = ("pslist", "pstree", "psscan", "netscan", "scheduled_tasks", "userassist")


def _walk(rows: list[Any]) -> list[dict]:
    """Flatten Volatility's ``__children`` tree renderer output."""
    out: list[dict] = []
    stack = list(reversed([r for r in rows or [] if isinstance(r, dict)]))
    while stack:
        row = stack.pop()
        out.append(row)
        children = row.get("__children") or []
        stack.extend(reversed([c for c in children if isinstance(c, dict)]))
    return out


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.year < _EARLIEST_REAL_YEAR:
        return None
    return parsed


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def _records(records: dict[str, list], *names: str) -> list[dict]:
    for name in names:
        if records.get(name):
            return _walk(records[name])
    return []


def _build_processes(records: dict[str, list]) -> dict[str, dict]:
    """One entry per process instance, keyed by PID and start time.

    Keyed by (PID, CreateTime) rather than PID alone: PIDs are reused, and a
    reused PID that inherits the wrong parent or command line would corrupt
    every lineage that runs through it.
    """
    procs: dict[str, dict] = {}

    def upsert(row: dict, source: str) -> None:
        pid = _int(row.get("PID"))
        created = _time(row.get("CreateTime"))
        if pid is None:
            return
        pid_key = f"{pid}@{_iso(created) or 'unknown'}"
        proc = procs.get(pid_key)
        if proc is None:
            proc = procs[pid_key] = {
                "id": pid_key, "pid": pid, "ppid": _int(row.get("PPID")),
                "name": str(row.get("ImageFileName") or ""), "created": created,
                "exited": None, "cmd": "", "path": "", "sources": [],
            }
        if source not in proc["sources"]:
            proc["sources"].append(source)
        exited = _time(row.get("ExitTime"))
        if exited and not proc["exited"]:
            proc["exited"] = exited
        if row.get("Cmd") and not proc["cmd"]:
            proc["cmd"] = str(row["Cmd"])
        if row.get("Path") and not proc["path"]:
            proc["path"] = str(row["Path"])
            # ImageFileName is truncated to 15 characters by the kernel
            # ("msedgedriver.e"); the full image path is not.
            proc["name"] = _basename(proc["path"]) or proc["name"]

    for source in ("pslist", "pstree", "psscan"):
        for row in _records(records, source):
            upsert(row, source)

    by_pid: dict[int, list[dict]] = defaultdict(list)
    for proc in procs.values():
        by_pid[proc["pid"]].append(proc)

    for proc in procs.values():
        # Only the live list can be trusted to say a process is still linked.
        proc["unlinked"] = "pslist" not in proc["sources"] and not proc["exited"]
        candidates = [
            p for p in by_pid.get(proc["ppid"], [])
            if p is not proc and p["created"] and proc["created"]
            and p["created"] <= proc["created"]
        ]
        parent = max(candidates, key=lambda p: p["created"], default=None)
        proc["parent_id"] = parent["id"] if parent else None
        proc["parent_recovered"] = bool(parent and "pslist" not in parent["sources"])
        proc["children_ids"] = []
    for proc in procs.values():
        if proc["parent_id"]:
            procs[proc["parent_id"]]["children_ids"].append(proc["id"])
    return procs


def _ancestors(procs: dict[str, dict], proc_id: str) -> list[str]:
    chain: list[str] = []
    current = procs[proc_id]["parent_id"]
    while current and current not in chain and len(chain) < MAX_LINEAGE_DEPTH:
        chain.append(current)
        current = procs[current]["parent_id"]
    return chain


def _descendants(procs: dict[str, dict], proc_id: str) -> list[str]:
    seen: list[str] = []
    frontier = list(procs[proc_id]["children_ids"])
    while frontier and len(seen) < 10_000:
        child = frontier.pop()
        if child in seen:
            continue
        seen.append(child)
        frontier.extend(procs[child]["children_ids"])
    return seen


def _task_label(row: dict) -> str:
    """Identical to how the scoring adapter labels a scheduled-task object."""
    name = str(row.get("Task Name") or "")
    act = str(row.get("Action") or "")
    args = str(row.get("Action Arguments") or "")
    return f"{name} :: {act} {args}".strip()


def _highest(risks: list[str]) -> str | None:
    ranked = [r for r in risks if r in RISK_ORDER]
    return min(ranked, key=risk_rank) if ranked else None


def build_timeline(records: dict[str, list], scored: list[dict]) -> dict:
    """Lay the cached records out on one clock and correlate them."""
    procs = _build_processes(records)

    # --- findings, indexed by what they name --------------------------------
    by_pid: dict[int, list[dict]] = defaultdict(list)
    by_label: dict[str, list[dict]] = defaultdict(list)
    for obj in scored or []:
        if not isinstance(obj, dict):
            continue
        link = {"ref": evidence_ref(obj), "risk": obj.get("risk"),
                "label": obj.get("label"), "object_type": obj.get("object_type")}
        if obj.get("pid") is not None and obj.get("object_type") != "persistence":
            pid = _int(obj.get("pid"))
            if pid is not None:
                by_pid[pid].append(link)
        else:
            by_label[str(obj.get("label") or "")].append(link)

    def live_process(pid: int) -> dict | None:
        """The instance a PID-keyed finding refers to: the linked one, else newest."""
        instances = [p for p in procs.values() if p["pid"] == pid]
        linked = [p for p in instances if "pslist" in p["sources"]] or instances
        return max(
            linked,
            key=lambda p: p["created"].timestamp() if p["created"] else float("-inf"),
            default=None,
        )

    for proc in procs.values():
        proc["findings"] = []
    for pid, links in by_pid.items():
        proc = live_process(pid)
        if proc is not None:
            proc["findings"].extend(links)

    flagged = [p for p in procs.values() if p["findings"]]

    # --- command-line links: task arguments seen in a process command line ---
    tasks = _records(records, "scheduled_tasks")
    task_links: dict[int, list[str]] = defaultdict(list)
    for index, row in enumerate(tasks):
        args = str(row.get("Action Arguments") or "").strip().lower()
        # Only a path identifies what a task launches. A bare word such as
        # "SYSTEM" is a substring of "system32" in half the command lines on a
        # Windows host, which would link unrelated processes.
        if len(args) < _MIN_ARGUMENT_MATCH or not ("\\" in args or "/" in args):
            continue
        for proc in procs.values():
            if args in proc["cmd"].lower():
                task_links[index].append(proc["id"])

    # --- events --------------------------------------------------------------
    events: list[dict] = []

    def add(kind: str, at: datetime | None, source: str, detail: str, *,
            proc: dict | None = None, pid: int | None = None,
            findings: list[dict] | None = None, links: list[dict] | None = None) -> None:
        if at is None:
            return
        events.append({
            "id": f"{kind}:{len(events)}",
            "at": at, "kind": kind, "source": source, "detail": detail,
            "process_id": proc["id"] if proc else None,
            "pid": proc["pid"] if proc else pid,
            "name": proc["name"] if proc else "",
            "findings": list(findings or []),
            "links": list(links or []),
        })

    for proc in procs.values():
        links: list[dict] = []
        if proc["parent_id"]:
            parent = procs[proc["parent_id"]]
            links.append({
                "type": "parent", "process_id": parent["id"],
                "text": (f"started by {parent['name']} ({parent['pid']})"
                         + (", recovered by psscan after it exited"
                            if proc["parent_recovered"] else "")),
            })
        elif proc["ppid"] not in (None, 0):
            links.append({"type": "parent_missing",
                          "text": f"parent PID {proc['ppid']} is in no process list"})
        if proc["unlinked"]:
            links.append({"type": "unlinked",
                          "text": "found only by psscan and not marked as exited"})
        detail = proc["cmd"] or proc["path"] or proc["name"]
        add("process_start", proc["created"], "/".join(proc["sources"]), detail,
            proc=proc, findings=proc["findings"], links=links)
        add("process_exit", proc["exited"], "/".join(proc["sources"]),
            f"{proc['name']} exited", proc=proc, findings=proc["findings"])

    for row in _records(records, "netscan"):
        pid = _int(row.get("PID"))
        proc = live_process(pid) if pid is not None else None
        detail = (f"{row.get('Proto') or ''} {row.get('LocalAddr') or ''}:"
                  f"{row.get('LocalPort') or ''} → {row.get('ForeignAddr') or ''}:"
                  f"{row.get('ForeignPort') or ''} {row.get('State') or ''}").strip()
        add("connection", _time(row.get("Created")), "netscan", detail, proc=proc,
            pid=pid, findings=by_pid.get(pid, []) if pid is not None else [])

    for index, row in enumerate(tasks):
        label = _task_label(row)
        if not label.strip(": "):
            continue  # no name, action or arguments: nothing to put on a timeline
        findings = by_label.get(label, [])
        links = [{
            "type": "command_line", "process_id": pid_key,
            "text": (f"its arguments appear in the command line of "
                     f"{procs[pid_key]['name']} ({procs[pid_key]['pid']})"),
        } for pid_key in task_links.get(index, [])]
        for kind, field in (("task_created", "Creation Time"),
                            ("task_last_success", "Last Successful Run Time"),
                            ("task_last_run", "Last Run Time")):
            add(kind, _time(row.get(field)), "scheduled_tasks", label,
                findings=findings, links=links)

    for row in _records(records, "userassist", "registry.userassist"):
        if row.get("Type") != "Value":
            continue
        name = str(row.get("Name") or "")
        if not name or name.startswith("UEME_"):
            continue
        count = row.get("Count")
        detail = f"{name}" + (f" (run count {count})" if count not in (None, "") else "")
        add("program_run", _time(row.get("Last Updated")), "userassist", detail,
            findings=by_label.get(name, []))

    # Pool scanners (netscan) and multi-trigger tasks report the same fact more
    # than once; one row per fact.
    unique: dict[tuple, dict] = {}
    for event in events:
        unique.setdefault((event["kind"], event["at"], event["pid"], event["detail"]), event)
    events = list(unique.values())

    # --- relevance: what an analyst needs around the flagged activity ---------
    # Descendants' activity is part of the flagged process's behaviour; its
    # ancestors are context for how it was launched, so only their start and exit
    # matter — not every socket a service host happens to hold open.
    lineage: dict[str, set[str]] = {}
    ancestry: dict[str, set[str]] = {}
    for proc in flagged:
        for member in {proc["id"], *_descendants(procs, proc["id"])}:
            lineage.setdefault(member, set()).add(proc["id"])
        for member in _ancestors(procs, proc["id"]):
            ancestry.setdefault(member, set()).add(proc["id"])

    task_linked_processes = {pid_key for ids in task_links.values() for pid_key in ids}

    for event in events:
        reasons: list[str] = []
        if event["findings"]:
            reasons.append("names a scored finding")
        pid_key = event["process_id"] or ""
        for owner in sorted(lineage.get(pid_key, set())):
            if owner != pid_key:
                reasons.append(
                    f"descends from {procs[owner]['name']} ({procs[owner]['pid']})"
                )
        if event["kind"] in ("process_start", "process_exit"):
            for owner in sorted(ancestry.get(pid_key, set())):
                reasons.append(
                    f"launched the lineage of {procs[owner]['name']} ({procs[owner]['pid']})"
                )
        if any(link["type"] == "command_line"
               and (link["process_id"] in lineage or link["process_id"] in ancestry)
               for link in event["links"]):
            reasons.append("launches a process in a flagged lineage")
        if pid_key in task_linked_processes and (pid_key in lineage or pid_key in ancestry):
            reasons.append("its command line is a scheduled task's action")
        event["reasons"] = list(dict.fromkeys(reasons))
        event["relevant"] = bool(event["reasons"])
        event["risk"] = _highest([f.get("risk") for f in event["findings"]])

    events.sort(key=lambda e: (e["at"], e["kind"] != "process_start"))

    out_events = []
    for event in events:
        event = dict(event, at=_iso(event["at"]))
        out_events.append(event)

    processes = {
        proc["id"]: {
            "id": proc["id"], "pid": proc["pid"], "ppid": proc["ppid"], "name": proc["name"],
            "created": _iso(proc["created"]), "exited": _iso(proc["exited"]),
            "cmd": proc["cmd"], "path": proc["path"], "sources": proc["sources"],
            "parent_id": proc["parent_id"], "parent_recovered": proc["parent_recovered"],
            "children_ids": proc["children_ids"], "unlinked": proc["unlinked"],
            "ancestors": _ancestors(procs, proc["id"]),
            "findings": proc["findings"],
            "risk": _highest([f.get("risk") for f in proc["findings"]]),
        }
        for proc in procs.values()
    }

    present = [s for s in SOURCES if records.get(s) or (
        s == "userassist" and records.get("registry.userassist"))]
    return {
        "events": out_events,
        "processes": processes,
        "flagged": [p["id"] for p in flagged],
        "sources": {"present": present,
                    "missing": [s for s in SOURCES if s not in present]},
    }
