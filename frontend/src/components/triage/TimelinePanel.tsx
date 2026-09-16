import { useEffect, useMemo, useState } from "react";

import { useApp } from "../../state/store";
import type { Timeline, TimelineEvent, TimelineEventKind, TimelineProcess } from "../../types";
import { EvidenceToggle } from "../report/EvidenceToggle";
import { Chip, EmptyState, Panel, RiskBadge } from "../primitives";

type Scope = "correlated" | "all";
type KindGroup = "processes" | "connections" | "tasks" | "programs";

const KIND_GROUP: Record<TimelineEventKind, KindGroup> = {
  process_start: "processes",
  process_exit: "processes",
  connection: "connections",
  task_created: "tasks",
  task_last_success: "tasks",
  task_last_run: "tasks",
  program_run: "programs",
};

const KIND_LABEL: Record<TimelineEventKind, string> = {
  process_start: "started",
  process_exit: "exited",
  connection: "connection",
  task_created: "task created",
  task_last_success: "task succeeded",
  task_last_run: "task ran",
  program_run: "program ran",
};

const GROUP_LABEL: Record<KindGroup, string> = {
  processes: "Processes",
  connections: "Connections",
  tasks: "Scheduled tasks",
  programs: "Programs (UserAssist)",
};

// What an analyst loses when a source was not part of the triage plan.
const MISSING_SOURCE_EFFECT: Record<string, string> = {
  psscan: "exited parents cannot be recovered, so some processes will look orphaned",
  netscan: "no network connections are shown",
  pstree: "command lines are not shown, so tasks cannot be linked to processes",
  scheduled_tasks: "scheduled tasks are not shown",
  userassist: "program run history is not shown",
};

const RENDER_LIMIT = 400;

function clock(iso: string): { day: string; time: string } {
  // The image's timestamps are UTC. Converting to the analyst's local zone would
  // make a printed timeline disagree with the plugin output it was built from.
  const [day, rest = ""] = iso.split("T");
  return { day, time: rest.slice(0, 8) };
}

/**
 * The image's events on one clock, linked by identity: process lineage (with
 * parents psscan recovers after they exit), scheduled tasks whose action appears
 * in a process's command line, and the scored findings each event names.
 * Proximity is shown as timing only; it never makes an event "correlated".
 */
export function TimelinePanel() {
  const { client, investigationId, triage, scored } = useApp();
  const [timeline, setTimeline] = useState<Timeline | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<Scope>("correlated");
  const [hidden, setHidden] = useState<Set<KindGroup>>(new Set());
  const [focus, setFocus] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    if (!investigationId || !triage) {
      setTimeline(null);
      return;
    }
    let cancelled = false;
    client
      .getTimeline(investigationId)
      .then((data) => {
        if (!cancelled) {
          setTimeline(data);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Timeline unavailable.");
      });
    return () => {
      cancelled = true;
    };
    // Re-scoring changes which events name a finding, so reload with it.
  }, [client, investigationId, triage, scored]);

  const lineage = useMemo(() => {
    if (!timeline || !focus) return null;
    const procs = timeline.processes;
    const descendants = new Set<string>();
    const stack = [...(procs[focus]?.children_ids ?? [])];
    while (stack.length) {
      const id = stack.pop()!;
      if (descendants.has(id)) continue;
      descendants.add(id);
      stack.push(...(procs[id]?.children_ids ?? []));
    }
    return {
      ancestors: new Set(procs[focus]?.ancestors ?? []),
      members: new Set([focus, ...descendants]),
    };
  }, [timeline, focus]);

  const visible = useMemo(() => {
    if (!timeline) return [];
    return timeline.events.filter((event) => {
      if (hidden.has(KIND_GROUP[event.kind])) return false;
      if (lineage && focus) {
        const pid = event.process_id ?? "";
        const inLineage = lineage.members.has(pid);
        const launchedIt =
          lineage.ancestors.has(pid) &&
          (event.kind === "process_start" || event.kind === "process_exit");
        const linkedTask = event.links.some(
          (link) =>
            link.type === "command_line" &&
            !!link.process_id &&
            (lineage.members.has(link.process_id) || lineage.ancestors.has(link.process_id)),
        );
        return inLineage || launchedIt || linkedTask;
      }
      return scope === "all" || event.relevant;
    });
  }, [timeline, hidden, lineage, focus, scope]);

  if (!triage) return null;

  const relevantCount = timeline?.events.filter((e) => e.relevant).length ?? 0;
  const rendered = showAll ? visible : visible.slice(0, RENDER_LIMIT);

  return (
    <Panel
      eyebrow="Correlation"
      title="Timeline"
      right={
        timeline ? (
          <span className="font-mono text-[11px] text-ink-400">
            {relevantCount} correlated · {timeline.events.length} events · UTC
          </span>
        ) : undefined
      }
    >
      <div className="space-y-3 p-4">
        {error && (
          <p className="text-[12px] text-risk-high" role="alert">
            {error}
          </p>
        )}
        {!timeline && !error && <p className="text-[12px] text-ink-400">Building timeline…</p>}

        {timeline && (
          <>
            {timeline.sources.missing.length > 0 && (
              <ul className="space-y-0.5 rounded-md border border-surface-700/60 bg-surface-900/40 px-3 py-2 text-[11px] text-ink-400">
                {timeline.sources.missing
                  .filter((source) => MISSING_SOURCE_EFFECT[source])
                  .map((source) => (
                    <li key={source}>
                      <span className="font-mono text-ink-300">{source}</span> was not part of
                      this triage: {MISSING_SOURCE_EFFECT[source]}.
                    </li>
                  ))}
              </ul>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex rounded border border-surface-600" role="group" aria-label="Scope">
                {(["correlated", "all"] as Scope[]).map((value) => (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={scope === value && !focus}
                    disabled={!!focus}
                    onClick={() => setScope(value)}
                    className={`px-2.5 py-1 text-[12px] disabled:opacity-50 ${
                      scope === value && !focus
                        ? "bg-surface-800 text-ink-100"
                        : "text-ink-400 hover:text-ink-200"
                    }`}
                  >
                    {value === "correlated"
                      ? `Correlated (${relevantCount})`
                      : `All events (${timeline.events.length})`}
                  </button>
                ))}
              </div>
              {(Object.keys(GROUP_LABEL) as KindGroup[]).map((group) => {
                const on = !hidden.has(group);
                return (
                  <button
                    key={group}
                    type="button"
                    aria-pressed={on}
                    onClick={() =>
                      setHidden((current) => {
                        const next = new Set(current);
                        if (on) next.add(group);
                        else next.delete(group);
                        return next;
                      })
                    }
                    className={`rounded px-2 py-1 text-[11px] ring-1 ring-inset ${
                      on
                        ? "bg-surface-800 text-ink-200 ring-surface-600"
                        : "text-ink-400 ring-surface-700 line-through"
                    }`}
                  >
                    {GROUP_LABEL[group]}
                  </button>
                );
              })}
            </div>

            {focus && timeline.processes[focus] && (
              <LineageBar
                timeline={timeline}
                focus={timeline.processes[focus]}
                onFocus={setFocus}
                onClear={() => setFocus(null)}
              />
            )}

            {visible.length === 0 ? (
              <EmptyState
                title={scope === "correlated" && !focus ? "Nothing correlated" : "No events"}
                hint={
                  scope === "correlated" && !focus
                    ? "No event is linked to a scored finding or its process lineage. Switch to All events to browse the full timeline."
                    : "Nothing matches the current filters."
                }
              />
            ) : (
              <ol className="divide-y divide-surface-800/70 rounded-md border border-surface-700/60">
                {rendered.map((event, index) => {
                  const previous = rendered[index - 1];
                  const newDay = !previous || clock(previous.at).day !== clock(event.at).day;
                  return (
                    <EventRow
                      key={event.id}
                      event={event}
                      dayHeader={newDay ? clock(event.at).day : null}
                      focused={!!focus && event.process_id === focus}
                      onFocus={setFocus}
                    />
                  );
                })}
              </ol>
            )}
            {visible.length > rendered.length && (
              <button type="button" className="btn-ghost text-xs" onClick={() => setShowAll(true)}>
                Show all {visible.length} events
              </button>
            )}
          </>
        )}
      </div>
    </Panel>
  );
}

function ProcessButton({
  process,
  onFocus,
}: {
  process: Pick<TimelineProcess, "id" | "name" | "pid">;
  onFocus: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onFocus(process.id)}
      className="font-mono text-[12px] text-ink-100 underline decoration-surface-600 underline-offset-2 hover:decoration-ink-300"
      title="Show this process's lineage"
    >
      {process.name} ({process.pid})
    </button>
  );
}

function EventRow({
  event,
  dayHeader,
  focused,
  onFocus,
}: {
  event: TimelineEvent;
  dayHeader: string | null;
  focused: boolean;
  onFocus: (id: string) => void;
}) {
  const { time } = clock(event.at);
  const finding = event.findings[0];
  // The row's own timestamp and sort order already show when things happened
  // relative to each other; only structural links need spelling out.
  const annotations = event.links.map((link) => link.text);

  return (
    <li className={focused ? "bg-accent/5" : undefined}>
      {dayHeader && (
        <div className="border-b border-surface-800/70 bg-surface-900/60 px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-ink-400">
          {dayHeader}
        </div>
      )}
      <div className="flex flex-wrap items-start gap-x-3 gap-y-1 px-3 py-2">
        <span className="w-16 shrink-0 font-mono text-[12px] text-ink-300">{time}</span>
        <span className="w-32 shrink-0">
          <Chip tone="mono">{KIND_LABEL[event.kind]}</Chip>
        </span>
        <div className="min-w-0 flex-1 basis-64">
          <div className="flex flex-wrap items-center gap-2">
            {event.process_id && event.pid !== null ? (
              <ProcessButton
                process={{ id: event.process_id, name: event.name, pid: event.pid }}
                onFocus={onFocus}
              />
            ) : null}
            <span
              className="min-w-0 break-all font-mono text-[12px] text-ink-300"
              title={event.detail}
            >
              {event.detail}
            </span>
          </div>
          {annotations.length > 0 && (
            <p className="mt-0.5 text-[11px] text-ink-400">{annotations.join(" · ")}</p>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {event.risk && <RiskBadge risk={event.risk} />}
          {finding && (
            <EvidenceToggle evidenceRef={finding.ref} label={finding.label} pid={event.pid} compact />
          )}
        </div>
      </div>
    </li>
  );
}

function LineageBar({
  timeline,
  focus,
  onFocus,
  onClear,
}: {
  timeline: Timeline;
  focus: TimelineProcess;
  onFocus: (id: string) => void;
  onClear: () => void;
}) {
  const procs = timeline.processes;
  const chain = [...focus.ancestors].reverse().map((id) => procs[id]).filter(Boolean);
  const children = focus.children_ids.map((id) => procs[id]).filter(Boolean);

  return (
    <div className="rounded-md border border-accent/30 bg-accent/5 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <div className="eyebrow">Lineage</div>
        <button type="button" className="btn-ghost text-xs" onClick={onClear}>
          Clear focus
        </button>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[12px]">
        {chain.map((proc) => (
          <span key={proc.id} className="flex items-center gap-1.5">
            <ProcessButton process={proc} onFocus={onFocus} />
            {!proc.sources.includes("pslist") && <Chip>psscan</Chip>}
            <span aria-hidden className="text-ink-400">
              →
            </span>
          </span>
        ))}
        <span className="flex items-center gap-1.5 rounded bg-surface-800 px-1.5 py-0.5">
          <span className="font-mono text-ink-100">
            {focus.name} ({focus.pid})
          </span>
          {focus.risk && <RiskBadge risk={focus.risk} />}
        </span>
        {!focus.parent_id && focus.ppid ? (
          <span className="text-[11px] text-ink-400">parent PID {focus.ppid} not in any process list</span>
        ) : null}
      </div>
      {focus.cmd && (
        <p className="mt-1 break-all font-mono text-[11px] text-ink-400" title={focus.cmd}>
          {focus.cmd}
        </p>
      )}
      {children.length > 0 && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-400">
          <span>launched:</span>
          {children.map((child) => (
            <ProcessButton key={child.id} process={child} onFocus={onFocus} />
          ))}
        </div>
      )}
    </div>
  );
}
