import { useEffect, useRef, useState } from "react";
import { useApp } from "../../state/store";
import type { TriageOptions } from "../../types";
import { JobProgressBar } from "../JobProgressBar";
import { PluginConsole } from "../plugins/PluginConsole";
import { PluginPicker } from "../plugins/PluginPicker";
import { PluginResults } from "../plugins/PluginResults";
import { PluginStatusGrid } from "../plugins/PluginStatusGrid";
import { useRunTiming } from "../plugins/useRunTiming";
import { EmptyState, Meter, Panel } from "../primitives";
import { TriageLauncher } from "./TriageLauncher";
import { AnalystNotice } from "./AnalystNotice";

type WorkbenchTab = "triage" | "manual";

export function VolatilityWorkbench() {
  const {
    investigationId,
    pluginCatalog,
    pluginRun,
    triageProgress,
    loadPluginCatalog,
    restoreLatestPluginRun,
  } = useApp();
  const [tab, setTab] = useState<WorkbenchTab>("triage");
  const restoredFor = useRef<string | null>(null);
  const triageLive = !!triageProgress && triageProgress.status !== "triaged"
    && triageProgress.status !== "failed" && triageProgress.stage !== "received";
  const manualLive = pluginRun?.status === "queued" || pluginRun?.status === "running";

  useEffect(() => {
    if (pluginCatalog.length === 0) void loadPluginCatalog();
  }, [pluginCatalog.length, loadPluginCatalog]);

  useEffect(() => {
    if (!investigationId) {
      restoredFor.current = null;
      return;
    }
    if (restoredFor.current === investigationId) return;
    restoredFor.current = investigationId;
    void restoreLatestPluginRun();
  }, [investigationId, restoreLatestPluginRun]);

  return (
    <div className="space-y-4">
      <AnalystNotice />

      {/* Settings live in a persistent left rail so changing plugins/coverage
          never requires scrolling away from the live results on the right. */}
      <div className="grid gap-5 lg:grid-cols-[320px_1fr] lg:items-start">
        <div className="space-y-4 lg:sticky lg:top-6">
          <Panel eyebrow="VolMemLyzer workbench" title="Choose your Volatility workflow">
            <div className="space-y-2 p-3">
              <Tab active={tab === "triage"} onClick={() => setTab("triage")}>
                <span className="block text-sm">Automated triage{triageLive && <Live />}</span>
                <span className="mt-1 block text-[11px] font-normal text-ink-400">Run a scored, repeatable evidence plan.</span>
              </Tab>
              <Tab active={tab === "manual"} onClick={() => setTab("manual")}>
                <span className="block text-sm">Manual plugin suite{manualLive && <Live />}</span>
                <span className="mt-1 block text-[11px] font-normal text-ink-400">Run individual Volatility plugins on demand.</span>
              </Tab>
            </div>
          </Panel>

          {tab === "triage" ? <AutomatedTriageControls /> : <ManualSuiteControls />}
        </div>

        <div className="min-w-0 space-y-4">
          {tab === "triage" ? <AutomatedTriageActivity /> : <ManualSuiteActivity />}
        </div>
      </div>
    </div>
  );
}

function Live() {
  return <span className="ml-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />;
}

function Tab({ active, onClick, children }: {
  active: boolean;
  onClick(): void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`block w-full rounded-md border px-4 py-3 text-left transition-colors ${
        active ? "bg-accent/15 text-accent-soft" : "text-ink-400 hover:text-ink-200"
      }`}
    >
      {children}
    </button>
  );
}

function AutomatedTriageControls() {
  const { investigationId, pluginCatalog, pluginRun, triageProgress, triageStarting, startTriage } = useApp();
  const stage = triageProgress?.stage ?? "";
  const running = !!triageProgress && triageProgress.status !== "triaged"
    && triageProgress.status !== "failed" && stage !== "received";
  const manualRunning = pluginRun?.status === "queued" || pluginRun?.status === "running";

  const run = (options: TriageOptions) => startTriage(options);

  return (
    <Panel eyebrow="Automated triage" title="Choose coverage">
      {pluginCatalog.length === 0 ? (
        <EmptyState title="Loading the plugin catalog…" />
      ) : (
        <TriageLauncher
          catalog={pluginCatalog}
          disabled={running || manualRunning}
          disabledLabel={manualRunning ? "Manual suite running…" : undefined}
          starting={triageStarting}
          hasInvestigation={!!investigationId}
          onRun={run}
        />
      )}
    </Panel>
  );
}

function AutomatedTriageActivity() {
  const { pluginRun, triageProgress, triageRunSeq } = useApp();
  const stage = triageProgress?.stage ?? "";
  const running = !!triageProgress && triageProgress.status !== "triaged"
    && triageProgress.status !== "failed" && stage !== "received";
  const events = triageProgress?.events ?? [];
  const requested = triageProgress?.requested_plugins ?? [];
  const manualRunning = pluginRun?.status === "queued" || pluginRun?.status === "running";
  const failedCount = new Set(events.filter((event) =>
    (event.type === "plugin_finished" && !event.ok)
      || event.type === "plugin_failed"
      || event.type === "plugin_unavailable")
    .map((event) => event.plugin)
    .filter(Boolean)).size;
  const { elapsed } = useRunTiming(events, running, triageRunSeq);

  return (
    <Panel
      eyebrow={triageProgress?.status === "failed" ? "Failed" : running ? "Live" : "Activity"}
      title={triageProgress?.message || "Triage activity"}
      right={triageProgress ? (
        <div className="flex items-center gap-3 font-mono text-[11px] text-ink-400">
          {running && (
            <span className="flex items-center gap-1.5 text-accent-soft">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
              elapsed {elapsed}
            </span>
          )}
          {!running && <span>ran {elapsed}</span>}
          <span>{triageProgress.progress}%</span>
        </div>
      ) : undefined}
    >
      <div className="space-y-4 p-4">
        {triageProgress ? (
          <>
            <JobProgressBar job={triageProgress} />
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-400">
              {triageProgress.triage_mode && <span className="capitalize">{triageProgress.triage_mode} triage</span>}
              {requested.length > 0 && <span>· {requested.length} plugin(s)</span>}
              {!!triageProgress.concurrency && (
                <span>· {triageProgress.concurrency === 1 ? "sequential" : `${triageProgress.concurrency} workers`}</span>
              )}
              {triageProgress.cache_source && (
                <span className="rounded bg-accent/10 px-1.5 py-0.5 font-mono text-accent-soft ring-1 ring-inset ring-accent/25">
                  cache: {triageProgress.cache_source}
                </span>
              )}
              {failedCount > 0 && <span className="text-risk-critical">{failedCount} failed</span>}
            </div>
          </>
        ) : (
          <div className="rounded-md border border-surface-700/60 bg-surface-900/30 px-3 py-3 text-[12px] text-ink-400">
            {manualRunning
              ? "The manual suite is using Volatility. Automated triage activity will appear here once it starts."
              : "No automated triage has started for this investigation."}
          </div>
        )}

        <div>
          <div className="eyebrow mb-2">Plugin status</div>
          {requested.length > 0 ? (
            <PluginStatusGrid requested={requested} events={events} />
          ) : (
            <p className="text-[12px] text-ink-400">Plugin states will appear when triage starts.</p>
          )}
        </div>

        {requested.length > 0 && (
          <details open={running}>
            <summary className="eyebrow mb-2 cursor-pointer select-none">
              Live Volatility console
            </summary>
            <PluginConsole events={events} />
          </details>
        )}
      </div>
    </Panel>
  );
}

function ManualSuiteControls() {
  const {
    investigationId,
    pluginCatalog,
    pluginRun,
    triageProgress,
    pluginRunStarting,
    runPlugins,
    newPluginRun,
    setStage,
  } = useApp();

  if (!investigationId) {
    return (
      <Panel eyebrow="Manual suite" title="Run Volatility plugins on demand">
        <EmptyState title="No investigation yet" hint="Upload a memory image before running a plugin." />
        <div className="flex justify-center pb-6">
          <button className="btn-ghost text-xs" onClick={() => setStage("ingest")}>← Go to ingest</button>
        </div>
      </Panel>
    );
  }

  const triageRunning = !!triageProgress && triageProgress.status !== "triaged"
    && triageProgress.status !== "failed" && triageProgress.stage !== "received";

  if (pluginRun) {
    const running = pluginRun.status === "queued" || pluginRun.status === "running";
    return (
      <Panel
        eyebrow={pluginRun.status === "failed" ? "Failed" : running ? "Live" : "Complete"}
        title="Manual plugin run"
        right={<button className="btn-ghost text-xs" disabled={running} onClick={newPluginRun}>New run</button>}
      >
        <div className="space-y-2 px-4 py-4 text-[12px] text-ink-300">
          <p>
            {pluginRun.requested_plugins.length} selected · {pluginRun.concurrency === 1
              ? "sequential"
              : `${pluginRun.concurrency} workers`}
          </p>
          {pluginRun.error && <p className="text-risk-critical">{pluginRun.error}</p>}
        </div>
      </Panel>
    );
  }

  return (
    <Panel eyebrow="Manual suite" title={`${pluginCatalog.length || "…"} plugins available`}>
      {pluginCatalog.length === 0 ? (
        <EmptyState title="Loading the plugin catalog…" />
      ) : (
        <PluginPicker
          catalog={pluginCatalog}
          onRun={runPlugins}
          starting={pluginRunStarting}
          blocked={triageRunning}
          blockedReason={triageRunning
            ? "Automated triage is using Volatility. The manual suite will be available when it finishes."
            : undefined}
        />
      )}
    </Panel>
  );
}

function ManualSuiteActivity() {
  const { investigationId, client, pluginRun } = useApp();
  const running = pluginRun?.status === "queued" || pluginRun?.status === "running";
  const { elapsed } = useRunTiming(pluginRun?.events ?? [], running, pluginRun?.plugin_run_id);

  if (!investigationId || !pluginRun) {
    return (
      <Panel eyebrow="Activity" title="Manual plugin run">
        <EmptyState
          title="No manual run yet"
          hint="Pick plugins on the left and run them to see live output here."
        />
      </Panel>
    );
  }

  const failedCount = Object.keys(pluginRun.failed_plugins ?? {}).length || new Set(pluginRun.events.filter((event) =>
    (event.type === "plugin_finished" && !event.ok)
      || event.type === "plugin_failed"
      || event.type === "plugin_unavailable")
    .map((event) => event.plugin)
    .filter(Boolean)).size;

  return (
    <div className="space-y-4">
      <Panel
        eyebrow={pluginRun.status === "failed" ? "Failed" : running ? "Live" : "Complete"}
        title={pluginRun.message || "Manual plugin run"}
        right={
          <div className="flex items-center gap-3 font-mono text-[11px] text-ink-400">
            {running ? (
              <span className="flex items-center gap-1.5 text-accent-soft">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
                elapsed {elapsed}
              </span>
            ) : (
              <span>ran {elapsed}</span>
            )}
            <span>{pluginRun.progress}%</span>
          </div>
        }
      >
        <div className="px-4 py-4">
          <Meter
            value={pluginRun.progress / 100}
            tone={pluginRun.status === "failed" || failedCount > 0 ? "risk" : "accent"}
            progress
            label={pluginRun.message || "Manual plugin run"}
          />
        </div>
      </Panel>

      <Panel eyebrow="Progress" title="Plugin status">
        <div className="p-4">
          <PluginStatusGrid requested={pluginRun.requested_plugins} events={pluginRun.events} />
        </div>
      </Panel>

      <Panel eyebrow="Volatility log" title="Live console">
        <div className="p-4">
          <details open={running}>
            <summary className="eyebrow mb-2 cursor-pointer select-none">
              Live Volatility console
            </summary>
            <PluginConsole events={pluginRun.events} />
          </details>
        </div>
      </Panel>

      <PluginResults client={client} investigationId={investigationId} run={pluginRun} />
    </div>
  );
}
