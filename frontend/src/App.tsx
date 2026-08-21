import { useEffect, useRef } from "react";
import { ErrorBanner } from "./components/ErrorBanner";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { LeftRail } from "./components/LeftRail";
import { TopBar } from "./components/TopBar";
import { AssistantView } from "./components/stages/AssistantView";
import { DeepDiveView } from "./components/stages/DeepDiveView";
import { IngestView } from "./components/stages/IngestView";
import { InventoryView } from "./components/stages/InventoryView";
import { ReportView } from "./components/stages/ReportView";
import { TriageView } from "./components/stages/TriageView";
import { useApp } from "./state/store";

export default function App() {
  const { stage, triageProgress, pluginRun, analysisProgress } = useApp();
  const allowNavigation = useRef(false);
  const workActive = (
    triageProgress?.status === "triaging"
    || pluginRun?.status === "queued"
    || pluginRun?.status === "running"
    || analysisProgress?.status === "analyzing"
    || analysisProgress?.status === "queued"
  );

  useEffect(() => {
    if (!workActive) return;
    window.history.pushState({ memtriageWorkGuard: true }, "", window.location.href);
    const onPopState = () => {
      if (allowNavigation.current) {
        allowNavigation.current = false;
        return;
      }
      const leave = window.confirm(
        "Analysis is still running. Leaving this page may make the live work harder to monitor. Continue?",
      );
      if (leave) {
        allowNavigation.current = true;
        window.history.back();
      } else {
        window.history.pushState({ memtriageWorkGuard: true }, "", window.location.href);
      }
    };
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("popstate", onPopState);
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => {
      window.removeEventListener("popstate", onPopState);
      window.removeEventListener("beforeunload", onBeforeUnload);
    };
  }, [workActive]);

  return (
    <div className="flex h-full flex-col">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <LeftRail />
        <main className="min-w-0 flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-[1180px]">
            <ErrorBanner />
            <ErrorBoundary key={stage}>
              {stage === "ingest" && <IngestView />}
              {stage === "triage" && <TriageView />}
              {stage === "inventory" && <InventoryView />}
              {stage === "deepdive" && <DeepDiveView />}
              {stage === "assist" && <AssistantView />}
              {stage === "report" && <ReportView />}
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  );
}
