import { useEffect } from "react";
import { LeftRail } from "./components/LeftRail";
import { TopBar } from "./components/TopBar";
import { DeepDiveView } from "./components/stages/DeepDiveView";
import { IngestView } from "./components/stages/IngestView";
import { InventoryView } from "./components/stages/InventoryView";
import { ReportView } from "./components/stages/ReportView";
import { TriageView } from "./components/stages/TriageView";
import { useApp } from "./state/store";

export default function App() {
  const { stage, demo, bootstrap, triage } = useApp();

  // Boot straight into a populated workspace in demo mode.
  useEffect(() => {
    if (demo && !triage) void bootstrap();
  }, [demo, triage, bootstrap]);

  return (
    <div className="flex h-full flex-col">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <LeftRail />
        <main className="min-w-0 flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-[1180px]">
            {stage === "ingest" && <IngestView />}
            {stage === "triage" && <TriageView />}
            {stage === "inventory" && <InventoryView />}
            {stage === "deepdive" && <DeepDiveView />}
            {stage === "report" && <ReportView />}
          </div>
        </main>
      </div>
    </div>
  );
}
