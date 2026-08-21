import { useEffect, useState } from "react";

const ACK_KEY = "memtriage.volmemlyzer.notice.acknowledged";

export function AnalystNotice() {
  const [open, setOpen] = useState(true);

  useEffect(() => {
    setOpen(window.sessionStorage.getItem(ACK_KEY) !== "1");
  }, []);

  const acknowledge = () => {
    window.sessionStorage.setItem(ACK_KEY, "1");
    setOpen(false);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-ink-950/80 p-4 backdrop-blur-sm">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="volmemlyzer-notice-title"
        className="w-full max-w-2xl rounded-lg border border-risk-medium/40 bg-ink-900 p-5 shadow-panel"
      >
        <div className="eyebrow text-risk-medium">Analyst notice</div>
        <h2 id="volmemlyzer-notice-title" className="mt-2 text-xl font-semibold text-mist-100">
          VolMemLyzer findings are review leads, not detections
        </h2>
        <p className="mt-3 text-sm leading-relaxed text-mist-300">
          This workbench is intentionally broad. It surfaces anything that could be interpreted
          as unsafe in any shape or form so an analyst can investigate it. False positives are
          expected by design; nothing here proves compromise, malware, or attribution.
        </p>
        <ul className="mt-4 space-y-2 text-[13px] leading-relaxed text-mist-300">
          <li>Confirm every lead against the raw artifact, process context, and other evidence.</li>
          <li>Risk thresholds and scoring profiles are configurable and can change what is surfaced.</li>
          <li>An empty result can indicate missing symbols or incomplete plugin output, not a clean image.</li>
        </ul>
        <div className="mt-5 flex justify-end">
          <button type="button" className="btn-accent" onClick={acknowledge}>
            I understand
          </button>
        </div>
      </section>
    </div>
  );
}