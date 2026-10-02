import { Panel } from "./primitives";

export function ExampleFileBanner({
  loading,
  onLoad,
  onRerun,
}: {
  loading?: boolean;
  onLoad(): void;
  onRerun(): void;
}) {
  return (
    <Panel eyebrow="Known sample" title="Example file detected">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <p className="max-w-3xl text-[12px] text-ink-300">
          A previously analyzed version of this sample is available. You can load the
          precomputed Volatility artifacts and investigation instead of running Volatility
          again, which may take several minutes.
        </p>
        <div className="flex shrink-0 gap-2">
          <button type="button" className="btn-accent text-xs" disabled={loading} onClick={onLoad}>
            {loading ? "Loading…" : "Load precomputed demo"}
          </button>
          <button type="button" className="btn-ghost text-xs" disabled={loading} onClick={onRerun}>
            Run analysis again
          </button>
        </div>
      </div>
    </Panel>
  );
}
