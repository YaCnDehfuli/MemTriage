import { useApp } from "../state/store";

/** The one place a failed request becomes visible. */
export function ErrorBanner() {
  const { error, clearError, retryLast } = useApp();
  if (!error) return null;
  return (
    <div
      role="alert"
      className="mb-4 flex items-start gap-3 rounded-lg border border-risk-critical/30 bg-risk-critical/10 px-4 py-3"
    >
      <span aria-hidden className="mt-0.5 text-risk-critical">▲</span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-mist-100">Something went wrong</div>
        <p className="mt-0.5 break-words text-[13px] text-mist-300">{error}</p>
      </div>
      <div className="flex shrink-0 gap-2">
        {retryLast && (
          <button className="btn-ghost text-[12px]" onClick={() => void retryLast()}>
            Retry
          </button>
        )}
        <button className="btn-ghost text-[12px]" onClick={clearError} aria-label="Dismiss">
          Dismiss
        </button>
      </div>
    </div>
  );
}
