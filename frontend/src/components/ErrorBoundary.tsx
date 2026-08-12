import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * A render error in one panel should not blank the workspace. Everything the
 * deep-dive draws comes from an untrusted memory image, so an unexpected shape
 * reaching a component is a case worth surviving rather than a case worth
 * crashing on.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("MemTriage render error", error, info.componentStack);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="panel p-6">
        <div className="eyebrow">Render error</div>
        <h2 className="mt-1 text-sm font-semibold text-mist-100">
          This view could not be drawn
        </h2>
        <p className="mt-2 max-w-xl text-[13px] text-mist-400">
          The rest of the workspace is still usable. {error.message}
        </p>
        <button
          className="btn-ghost mt-4"
          onClick={() => this.setState({ error: null })}
        >
          Try again
        </button>
      </div>
    );
  }
}
