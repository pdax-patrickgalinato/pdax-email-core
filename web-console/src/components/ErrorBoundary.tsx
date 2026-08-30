import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = { children: ReactNode };
type State = { message: string };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { message: "" };

  static getDerivedStateFromError(err: Error): State {
    return { message: err && err.message ? err.message : "render failed" };
  }

  componentDidCatch(err: Error, info: ErrorInfo) {
    console.warn("console render failed", err, info);
  }

  render() {
    if (!this.state.message) return this.props.children;
    return (
      <section className="page active">
        <div className="empty-state">
          This page failed to render. Reload the console.
          <div className="card-sub" style={{ marginTop: 8 }}>{this.state.message}</div>
        </div>
      </section>
    );
  }
}
