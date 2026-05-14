import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
  }

  render() {
    if (!this.state.error) {
      return this.props.children;
    }

    return (
      <div style={{
        minHeight: "100vh",
        padding: 32,
        background: "#f8fafc",
        color: "#0f172a",
        fontFamily: "Inter, system-ui, sans-serif",
      }}>
        <div style={{
          maxWidth: 900,
          margin: "0 auto",
          background: "#fff",
          border: "1px solid #e2e8f0",
          borderRadius: 8,
          padding: 24,
          boxShadow: "0 10px 30px rgba(15,23,42,0.08)",
        }}>
          <h1 style={{ margin: "0 0 8px", fontSize: 22 }}>Something crashed while rendering this page</h1>
          <p style={{ margin: "0 0 16px", color: "#64748b" }}>
            The scan result was saved, but the UI hit a runtime error. Share this message to fix the exact line.
          </p>
          <pre style={{
            whiteSpace: "pre-wrap",
            background: "#0f172a",
            color: "#f8fafc",
            padding: 16,
            borderRadius: 6,
            overflowX: "auto",
            fontSize: 13,
          }}>
            {String(this.state.error?.stack || this.state.error?.message || this.state.error)}
            {this.state.info?.componentStack ? `\n\nComponent stack:${this.state.info.componentStack}` : ""}
          </pre>
          <button
            onClick={() => window.location.assign("/scan")}
            style={{
              marginTop: 16,
              border: 0,
              borderRadius: 6,
              padding: "10px 14px",
              background: "#2563eb",
              color: "#fff",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            Start New Scan
          </button>
        </div>
      </div>
    );
  }
}
