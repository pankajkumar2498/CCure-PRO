import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // You can also log the error to an error reporting service
    console.error("ErrorBoundary caught an error:", error, errorInfo);
    this.setState({ error, errorInfo });
  }

  render() {
    if (this.state.hasError) {
      // You can render any custom fallback UI
      return (
        <div
          style={{
            padding: "24px",
            background: "rgba(239, 68, 68, 0.05)",
            border: "1px solid var(--danger)",
            borderRadius: "8px",
            color: "var(--text)",
            margin: "20px",
          }}
        >
          <h2 style={{ color: "var(--danger)", marginBottom: "12px" }}>
            Something went wrong.
          </h2>
          <details
            style={{
              whiteSpace: "pre-wrap",
              fontSize: "0.85rem",
              color: "var(--text-muted)",
            }}
          >
            <summary style={{ cursor: "pointer", marginBottom: "8px" }}>
              View Error Details
            </summary>
            {this.state.error && this.state.error.toString()}
            <br />
            {this.state.errorInfo && this.state.errorInfo.componentStack}
          </details>
          <button
            className="btn btn--outline"
            style={{ marginTop: "16px" }}
            onClick={() => window.location.reload()}
          >
            Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
