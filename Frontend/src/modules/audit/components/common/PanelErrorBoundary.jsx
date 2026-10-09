import { CcureButton, CcureAlert } from "../../../../design-system";
import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(_error) {
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
      return (
        <CcureAlert variant="danger" title="Something went wrong.">
          <details
            style={{
              whiteSpace: "pre-wrap",
              overflowWrap: "anywhere",
              fontSize: "var(--ccure-text-sm)",
            }}
          >
            <summary>View Error Details</summary>
            {this.state.error && this.state.error.toString()}
            <br />
            {this.state.errorInfo && this.state.errorInfo.componentStack}
          </details>
          <CcureButton
            variant="secondary"
            onClick={() => window.location.reload()}
          >
            Reload Page
          </CcureButton>
        </CcureAlert>
      );
    }

    return this.props.children;
  }
}
