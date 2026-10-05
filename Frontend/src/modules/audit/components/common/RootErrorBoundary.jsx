import { CcureButton, CcureCard, CcureAlert } from "../../../../design-system";
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
      <main
        style={{
          minHeight: "100vh",
          padding: "var(--ccure-space-xl)",
          background: "var(--ccure-bg)",
          color: "var(--ccure-text)",
        }}
      >
        <CcureCard
          headingLevel={1}
          title="Something crashed while rendering this page"
          subtitle="The scan result was saved, but the UI hit a runtime error. Share this message to fix the exact line."
        >
          <CcureAlert variant="danger">
            <pre
              style={{
                whiteSpace: "pre-wrap",
                overflowWrap: "anywhere",
                fontSize: "var(--ccure-text-sm)",
              }}
            >
              {String(
                this.state.error?.stack ||
                  this.state.error?.message ||
                  this.state.error,
              )}
              {this.state.info?.componentStack
                ? `\n\nComponent stack:${this.state.info.componentStack}`
                : ""}
            </pre>
          </CcureAlert>
          <CcureButton
            variant="primary"
            onClick={() => window.location.assign("/scan")}
          >
            Start New Scan
          </CcureButton>
        </CcureCard>
      </main>
    );
  }
}
