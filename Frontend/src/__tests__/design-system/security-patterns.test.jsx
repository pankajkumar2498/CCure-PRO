/**
 * Checkpoint 3B security patterns.
 *
 * Three patterns, each built because the survey found repeated implementations
 * that disagreed with each other. The assertions below are mostly about
 * *security meaning* rather than appearance: that a band is named, that an
 * unrecognised scan status is not reported as a running one, and that unknown
 * progress is never rendered as a number.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import CcureSeverityBadge, {
  SEVERITIES,
  normalizeSeverity,
} from "../../design-system/patterns/CcureSeverityBadge";
import CcureScanStatus, {
  SCAN_STATUSES,
} from "../../design-system/patterns/CcureScanStatus";
import CcureScanProgress from "../../design-system/patterns/CcureScanProgress";
import RiskBadge from "@audit/components/scan/RiskBadge";

/* ══════════════════════════════════════════════════════════════════════════
   Severity
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureSeverityBadge", () => {
  it("renders every band in the application's vocabulary", () => {
    for (const level of SEVERITIES) {
      const { unmount, container } = render(
        <CcureSeverityBadge severity={level} />,
      );
      expect(container.querySelector(`.cc-sev--${level}`)).not.toBeNull();
      unmount();
    }
  });

  it("names the band in text, never colour alone", () => {
    render(<CcureSeverityBadge severity="critical" />);
    // WCAG 1.4.1. On a triage queue this is the difference between acting on a
    // finding and not seeing it.
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("keeps the band in the accessible name when the label is hidden", () => {
    const { container } = render(
      <CcureSeverityBadge severity="high" showLabel={false} />,
    );
    expect(container.textContent).toContain("High");
    expect(container.querySelector(".cc-sr-only")).toHaveTextContent("High");
  });

  it("accepts both spellings the API returns", () => {
    // Phase3Results ships a getSevColor helper that exists solely to try
    // "Critical", then "critical", then a fallback.
    const { container: a } = render(<CcureSeverityBadge severity="Critical" />);
    const { container: b } = render(<CcureSeverityBadge severity="critical" />);
    expect(a.querySelector(".cc-sev--critical")).not.toBeNull();
    expect(b.querySelector(".cc-sev--critical")).not.toBeNull();
  });

  it("maps informational onto info", () => {
    expect(normalizeSeverity("informational")).toBe("info");
  });

  it("keeps none and unscored distinct from info", () => {
    // "No severity assigned" and "no rating published" are both weaker claims
    // than "informational", and on a compliance report the difference decides
    // whether a control counts.
    expect(normalizeSeverity("none")).toBe("none");
    expect(normalizeSeverity("unscored")).toBe("unscored");
    expect(normalizeSeverity("none")).not.toBe("info");
  });

  it("treats an unrecognised value as unscored, not as info", () => {
    // The old RiskBadge fell back to Info, which asserts a rating that was
    // never published.
    expect(normalizeSeverity("banana")).toBe("unscored");
    expect(normalizeSeverity(null)).toBe("unscored");
    expect(normalizeSeverity(undefined)).toBe("unscored");
    render(<CcureSeverityBadge severity="banana" />);
    expect(screen.getByText("Unscored")).toBeInTheDocument();
  });

  it("renders a score alongside the band when one is supplied", () => {
    render(<CcureSeverityBadge severity="high" score={7.5} />);
    expect(screen.getByText("7.5")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("hardcodes no colour", () => {
    const { container } = render(
      <CcureSeverityBadge severity="critical" score={9.8} />,
    );
    // Colour must come from --ccure-sev-* so it inverts with the theme; that
    // is exactly what the eleven ad-hoc implementations got wrong.
    for (const el of container.querySelectorAll("*")) {
      expect(el.getAttribute("style") ?? "").not.toMatch(/color|background/);
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Scan status
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureScanStatus", () => {
  it("labels every status in the application's vocabulary", () => {
    const expected = {
      complete: "Completed",
      completed: "Completed",
      running: "Running",
      queued: "Queued",
      pending: "Pending",
      failed: "Failed",
      unreachable: "Host Unreachable",
      cancelled: "Cancelled",
      canceled: "Cancelled",
    };
    for (const [status, label] of Object.entries(expected)) {
      const { unmount } = render(<CcureScanStatus status={status} />);
      expect(screen.getByText(label)).toBeInTheDocument();
      unmount();
    }
    expect(SCAN_STATUSES.sort()).toEqual(Object.keys(expected).sort());
  });

  it("carries both spellings of completed and cancelled", () => {
    // The API returns both; dropping either would render real scans as unknown.
    const { unmount } = render(<CcureScanStatus status="complete" />);
    expect(screen.getByText("Completed")).toBeInTheDocument();
    unmount();
    render(<CcureScanStatus status="completed" />);
    expect(screen.getByText("Completed")).toBeInTheDocument();
  });

  it("reports an unrecognised status as Unknown, NOT as running", () => {
    // ArchivedScans.jsx does `STATUS_STYLE[status] || STATUS_STYLE.running`,
    // so an unknown status displays as a scan in progress — a false statement
    // about a scan on a page whose job is to report what happened.
    render(<CcureScanStatus status="something_new" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.queryByText("Running")).toBeNull();
  });

  it("surfaces the raw value of an unrecognised status", () => {
    const { container } = render(<CcureScanStatus status="weird_state" />);
    // So an operator can see what the API actually said.
    expect(container.firstChild).toHaveAttribute(
      "title",
      "Unrecognised status: weird_state",
    );
  });

  it("handles a missing status without inventing one", () => {
    render(<CcureScanStatus status={null} />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("keeps unreachable distinct from failed", () => {
    // "The scanner broke" and "the host never answered" send an operator to
    // different places.
    const { unmount } = render(<CcureScanStatus status="unreachable" />);
    expect(screen.getByText("Host Unreachable")).toBeInTheDocument();
    unmount();
    render(<CcureScanStatus status="failed" />);
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("pulses only while running", () => {
    const { container: a, unmount } = render(
      <CcureScanStatus status="running" />,
    );
    expect(a.querySelector(".cc-scan-status__pulse")).not.toBeNull();
    unmount();
    const { container: b } = render(<CcureScanStatus status="complete" />);
    // Animating a settled state would suggest work is still happening.
    expect(b.querySelector(".cc-scan-status__pulse")).toBeNull();
  });

  it("hides the pulse from assistive technology", () => {
    const { container } = render(<CcureScanStatus status="running" />);
    expect(container.querySelector(".cc-scan-status__pulse")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Scan progress
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureScanProgress", () => {
  it("reports a known percentage", () => {
    render(<CcureScanProgress value={67} status="running" />);
    const bar = screen.getByRole("progressbar", { name: "Scan progress" });
    expect(bar).toHaveAttribute("aria-valuenow", "67");
    expect(screen.getByText("67%")).toBeInTheDocument();
  });

  it("treats unknown progress as indeterminate, never as a number", () => {
    render(<CcureScanProgress value={null} status="running" />);
    const bar = screen.getByRole("progressbar");
    // SecurityDashboard does `scan.progress_pct || 5` and Phase1Results
    // hardcodes 65%. Both assert a measurement that was never taken.
    expect(bar).not.toHaveAttribute("aria-valuenow");
    expect(bar).toHaveAttribute("aria-valuetext", "In progress");
    expect(screen.queryByText(/%/)).toBeNull();
  });

  it("does not render 0% for a stopped scan of unknown extent", () => {
    render(<CcureScanProgress value={null} status="failed" />);
    const bar = screen.getByRole("progressbar");
    // "No progress was made" is a different and unsupported claim from
    // "we never learned how far it got".
    expect(bar).not.toHaveAttribute("aria-valuenow");
    expect(bar).toHaveAttribute("aria-valuetext", "Progress unknown");
    expect(screen.queryByText("0%")).toBeNull();
  });

  it("stops animating once a scan has stopped", () => {
    const { container } = render(
      <CcureScanProgress value={null} status="cancelled" />,
    );
    // A bar sliding forever under a scan that failed ten minutes ago is
    // actively misleading.
    expect(container.querySelector(".cc-progress--indeterminate")).toBeNull();
  });

  it("still animates while a scan is live with unknown progress", () => {
    const { container } = render(
      <CcureScanProgress value={null} status="running" />,
    );
    expect(
      container.querySelector(".cc-progress--indeterminate"),
    ).not.toBeNull();
  });

  it("shows a completed scan as 100% whatever the last poll said", () => {
    render(<CcureScanProgress value={97} status="complete" />);
    // Leaving it short suggests something is still outstanding.
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "100",
    );
  });

  it("clamps an out-of-range value", () => {
    render(<CcureScanProgress value={140} status="running" />);
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "100",
    );
  });

  it("renders the phase caption when supplied", () => {
    render(
      <CcureScanProgress
        value={40}
        status="running"
        phase="Phase 2 — port scan"
      />,
    );
    expect(screen.getByText("Phase 2 — port scan")).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RiskBadge consolidation
   ══════════════════════════════════════════════════════════════════════════ */

describe("RiskBadge (deprecated adapter)", () => {
  it("keeps working for its two existing consumers", () => {
    // CredentialedResults passes `level`; ScanHistory passes `level` + `score`.
    render(<RiskBadge level="Critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("still accepts a score", () => {
    render(<RiskBadge level="High" score={8.1} />);
    expect(screen.getByText("8.1")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("no longer hardcodes a colour", () => {
    const { container } = render(<RiskBadge level="Critical" />);
    // Every colour it used to carry failed WCAG AA on white — Critical at
    // 3.27:1, Medium at 2.15:1 — and none of them responded to data-theme.
    for (const el of container.querySelectorAll("*")) {
      expect(el.getAttribute("style") ?? "").not.toMatch(/color|background/);
    }
  });

  it("renders one badge, not two competing implementations", () => {
    const { container } = render(<RiskBadge level="Low" />);
    expect(container.querySelectorAll(".cc-badge")).toHaveLength(1);
    expect(container.querySelector(".cc-sev--low")).not.toBeNull();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Theme
   ══════════════════════════════════════════════════════════════════════════ */

describe("security patterns under dark theme", () => {
  it("render without inline colour in either theme", () => {
    for (const theme of ["light", "dark"]) {
      if (theme === "dark")
        document.documentElement.setAttribute("data-theme", "dark");
      const { container, unmount } = render(
        <>
          <CcureSeverityBadge severity="critical" score={9.8} />
          <CcureScanStatus status="running" />
          <CcureScanProgress value={50} status="running" />
        </>,
      );
      for (const el of container.querySelectorAll("*")) {
        const style = el.getAttribute("style") ?? "";
        // Width on the progress bar is legitimate — a per-instance value, not
        // a design decision. Colour never is.
        expect(style).not.toMatch(/(^|;)\s*(color|background)/);
      }
      unmount();
      document.documentElement.removeAttribute("data-theme");
    }
  });
});
