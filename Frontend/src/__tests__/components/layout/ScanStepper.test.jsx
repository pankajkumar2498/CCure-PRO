/**
 * ScanStepper — Checkpoint 3C batch 15.
 *
 * Written against the legacy stepper BEFORE migration. Everything up to the
 * last block holds on both sides; the last block is the migration spec and
 * fails on the baseline.
 *
 * Consumed by Phase1Results, Phase2Results and Phase3Results, all unmigrated,
 * each passing only `current`. The rest comes from ScanContext, mocked here so
 * every pipeline state can be set directly.
 *
 * ── Dual-path helper ───────────────────────────────────────────────────────
 * The legacy steps are `.stepper-step` divs; migrated ones are list items.
 * `step(label)` finds the step containing a label either way, and every
 * regression assertion reads the step's visible words rather than its class.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";

import ScanStepper from "../../../components/layout/ScanStepper";
import { PIPELINE_STATES } from "../../../context/ScanContext";

let scan;
vi.mock("../../../context/ScanContext", async (importOriginal) => ({
  ...(await importOriginal()),
  useScan: () => scan,
}));

const setScan = (over = {}) => {
  scan = {
    scanId: null,
    scanNo: null,
    pipelineMode: "basic",
    pipelineState: PIPELINE_STATES.IDLE,
    ...over,
  };
};

const LABELS = ["Discovery", "Port Scan", "Vulnerability", "Topology"];
const shownSteps = () =>
  LABELS.filter((l) => screen.queryByText(l, { exact: true }));
const step = (label) =>
  screen.getByText(label, { exact: true }).closest("li, .stepper-step");

beforeEach(() => setScan());

/* ══════════════════════════════════════════════════════════════════════════
   Which steps a pipeline shows
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanStepper — steps per pipeline", () => {
  it.each([
    ["basic", ["Discovery"]],
    ["asset", ["Discovery", "Port Scan"]],
    ["vulnerability_audit", ["Discovery", "Port Scan", "Vulnerability"]],
    ["advanced", ["Discovery", "Port Scan", "Vulnerability"]],
  ])("%s shows %j", (mode, expected) => {
    setScan({ pipelineMode: mode });
    render(<ScanStepper />);
    expect(shownSteps()).toEqual(expected);
  });

  it("falls back to the basic pipeline when no mode is set", () => {
    setScan({ pipelineMode: null });
    render(<ScanStepper />);
    expect(shownSteps()).toEqual(["Discovery"]);
  });

  it("shows topology while topology mapping is genuinely running", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.TOPOLOGY_MAP,
    });
    render(<ScanStepper />);
    expect(shownSteps()).toContain("Topology");
    expect(step("Topology")).toHaveTextContent("Scanning…");
    expect(step("Vulnerability")).toHaveTextContent("Complete");
  });

  it("does not claim a topology step on a finished two-phase scan", () => {
    setScan({ pipelineMode: "asset", pipelineState: PIPELINE_STATES.COMPLETE });
    render(<ScanStepper />);
    expect(shownSteps()).toEqual(["Discovery", "Port Scan"]);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   What each step says
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanStepper — step state in words", () => {
  it("reads done, running and pending off the pipeline state", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.PORT_SCAN,
    });
    render(<ScanStepper />);
    expect(step("Discovery")).toHaveTextContent("Complete");
    expect(step("Port Scan")).toHaveTextContent("Scanning…");
    expect(step("Vulnerability")).toHaveTextContent("CVE & risk audit");
    expect(step("Vulnerability")).not.toHaveTextContent(
      /Complete|Scanning|Failed/,
    );
  });

  it.each([[PIPELINE_STATES.COMPLETE], [PIPELINE_STATES.REPORT_READY]])(
    "marks every step complete at %s",
    (state) => {
      setScan({ pipelineMode: "vulnerability_audit", pipelineState: state });
      render(<ScanStepper current={1} />);
      for (const l of ["Discovery", "Port Scan", "Vulnerability"]) {
        expect(step(l)).toHaveTextContent("Complete");
      }
    },
  );

  it("names the failed step when the pipeline errors", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.ERROR,
    });
    render(<ScanStepper current={2} />);
    expect(step("Discovery")).toHaveTextContent("Complete");
    expect(step("Port Scan")).toHaveTextContent("Failed");
    expect(step("Vulnerability")).toHaveTextContent("CVE & risk audit");
  });

  it("falls back to the page's `current` when the pipeline is idle", () => {
    setScan({ pipelineMode: "asset", pipelineState: PIPELINE_STATES.IDLE });
    render(<ScanStepper current={2} />);
    expect(step("Discovery")).toHaveTextContent("Complete");
    // Active but not running: the step's own description, not "Scanning…".
    expect(step("Port Scan")).toHaveTextContent("Map open services");
    expect(step("Port Scan")).not.toHaveTextContent(/Scanning|Complete/);
  });

  it("falls back to `current` for a state it does not map (paused)", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.PAUSED,
    });
    render(<ScanStepper current={3} />);
    expect(step("Port Scan")).toHaveTextContent("Complete");
    expect(step("Vulnerability")).toHaveTextContent("CVE & risk audit");
  });

  it("shows every step pending with no state and no `current`", () => {
    setScan({ pipelineMode: "vulnerability_audit" });
    render(<ScanStepper />);
    expect(step("Discovery")).toHaveTextContent("Find live hosts");
    expect(screen.queryByText("Complete")).toBeNull();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Scan number
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanStepper — scan number", () => {
  it("shows the scan number once a scan exists", () => {
    setScan({ scanId: "scan-uuid-1", scanNo: 42 });
    render(<ScanStepper />);
    expect(screen.getByText("Scan No. 42")).toBeInTheDocument();
  });

  it("shows a dash when the number has not arrived", () => {
    setScan({ scanId: "scan-uuid-1", scanNo: null });
    render(<ScanStepper />);
    expect(screen.getByText("Scan No. -")).toBeInTheDocument();
  });

  it("shows nothing before a scan exists", () => {
    render(<ScanStepper />);
    expect(screen.queryByText(/Scan No\./)).toBeNull();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Migration spec — fails on the baseline
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanStepper — migration spec", () => {
  it("is an ordered list named for the pipeline", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.PORT_SCAN,
    });
    render(<ScanStepper />);
    const list = screen.getByRole("list", { name: "Scan pipeline" });
    expect(list.tagName).toBe("OL");
    expect(within(list).getAllByRole("listitem")).toHaveLength(3);
  });

  it("marks exactly the active step as the current step", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.PORT_SCAN,
    });
    const { container } = render(<ScanStepper />);
    const current = container.querySelectorAll('[aria-current="step"]');
    expect(current).toHaveLength(1);
    expect(current[0]).toHaveTextContent("Port Scan");
  });

  it("marks no step current once the scan is complete", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.COMPLETE,
    });
    const { container } = render(<ScanStepper />);
    // The list is asserted first so this cannot pass vacuously on a stepper
    // that never sets aria-current at all.
    expect(
      screen.getByRole("list", { name: "Scan pipeline" }),
    ).toBeInTheDocument();
    expect(container.querySelectorAll("[aria-current]")).toHaveLength(0);
  });

  it("keeps the markers and separators out of the accessible text", () => {
    // ✓, !, the step number and › duplicate what the words already say, and a
    // screen reader otherwise reads "check mark", "exclamation", "1", "›".
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.ERROR,
      scanId: "scan-uuid-1",
      scanNo: 42,
    });
    const { container } = render(<ScanStepper current={2} />);
    const glyphs = [...container.querySelectorAll("*")].filter(
      (el) =>
        el.children.length === 0 &&
        /^(✓|!|›|[1-4])$/.test(el.textContent.trim()),
    );
    expect(glyphs.length).toBeGreaterThanOrEqual(4);
    for (const el of glyphs) {
      expect(el.closest('[aria-hidden="true"]'), el.outerHTML).not.toBeNull();
    }
  });

  it("renders no inline styles", () => {
    setScan({
      pipelineMode: "vulnerability_audit",
      pipelineState: PIPELINE_STATES.VULN_SCAN,
      scanId: "scan-uuid-1",
      scanNo: 42,
    });
    const { container } = render(<ScanStepper />);
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
  });
});
