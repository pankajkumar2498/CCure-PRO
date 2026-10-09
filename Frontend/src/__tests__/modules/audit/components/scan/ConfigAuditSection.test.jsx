/**
 * Configuration Audit section.
 *
 * The properties defended here are the ones whose absence produced the gap
 * this section exists to close, and whose *misbehaviour* would be worse than
 * the gap was:
 *
 * * **ERROR is its own verdict.** Folding it into fail, manual review or
 *   not-applicable claims an assessment nobody performed. The engine keeps
 *   four states apart for exactly this reason and the UI must not undo it.
 *
 * * **"Not assessed" never renders as zeroes.** A host whose audit did not run
 *   and a host that passed everything are different facts; a tidy set of
 *   zeroes reads as the second.
 *
 * * **The counts are the API's.** Recomputing them from the rows produces a
 *   number that agrees until the table is filtered or paged, and then quietly
 *   does not.
 *
 * * **254 checks do not all mount at once.** The page this replaces rendered
 *   every row it was given.
 */

import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ConfigAuditSection from "@audit/components/scan/ConfigAuditSection";

/** Shaped exactly as `credentialed.report.config_audit` arrives. */
function audit(overrides = {}) {
  return {
    assessed: true,
    platform: "windows",
    policy_name: null,
    policy_fingerprint: null,
    checks_run: 254,
    checks_assessed: 254,
    benchmark_checks: 198,
    score_pct: 49.1,
    counts: {
      pass: 106,
      fail: 110,
      not_applicable: 32,
      manual_review: 6,
      error: 0,
    },
    results: [],
    ...overrides,
  };
}

function check(overrides = {}) {
  return {
    check_id: "rule_stig_win11_wn11_so_000005",
    title: "Minimum password length is at least 14 characters",
    outcome: "fail",
    severity: "medium",
    remediation: "Set the minimum password length to 14 or more.",
    qod: 95,
    confidence: "Confirmed",
    detection_method: "active_check",
    target: "10.180.6.30",
    cve_ids: [],
    references: [],
    error: null,
    evidence: [
      {
        raw: "password_policy[min_length]=0",
        expected: "at least 14 characters",
        observed: "0",
        collector: "windows_security_policy:collected",
        description: "Minimum password length is at least 14 characters",
        collected_at: "2026-09-22T07:57:37.925649+00:00",
      },
    ],
    metadata: {
      domain: "host_configuration",
      asset_id: null,
      check_type: "security_policy",
      finding_type: "config_check",
      collection_status: "collected",
    },
    ...overrides,
  };
}

describe("ConfigAuditSection — empty-state semantics", () => {
  it("says 'not assessed' rather than showing zeroes when no audit ran", () => {
    render(<ConfigAuditSection configAudit={null} />);
    expect(screen.getByText(/not assessed/i)).toBeInTheDocument();
    expect(
      screen.getByText(
        /not a statement that the host is\s+correctly configured/i,
      ),
    ).toBeInTheDocument();
    // The failure mode: a summary of zeroes that reads as a clean machine.
    expect(screen.queryByText("Compliance score")).not.toBeInTheDocument();
  });

  it("treats assessed:false as not assessed even when counts are present", () => {
    render(
      <ConfigAuditSection
        configAudit={audit({ assessed: false, counts: { pass: 0, fail: 0 } })}
      />,
    );
    expect(screen.getByText(/not assessed/i)).toBeInTheDocument();
  });

  it("distinguishes 'assessed, no individual results' from 'not assessed'", () => {
    render(<ConfigAuditSection configAudit={audit({ results: [] })} />);
    expect(screen.queryByText(/not assessed/i)).not.toBeInTheDocument();
    expect(
      screen.getByText(/recorded no individual check results/i),
    ).toBeInTheDocument();
  });
});

describe("ConfigAuditSection — counts come from the API", () => {
  it("renders the API's counts, not a recount of the rows", () => {
    // One row present, counts claiming 254. The counts must win: they are
    // authoritative and the rows are a page of them.
    render(<ConfigAuditSection configAudit={audit({ results: [check()] })} />);
    // "Passed"/"Failed" also label the filter chips, so scope to the metric
    // grid rather than the document.
    const metrics = document.querySelector(".ca-metrics");
    const passed = within(metrics).getByText("Passed").closest(".ca-metric");
    expect(within(passed).getByText("106")).toBeInTheDocument();
    const failed = within(metrics).getByText("Failed").closest(".ca-metric");
    expect(within(failed).getByText("110")).toBeInTheDocument();
    expect(screen.getByText("49.1%")).toBeInTheDocument();
  });

  it("shows a missing score as a dash rather than zero", () => {
    render(<ConfigAuditSection configAudit={audit({ score_pct: null })} />);
    const score = screen.getByText("Compliance score").closest(".ca-metric");
    expect(within(score).getByText("—")).toBeInTheDocument();
  });
});

describe("ConfigAuditSection — ERROR is its own state", () => {
  it("offers ERROR as a filter of its own", () => {
    render(<ConfigAuditSection configAudit={audit()} />);
    expect(
      screen.getByRole("button", { name: /^Error \(/ }),
    ).toBeInTheDocument();
  });

  it("surfaces the error count separately from every verdict", () => {
    render(
      <ConfigAuditSection
        configAudit={audit({
          counts: {
            pass: 106,
            fail: 110,
            not_applicable: 32,
            manual_review: 5,
            error: 1,
          },
        })}
      />,
    );
    const errors = screen.getByText("Errors").closest(".ca-metric");
    expect(within(errors).getByText("1")).toBeInTheDocument();
    expect(within(errors).getByText(/not a verdict/i)).toBeInTheDocument();
  });

  it("filters to error rows without matching failures", async () => {
    const user = userEvent.setup();
    render(
      <ConfigAuditSection
        configAudit={audit({
          counts: {
            pass: 0,
            fail: 1,
            not_applicable: 0,
            manual_review: 0,
            error: 1,
          },
          results: [
            check({
              check_id: "c-fail",
              title: "A failing check",
              outcome: "fail",
            }),
            check({
              check_id: "c-error",
              title: "An unassessable check",
              outcome: "error",
              error: "the host did not answer",
            }),
          ],
        })}
      />,
    );
    await user.click(screen.getByRole("button", { name: /^Error \(/ }));
    expect(screen.getByText("An unassessable check")).toBeInTheDocument();
    expect(screen.queryByText("A failing check")).not.toBeInTheDocument();
  });
});

describe("ConfigAuditSection — detail and evidence", () => {
  it("keeps evidence out of the DOM until it is asked for", async () => {
    const user = userEvent.setup();
    render(<ConfigAuditSection configAudit={audit({ results: [check()] })} />);
    expect(
      screen.queryByText("password_policy[min_length]=0"),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show" }));
    expect(
      screen.getByText("password_policy[min_length]=0"),
    ).toBeInTheDocument();
    expect(screen.getByText("at least 14 characters")).toBeInTheDocument();
    expect(
      screen.getByText(/Set the minimum password length/),
    ).toBeInTheDocument();
  });

  it("exposes the metadata the API carries, not a subset", async () => {
    const user = userEvent.setup();
    render(<ConfigAuditSection configAudit={audit({ results: [check()] })} />);
    await user.click(screen.getByRole("button", { name: "Show" }));
    for (const value of [
      "security_policy",
      "host_configuration",
      "config_check",
      "collected",
      "active_check",
      "Confirmed",
      "95%",
    ]) {
      expect(screen.getByText(value)).toBeInTheDocument();
    }
  });

  it("renders a check that could not run with its reason", async () => {
    const user = userEvent.setup();
    render(
      <ConfigAuditSection
        configAudit={audit({
          results: [
            check({
              outcome: "error",
              error: "windows:userright_object: the state comparison failed",
              evidence: [],
            }),
          ],
        })}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Show" }));
    // The same phrase labels the Errors metric hint, so scope to the
    // expanded detail card rather than the whole document.
    const card = document.querySelector(".ca-detail-card");
    expect(
      within(card).getByText(/Could not be assessed/i),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/the state comparison failed/).length,
    ).toBeGreaterThan(0);
  });
});

describe("ConfigAuditSection — large result sets", () => {
  const many = Array.from({ length: 254 }, (_, i) =>
    check({ check_id: `check-${i}`, title: `Check number ${i}` }),
  );

  it("pages rather than mounting every row", () => {
    render(<ConfigAuditSection configAudit={audit({ results: many })} />);
    // 25 is the first page size; the rest must not be in the document.
    expect(screen.getByText("Check number 0")).toBeInTheDocument();
    expect(screen.queryByText("Check number 200")).not.toBeInTheDocument();
    expect(screen.getByText(/Showing 1–25 of 254 checks/)).toBeInTheDocument();
  });

  it("filters across the whole set, not only the visible page", async () => {
    const user = userEvent.setup();
    render(<ConfigAuditSection configAudit={audit({ results: many })} />);
    const search = screen.getByLabelText(/search checks/i);
    await user.type(search, "number 200");
    expect(screen.getByText("Check number 200")).toBeInTheDocument();
  });
});

describe("ConfigAuditSection — malformed and partial payloads", () => {
  it("survives results missing every optional field", async () => {
    const user = userEvent.setup();
    render(
      <ConfigAuditSection
        configAudit={audit({
          results: [{ check_id: "bare", outcome: "pass" }],
        })}
      />,
    );
    expect(screen.getAllByText("bare").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Show" }));
    // No throw, and the absent fields read as absent rather than as values.
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("survives counts being absent entirely", () => {
    render(<ConfigAuditSection configAudit={audit({ counts: undefined })} />);
    const metrics = document.querySelector(".ca-metrics");
    const passed = within(metrics).getByText("Passed").closest(".ca-metric");
    expect(within(passed).getByText("0")).toBeInTheDocument();
  });
});
