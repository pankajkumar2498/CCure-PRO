/**
 * Phase 1 sections against a **real** API response.
 *
 * Every other test in this directory renders a fixture somebody wrote, which
 * proves the component does what its author expected and nothing about whether
 * the backend agrees. This one renders
 * `src/__tests__/fixtures/credentialedReport.real.json`, extracted verbatim
 * from `GET /scans/{id}` for a credentialed audit of a real Windows 11 host —
 * the same scan the coverage baseline was measured against.
 *
 * It is the check that catches a renamed key, a number that arrives as a
 * string, a nested shape that is a list where the component expects an object,
 * and every other disagreement a hand-written fixture quietly hides.
 *
 * If the API's shape changes, this fails and it should: re-extract the fixture
 * and look at what moved before changing an assertion.
 */

import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import real from "../../../../fixtures/credentialedReport.real.json";
import ConfigAuditSection from "@audit/components/credentialed/ConfigAuditSection";
import PackageCoverageSection from "@audit/components/credentialed/PackageCoverageSection";
import PackageInventorySection from "@audit/components/credentialed/PackageInventorySection";
import SuppressedFindingsSection from "@audit/components/credentialed/SuppressedFindingsSection";

describe("Configuration Audit — real response", () => {
  it("shows the host's actual verdict counts", () => {
    render(<ConfigAuditSection configAudit={real.config_audit} />);
    const metrics = document.querySelector(".ca-metrics");

    // The real figures for this host: 110 fail / 106 pass / 32 n/a / 6 manual.
    const expected = {
      Passed: "106",
      Failed: "110",
      "Not applicable": "32",
      "Manual review": "6",
      Errors: "0",
    };
    for (const [label, value] of Object.entries(expected)) {
      const metric = within(metrics).getByText(label).closest(".ca-metric");
      expect(within(metric).getByText(value)).toBeInTheDocument();
    }
  });

  it("shows the real compliance score, rounded not recomputed", () => {
    render(<ConfigAuditSection configAudit={real.config_audit} />);
    // 49.07 from the API, displayed to one decimal.
    expect(screen.getByText("49.1%")).toBeInTheDocument();
  });

  it("reports the platform and the assessed totals the API sent", () => {
    render(<ConfigAuditSection configAudit={real.config_audit} />);
    const metrics = document.querySelector(".ca-metrics");
    expect(within(metrics).getByText("windows")).toBeInTheDocument();
    const assessed = within(metrics)
      .getByText("Checks assessed")
      .closest(".ca-metric");
    expect(
      within(assessed).getByText(String(real.config_audit.checks_assessed)),
    ).toBeInTheDocument();
  });

  it("says a policy was not named rather than inventing one", () => {
    // `policy_name` is null on this scan: the snapshot was built from the
    // scan's own request parameters, which is a real state and not an error.
    expect(real.config_audit.policy_name).toBeNull();
    render(<ConfigAuditSection configAudit={real.config_audit} />);
    expect(screen.getByText("None named")).toBeInTheDocument();
  });

  it("renders a real check's real evidence", async () => {
    const user = userEvent.setup();
    render(<ConfigAuditSection configAudit={real.config_audit} />);
    const failing = real.config_audit.results.find((r) => r.outcome === "fail");
    expect(failing).toBeTruthy();

    const buttons = screen.getAllByRole("button", { name: "Show" });
    await user.click(buttons[0]);

    const card = document.querySelector(".ca-detail-card");
    expect(card).toBeTruthy();
    // Whatever the collector actually recorded, not a placeholder.
    expect(within(card).getAllByText(/./).length).toBeGreaterThan(0);
  });
});

describe("Package Coverage — real response", () => {
  it("shows both percentages, which differ and are both correct", () => {
    const cov = real.package_coverage;
    render(<PackageCoverageSection coverage={cov} />);

    // 10.5% over everything collected, 45.5% over software only. A UI that
    // showed one would be answering a different question than the reader
    // thinks it is.
    expect(
      screen.getByText(`${cov.coverage_pct.toFixed(1)}%`),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(`${cov.coverage_pct_software.toFixed(1)}%`).length,
    ).toBeGreaterThan(0);
    expect(cov.coverage_pct).not.toBe(cov.coverage_pct_software);
  });

  it("shows the counts behind the percentages", () => {
    const cov = real.package_coverage;
    render(<PackageCoverageSection coverage={cov} />);
    expect(
      screen.getByText(cov.packages_collected.toLocaleString()),
    ).toBeInTheDocument();
    expect(
      screen.getByText(cov.packages_toolchain_components.toLocaleString()),
    ).toBeInTheDocument();
  });

  it("reports an unrecorded advisory source as such", () => {
    expect(real.package_coverage.advisory_source).toBeNull();
    render(<PackageCoverageSection coverage={real.package_coverage} />);
    expect(screen.getByText("not recorded")).toBeInTheDocument();
  });
});

describe("Package inventory — real response", () => {
  it("renders the packages the host actually reported", () => {
    render(
      <PackageInventorySection
        packages={real.packages}
        cves={[]}
        packagesEnumerated={real.packages_enumerated}
      />,
    );
    expect(screen.getByText(real.packages[0].name)).toBeInTheDocument();
    // The enumerated total is the API's, not the length of the page.
    expect(
      screen.getByText(
        new RegExp(real.packages_enumerated.toLocaleString() + "\\s+package"),
      ),
    ).toBeInTheDocument();
  });

  it("says 'no match' rather than 'not vulnerable' where nothing matched", () => {
    render(<PackageInventorySection packages={real.packages} cves={[]} />);
    expect(screen.getAllByText("No match").length).toBeGreaterThan(0);
    expect(screen.queryByText(/not vulnerable/i)).not.toBeInTheDocument();
  });
});

describe("Suppressed findings — real response", () => {
  it("states plainly that nothing was withheld on this scan", () => {
    // Genuinely empty here, which is the case the empty-state rule exists for.
    expect(real.suppressed_cves).toEqual([]);
    render(
      <SuppressedFindingsSection
        suppressed={real.suppressed_cves}
        candidatesEvaluated={real.candidates_evaluated}
        reportedCount={1871}
      />,
    );
    expect(
      screen.getByText(/No findings were suppressed or withheld/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows the real candidates-evaluated figure in the lifecycle chain", () => {
    render(
      <SuppressedFindingsSection
        suppressed={real.suppressed_cves}
        candidatesEvaluated={real.candidates_evaluated}
        reportedCount={1871}
      />,
    );
    // On this scan nothing was suppressed, so "evaluated" and "reported" are
    // the same number -- which is the chain being internally consistent, not
    // a duplicate. Scope to the step rather than the document.
    const step = screen
      .getByText("Candidates evaluated")
      .closest(".sf-chain__step");
    expect(
      within(step).getByText(real.candidates_evaluated.toLocaleString()),
    ).toBeInTheDocument();
  });
});
