/**
 * A failed feed lookup is not a clean inventory, and neither is a kernel the
 * matcher deliberately left out.
 *
 * 13 Oct 2026: a credentialed audit of an Ubuntu 24.04 host collected 2,699
 * packages, the feed query failed, and the result showed coverage of 0% beside
 * no package findings — which reads as "nothing was vulnerable". The backend
 * now reports `lookup_failures`; the section must say so.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import PackageCoverageSection from "@audit/components/scan/PackageCoverageSection";

const base = {
  packages_collected: 2699,
  packages_assessable: 0,
  packages_cpe_resolved: 0,
  packages_toolchain_components: 0,
  packages_assessable_software: 2699,
  osv_advisories_without_range: 0,
  advisory_source: "Ubuntu:24.04:LTS",
  coverage_pct: 0,
  coverage_pct_software: 0,
};

describe("Package coverage — feed lookup failure", () => {
  it("names the failure instead of leaving a bare 0%", () => {
    render(
      <PackageCoverageSection
        coverage={{
          ...base,
          lookup_failures: ["Batch vulnerability query: connection lost"],
        }}
      />,
    );
    expect(
      screen.getByText("Vulnerability feed lookup failed"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Batch vulnerability query: connection lost"),
    ).toBeInTheDocument();
  });

  it("says nothing extra when every lookup succeeded", () => {
    render(
      <PackageCoverageSection coverage={{ ...base, lookup_failures: [] }} />,
    );
    expect(
      screen.queryByText("Vulnerability feed lookup failed"),
    ).not.toBeInTheDocument();
  });
});

describe("Package coverage — kernels that are not running", () => {
  it("names the kernels left out and the one that runs", () => {
    render(
      <PackageCoverageSection
        coverage={{
          ...base,
          lookup_failures: [],
          running_kernel: "6.8.0-146",
          packages_inactive_kernel: 7,
          inactive_kernels: ["6.8.0-142", "6.8.0-58"],
        }}
      />,
    );
    expect(
      screen.getByText("Installed kernels that are not running — not assessed"),
    ).toBeInTheDocument();
    expect(screen.getByText(/6\.8\.0-142, 6\.8\.0-58/)).toBeInTheDocument();
    expect(screen.getByText(/runs\s+6\.8\.0-146/)).toBeInTheDocument();
  });

  it("says nothing when every installed kernel is the running one", () => {
    render(
      <PackageCoverageSection
        coverage={{ ...base, lookup_failures: [], packages_inactive_kernel: 0 }}
      />,
    );
    expect(screen.queryByText(/not running/)).not.toBeInTheDocument();
  });
});
