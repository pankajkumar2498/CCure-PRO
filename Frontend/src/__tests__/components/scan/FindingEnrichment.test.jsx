/**
 * P1-1 — the CVE enrichment the credentialed findings list never showed.
 *
 * Measured at **zero references** to fourteen fields across every renderer on
 * that page. On one live scan of 1,976 findings that hid 10 KEV-listed CVEs,
 * 11 with a public exploit, 2 linked to ransomware and 42 carrying the only
 * remediation text written for them.
 *
 * The row below is shaped from a real one.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  FindingSignals,
  FindingDetail,
  isPresent,
} from "../../../components/scan/FindingEnrichment";

const CVE = {
  cve_id: "CVE-2025-10585",
  severity: "Critical",
  cvss: 9.8,
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  cvss_version: "3.1",
  in_kev: true,
  kev_due_date: "2025-10-14",
  has_exploit: true,
  verified_exploit: false,
  canary_confirmed: false,
  ransomware_linked: false,
  epss_score: 0.007,
  epss_percentile: 0.72061,
  priority_level: "P0",
  priority_score: 100.0,
  installed_version: "138.0.7204.184",
  fixed_version: "140.0.7339.185",
  detected_version: "138.0.7204.184",
  matched_by: "cpe",
  detection_method: "credentialed_package",
  qod: 97,
  confidence: "Confirmed",
  attack_surface: "remote",
  exploit_sources: ["CISA KEV", "VulnCheck KEV"],
  vendor_remediation:
    "CISA ICSA-26-202-06: Block access to untrusted or external web content",
  vendor_advisories: [
    { advisory_id: "ICSA-26-202-06", url: "https://example.test/a" },
  ],
};

describe("signals on the row", () => {
  it("shows KEV with its mandated due date", () => {
    render(<FindingSignals cve={CVE} />);
    expect(screen.getByText(/KEV · due 2025-10-14/)).toBeInTheDocument();
  });

  it("labels has_exploit as availability, never as exploitability", () => {
    render(<FindingSignals cve={CVE} />);
    const badge = screen.getByText("Exploit available");
    // CLAUDE.md: it means a public exploit exists for the CVE, and says
    // nothing about whether this host can be exploited.
    expect(badge).toHaveAttribute(
      "title",
      expect.stringMatching(/does not mean this host is exploitable/i),
    );
  });

  it("shows the computed priority and the EPSS probability", () => {
    render(<FindingSignals cve={CVE} />);
    expect(screen.getByText("P0")).toBeInTheDocument();
    expect(screen.getByText("EPSS 0.7%")).toBeInTheDocument();
  });

  it("does not show a signal the API reported as false", () => {
    render(<FindingSignals cve={CVE} />);
    expect(screen.queryByText("Verified exploit")).toBeNull();
    expect(screen.queryByText("Ransomware")).toBeNull();
    expect(screen.queryByText("Seen exploited")).toBeNull();
  });

  it("shows ransomware and verified-exploit when the API reports them", () => {
    render(
      <FindingSignals
        cve={{ ...CVE, verified_exploit: true, ransomware_linked: true }}
      />,
    );
    expect(screen.getByText("Verified exploit")).toBeInTheDocument();
    expect(screen.getByText("Ransomware")).toBeInTheDocument();
  });

  it("renders nothing at all for a finding with no enrichment", () => {
    const { container } = render(
      <FindingSignals cve={{ cve_id: "CVE-2020-1", severity: "Low" }} />,
    );
    // Absent, not a row of empty or false badges.
    expect(container).toBeEmptyDOMElement();
  });
});

describe("the detail block", () => {
  it("renders the fields that decide remediation", () => {
    render(<FindingDetail cve={CVE} />);
    expect(screen.getByText("Installed version")).toBeInTheDocument();
    // Installed and detected carry the same string on this finding.
    expect(screen.getAllByText("138.0.7204.184").length).toBe(2);
    expect(screen.getByText("Fixed in")).toBeInTheDocument();
    expect(screen.getByText("140.0.7339.185")).toBeInTheDocument();
  });

  it("names how the finding was matched", () => {
    render(<FindingDetail cve={CVE} />);
    expect(screen.getByText("Matched by")).toBeInTheDocument();
    expect(screen.getByText("cpe")).toBeInTheDocument();
  });

  it("renders vendor remediation verbatim, keeping its advisory prefix", () => {
    render(<FindingDetail cve={CVE} />);
    // The backend prefixes it so ICS guidance can never read as the desktop
    // vendor's own advice; re-wording it here would undo that.
    expect(
      screen.getByText(
        "CISA ICSA-26-202-06: Block access to untrusted or external web content",
      ),
    ).toBeInTheDocument();
  });

  it("links the vendor advisory by its own id", () => {
    render(<FindingDetail cve={CVE} />);
    const link = screen.getByRole("link", { name: "ICSA-26-202-06" });
    expect(link).toHaveAttribute("href", "https://example.test/a");
  });

  it("names the exploit intelligence sources", () => {
    render(<FindingDetail cve={CVE} />);
    expect(screen.getByText("CISA KEV, VulnCheck KEV")).toBeInTheDocument();
  });

  it("shows the quality of detection beside its word", () => {
    render(<FindingDetail cve={CVE} />);
    expect(screen.getByText("97 · Confirmed")).toBeInTheDocument();
  });

  it("omits a field the API did not send rather than printing a blank", () => {
    render(<FindingDetail cve={{ cve_id: "CVE-2020-1", matched_by: "cpe" }} />);
    expect(screen.getByText("Matched by")).toBeInTheDocument();
    expect(screen.queryByText("Fixed in")).toBeNull();
    expect(screen.queryByText("EPSS percentile")).toBeNull();
    expect(screen.queryByText("Vendor remediation")).toBeNull();
  });

  it("renders nothing for a finding with no enrichment at all", () => {
    const { container } = render(<FindingDetail cve={{ cve_id: "x" }} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("isPresent", () => {
  it("keeps zero and false as answers", () => {
    // `value || 0` would have folded both into absence, which is the rule
    // this whole component exists to hold.
    expect(isPresent(0)).toBe(true);
    expect(isPresent(false)).toBe(true);
    expect(isPresent(null)).toBe(false);
    expect(isPresent(undefined)).toBe(false);
    expect(isPresent("")).toBe(false);
  });
});
