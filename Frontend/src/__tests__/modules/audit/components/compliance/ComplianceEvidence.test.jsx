/**
 * P1-3 — the evidence behind a compliance verdict.
 *
 * The only appearance of `evidence` in the whole 4,987-line workspace was
 * `JSON.stringify(...)` inside an edit-rule hint. CLAUDE.md, Phase 15: "on a
 * configuration check the evidence *is* the finding" — and a reviewer asked to
 * accept or remediate a FAIL could not see what the scanner read.
 *
 * The fixture is a live `/compliance/findings` row, STIG content included.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import ComplianceEvidence from "@audit/components/compliance/ComplianceEvidence";

const FINDING = {
  id: "cf_1",
  control_id: "WN11-CC-000005",
  rule_name: "Consumer account authentication must be blocked",
  status: "fail",
  last_seen: "2026-09-22T08:01:04.995270+00:00",
  evidence: {
    check_id: "xccdf_mil.disa.stig_rule_SV-253256r828985_rule",
    qod: 95,
    detection_method: "scap_rule",
    outcome: "fail",
    check_metadata: {
      domain: "host_configuration",
      check_type: "scap_rule",
      finding_type: "config_check",
      collection_status: "collected",
    },
    observations: [
      {
        raw: "windows:registry_object: 0 item(s) collected, which does not satisfy at_least_one_exists",
        expected: "the host is in the state the benchmark requires",
        observed: "non_compliant",
        collector: "scap_rule",
        description:
          "Windows 11 systems must block consumer account user authentication.",
        collected_at: "2026-09-22T08:01:04.995270+00:00",
      },
    ],
  },
  check_definition: {
    metadata: {
      benchmark: "DISA Windows 11 STIG V2R10",
      stig_id: "WN11-CC-000005",
      xccdf_rule_id: "xccdf_mil.disa.stig_rule_SV-253256r828985_rule",
      cci: ["CCI-000381"],
    },
  },
};

describe("the observation is rendered, not summarised", () => {
  it("shows what was expected and what was observed", () => {
    render(<ComplianceEvidence finding={FINDING} />);
    expect(
      screen.getByText("the host is in the state the benchmark requires"),
    ).toBeInTheDocument();
    expect(screen.getByText("non_compliant")).toBeInTheDocument();
  });

  it("shows the raw reading the engine recorded", () => {
    render(<ComplianceEvidence finding={FINDING} />);
    // `observation.raw` names the OVAL object and the existence check it
    // failed — the part that says *why*, rather than the verdict word.
    expect(
      screen.getByText(/registry_object: 0 item\(s\) collected/),
    ).toBeInTheDocument();
  });

  it("names the collector and when it read", () => {
    render(<ComplianceEvidence finding={FINDING} />);
    // `scap_rule` is both the check type and the collector on this finding.
    expect(screen.getAllByText("scap_rule").length).toBe(3);
    expect(screen.getByText("Collected at")).toBeInTheDocument();
  });
});

describe("collection status is its own state", () => {
  it("renders the status the payload carries", () => {
    render(<ComplianceEvidence finding={FINDING} />);
    expect(screen.getByText("collected")).toBeInTheDocument();
  });

  it("renders a non-collected status distinctly", () => {
    render(
      <ComplianceEvidence
        finding={{
          ...FINDING,
          evidence: {
            ...FINDING.evidence,
            check_metadata: {
              ...FINDING.evidence.check_metadata,
              collection_status: "unavailable",
            },
          },
        }}
      />,
    );
    expect(screen.getByText("unavailable")).toBeInTheDocument();
  });
});

describe("benchmark identity", () => {
  it("shows the STIG and CCI identifiers a reviewer cross-references", () => {
    render(<ComplianceEvidence finding={FINDING} />);
    expect(screen.getByText("WN11-CC-000005")).toBeInTheDocument();
    expect(screen.getByText("CCI-000381")).toBeInTheDocument();
    expect(screen.getByText("DISA Windows 11 STIG V2R10")).toBeInTheDocument();
  });

  it("renders no benchmark block for a non-benchmark finding", () => {
    render(
      <ComplianceEvidence finding={{ ...FINDING, check_definition: null }} />,
    );
    expect(screen.queryByText("STIG id")).toBeNull();
  });
});

describe("absence is stated", () => {
  it("says a finding carries no recorded observation rather than showing nothing", () => {
    render(
      <ComplianceEvidence
        finding={{ ...FINDING, evidence: { check_id: "x", observations: [] } }}
      />,
    );
    expect(
      screen.getByText(/carries no recorded observation/i),
    ).toBeInTheDocument();
  });

  it("says nothing was read rather than leaving the observed cell blank", () => {
    render(
      <ComplianceEvidence
        finding={{
          ...FINDING,
          evidence: {
            ...FINDING.evidence,
            observations: [{ expected: "something", collector: "shell" }],
          },
        }}
      />,
    );
    expect(screen.getByText("nothing was read")).toBeInTheDocument();
  });

  it("survives a finding with no evidence block at all", () => {
    render(<ComplianceEvidence finding={{ id: "cf_2" }} />);
    expect(
      screen.getByText(/carries no recorded observation/i),
    ).toBeInTheDocument();
  });
});
