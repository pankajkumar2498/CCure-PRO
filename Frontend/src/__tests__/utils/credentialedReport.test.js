/**
 * P0-1 — where a credentialed report lives.
 *
 * The page read `results.credentialed.report` alone, so a vulnerability-audit
 * scan — which nests one report per host under `results.phase3.data[]` —
 * resolved to nothing, and the caller read that as "keep polling". These
 * assertions pin all three shapes and the genuinely-empty case.
 *
 * The nested fixture mirrors scan `scn_defa_c522b539_31aug26_sknk`, measured
 * live: `results.credentialed` absent, `phase3.data[0].credentialed_report`
 * present with a `config_audit` block.
 */

import { describe, it, expect } from "vitest";

import {
  collectCredentialedReports,
  collectFailedHosts,
  hasReportContent,
} from "../../utils/credentialedReport";

const report = (extra = {}) => ({
  target: "10.180.6.14",
  system_info: { os_name: "Ubuntu" },
  cves: [],
  ...extra,
});

describe("shape 1 — the standalone credentialed scan", () => {
  it("resolves results.credentialed.report", () => {
    const out = collectCredentialedReports({
      results: { credentialed: { report: report() } },
    });
    expect(out).toHaveLength(1);
    expect(out[0].system_info.os_name).toBe("Ubuntu");
  });

  it("prefers the per-host list and does not repeat its first entry", () => {
    // `report` repeats `reports[0]` for consumers written before multi-host
    // support; showing it twice would make the host selector disagree with
    // the scan.
    const first = report({ target: "10.0.0.1" });
    const second = report({ target: "10.0.0.2" });
    const out = collectCredentialedReports({
      results: { credentialed: { reports: [first, second], report: first } },
    });
    expect(out.map((r) => r._host)).toEqual(["10.0.0.1", "10.0.0.2"]);
  });
});

describe("shape 2 — the vulnerability-audit pipeline", () => {
  it("resolves results.phase3.data[].credentialed_report", () => {
    const detail = {
      id: "scn_defa_c522b539_31aug26_sknk",
      results: {
        phase3: {
          data: [
            {
              ip_address: "10.180.6.14",
              credentialed: true,
              credentialed_report: report({
                config_audit: { results: [], assessed: true },
              }),
            },
          ],
        },
      },
    };
    const out = collectCredentialedReports(detail);
    expect(out).toHaveLength(1);
    expect(out[0].config_audit).toBeTruthy();
    // The host comes from the record's own container, so a walk can never
    // attribute one machine's report to another.
    expect(out[0]._host).toBe("10.180.6.14");
  });

  it("resolves one report per credentialed host", () => {
    const out = collectCredentialedReports({
      results: {
        phase3: {
          data: [
            {
              ip_address: "10.0.0.1",
              credentialed_report: report({ target: "10.0.0.1" }),
            },
            {
              ip_address: "10.0.0.2",
              credentialed_report: report({ target: "10.0.0.2" }),
            },
            { ip_address: "10.0.0.3" },
          ],
        },
      },
    });
    expect(out.map((r) => r._host)).toEqual(["10.0.0.1", "10.0.0.2"]);
  });

  it("also reads the _phase_data spelling the export layer names", () => {
    const out = collectCredentialedReports({
      results: { _phase_data: [{ credentialed_report: report() }] },
    });
    expect(out).toHaveLength(1);
  });
});

describe("shape 3 — the scan record's own copy", () => {
  it("resolves options.credentialed_report", () => {
    const out = collectCredentialedReports({
      options: { credentialed_report: report() },
    });
    expect(out).toHaveLength(1);
  });
});

describe("no credentialed report anywhere", () => {
  it("returns an empty list rather than null", () => {
    // The caller renders a terminal state from this. Returning null and
    // letting the poll continue is what produced an indefinite spinner.
    expect(collectCredentialedReports({ results: { phase1: {} } })).toEqual([]);
    expect(collectCredentialedReports({})).toEqual([]);
    expect(collectCredentialedReports(null)).toEqual([]);
  });

  it("does not treat an empty report object as a report", () => {
    // The pipeline writes a `credentialed_report` key on every host it
    // attempted, including ones where nothing was collected.
    expect(
      collectCredentialedReports({
        results: { phase3: { data: [{ credentialed_report: {} }] } },
      }),
    ).toEqual([]);
  });
});

describe("hasReportContent", () => {
  it("is false for nothing, an empty object and an array", () => {
    expect(hasReportContent(null)).toBe(false);
    expect(hasReportContent({})).toBe(false);
    expect(hasReportContent([])).toBe(false);
  });

  it("counts a report that carries only collection errors", () => {
    // A host that could be reached but served nothing still has something to
    // say, and it is the most important thing on the page.
    expect(
      hasReportContent({ collection_errors: { "item:uptime": "no" } }),
    ).toBe(true);
  });

  it("does not count empty collections as content", () => {
    expect(hasReportContent({ cves: [], packages: [], config_audit: {} })).toBe(
      false,
    );
  });
});

describe("collectFailedHosts", () => {
  it("returns the recorded failures, and an empty list otherwise", () => {
    expect(
      collectFailedHosts({
        results: { credentialed: { hosts_failed: [{ host: "10.0.0.9" }] } },
      }),
    ).toHaveLength(1);
    expect(collectFailedHosts({})).toEqual([]);
  });
});
