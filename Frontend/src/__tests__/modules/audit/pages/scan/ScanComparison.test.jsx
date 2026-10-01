/**
 * Scan Comparison.
 *
 * GAP-13 produced this data long before anything rendered it, and the ways a
 * comparison UI can mislead are all ways of claiming more than the backend
 * established. Those are what these tests defend:
 *
 * * **`not_assessed` must be as visible as `fixed`.** On the real scan these
 *   are 1,869 and 24. A page that showed "24 fixed" without "1,869 not
 *   assessed" would report progress nothing established.
 *
 * * **Policy agreement is three states, not two.** `policies_match: false`
 *   covers both "different" and "neither recorded", and the backend says the
 *   second is unknown rather than equivalent. Rendering it as a mismatch is
 *   asserting what the backend refused to.
 *
 * * **Counts are authoritative; rows are a sample.** `limit` bounds rows and
 *   never counts, so a page that derived totals from the table would print a
 *   wrong number on any estate past the limit.
 *
 * * **An incomparable pair is an answer, not an error.** A first scan has no
 *   baseline; the backend returns the shape with a reason, and a table of
 *   zeroes would read as "nothing changed".
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import ScanComparison from "@audit/pages/scan/ScanComparison";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: { id: "u1", role: { name: "superadmin" } } }),
}));

/** Shaped exactly as GET /scans/{id}/comparison answers. */
function comparison(overrides = {}) {
  return {
    current_scan_id: "scn_current",
    baseline_scan_id: "scn_baseline",
    comparable: true,
    reason: "",
    summary: "0 new, 1862 unchanged, 24 fixed, 0 reappeared, 1869 not assessed",
    counts: {
      new: 0,
      still_open: 1862,
      fixed: 24,
      reappeared: 0,
      not_assessed: 1869,
    },
    severity_counts: {
      new: {},
      still_open: { critical: 154, high: 860 },
      fixed: { medium: 23, high: 1 },
      reappeared: {},
      not_assessed: { critical: 158 },
    },
    assets: ["ast_a"],
    current_scope: {
      recorded: true,
      families: ["credentialed_package"],
      assets: ["ast_a"],
      detail: { checks_assessed: 216, config_audit_assessed: true },
    },
    baseline_scope: {
      recorded: true,
      families: ["credentialed_package"],
      assets: ["ast_a"],
      detail: { checks_assessed: 216, config_audit_assessed: true },
    },
    current_policy: { recorded: false },
    baseline_policy: { recorded: false },
    policies_match: false,
    findings: [],
    ...overrides,
  };
}

function finding(overrides = {}) {
  return {
    finding_id: "fnd_1",
    vuln_id: "CVE-2026-59999",
    asset_id: "ast_a",
    classification: "fixed",
    severity: "high",
    title: "",
    source_family: "network_service",
    first_found_at: "2026-08-11T04:35:07+00:00",
    last_found_at: "2026-08-31T11:21:43+00:00",
    fixed_at: "2026-09-01T15:03:48+00:00",
    evidence: "Port/Protocol : 22/tcp\nService : ssh",
    ...overrides,
  };
}

/** Route the two GETs the page makes: the scan, then the comparison. */
function wire({ scan = {}, cmp = comparison(), candidates = [] } = {}) {
  api.get.mockImplementation((url) => {
    if (url.includes("/comparison")) return Promise.resolve({ data: cmp });
    if (url === "/scans") return Promise.resolve({ data: candidates });
    if (url.startsWith("/scans/"))
      return Promise.resolve({
        data: {
          id: "scn_current",
          scan_no: 84,
          pipeline_mode: "credentialed",
          ...scan,
        },
      });
    return Promise.resolve({ data: {} });
  });
}

const renderPage = (search = "?scan_id=scn_current") =>
  render(
    <MemoryRouter initialEntries={[`/scan/comparison${search}`]}>
      <ScanComparison />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  global.URL.createObjectURL = vi.fn(() => "blob:mock");
  global.URL.revokeObjectURL = vi.fn();
});

describe("ScanComparison — the five classes", () => {
  it("renders every class the backend defines and invents none", async () => {
    wire();
    renderPage();
    await screen.findByText(/1,862/);

    for (const label of [
      "New",
      "Reappeared",
      "Unchanged",
      "Fixed",
      "Not assessed",
    ]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
    // The vocabulary is exactly five; "Changed" is not one of them.
    expect(screen.queryByText("Changed")).toBeNull();
  });

  it("shows not_assessed with the same weight as fixed", async () => {
    wire();
    renderPage();
    await screen.findByText(/1,862/);

    const cards = document.querySelectorAll(".sc-count");
    const text = [...cards].map((c) => c.textContent).join(" ");
    expect(text).toContain("1,869");
    expect(text).toContain("24");
  });

  it("takes the totals from counts, not from the returned rows", async () => {
    // One row, counts claiming thousands. The counts must win: `limit` bounds
    // rows and never counts.
    wire({ cmp: comparison({ findings: [finding()] }) });
    renderPage();
    await screen.findByText(/1,862/);

    const fixed = [...document.querySelectorAll(".sc-count")].find((c) =>
      c.textContent.startsWith("Fixed"),
    );
    expect(within(fixed).getByText("24")).toBeInTheDocument();
  });

  it("says the list is a sample when it is shorter than the counts", async () => {
    wire({ cmp: comparison({ findings: [finding()] }) });
    renderPage();
    await screen.findByText(/1,862/);
    expect(screen.getByText(/this list is a sample/i)).toBeInTheDocument();
  });

  it("breaks each class down by severity", async () => {
    wire();
    renderPage();
    await screen.findByText(/1,862/);
    expect(screen.getByText(/154 critical/)).toBeInTheDocument();
    expect(screen.getByText(/23 medium/)).toBeInTheDocument();
  });
});

describe("ScanComparison — policy agreement is three states", () => {
  it("reports two unrecorded policies as unknown, never as a difference", async () => {
    wire();
    renderPage();
    await screen.findByText(/1,862/);

    expect(screen.getByText(/Scan policy — Not recorded/)).toBeInTheDocument();
    expect(
      screen.getByText(/not a statement that they differ/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Different configuration/)).toBeNull();
  });

  it("reports a real mismatch as a difference", async () => {
    wire({
      cmp: comparison({
        current_policy: { recorded: true, fingerprint: "aaa" },
        baseline_policy: { recorded: true, fingerprint: "bbb" },
        policies_match: false,
      }),
    });
    renderPage();
    await screen.findByText(/1,862/);
    expect(
      screen.getByText(/Scan policy — Different configuration/),
    ).toBeInTheDocument();
    expect(screen.getByText(/change in scope/i)).toBeInTheDocument();
  });

  it("reports agreement when both are recorded and match", async () => {
    wire({
      cmp: comparison({
        current_policy: { recorded: true, fingerprint: "aaa" },
        baseline_policy: { recorded: true, fingerprint: "aaa" },
        policies_match: true,
      }),
    });
    renderPage();
    await screen.findByText(/1,862/);
    expect(
      screen.getByText(/Scan policy — Same configuration/),
    ).toBeInTheDocument();
  });
});

describe("ScanComparison — incomparable and empty states", () => {
  it("renders a first scan's missing baseline as an answer, not an error", async () => {
    wire({
      cmp: {
        current_scan_id: "scn_current",
        baseline_scan_id: null,
        comparable: false,
        reason:
          "no earlier completed scan of the same kind exists for this organisation",
        summary: "",
        counts: {},
        severity_counts: {},
        assets: [],
        findings: [],
      },
    });
    renderPage();

    await screen.findByText(/Not comparable/);
    expect(screen.getByText(/no earlier completed scan/)).toBeInTheDocument();
    // A grid of zeroes here would read as "nothing changed".
    expect(document.querySelectorAll(".sc-count").length).toBe(0);
  });

  it("surfaces a caveat that accompanies a comparable result", async () => {
    // A comparison can be comparable and still carry the reason the fixed
    // count is zero.
    wire({
      cmp: comparison({
        reason: "the current scan recorded no assessment scope",
      }),
    });
    renderPage();
    await screen.findByText(/1,862/);
    expect(
      screen.getByText(/recorded no assessment scope/),
    ).toBeInTheDocument();
  });

  it("says so when a scope was never recorded", async () => {
    wire({
      cmp: comparison({
        current_scope: {
          recorded: false,
          families: [],
          assets: [],
          detail: {},
        },
      }),
    });
    renderPage();
    await screen.findByText(/1,862/);
    expect(
      screen.getByText(/Nothing can be reported as fixed from it/),
    ).toBeInTheDocument();
  });

  it("asks for a scan when none was named", async () => {
    renderPage("");
    expect(await screen.findByText(/No scan selected/)).toBeInTheDocument();
    expect(api.get).not.toHaveBeenCalled();
  });
});

describe("ScanComparison — baseline selection", () => {
  it("offers only completed scans of the same pipeline mode", async () => {
    wire({
      candidates: [
        { id: "scn_other", scan_no: 83, pipeline_mode: "credentialed" },
      ],
    });
    renderPage();
    await screen.findByText(/1,862/);

    const call = api.get.mock.calls.find((c) => c[0] === "/scans");
    expect(call[1].params).toMatchObject({
      status: "complete",
      pipeline_mode: "credentialed",
    });
  });

  it("never offers the scan as its own baseline", async () => {
    wire({
      candidates: [
        { id: "scn_current", scan_no: 84, pipeline_mode: "credentialed" },
        { id: "scn_other", scan_no: 83, pipeline_mode: "credentialed" },
      ],
    });
    renderPage();
    await screen.findByText(/1,862/);

    const select = screen.getByLabelText("Compare against");
    const values = [...select.querySelectorAll("option")].map((o) => o.value);
    expect(values).not.toContain("scn_current");
    expect(values).toContain("scn_other");
  });

  it("requests the chosen baseline", async () => {
    wire({
      candidates: [
        { id: "scn_other", scan_no: 83, pipeline_mode: "credentialed" },
      ],
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(/1,862/);

    api.get.mockClear();
    await user.selectOptions(
      screen.getByLabelText("Compare against"),
      "scn_other",
    );

    await waitFor(() => {
      const call = api.get.mock.calls.find((c) =>
        String(c[0]).includes("/comparison"),
      );
      expect(call[1].params.baseline).toBe("scn_other");
    });
  });
});

describe("ScanComparison — filters", () => {
  it("offers only assets the response returned", async () => {
    /*
     * The backend intersects requested ids with the shared assets and, when
     * the intersection is empty, drops the asset predicate entirely — so a
     * nonexistent id returns *more* rows, reclassified as not_assessed
     * (measured 1,869 -> 2,878). Constraining the picker makes that
     * unreachable from the UI.
     */
    wire();
    renderPage();
    await screen.findByText(/1,862/);

    const select = screen.getByLabelText("Asset");
    const values = [...select.querySelectorAll("option")].map((o) => o.value);
    expect(values).toEqual(["", "ast_a"]);
  });

  it("sends severity as repeated keys", async () => {
    wire();
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(/1,862/);

    api.get.mockClear();
    // The embedded export panel has its own severity filter, so scope to the
    // comparison's. They filter different things: this one narrows the view,
    // that one narrows the exported file.
    const filter = document.querySelector(".sc-sevfilter");
    await user.click(
      within(filter).getByRole("checkbox", { name: "critical" }),
    );

    await waitFor(() => {
      const call = api.get.mock.calls.find((c) =>
        String(c[0]).includes("/comparison"),
      );
      expect(call[1].params.severity).toEqual(["critical"]);
      // FastAPI ignores `severity[]`; axios sends that by default.
      expect(call[1].paramsSerializer).toEqual({ indexes: null });
    });
  });

  it("filters the table by classification without refetching", async () => {
    wire({
      cmp: comparison({
        findings: [
          finding({
            finding_id: "f1",
            classification: "fixed",
            vuln_id: "CVE-A",
          }),
          finding({
            finding_id: "f2",
            classification: "new",
            vuln_id: "CVE-B",
          }),
        ],
      }),
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("CVE-A");

    await user.click(screen.getByRole("button", { name: /^New \(/ }));
    expect(screen.getByText("CVE-B")).toBeInTheDocument();
    expect(screen.queryByText("CVE-A")).toBeNull();
  });
});

describe("ScanComparison — findings table", () => {
  it("keeps evidence out of the DOM until asked for", async () => {
    wire({ cmp: comparison({ findings: [finding()] }) });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("CVE-2026-59999");

    expect(screen.queryByText(/Port\/Protocol/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "Show" }));
    expect(screen.getByText(/Port\/Protocol/)).toBeInTheDocument();
    expect(screen.getByText("2026-09-01T15:03:48+00:00")).toBeInTheDocument();
  });

  it("pages rather than mounting every row", async () => {
    const many = Array.from({ length: 120 }, (_, i) =>
      finding({ finding_id: `f${i}`, vuln_id: `CVE-X-${i}` }),
    );
    wire({ cmp: comparison({ findings: many }) });
    renderPage();
    await screen.findByText("CVE-X-0");

    expect(screen.queryByText("CVE-X-100")).toBeNull();
    expect(screen.getByText(/Showing 1–25 of 120 changes/)).toBeInTheDocument();
  });
});

describe("ScanComparison — API failures", () => {
  it.each([
    [403, { message: "Forbidden" }, /Forbidden/],
    [404, { message: "Scan not found." }, /Scan not found/],
    [500, { message: "boom" }, /boom/],
  ])("surfaces a %s", async (status, data, match) => {
    api.get.mockImplementation((url) => {
      if (url.includes("/comparison"))
        return Promise.reject({ response: { status, data } });
      return Promise.resolve({
        data: { id: "scn_current", pipeline_mode: "credentialed" },
      });
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(match)).toBeInTheDocument());
  });

  it("names the wait on a 429", async () => {
    api.get.mockImplementation((url) => {
      if (url.includes("/comparison"))
        return Promise.reject({
          response: { status: 429, data: { retry_after_seconds: 60 } },
        });
      return Promise.resolve({
        data: { id: "scn_current", pipeline_mode: "credentialed" },
      });
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/try again in 60 seconds/i)).toBeInTheDocument(),
    );
  });
});
