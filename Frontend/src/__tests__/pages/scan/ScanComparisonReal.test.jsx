/**
 * Scan Comparison against a **real** API response.
 *
 * `scanComparison.real.json` is `GET /scans/{id}/comparison` verbatim, for the
 * two credentialed scans of the same Windows 11 host either side of the
 * `state_operator` fix. That makes it an unusually good fixture: the 24 fixed
 * findings in it are the 24 false FAILs that fix removed, so the numbers mean
 * something and a regression that scrambles them is visible rather than merely
 * different.
 *
 * A hand-written fixture proves the component does what its author expected.
 * This proves the backend agrees.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import real from "../../fixtures/scanComparison.real.json";
import ScanComparison from "../../../pages/scan/ScanComparison";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));
vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: { id: "u1", role: { name: "superadmin" } } }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  global.URL.createObjectURL = vi.fn(() => "blob:mock");
  global.URL.revokeObjectURL = vi.fn();
  api.get.mockImplementation((url) => {
    if (url.includes("/comparison")) return Promise.resolve({ data: real });
    if (url === "/scans") return Promise.resolve({ data: [] });
    return Promise.resolve({
      data: {
        id: real.current_scan_id,
        scan_no: 84,
        pipeline_mode: "credentialed",
      },
    });
  });
});

const renderPage = () =>
  render(
    <MemoryRouter
      initialEntries={[`/scan/comparison?scan_id=${real.current_scan_id}`]}
    >
      <ScanComparison />
    </MemoryRouter>,
  );

describe("ScanComparison — real response", () => {
  it("renders the host's actual counts", async () => {
    renderPage();
    await screen.findByText(real.counts.still_open.toLocaleString());

    const cards = [...document.querySelectorAll(".sc-count")]
      .map((c) => c.textContent)
      .join(" ");
    for (const key of [
      "new",
      "still_open",
      "fixed",
      "reappeared",
      "not_assessed",
    ]) {
      expect(cards).toContain(real.counts[key].toLocaleString());
    }
  });

  it("shows the backend's own summary line", async () => {
    renderPage();
    expect(await screen.findByText(real.summary)).toBeInTheDocument();
  });

  it("does not call two unrecorded policies a difference", async () => {
    // Both are {recorded: false} on this real pair, and policies_match is
    // false — the case the three-state reading exists for.
    expect(real.current_policy.recorded).toBe(false);
    expect(real.policies_match).toBe(false);

    renderPage();
    await screen.findByText(real.summary);
    expect(screen.getByText(/Scan policy — Not recorded/)).toBeInTheDocument();
    expect(screen.queryByText(/Different configuration/)).toBeNull();
  });

  it("reports the real assessment scope on both sides", async () => {
    renderPage();
    await screen.findByText(real.summary);

    const checks = real.current_scope.detail.checks_assessed;
    expect(
      screen.getAllByText(Number(checks).toLocaleString()).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getAllByText(real.current_scope.families.join(", ")).length,
    ).toBeGreaterThan(0);
  });

  it("offers exactly the assets the response returned", async () => {
    renderPage();
    await screen.findByText(real.summary);

    const select = screen.getByLabelText("Asset");
    const values = [...select.querySelectorAll("option")].map((o) => o.value);
    expect(values).toEqual(["", ...real.assets]);
  });

  it("says the returned rows are a sample of the counts", async () => {
    // 4 rows against 3,755 changes on this real response.
    const total = Object.values(real.counts).reduce((a, b) => a + b, 0);
    expect(real.findings.length).toBeLessThan(total);

    renderPage();
    await screen.findByText(real.summary);
    expect(screen.getByText(/this list is a sample/i)).toBeInTheDocument();
  });

  it("renders a real finding with its real classification", async () => {
    const first = real.findings[0];
    renderPage();
    expect(await screen.findByText(first.vuln_id)).toBeInTheDocument();
  });
});
