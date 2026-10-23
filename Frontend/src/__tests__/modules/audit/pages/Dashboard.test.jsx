/**
 * Dashboard (`/scan`, the scan-template picker) — Checkpoint 3C batch 11
 * baseline.
 *
 * Written against the page BEFORE migration. The passing set is the
 * regression gate; the failing set is the migration specification.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * This page issues NO request. Its only outputs are three client-side effects
 * of choosing a template:
 *
 *   * pipeline cards   → `resetScan()` THEN `setPipelineMode(mode)` on
 *                        ScanContext, then `navigate("/scan/new")`
 *   * direct-route cards → `navigate(route)` and nothing on the context
 *   * unmapped cards   → hidden from the grid and search results
 *
 * `resetScan` before `setPipelineMode` is load-bearing: reset clears the mode
 * back to "basic", so the other order would start every pipeline as basic.
 * The order is asserted, not just the calls.
 *
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Dashboard from "@audit/pages/Dashboard";
import axiosInstance from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const navigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

const resetScan = vi.fn();
const setPipelineMode = vi.fn();
vi.mock("@audit/context/ScanContext", () => ({
  useScan: () => ({ resetScan, setPipelineMode }),
}));

/* All thirteen definitions remain; only the six mapped templates are shown.
   A visible card's accessible name starts with its title. */
const MAPPED = [
  "Basic Network Scan",
  "Asset Discovery",
  "Vulnerability Audit",
  "Web Application Scanning",
  "Policy Compliance Scanning",
  "Host Security Assessment (Authenticated)",
];
const UNMAPPED = [
  "Network Based Scanning",
  "Malware Scan",
  "Active Directory Scan",
  "Cloud Scanning",
  "Patch Management",
  "Agent Based Monitoring",
  "Offline Configuration Scan",
];

/* Match titles literally within accessible names, including parentheses. */
const card = (title, root = screen) =>
  root.getByRole("button", { name: (name) => name.includes(title) });

const allCards = () => screen.queryAllByRole("button");

beforeEach(() => {
  vi.clearAllMocks();
});

/* ── Rendering ────────────────────────────────────────────────────────────── */
describe("Dashboard — template grid", () => {
  it("renders the page heading as an h1 and the shell page title", () => {
    render(<Dashboard />);
    expect(
      screen.getByRole("heading", { level: 1, name: "Scan Templates" }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("app-layout")).toHaveAttribute(
      "data-page-title",
      "Scan Templates",
    );
  });

  it("renders only the six available templates as buttons", () => {
    render(<Dashboard />);
    expect(allCards()).toHaveLength(MAPPED.length);
    for (const t of MAPPED) {
      expect(card(t)).toBeInTheDocument();
    }
  });

  it("enables exactly the six mapped templates", () => {
    render(<Dashboard />);
    for (const t of MAPPED) expect(card(t)).toBeEnabled();
    expect(
      screen.queryAllByRole("button").filter((b) => b.disabled),
    ).toHaveLength(0);
  });

  it("omits all upcoming templates from the rendered page", () => {
    render(<Dashboard />);
    for (const t of UNMAPPED) {
      expect(screen.queryByText(t)).not.toBeInTheDocument();
    }
  });

  it("shows no upcoming-template badges", () => {
    render(<Dashboard />);
    expect(screen.queryByText("Soon")).not.toBeInTheDocument();
    expect(screen.queryByText("Beta")).not.toBeInTheDocument();
  });

  it("issues no request on mount", () => {
    render(<Dashboard />);
    expect(axiosInstance.get).not.toHaveBeenCalled();
    expect(axiosInstance.post).not.toHaveBeenCalled();
  });
});

/* ── Choosing a template ──────────────────────────────────────────────────── */
describe("Dashboard — pipeline-mode selection", () => {
  it.each([
    ["Basic Network Scan", "basic"],
    ["Asset Discovery", "asset"],
    ["Vulnerability Audit", "vulnerability_audit"],
  ])(
    "%s resets the scan, sets mode %s, then opens the scan form",
    async (title, mode) => {
      const user = userEvent.setup();
      render(<Dashboard />);
      await user.click(card(title));

      expect(resetScan).toHaveBeenCalledTimes(1);
      expect(setPipelineMode).toHaveBeenCalledTimes(1);
      expect(setPipelineMode).toHaveBeenCalledWith(mode);
      expect(navigate).toHaveBeenCalledTimes(1);
      expect(navigate).toHaveBeenCalledWith("/scan/new");

      // Order is the contract: reset returns the mode to "basic", so
      // reset-after-set would start every pipeline as basic.
      expect(resetScan.mock.invocationCallOrder[0]).toBeLessThan(
        setPipelineMode.mock.invocationCallOrder[0],
      );
      expect(setPipelineMode.mock.invocationCallOrder[0]).toBeLessThan(
        navigate.mock.invocationCallOrder[0],
      );
    },
  );

  it.each([
    ["Web Application Scanning", "/web-scans/dashboard"],
    ["Policy Compliance Scanning", "/compliance"],
    ["Host Security Assessment (Authenticated)", "/scan/credentialed"],
  ])(
    "%s navigates straight to %s and leaves the scan context alone",
    async (title, route) => {
      const user = userEvent.setup();
      render(<Dashboard />);
      await user.click(card(title));

      expect(navigate).toHaveBeenCalledTimes(1);
      expect(navigate).toHaveBeenCalledWith(route);
      expect(resetScan).not.toHaveBeenCalled();
      expect(setPipelineMode).not.toHaveBeenCalled();
    },
  );

  it.each(UNMAPPED)("keeps %s hidden when searched for", async (title) => {
    const user = userEvent.setup();
    render(<Dashboard />);
    await user.type(screen.getByLabelText(/search templates/i), title);
    expect(allCards()).toHaveLength(0);
    expect(screen.getByRole("status")).toHaveTextContent(
      `No templates match "${title}"`,
    );
    expect(navigate).not.toHaveBeenCalled();
    expect(resetScan).not.toHaveBeenCalled();
    expect(setPipelineMode).not.toHaveBeenCalled();
  });

  it("never issues a request when a template is chosen", async () => {
    const user = userEvent.setup();
    render(<Dashboard />);
    await user.click(card("Basic Network Scan"));
    await user.click(card("Host Security Assessment (Authenticated)"));
    expect(axiosInstance.get).not.toHaveBeenCalled();
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });
});

/* ── Search ───────────────────────────────────────────────────────────────── */
describe("Dashboard — search", () => {
  it("filters by title, case-insensitively", async () => {
    const user = userEvent.setup();
    render(<Dashboard />);
    await user.type(screen.getByPlaceholderText("Search templates…"), "ASSET");
    expect(allCards()).toHaveLength(1);
    expect(card("Asset Discovery")).toBeInTheDocument();
  });

  it("filters by description too", async () => {
    const user = userEvent.setup();
    render(<Dashboard />);
    await user.type(
      screen.getByPlaceholderText("Search templates…"),
      "authentication",
    );
    expect(
      card("Host Security Assessment (Authenticated)"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Basic Network Scan/ }),
    ).not.toBeInTheDocument();
  });

  it("shows an empty state naming the query when nothing matches", async () => {
    const user = userEvent.setup();
    render(<Dashboard />);
    await user.type(screen.getByPlaceholderText("Search templates…"), "zzz");
    expect(screen.getByText('No templates match "zzz"')).toBeInTheDocument();
    expect(allCards()).toHaveLength(0);
  });
});

/* ── Migration specification (expected to FAIL before migration) ──────────── */
describe("Dashboard — accessibility and design-system expectations", () => {
  it("names the search control (not just a placeholder)", () => {
    render(<Dashboard />);
    // getByLabelText ignores placeholder by design: a placeholder disappears
    // the moment the user types and is not a label.
    expect(screen.getByLabelText(/search templates/i)).toBeInTheDocument();
  });

  it("renders no inline styles — template icon tones come from classes", () => {
    const { container } = render(<Dashboard />);
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
  });

  it("hides the decorative card icons from assistive technology", () => {
    render(<Dashboard />);
    const svgs = card("Basic Network Scan").querySelectorAll("svg");
    expect(svgs.length).toBeGreaterThan(0);
    for (const s of svgs) expect(s).toHaveAttribute("aria-hidden", "true");
  });

  it("marks the empty-search state as a live status region", async () => {
    const user = userEvent.setup();
    render(<Dashboard />);
    await user.type(screen.getByPlaceholderText("Search templates…"), "zzz");
    expect(screen.getByRole("status")).toHaveTextContent(/no templates match/i);
  });
});
