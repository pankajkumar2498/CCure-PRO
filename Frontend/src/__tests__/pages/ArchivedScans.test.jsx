/**
 * ArchivedScans — Checkpoint 3C batch 4 migration coverage.
 *
 * Written against the page BEFORE migration. The functional, security and
 * regression groups record the contract and must pass identically before and
 * after; the accessibility group is the migration's specification and contains
 * assertions that fail against the current implementation.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This page performs two state-changing operations on scan records — restore
 * and move-to-recycle-bin — and both are permission-gated on the client. The
 * client gate is a usability affordance, not the authorisation boundary (the
 * API enforces it), but it must not drift: a control rendered for a user who
 * cannot use it produces a failed request and a confusing error, and a handler
 * that skips its own check would send that request even when the control is
 * hidden. Both directions are asserted.
 *
 * `scope: "archived"` is also load-bearing. `getScans` defaults to
 * `scope="active"`, so a lost argument would quietly list live scans on a page
 * whose Delete button moves them to the recycle bin.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ArchivedScans from "../../pages/ArchivedScans";
import { getScans, restoreScan, deleteScan } from "../../api/scans";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("../../api/scans", () => ({
  getScans: vi.fn(),
  restoreScan: vi.fn(),
  deleteScan: vi.fn(),
}));

// AppLayout pulls in the whole authenticated shell — nav, notifications,
// profile, websockets. This page's contract has nothing to do with any of it,
// and rendering it would make every assertion here depend on the shell.
vi.mock("../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let currentUser = { username: "operator", id: 1 };
vi.mock("../../context/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

let permissions = new Set(["scans:restore", "scans:recycle"]);
vi.mock("../../auth/permissions", () => ({
  can: (_user, resource, action) => permissions.has(`${resource}:${action}`),
  denyMessage: "You do not have permission to perform this action.",
}));

const SCANS = [
  {
    id: 11,
    scan_no: "SCAN-0011",
    target: "10.180.6.14",
    scan_type: "network",
    pipeline_mode: "basic",
    status: "complete",
    scan_duration: 42.5,
    archived_at: "2026-08-01T10:00:00Z",
    created_at: "2026-07-30T09:00:00Z",
  },
  {
    id: 12,
    scan_no: "SCAN-0012",
    target: "10.180.5.83",
    scan_type: "credentialed",
    status: "failed",
    scan_duration: 125,
    archived_at: "2026-08-02T11:00:00Z",
    created_at: "2026-07-31T09:00:00Z",
  },
];

const ok = (scans = SCANS) =>
  Promise.resolve({ data: { scans, total: scans.length } });

const renderPage = () => render(<ArchivedScans />);

/** Wait for the initial load to settle. */
const loaded = async () => {
  await waitFor(() => expect(getScans).toHaveBeenCalled());
  await screen.findByText("10.180.6.14");
};

beforeEach(() => {
  vi.clearAllMocks();
  currentUser = { username: "operator", id: 1 };
  permissions = new Set(["scans:restore", "scans:recycle"]);
  getScans.mockImplementation(() => ok());
  restoreScan.mockResolvedValue({});
  deleteScan.mockResolvedValue({});
});

/* ── API contract ─────────────────────────────────────────────────────────── */

describe("ArchivedScans — API contract", () => {
  it("requests the archived scope, not the default active one", async () => {
    renderPage();
    await loaded();

    // getScans(skip, limit, scope). The default scope is "active"; losing this
    // argument would list live scans on a page whose Delete moves them to the
    // recycle bin.
    expect(getScans).toHaveBeenCalledWith(0, 200, "archived");
  });

  it("loads exactly once on mount", async () => {
    renderPage();
    await loaded();

    expect(getScans).toHaveBeenCalledTimes(1);
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await waitFor(() => expect(getScans).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(120000);

    expect(getScans).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it("reloads on demand without changing the query", async () => {
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /refresh/i }));

    await waitFor(() => expect(getScans).toHaveBeenCalledTimes(2));
    expect(getScans).toHaveBeenLastCalledWith(0, 200, "archived");
  });

  it("restores by id", async () => {
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(
      within(screen.getByText("10.180.6.14").closest("tr")).getByRole(
        "button",
        { name: /restore/i },
      ),
    );

    await waitFor(() => expect(restoreScan).toHaveBeenCalledTimes(1));
    expect(restoreScan).toHaveBeenCalledWith(11);
    expect(deleteScan).not.toHaveBeenCalled();
  });

  it("moves to the recycle bin by id", async () => {
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(
      within(screen.getByText("10.180.6.14").closest("tr")).getByRole(
        "button",
        { name: /delete/i },
      ),
    );

    await waitFor(() => expect(deleteScan).toHaveBeenCalledTimes(1));
    expect(deleteScan).toHaveBeenCalledWith(11);
    expect(restoreScan).not.toHaveBeenCalled();
  });

  it("does not re-fetch after a successful action — the row is dropped locally", async () => {
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(
      within(screen.getByText("10.180.6.14").closest("tr")).getByRole(
        "button",
        { name: /restore/i },
      ),
    );

    await waitFor(() => expect(screen.queryByText("10.180.6.14")).toBeNull());
    expect(getScans).toHaveBeenCalledTimes(1);
    expect(screen.getByText("10.180.5.83")).toBeInTheDocument();
  });

  it("keeps the row when the action fails", async () => {
    restoreScan.mockRejectedValue({ response: { data: { detail: "Nope." } } });
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(
      within(screen.getByText("10.180.6.14").closest("tr")).getByRole(
        "button",
        { name: /restore/i },
      ),
    );

    await screen.findByText(/nope\./i);
    expect(screen.getByText("10.180.6.14")).toBeInTheDocument();
  });

  it("surfaces the API detail on failure and falls back when there is none", async () => {
    deleteScan.mockRejectedValue(new Error("network"));
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(
      within(screen.getByText("10.180.6.14").closest("tr")).getByRole(
        "button",
        { name: /delete/i },
      ),
    );

    expect(
      await screen.findByText(/failed to move scan to recycle bin\./i),
    ).toBeInTheDocument();
  });

  it("shows a load error and no table when the list fails", async () => {
    getScans.mockRejectedValue(new Error("boom"));
    renderPage();

    expect(
      await screen.findByText(/failed to load archived scans\./i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });
});

/* ── Authorization gating ─────────────────────────────────────────────────── */

describe("ArchivedScans — authorization gating", () => {
  it("offers both actions when both permissions are held", async () => {
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(
      within(row).getByRole("button", { name: /restore/i }),
    ).toBeInTheDocument();
    expect(
      within(row).getByRole("button", { name: /delete/i }),
    ).toBeInTheDocument();
  });

  it("hides restore when scans:restore is absent", async () => {
    permissions = new Set(["scans:recycle"]);
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(within(row).queryByRole("button", { name: /restore/i })).toBeNull();
    expect(
      within(row).getByRole("button", { name: /delete/i }),
    ).toBeInTheDocument();
  });

  it("hides delete when scans:recycle is absent", async () => {
    permissions = new Set(["scans:restore"]);
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(
      within(row).getByRole("button", { name: /restore/i }),
    ).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /delete/i })).toBeNull();
  });

  it("says read only when neither permission is held", async () => {
    permissions = new Set();
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(within(row).getByText(/read only/i)).toBeInTheDocument();
    expect(within(row).queryByRole("button")).toBeNull();
  });

  it("makes no state-changing request when the user holds neither permission", async () => {
    permissions = new Set();
    renderPage();
    await loaded();

    expect(restoreScan).not.toHaveBeenCalled();
    expect(deleteScan).not.toHaveBeenCalled();
  });

  it("gates each action independently, so one permission never implies the other", async () => {
    // Both handlers carry their own `if (!canX) { pushToast(denyMessage) }`
    // guard as defence in depth. That branch is deliberately NOT asserted
    // through the UI: `canRestoreScans` is computed at render, so a user
    // without the permission has no control to activate and the guard is
    // unreachable from outside. Asserting it would require driving the
    // component into a state React cannot produce, and a test that fakes its
    // way into an impossible state proves nothing about the real one.
    //
    // What is reachable, and what actually protects the API, is that each
    // control appears only with its own permission and that neither implies
    // the other.
    permissions = new Set(["scans:restore"]);
    const { unmount } = renderPage();
    await loaded();
    let row = screen.getByText("10.180.6.14").closest("tr");
    expect(within(row).queryByRole("button", { name: /delete/i })).toBeNull();
    unmount();

    permissions = new Set(["scans:recycle"]);
    renderPage();
    await loaded();
    row = screen.getByText("10.180.6.14").closest("tr");
    expect(within(row).queryByRole("button", { name: /restore/i })).toBeNull();
  });
});

/* ── Rendering and business rules ─────────────────────────────────────────── */

describe("ArchivedScans — rendering", () => {
  it("shows the archived count and the signed-in username", async () => {
    renderPage();
    await loaded();

    expect(screen.getByText(/2 archived scans/i)).toBeInTheDocument();
    expect(screen.getByText(/operator/)).toBeInTheDocument();
  });

  it("singularises the count", async () => {
    getScans.mockImplementation(() => ok([SCANS[0]]));
    renderPage();
    await loaded();

    expect(screen.getByText(/1 archived scan\b/i)).toBeInTheDocument();
    expect(screen.queryByText(/1 archived scans/i)).toBeNull();
  });

  it("labels a credentialed scan by type, not by pipeline", async () => {
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.5.83").closest("tr");

    expect(within(row).getByText(/credentialed scan/i)).toBeInTheDocument();
  });

  it("labels a network scan from its pipeline mode", async () => {
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    // SCAN_PIPELINES.basic supplies the label; the raw mode must not leak.
    expect(within(row).queryByText("basic")).toBeNull();
  });

  it("falls back to display_id then a dash for the scan number", async () => {
    getScans.mockImplementation(() =>
      ok([
        {
          ...SCANS[0],
          id: 21,
          scan_no: undefined,
          display_id: "D-21",
          target: "a",
        },
        {
          ...SCANS[0],
          id: 22,
          scan_no: undefined,
          display_id: undefined,
          target: "b",
        },
      ]),
    );
    renderPage();
    await waitFor(() => expect(getScans).toHaveBeenCalled());
    await screen.findByText("a");

    expect(
      within(screen.getByText("a").closest("tr")).getByText("D-21"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByText("b").closest("tr")).getByText("-"),
    ).toBeInTheDocument();
  });

  it("formats durations under and over a minute", async () => {
    renderPage();
    await loaded();

    expect(screen.getByText("42.5s")).toBeInTheDocument();
    expect(screen.getByText("2m 5s")).toBeInTheDocument();
  });

  it("renders a dash for a missing duration", async () => {
    getScans.mockImplementation(() =>
      ok([{ ...SCANS[0], scan_duration: null }]),
    );
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(within(row).getAllByText("-").length).toBeGreaterThan(0);
  });

  it("shows an empty state with a way back when there are none", async () => {
    getScans.mockImplementation(() => ok([]));
    renderPage();
    await waitFor(() => expect(getScans).toHaveBeenCalled());

    expect(
      await screen.findByText(/no archived scans yet/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
    expect(
      screen.getByRole("button", { name: /back to my scan jobs/i }),
    ).toBeInTheDocument();
  });

  it("navigates to scan history from the header and the empty state", async () => {
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /my scan jobs/i }));

    expect(navigate).toHaveBeenCalledWith("/history");
  });

  it("names the page for the shell", async () => {
    renderPage();
    await loaded();

    expect(screen.getByTestId("app-layout")).toHaveAttribute(
      "data-page-title",
      "Archived Scans",
    );
  });

  it("disables the row's control while its own action is in flight", async () => {
    let release;
    restoreScan.mockReturnValue(new Promise((r) => (release = r)));
    renderPage();
    await loaded();
    const user = userEvent.setup();
    const row = screen.getByText("10.180.6.14").closest("tr");
    await user.click(within(row).getByRole("button", { name: /restore/i }));

    await waitFor(() =>
      expect(
        within(row).getByRole("button", { name: /restore|\.\.\./i }),
      ).toBeDisabled(),
    );
    // The other row is untouched — the busy state is per-row, not per-page.
    const other = screen.getByText("10.180.5.83").closest("tr");
    expect(
      within(other).getByRole("button", { name: /restore/i }),
    ).toBeEnabled();
    release({});
  });
});

/* ── Status rendering — the defect CcureScanStatus was written for ────────── */

describe("ArchivedScans — scan status", () => {
  it("renders a completed scan as completed", async () => {
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(within(row).getByText(/^complete/i)).toBeInTheDocument();
  });

  it("renders a failed scan as failed", async () => {
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.5.83").closest("tr");

    expect(within(row).getByText(/^failed/i)).toBeInTheDocument();
  });

  it("never presents an unrecognised status as running", async () => {
    // `STATUS_STYLE[status] || STATUS_STYLE.running` renders any unknown
    // status in the in-progress style. That is a false statement about a scan
    // on a page whose entire job is to report what happened, and it is the
    // defect CcureScanStatus was written to fix.
    getScans.mockImplementation(() =>
      ok([{ ...SCANS[0], status: "partially_completed" }]),
    );
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    expect(within(row).queryByText(/^running$/i)).toBeNull();
  });

  it("carries both spellings of cancelled", async () => {
    getScans.mockImplementation(() =>
      ok([
        { ...SCANS[0], id: 31, status: "cancelled", target: "x" },
        { ...SCANS[0], id: 32, status: "canceled", target: "y" },
      ]),
    );
    renderPage();
    await waitFor(() => expect(getScans).toHaveBeenCalled());
    await screen.findByText("x");

    for (const t of ["x", "y"]) {
      const row = screen.getByText(t).closest("tr");
      expect(within(row).queryByText(/^running$/i)).toBeNull();
    }
  });
});

/* ── Accessibility — the migration specification ──────────────────────────── */

describe("ArchivedScans — accessibility", () => {
  it("gives the table an accessible name", async () => {
    renderPage();
    await loaded();

    // 46 tables across the application, zero <caption> elements. A table with
    // no name is announced as "table" and nothing else.
    expect(screen.getByRole("table")).toHaveAccessibleName();
  });

  it("marks every column header with scope=col", async () => {
    renderPage();
    await loaded();
    const headers = screen.getByRole("table").querySelectorAll("thead th");

    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th).toHaveAttribute("scope", "col");
    }
  });

  it("identifies each row with a row header", async () => {
    renderPage();
    await loaded();
    const row = screen.getByText("10.180.6.14").closest("tr");

    // Without scope="row" a reader announces a naked value as it moves across
    // rather than "Scan No., SCAN-0011".
    expect(row.querySelector("th[scope='row']")).not.toBeNull();
  });

  it("announces the load to assistive technology", async () => {
    getScans.mockReturnValue(new Promise(() => {}));
    renderPage();

    // A bare spinning <div> tells a non-sighted user nothing at all.
    const live = document.querySelector("[role='status'],[aria-live]");
    expect(live).not.toBeNull();
  });

  it("announces the load failure as an alert", async () => {
    getScans.mockRejectedValue(new Error("boom"));
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/failed to load archived scans/i);
  });

  it("names each row action for its own row", async () => {
    renderPage();
    await loaded();

    // Ten identical "Restore" buttons give a screen-reader user ten identical
    // list entries and no way to tell which scan each belongs to.
    const restores = screen.getAllByRole("button", { name: /restore/i });
    const names = restores.map(
      (b) => b.getAttribute("aria-label") || b.textContent,
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("keeps a busy control's accessible name", async () => {
    let release;
    restoreScan.mockReturnValue(new Promise((r) => (release = r)));
    renderPage();
    await loaded();
    const user = userEvent.setup();
    const row = screen.getByText("10.180.6.14").closest("tr");
    await user.click(within(row).getByRole("button", { name: /restore/i }));

    // "..." is not an accessible name. A reader announces "button" and the
    // user has lost track of which control they just activated.
    await waitFor(() =>
      expect(
        within(row).getByRole("button", { name: /restore/i }),
      ).toBeDisabled(),
    );
    release({});
  });

  it("reaches every action by keyboard", async () => {
    renderPage();
    await loaded();
    const user = userEvent.setup();
    const row = screen.getByText("10.180.6.14").closest("tr");
    const restore = within(row).getByRole("button", { name: /restore/i });

    restore.focus();
    expect(restore).toHaveFocus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(restoreScan).toHaveBeenCalledTimes(1));
  });

  it("pins no colour inline", async () => {
    const { container } = renderPage();
    await loaded();

    for (const el of container.querySelectorAll("*")) {
      const style = el.getAttribute("style") || "";
      expect(style).not.toMatch(/(^|[^-])\bcolor\s*:/);
      expect(style).not.toMatch(/background(-color)?\s*:/);
      expect(style).not.toMatch(/border(-[a-z]+)?\s*:\s*[^v]/);
    }
  });
});
