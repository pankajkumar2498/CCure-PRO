/**
 * RecycleBin — Checkpoint 3C batch 5 migration coverage.
 *
 * Written against the page BEFORE migration. The functional, security and
 * regression groups record the contract and must pass identically before and
 * after; the accessibility group is the migration's specification and contains
 * assertions that fail against the current implementation.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This is the most destructive page in the scan lifecycle: `purgeScan` removes
 * a scan record permanently, and CLAUDE.md records that `archive_mode` is off,
 * so there is no point-in-time recovery behind it. Three properties matter:
 *
 *   * `scope: "deleted"` is load-bearing. `getScans` defaults to
 *     `scope="active"`, so a lost argument would list LIVE scans on a page
 *     whose second button purges them.
 *   * Purge is gated on `scans:purge`, restore on `scans:restore`, and they are
 *     different permissions — a user who may undo a deletion is not thereby a
 *     user who may make one permanent.
 *   * Purge requires an explicit confirmation. Restore does not, and should
 *     not: it is the reversible direction.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import RecycleBin from "@audit/pages/RecycleBin";
import { getScans, restoreScan, purgeScan } from "@audit/api/scans";
import { keySetHolds } from "../../../fixtures/authorization";
import { personaFrom } from "../../../fixtures/authorization";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("@audit/api/scans", () => ({
  getScans: vi.fn(),
  restoreScan: vi.fn(),
  purgeScan: vi.fn(),
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let currentUser = { username: "operator", id: 1 };
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(currentUser) }),
}));

let permissions = new Set(["audit.scan.lifecycle", "audit.scan.purge"]);
vi.mock("@shell/auth/permissions", () => ({
  can: (_user, resource, action) => keySetHolds(permissions, resource, action),
  denyMessage: "You do not have permission to perform this action.",
}));

const SCANS = [
  {
    id: 21,
    scan_no: "SCAN-0021",
    target: "10.180.6.14",
    scan_type: "network",
    pipeline_mode: "basic",
    status: "complete",
    scan_duration: 42.5,
    deleted_at: "2026-08-01T10:00:00Z",
    created_at: "2026-07-30T09:00:00Z",
  },
  {
    id: 22,
    scan_no: "SCAN-0022",
    target: "10.180.5.83",
    scan_type: "credentialed",
    status: "failed",
    scan_duration: 125,
    deleted_at: "2026-08-02T11:00:00Z",
    created_at: "2026-07-31T09:00:00Z",
  },
  {
    id: 23,
    scan_no: "SCAN-0023",
    target: "192.168.1.7",
    scan_type: "network",
    pipeline_mode: "asset",
    // Genuinely in flight. The control for the two rows below it.
    status: "running",
    scan_duration: 8,
    deleted_at: "2026-08-03T12:00:00Z",
    created_at: "2026-08-01T08:00:00Z",
  },
  {
    id: 24,
    scan_no: "SCAN-0024",
    target: "172.16.0.9",
    scan_type: "network",
    pipeline_mode: "basic",
    // A real backend status that RecycleBin's local STATUS_STYLE map does not
    // carry. `|| STATUS_STYLE.running` therefore paints it as a scan in
    // progress.
    status: "queued",
    scan_duration: 3,
    deleted_at: "2026-08-04T12:00:00Z",
    created_at: "2026-08-02T08:00:00Z",
  },
  {
    id: 25,
    scan_no: "SCAN-0025",
    target: "172.16.0.10",
    scan_type: "network",
    pipeline_mode: "basic",
    // Recognised by neither implementation — the true unknown case.
    status: "reaped",
    scan_duration: 1,
    deleted_at: "2026-08-05T12:00:00Z",
    created_at: "2026-08-03T08:00:00Z",
  },
];

/** How a row presents its status, independent of which implementation drew it.
 *  Pre-migration that is an inline `color`; post-migration it is a variant
 *  class. Comparing two rows' presentation is the only assertion that means
 *  the same thing on both sides of the migration. */
const statusPresentation = (scanNo) => {
  const row = screen.getByText(scanNo).closest("tr");
  const cell = row.querySelectorAll("td, th")[3];
  const el = cell.querySelector("span") || cell;
  return `${el.getAttribute("style") || ""}|${el.className || ""}`;
};

/* Row-scoped accessors. The migration gives each row's controls a distinct
   accessible name ("Restore scan SCAN-0021"), which is the whole point of the
   two "disambiguates" assertions below — so a page-wide query on the bare verb
   stops matching. Scoping to the row is what makes a short pattern
   unambiguous, and it is stricter than the page-wide query it replaces, not
   looser: the page-wide uniqueness check is still asserted separately. */
const restoreBtn = (row) =>
  within(row).getByRole("button", { name: /restore/i });
const purgeBtn = (row) => within(row).getByRole("button", { name: /delete/i });

const ok = (scans = SCANS) =>
  Promise.resolve({ data: { scans, total: scans.length } });

const renderPage = async () => {
  const result = render(<RecycleBin />);
  await waitFor(() => expect(getScans).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  currentUser = { username: "operator", id: 1 };
  permissions = new Set(["audit.scan.lifecycle", "audit.scan.purge"]);
  getScans.mockImplementation(() => ok());
  restoreScan.mockResolvedValue({});
  purgeScan.mockResolvedValue({});
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("RecycleBin — functional", () => {
  it("requests the deleted scope, not the default active scope", async () => {
    await renderPage();
    expect(getScans).toHaveBeenCalledWith(0, 200, "deleted");
  });

  it("renders one row per returned scan", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(screen.getByText("SCAN-0022")).toBeInTheDocument();
    expect(screen.getByText("SCAN-0023")).toBeInTheDocument();
    expect(screen.getByText("SCAN-0024")).toBeInTheDocument();
    expect(screen.getByText("SCAN-0025")).toBeInTheDocument();
  });

  it("renders the total in the subtitle, pluralised", async () => {
    await renderPage();
    expect(
      await screen.findByText(/5 scans ready for permanent deletion/i),
    ).toBeInTheDocument();
  });

  it("renders the singular form for exactly one scan", async () => {
    getScans.mockImplementation(() => ok([SCANS[0]]));
    await renderPage();
    expect(
      await screen.findByText(/1 scan ready for permanent deletion/i),
    ).toBeInTheDocument();
  });

  it("shows an empty state when nothing is in the bin", async () => {
    getScans.mockImplementation(() => ok([]));
    await renderPage();
    expect(
      await screen.findByText(/recycle bin is empty/i),
    ).toBeInTheDocument();
  });

  it("shows an error message when the load fails", async () => {
    getScans.mockRejectedValue(new Error("network"));
    await renderPage();
    expect(
      await screen.findByText(/failed to load recycle bin/i),
    ).toBeInTheDocument();
  });

  it("does not render the table when the load failed", async () => {
    getScans.mockRejectedValue(new Error("network"));
    await renderPage();
    await screen.findByText(/failed to load recycle bin/i);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("refreshes on demand", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("SCAN-0021");
    await user.click(screen.getByRole("button", { name: /refresh/i }));
    await waitFor(() => expect(getScans).toHaveBeenCalledTimes(2));
  });

  it("navigates to scan history from the header", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /my scan jobs/i }));
    expect(navigate).toHaveBeenCalledWith("/history");
  });

  it("navigates to scan history from the empty state", async () => {
    getScans.mockImplementation(() => ok([]));
    const user = userEvent.setup();
    await renderPage();
    await user.click(
      await screen.findByRole("button", { name: /back to scan jobs/i }),
    );
    expect(navigate).toHaveBeenCalledWith("/history");
  });

  it("labels a credentialed scan by type rather than pipeline", async () => {
    await renderPage();
    expect(await screen.findByText("Credentialed Scan")).toBeInTheDocument();
  });

  it("formats a sub-minute duration in seconds", async () => {
    await renderPage();
    expect(await screen.findByText("42.5s")).toBeInTheDocument();
  });

  it("formats a duration over a minute as minutes and seconds", async () => {
    await renderPage();
    expect(await screen.findByText("2m 5s")).toBeInTheDocument();
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<RecycleBin />);
      await waitFor(() => expect(getScans).toHaveBeenCalledTimes(1));
      await vi.advanceTimersByTimeAsync(120000);
      expect(getScans).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("RecycleBin — security", () => {
  it("restores a scan and drops the row without re-fetching", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(restoreBtn(row));

    await waitFor(() => expect(restoreScan).toHaveBeenCalledWith(21));
    await waitFor(() =>
      expect(screen.queryByText("SCAN-0021")).not.toBeInTheDocument(),
    );
    expect(getScans).toHaveBeenCalledTimes(1);
  });

  it("keeps the row when a restore fails", async () => {
    restoreScan.mockRejectedValue({
      response: { data: { detail: "Scan is locked." } },
    });
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(restoreBtn(row));

    await waitFor(() => expect(restoreScan).toHaveBeenCalled());
    expect(screen.getByText("SCAN-0021")).toBeInTheDocument();
  });

  it("never purges without an explicit confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));

    // The dialog is open; nothing has been sent.
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(purgeScan).not.toHaveBeenCalled();
  });

  it("purges only after the confirmation is accepted", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: /delete permanently/i }),
    );

    await waitFor(() => expect(purgeScan).toHaveBeenCalledWith(21));
    await waitFor(() =>
      expect(screen.queryByText("SCAN-0021")).not.toBeInTheDocument(),
    );
  });

  it("sends nothing when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(purgeScan).not.toHaveBeenCalled();
    expect(screen.getByText("SCAN-0021")).toBeInTheDocument();
  });

  it("names the scan being purged in the confirmation", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/SCAN-0021/)).toBeInTheDocument();
  });

  it("states that the purge is irreversible", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/irreversible/i)).toBeInTheDocument();
  });

  it("hides restore from a user without scans:restore", async () => {
    permissions = new Set(["audit.scan.purge"]);
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(
      screen.queryByRole("button", { name: /restore/i }),
    ).not.toBeInTheDocument();
  });

  it("hides purge from a user without scans:purge", async () => {
    permissions = new Set(["audit.scan.lifecycle"]);
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
  });

  it("treats restore and purge as separate permissions", async () => {
    permissions = new Set(["audit.scan.lifecycle"]);
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(screen.getAllByRole("button", { name: /restore/i }).length).toBe(5);
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
  });

  it("shows a read-only marker when neither permission is held", async () => {
    permissions = new Set();
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(screen.getAllByText(/read only/i).length).toBe(5);
    expect(
      screen.queryByRole("button", { name: /restore/i }),
    ).not.toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("RecycleBin — accessibility", () => {
  it("gives the table an accessible name", async () => {
    await renderPage();
    const table = await screen.findByRole("table");
    expect(table).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th.getAttribute("scope")).toBe("col");
    }
  });

  it("marks the identifying cell as its row's header", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(5);
  });

  it("disambiguates the restore control per row", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    const buttons = screen.getAllByRole("button", { name: /restore/i });
    expect(buttons.length).toBe(5);
    const names = buttons.map(
      (b) => b.getAttribute("aria-label") || b.textContent.trim(),
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("disambiguates the purge control per row", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    const buttons = screen.getAllByRole("button", { name: /delete/i });
    expect(buttons.length).toBe(5);
    const names = buttons.map(
      (b) => b.getAttribute("aria-label") || b.textContent.trim(),
    );
    expect(new Set(names).size).toBe(names.length);
  });

  it("announces the loading state", async () => {
    let settle;
    getScans.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ data: { scans: [], total: 0 } });
        }),
    );
    render(<RecycleBin />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|recycle bin/i);
    settle();
  });

  it("announces a load failure assertively", async () => {
    getScans.mockRejectedValue(new Error("network"));
    await renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/failed to load recycle bin/i);
  });

  it("describes the confirmation dialog, not only labels it", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAccessibleDescription();
  });

  it("traps focus inside the confirmation dialog", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    const dialog = await screen.findByRole("dialog");

    // Tab through more stops than the dialog holds; focus must never leave it.
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("returns focus to the invoking control when the dialog closes", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    const trigger = purgeBtn(row);
    await user.click(trigger);
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));

    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });

  it("closes the confirmation on Escape", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("SCAN-0021")).closest("tr");
    await user.click(purgeBtn(row));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  /* These two assert on *presentation*, not on the status text. The first
     version of each checked only that the raw word was rendered, which the
     pre-migration page satisfies while painting the row in the running style —
     so it passed without touching the defect it was written for. Comparing a
     row against a genuinely-running control is the assertion that means the
     same thing before and after. */
  it("does not present a queued scan as a running one", async () => {
    await renderPage();
    await screen.findByText("SCAN-0024");
    expect(statusPresentation("SCAN-0024")).not.toBe(
      statusPresentation("SCAN-0023"),
    );
  });

  it("does not present an unrecognised status as a running one", async () => {
    await renderPage();
    await screen.findByText("SCAN-0025");
    expect(statusPresentation("SCAN-0025")).not.toBe(
      statusPresentation("SCAN-0023"),
    );
  });

  it("names an unrecognised status as unknown rather than inventing one", async () => {
    await renderPage();
    const row = (await screen.findByText("SCAN-0025")).closest("tr");
    expect(within(row).queryByText(/^running$/i)).not.toBeInTheDocument();
    expect(within(row).getByText(/unknown/i)).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   VISUAL / REGRESSION SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("RecycleBin — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("SCAN-0021");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("SCAN-0021");
    const html = container.innerHTML;
    expect(html).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(html).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("SCAN-0021");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("renders one row per scan and no more", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(document.querySelectorAll("tbody tr").length).toBe(5);
  });

  it("keeps the page heading", async () => {
    await renderPage();
    expect(
      screen.getByRole("heading", { name: /recycle bin/i }),
    ).toBeInTheDocument();
  });

  it("renders exactly one heading for the page", async () => {
    await renderPage();
    await screen.findByText("SCAN-0021");
    expect(
      screen.getAllByRole("heading", { name: /recycle bin/i }).length,
    ).toBe(1);
  });
});
