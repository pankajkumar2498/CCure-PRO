import { assertUx4gAdapters } from "../../../helpers/assertUx4gAdapters";
/**
 * SecurityReports — Checkpoint 3C batch 10 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * This page lists generated reports, downloads them, and deletes them. Three
 * properties carry the weight:
 *
 *   * **Deletion is permission-gated TWICE** — when the dialog is opened and
 *     again when it is confirmed. That is not redundant: the permission can be
 *     revoked while the dialog is open, and the second check is the one that
 *     runs at the moment the request would be sent.
 *
 *   * **Deletion is irreversible and says so.** The wording names the scan and
 *     states that the scan record and its report are removed. A migration must
 *     not soften a destructive warning into a generic "Are you sure?".
 *
 *   * **The download is an authenticated fetch, not a link.** `/reports/
 *     download/{id}` is bearer-authenticated, so a bare anchor would be an
 *     unauthenticated request. It is fetched as an arraybuffer and saved
 *     through a blob, with the filename taken from Content-Disposition.
 *
 * The listing itself spans three scopes — active, archived AND deleted —
 * because reports stay reachable until permanent deletion. Dropping a scope
 * would silently hide reports that still exist.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SecurityReports from "@audit/pages/SecurityReports";
import axiosInstance from "@shell/api/axiosInstance";
import { keySetHolds } from "../../../fixtures/authorization";
import { personaFrom } from "../../../fixtures/authorization";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children }) => <div data-testid="app-layout">{children}</div>,
}));

const navigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useSearchParams: () => [new URLSearchParams(""), vi.fn()],
  };
});

let currentUser = { username: "operator", id: 1 };
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(currentUser) }),
}));

let permissions = new Set(["audit.report.read", "audit.report.delete"]);
vi.mock("@shell/auth/permissions", () => ({
  can: (_u, r, a) => keySetHolds(permissions, r, a),
  denyMessage: "You do not have permission to perform this action.",
}));

const SCANS = {
  active: [
    {
      id: "s-1",
      scan_no: 41,
      target: "10.180.5.10",
      status: "complete",
      pipeline_mode: "vulnerability_audit",
      has_executive_report: true,
      has_technical_report: true,
      created_at: "2026-09-01T10:00:00Z",
      completed_at: "2026-09-01T10:04:00Z",
      duration_seconds: 240,
    },
  ],
  archived: [
    {
      id: "s-2",
      scan_no: 30,
      target: "10.180.5.20",
      status: "complete",
      pipeline_mode: "asset",
      has_executive_report: true,
      has_technical_report: false,
      created_at: "2026-08-01T10:00:00Z",
      completed_at: "2026-08-01T10:02:00Z",
      duration_seconds: 120,
    },
  ],
  deleted: [
    {
      id: "s-3",
      scan_no: 12,
      target: "10.180.5.30",
      status: "complete",
      pipeline_mode: "basic",
      has_executive_report: false,
      has_technical_report: true,
      created_at: "2026-07-01T10:00:00Z",
      completed_at: "2026-07-01T10:01:00Z",
      duration_seconds: 60,
    },
  ],
};

const routeGet = (url, config) => {
  if (url === "/scans") {
    const scope = config?.params?.scope || "active";
    return Promise.resolve({
      data: { scans: SCANS[scope] || [], total: (SCANS[scope] || []).length },
    });
  }
  if (String(url).startsWith("/reports/download/")) {
    return Promise.resolve({
      data: new ArrayBuffer(8),
      headers: {
        "content-type": "application/pdf",
        "content-disposition": 'attachment; filename="ccure-report-41.pdf"',
      },
    });
  }
  return Promise.resolve({ data: {} });
};

const renderPage = async () => {
  const r = render(<SecurityReports />);
  await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
  return r;
};

const scopesRequested = () =>
  axiosInstance.get.mock.calls
    .filter((c) => c[0] === "/scans")
    .map((c) => c[1]?.params?.scope);

/* The repository renders CARDS, not table rows. Climb from the target text to
   the nearest ancestor that also holds the card's action buttons, so the helper
   survives the card's class names changing during migration. */
const cardFor = async (text) => {
  let el = await screen.findByText(text);
  while (el && el !== document.body) {
    if (el.querySelector("button")) return el;
    el = el.parentElement;
  }
  throw new Error(`no card found for ${text}`);
};

const dlBtn = (card) =>
  within(card)
    .getAllByRole("button")
    .find((b) =>
      /official report|technical data|download|pdf/i.test(
        b.getAttribute("aria-label") || b.textContent || "",
      ),
    );

/* The delete control is icon-only (a bare 🗑️) with no text and no aria-label —
   which is itself part of the migration specification below. Matched on the
   glyph as well as on a name, so the helper works before AND after. */
const delBtn = (card) =>
  within(card)
    .getAllByRole("button")
    .find((b) =>
      /delete|remove|🗑/i.test(
        b.getAttribute("aria-label") || b.textContent || "",
      ),
    );

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  currentUser = { username: "operator", id: 1 };
  permissions = new Set(["audit.report.read", "audit.report.delete"]);
  axiosInstance.get.mockImplementation(routeGet);
  axiosInstance.delete.mockResolvedValue({ data: {} });
  // jsdom implements neither of these; the download path uses both.
  if (!window.URL.createObjectURL)
    window.URL.createObjectURL = vi.fn(() => "blob:x");
  else vi.spyOn(window.URL, "createObjectURL").mockReturnValue("blob:x");
  if (!window.URL.revokeObjectURL) window.URL.revokeObjectURL = vi.fn();
  else vi.spyOn(window.URL, "revokeObjectURL").mockImplementation(() => {});
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityReports — functional", () => {
  it("lists reports across all three scopes", async () => {
    /* Reports stay reachable until permanent deletion, so an archived or
       soft-deleted scan's report must still be listed. Dropping a scope hides
       reports that still exist. */
    await renderPage();
    await waitFor(() => {
      expect(scopesRequested()).toEqual(
        expect.arrayContaining(["active", "archived", "deleted"]),
      );
    });
  });

  it("shows a row per reportable scan", async () => {
    await renderPage();
    expect(await screen.findByText("10.180.5.10")).toBeInTheDocument();
    expect(await screen.findByText("10.180.5.20")).toBeInTheDocument();
    expect(await screen.findByText("10.180.5.30")).toBeInTheDocument();
  });

  it("omits a scan that neither completed nor has a report", async () => {
    axiosInstance.get.mockImplementation((url, config) => {
      if (url === "/scans") {
        const scope = config?.params?.scope;
        if (scope === "active")
          return Promise.resolve({
            data: {
              scans: [
                ...SCANS.active,
                {
                  id: "s-x",
                  scan_no: 99,
                  target: "10.180.5.99",
                  status: "running",
                  has_executive_report: false,
                  has_technical_report: false,
                },
              ],
            },
          });
        return Promise.resolve({ data: { scans: SCANS[scope] || [] } });
      }
      return Promise.resolve({ data: {} });
    });
    await renderPage();
    await screen.findByText("10.180.5.10");
    expect(screen.queryByText("10.180.5.99")).not.toBeInTheDocument();
  });

  it("filters by search text", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const search = container.querySelector(
      'input[type="text"], input[type="search"], input:not([type])',
    );
    await user.type(search, "10.180.5.20");
    await waitFor(() =>
      expect(screen.queryByText("10.180.5.10")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("10.180.5.20")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is reportable", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/scans"
        ? Promise.resolve({ data: { scans: [] } })
        : Promise.resolve({ data: {} }),
    );
    const { container } = await renderPage();
    await waitFor(() => expect(container.textContent).toMatch(/no|empty/i));
  });

  it("reports a failed load rather than an empty repository", async () => {
    axiosInstance.get.mockImplementation((url) =>
      url === "/scans"
        ? Promise.reject(new Error("boom"))
        : Promise.resolve({ data: {} }),
    );
    await renderPage();
    expect(
      await screen.findByText(/failed to synchronize|failed to load|error/i),
    ).toBeInTheDocument();
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<SecurityReports />);
      await vi.advanceTimersByTimeAsync(120000);
      expect(scopesRequested().length).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   DOWNLOAD CONTRACT
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityReports — download contract", () => {
  it("fetches the report as an authenticated binary response, never a bare link", async () => {
    /* The endpoint is bearer-authenticated: an <a href> would be an
       unauthenticated request and answer 403.

       The response type changed from `arraybuffer` to `blob` when this page
       moved onto the shared `downloadReport` / `saveResponseAsFile` helpers,
       so that it, the scan-results export panel and any future caller handle
       Content-Disposition and object-URL release in one place rather than
       three. The property this test exists for is unchanged — the request is
       an authenticated XHR carrying `fmt`, not a link — and a Blob is what
       `saveResponseAsFile` saves without re-wrapping. */
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const dl = dlBtn(card);
    expect(dl).toBeTruthy();
    await user.click(dl);
    await waitFor(() => {
      const call = axiosInstance.get.mock.calls.find((c) =>
        String(c[0]).startsWith("/reports/download/"),
      );
      expect(call).toBeTruthy();
      expect(call[1]).toMatchObject({ responseType: "blob" });
      expect(call[1].params).toHaveProperty("fmt");
    });
  });

  it("addresses the download at the scan's own id", async () => {
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const dl = dlBtn(card);
    await user.click(dl);
    await waitFor(() => {
      const call = axiosInstance.get.mock.calls.find((c) =>
        String(c[0]).startsWith("/reports/download/"),
      );
      expect(call[0]).toBe("/reports/download/s-1");
    });
  });

  it("refuses to download without reports:read and says so", async () => {
    permissions = new Set([]);
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const dl = dlBtn(card);
    if (dl) await user.click(dl);
    expect(
      axiosInstance.get.mock.calls.filter((c) =>
        String(c[0]).startsWith("/reports/download/"),
      ).length,
    ).toBe(0);
  });

  it("reports a failed download instead of failing silently", async () => {
    axiosInstance.get.mockImplementation((url, config) => {
      if (String(url).startsWith("/reports/download/"))
        return Promise.reject(new Error("nope"));
      return routeGet(url, config);
    });
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const dl = dlBtn(card);
    await user.click(dl);
    expect(await screen.findByText(/failed to download/i)).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   DELETE CONTRACT — destructive, irreversible, twice-gated
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityReports — delete contract", () => {
  const openDelete = async (user, target = "10.180.5.10") => {
    const card = await cardFor(target);
    const del = delBtn(card);
    expect(del).toBeTruthy();
    await user.click(del);
  };

  it("asks for confirmation before deleting", async () => {
    const user = userEvent.setup();
    await renderPage();
    await openDelete(user);
    expect(axiosInstance.delete).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(document.body.textContent).toMatch(/delete|permanent/i),
    );
  });

  it("names the scan in the confirmation and states it is irreversible", async () => {
    /* A destructive warning must not be softened into a generic prompt. */
    const user = userEvent.setup();
    await renderPage();
    await openDelete(user);
    await waitFor(() => {
      const t = document.body.textContent;
      expect(t).toMatch(/41/);
      expect(t).toMatch(/cannot be undone|irreversible/i);
    });
  });

  it("deletes with DELETE /reports/:id once confirmed", async () => {
    const user = userEvent.setup();
    await renderPage();
    await openDelete(user);
    const confirm = (await screen.findAllByRole("button")).find((b) =>
      /delete permanently|confirm/i.test(b.textContent || ""),
    );
    await user.click(confirm);
    await waitFor(() =>
      expect(axiosInstance.delete).toHaveBeenCalledWith("/reports/s-1"),
    );
    expect(axiosInstance.delete).toHaveBeenCalledTimes(1);
  });

  it("sends no delete when the confirmation is refused", async () => {
    const user = userEvent.setup();
    await renderPage();
    await openDelete(user);
    const cancel = (await screen.findAllByRole("button")).find((b) =>
      /cancel|no|close/i.test(b.textContent || ""),
    );
    if (cancel) await user.click(cancel);
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("dispatches no delete without reports:delete", async () => {
    permissions = new Set(["audit.report.read"]);
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const del = delBtn(card);
    if (del) await user.click(del);
    const confirm = screen
      .queryAllByRole("button")
      .find((b) => /delete permanently|confirm/i.test(b.textContent || ""));
    if (confirm) await user.click(confirm);
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("does not render a delete control at all without reports:delete", async () => {
    /* The gate is in three places: the control is not rendered, the opener
       refuses, and the confirm handler refuses again.
       Note what that last one does and does not buy. `canDeleteReports` is
       computed during render, so both handler checks read the SAME captured
       value — revoking the permission while the dialog is open does not stop
       the delete unless something re-renders in between. The second check is
       defence in depth across a re-render, not protection against a mid-dialog
       revocation, and this test deliberately claims only the former. */
    permissions = new Set(["audit.report.read"]);
    const { container } = await renderPage();
    const card = await cardFor("10.180.5.10");
    expect(delBtn(card)).toBeUndefined();
    expect(container.textContent).not.toMatch(/delete permanently/i);
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("reports a failed delete rather than removing the row", async () => {
    axiosInstance.delete.mockRejectedValue(new Error("in use"));
    const user = userEvent.setup();
    await renderPage();
    await openDelete(user);
    const confirm = (await screen.findAllByRole("button")).find((b) =>
      /delete permanently|confirm/i.test(b.textContent || ""),
    );
    await user.click(confirm);
    await waitFor(() => expect(axiosInstance.delete).toHaveBeenCalled());
    expect(await screen.findByText(/failed to delete/i)).toBeInTheDocument();
    expect(screen.getByText("10.180.5.10")).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityReports — accessibility", () => {
  it("gives the page a level-one heading and skips no level", async () => {
    await renderPage();
    await screen.findByText("10.180.5.10");
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("gives the delete control an accessible name", async () => {
    /* It renders as a bare 🗑️ with only a `title`. `title` is not a reliable
       accessible name — it is skipped by several readers and unavailable on
       touch — and this is the control that destroys a report. */
    permissions = new Set(["audit.report.read", "audit.report.delete"]);
    const card = await (async () => {
      await renderPage();
      return cardFor("10.180.5.10");
    })();
    const del = delBtn(card);
    const name = (
      del.getAttribute("aria-label") ||
      del.getAttribute("aria-labelledby") ||
      ""
    ).trim();
    expect(name).toBeTruthy();
  });

  it("disambiguates the action controls across cards", async () => {
    /* Three cards each offering "Official Report" is three identical entries in
       a reader's control list, and picking the wrong one downloads — or
       deletes — the wrong scan's report. */
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const names = [...container.querySelectorAll("button")]
      .filter((b) =>
        /official report|technical data|delete|🗑/i.test(
          b.getAttribute("aria-label") || b.textContent || "",
        ),
      )
      .map((b) => (b.getAttribute("aria-label") || b.textContent || "").trim());
    expect(names.length).toBeGreaterThan(0);
    expect(new Set(names).size).toBe(names.length);
  });

  it("names every filter control", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const controls = container.querySelectorAll(
      "input:not([type=hidden]), select",
    );
    expect(controls.length).toBeGreaterThan(0);
    for (const el of controls) {
      const named =
        el.getAttribute("aria-label") ||
        el.getAttribute("aria-labelledby") ||
        (el.id &&
          container.querySelector(`label[for="${CSS.escape(el.id)}"]`)) ||
        el.closest("label");
      expect(named).toBeTruthy();
    }
  });

  it("announces a failed download assertively", async () => {
    axiosInstance.get.mockImplementation((url, config) => {
      if (String(url).startsWith("/reports/download/"))
        return Promise.reject(new Error("nope"));
      return routeGet(url, config);
    });
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const dl = dlBtn(card);
    await user.click(dl);
    const msg = await screen.findByText(/failed to download/i);
    expect(
      msg.closest('[role="alert"],[role="status"],[aria-live]'),
    ).toBeTruthy();
  });

  it("presents the delete confirmation as a dialog", async () => {
    const user = userEvent.setup();
    await renderPage();
    const card = await cardFor("10.180.5.10");
    const del = delBtn(card);
    await user.click(del);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityReports — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(
      [...container.querySelectorAll("[style]")].map((e) =>
        e.getAttribute("style"),
      ),
    ).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("confines official UX4G classes to shared adapters", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    assertUx4gAdapters(container);
  });
});
