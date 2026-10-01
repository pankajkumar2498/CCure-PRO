/**
 * AuditLogs — Checkpoint 3C batch 10 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The audit trail is tamper-evident and retention-governed. This page READS it
 * and exports it; nothing here writes or deletes an audit row, and nothing may
 * gain the ability to. `CLAUDE.md` is explicit that no HTTP endpoint deletes an
 * audit row — destroying audit history needs shell access to the host — so the
 * retention panel here is a PREVIEW and must stay one.
 *
 * ── The polling contract, which the migration must not touch ───────────────
 * A 5-second `setInterval` asks for the newest 10 rows **under the currently
 * active filters** and compares their timestamps against the newest row already
 * on screen. It sets a "N new events" counter. It deliberately does NOT reload
 * the table, and its errors are deliberately swallowed — a background check
 * that interrupts the reader with a toast every five seconds is worse than one
 * that quietly misses a tick.
 *
 * The dependency is `JSON.stringify(filters)`, not the ten filters listed out.
 * That is load-bearing: listing them is how a newly added filter silently stops
 * being applied to the poll while still applying to the table.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AuditLogs from "@audit/pages/admin/AuditLogs";
import axiosInstance from "@shell/api/axiosInstance";

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

let currentUser = { username: "root", id: 1, role: { name: "superadmin" } };
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: currentUser }),
}));

let superadmin = true;
vi.mock("@shell/auth/permissions", () => ({
  can: () => true,
  isSuperAdmin: () => superadmin,
  denyMessage: "You do not have permission to perform this action.",
}));

const LOGS = [
  {
    id: "e-1",
    created_at: "2026-09-10T12:00:00Z",
    user_email: "alice@example.test",
    username: "alice",
    action: "user.login",
    resource_type: "user",
    resource_id: "u-1",
    status: "success",
    severity: "info",
    ip_address: "10.180.6.20",
  },
  {
    id: "e-2",
    created_at: "2026-09-10T11:00:00Z",
    user_email: "bob@example.test",
    username: "bob",
    action: "scan.delete",
    resource_type: "scan",
    resource_id: "s-9",
    status: "failure",
    severity: "critical",
    ip_address: "10.180.6.21",
  },
];

const LIST = { logs: LOGS, total: 2 };

const routeGet = (url) => {
  if (String(url).startsWith("/admin/audit-logs/export"))
    return Promise.resolve({ data: new Blob(["a,b"]), headers: {} });
  if (String(url).startsWith("/admin/audit-logs/retention/preview"))
    return Promise.resolve({ data: { organizations: [], enabled: false } });
  if (String(url).match(/^\/admin\/audit-logs\/[^/]+$/))
    return Promise.resolve({ data: { ...LOGS[0], session_id: "sess-1" } });
  if (String(url).startsWith("/admin/audit-logs"))
    return Promise.resolve({ data: LIST });
  return Promise.resolve({ data: {} });
};

const renderPage = async () => {
  const r = render(<AuditLogs />);
  await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
  return r;
};

/* Innermost match. `[...querySelectorAll("*")].find(...)` returns the first
   element in DOCUMENT order whose text matches, which is an outer wrapper —
   and `.closest()` from a wrapper walks past the live region that sits inside
   it. Selecting the innermost matching element is what makes the assertion
   about the element that actually carries the text. */
const innermost = (container, re) =>
  [...container.querySelectorAll("*")]
    .filter((el) => re.test(el.textContent || ""))
    .filter((el) => ![...el.children].some((c) => re.test(c.textContent || "")))
    .pop();

const listCalls = () =>
  axiosInstance.get.mock.calls.filter((c) => c[0] === "/admin/audit-logs/");

beforeEach(() => {
  vi.clearAllMocks();
  superadmin = true;
  currentUser = { username: "root", id: 1, role: { name: "superadmin" } };
  axiosInstance.get.mockImplementation(routeGet);
});

afterEach(() => {
  vi.useRealTimers();
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("AuditLogs — functional", () => {
  it("loads the audit trail on mount", async () => {
    await renderPage();
    await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
    expect(listCalls()[0][0]).toBe("/admin/audit-logs/");
  });

  it("renders a row per event", async () => {
    /* Anchored on the actor's email, which renders verbatim. The action cell
       shows a formatted label rather than the raw `user.login` key. */
    await renderPage();
    expect(await screen.findByText("alice@example.test")).toBeInTheDocument();
    expect(await screen.findByText("bob@example.test")).toBeInTheDocument();
  });

  it("requests the first page with skip 0", async () => {
    await renderPage();
    await waitFor(() =>
      expect(listCalls()[0][1]?.params).toMatchObject({ skip: 0 }),
    );
  });

  it("carries a limit that matches the page size", async () => {
    await renderPage();
    await waitFor(() => {
      const p = listCalls()[0][1]?.params;
      expect(p).toHaveProperty("limit");
      expect(typeof p.limit).toBe("number");
    });
  });

  it("omits empty filters from the query rather than sending blanks", async () => {
    /* A blank filter sent as "" is a filter the server has to interpret; the
       page drops them so an unset filter is genuinely absent. */
    await renderPage();
    await waitFor(() => {
      const params = listCalls()[0][1]?.params || {};
      expect(Object.values(params)).not.toContain("");
    });
  });

  it("shows an empty state when there are no events", async () => {
    axiosInstance.get.mockImplementation((url) =>
      String(url).startsWith("/admin/audit-logs") &&
      !String(url).includes("export")
        ? Promise.resolve({ data: { logs: [], total: 0 } })
        : Promise.resolve({ data: {} }),
    );
    const { container } = await renderPage();
    await waitFor(() => expect(container.textContent).toMatch(/no |empty/i));
  });

  it("reports a failed load rather than an empty trail", async () => {
    axiosInstance.get.mockImplementation((url) =>
      String(url).startsWith("/admin/audit-logs") &&
      !String(url).includes("export")
        ? Promise.reject(new Error("boom"))
        : Promise.resolve({ data: {} }),
    );
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(/failed to load audit logs/i),
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   READ-ONLY CONTRACT
   ══════════════════════════════════════════════════════════════════════════ */
describe("AuditLogs — read-only contract", () => {
  it("never writes or deletes an audit row", async () => {
    /* No HTTP endpoint deletes an audit row. Retention is beat or a host
       script, and the panel here is a preview. */
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    for (const btn of [...container.querySelectorAll("button")].slice(0, 25)) {
      await user.click(btn);
    }
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("reaches the retention endpoint only as a preview", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    const retentionCalls = axiosInstance.get.mock.calls.filter((c) =>
      String(c[0]).includes("retention"),
    );
    for (const c of retentionCalls) {
      expect(String(c[0])).toMatch(/retention\/preview/);
    }
    expect(container.textContent).not.toMatch(
      /purge now|delete logs|apply retention/i,
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   POLLING CONTRACT — application behaviour, not to be changed
   ══════════════════════════════════════════════════════════════════════════ */
describe("AuditLogs — polling contract", () => {
  it("polls every 5 seconds once the first page has loaded", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      const before = listCalls().length;
      await vi.advanceTimersByTimeAsync(5000);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(before));
    } finally {
      vi.useRealTimers();
    }
  });

  it("asks the poll for only the newest ten rows", async () => {
    /* The poll is a cheap freshness check, not a table reload. A poll that
       requested the whole page would multiply the cost of the screen by twelve
       every minute. */
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      const before = listCalls().length;
      await vi.advanceTimersByTimeAsync(5000);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(before));
      const poll = listCalls()[listCalls().length - 1][1]?.params;
      expect(poll).toMatchObject({ skip: 0, limit: 10 });
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not replace the table from a poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      await vi.advanceTimersByTimeAsync(15000);
      // The two seeded rows are still the rows on screen.
      expect(screen.getAllByText("alice@example.test").length).toBeGreaterThan(
        0,
      );
      expect(screen.getAllByText("bob@example.test").length).toBeGreaterThan(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops polling when the page unmounts", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { unmount } = render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      await vi.advanceTimersByTimeAsync(5000);
      const atUnmount = listCalls().length;
      unmount();
      await vi.advanceTimersByTimeAsync(30000);
      expect(listCalls().length).toBe(atUnmount);
    } finally {
      vi.useRealTimers();
    }
  });

  it("swallows a poll failure rather than interrupting the reader", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      axiosInstance.get.mockImplementation(() =>
        Promise.reject(new Error("poll failed")),
      );
      await vi.advanceTimersByTimeAsync(15000);
      // The already-rendered rows survive; nothing is torn down.
      expect(screen.getAllByText("alice@example.test").length).toBeGreaterThan(
        0,
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("runs exactly one timer, not one per render", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      const before = listCalls().length;
      await vi.advanceTimersByTimeAsync(5100);
      const after = listCalls().length;
      expect(after - before).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   EXPORT CONTRACT
   ══════════════════════════════════════════════════════════════════════════ */
describe("AuditLogs — export contract", () => {
  it("exports through the export endpoint, carrying the active filters", async () => {
    /* The export is what is on screen, under the same filters — never the whole
       table. */
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    const btn = [...container.querySelectorAll("button")].find((b) =>
      /csv/i.test(b.textContent || ""),
    );
    expect(btn).toBeTruthy();
    await user.click(btn);
    await waitFor(() => {
      const call = axiosInstance.get.mock.calls.find((c) =>
        String(c[0]).includes("/admin/audit-logs/export"),
      );
      expect(call).toBeTruthy();
      expect(call[1]).toMatchObject({ responseType: "blob" });
      expect(call[1].params).toHaveProperty("format");
    });
  });

  it("does not send pagination with the export", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    const btn = [...container.querySelectorAll("button")].find((b) =>
      /csv/i.test(b.textContent || ""),
    );
    await user.click(btn);
    await waitFor(() => {
      const call = axiosInstance.get.mock.calls.find((c) =>
        String(c[0]).includes("/admin/audit-logs/export"),
      );
      expect(call[1].params).not.toHaveProperty("skip");
    });
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("AuditLogs — accessibility", () => {
  it("gives the page a level-one heading and skips no level", async () => {
    await renderPage();
    await screen.findByText("alice@example.test");
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("gives the audit table an accessible name", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    const table = container.querySelector("table");
    expect(table).toBeTruthy();
    expect(
      table.querySelector("caption") ||
        table.getAttribute("aria-label") ||
        table.getAttribute("aria-labelledby"),
    ).toBeTruthy();
  });

  it("scopes every column header", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    const ths = [...container.querySelectorAll("table thead th")];
    expect(ths.length).toBeGreaterThan(0);
    expect(ths.every((th) => th.getAttribute("scope") === "col")).toBe(true);
  });

  it("names every filter control", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
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

  it("announces the arrival of new events politely, not assertively", async () => {
    /* A background freshness notice is not an emergency: announcing it
       assertively interrupts whatever the reader is on every five seconds. */
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { container } = render(<AuditLogs />);
      await vi.advanceTimersByTimeAsync(100);
      await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
      axiosInstance.get.mockImplementation((url) =>
        String(url).startsWith("/admin/audit-logs") &&
        !String(url).includes("export")
          ? Promise.resolve({
              data: {
                logs: [
                  {
                    ...LOGS[0],
                    id: "e-new",
                    created_at: "2026-09-11T09:00:00Z",
                  },
                ],
                total: 3,
              },
            })
          : Promise.resolve({ data: {} }),
      );
      await vi.advanceTimersByTimeAsync(5100);
      await waitFor(() => expect(container.textContent).toMatch(/new event/i));
      const banner = innermost(container, /new event/i);
      const live = banner.closest('[role="status"],[aria-live="polite"]');
      expect(live).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("conveys status and severity as text, not by colour alone", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    expect(container.textContent).toMatch(/success/i);
    expect(container.textContent).toMatch(/failure/i);
    expect(container.textContent).toMatch(/critical/i);
  });

  it("puts a load failure in a live region", async () => {
    axiosInstance.get.mockImplementation((url) =>
      String(url).startsWith("/admin/audit-logs") &&
      !String(url).includes("export")
        ? Promise.reject(new Error("boom"))
        : Promise.resolve({ data: {} }),
    );
    /* Anchored on the page's actual message. A loose /fail/ also matches the
       Action filter's "Login Failed" option, which sits LATER in the DOM and
       is not in a live region — the assertion was measuring a dropdown. */
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(/failed to load audit logs/i),
    );
    const msg = innermost(container, /failed to load audit logs/i);
    expect(
      msg.closest('[role="alert"],[role="status"],[aria-live]'),
    ).toBeTruthy();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("AuditLogs — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    expect(
      [...container.querySelectorAll("[style]")].map((e) =>
        e.getAttribute("style"),
      ),
    ).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("alice@example.test");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });
});
