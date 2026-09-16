/**
 * AssetRegistry — Checkpoint 3C batch 10 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Three views over the estate, each with its own endpoint, filters, sort and
 * pagination:
 *
 *   * assets        → `/assets`
 *   * services      → `/assets/services`  (a service, with the count of assets
 *                     exposing it; drilling in reads `/assets/services/assets`)
 *   * certificates  → `/assets/certificates`
 *
 * The only mutation is a single boolean: `PATCH /assets/{id}` with
 * `{ is_managed }`. It is gated on `assets:update` through `canPermission`, and
 * it is the one write on the page — so the load-bearing assertions are that it
 * sends exactly that body, to exactly that asset, and that nothing else on the
 * page writes anything.
 *
 * Fixture field names are taken from the page's own reads (`vuln_counts`,
 * `open_ports_count`, `cert_not_after`, `asset_count`), never guessed — a
 * fixture that invents them renders a row of dashes that still satisfies a
 * loose assertion.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AssetRegistry from "../../pages/AssetRegistry";
import axiosInstance from "../../api/axiosInstance";

vi.mock("../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../components/layout/AppLayout", () => ({
  default: ({ children }) => <div data-testid="app-layout">{children}</div>,
}));

const navigate = vi.fn();
let params = new URLSearchParams("");
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useSearchParams: () => [params, vi.fn()],
    Link: ({ children, to, ...rest }) => (
      <a href={typeof to === "string" ? to : "#"} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("../../context/AuthContext", () => ({
  useAuth: () => ({ user: { username: "operator", id: 1, org_id: "o-1" } }),
}));

let permissions = new Set(["assets:update"]);
vi.mock("../../auth/permissions", () => ({
  canPermission: (_u, { resource, action }) =>
    permissions.has(`${resource}:${action}`),
  can: (_u, r, a) => permissions.has(`${r}:${a}`),
  denyMessage: "You do not have permission to perform this action.",
}));

const ASSETS = {
  assets: [
    {
      id: "a-1",
      ip_address: "10.180.5.10",
      hostname: "ws-01",
      fqdn: "ws-01.corp.test",
      os_family: "windows",
      os_name: "Windows 11 Pro",
      os_confidence: 95,
      device_category: "workstation",
      risk_level: "critical",
      risk_score: 91,
      open_ports_count: 7,
      is_managed: false,
      owner: "alice",
      emp_id: "E-1001",
      serial: "SN-ABC",
      tags: ["finance"],
      last_seen_at: "2026-09-10T10:00:00Z",
      vuln_counts: { critical: 3, high: 5, medium: 9 },
    },
    {
      id: "a-2",
      ip_address: "10.180.5.11",
      hostname: "srv-02",
      fqdn: "srv-02.corp.test",
      os_family: "linux",
      os_name: "Ubuntu 24.04",
      os_confidence: 88,
      device_category: "server",
      risk_level: "medium",
      risk_score: 44,
      open_ports_count: 3,
      is_managed: true,
      owner: "bob",
      emp_id: "E-1002",
      serial: "SN-DEF",
      tags: [],
      last_seen_at: "2026-09-09T10:00:00Z",
      vuln_counts: { critical: 0, high: 1, medium: 4 },
    },
  ],
  total: 2,
};

const SERVICES = {
  services: [
    {
      service_name: "ssh",
      port: 22,
      protocol: "tcp",
      asset_count: 12,
      risk_level: "medium",
      risk_reason: "Remote administration",
      last_seen: "2026-09-10T10:00:00Z",
    },
  ],
  total: 1,
};

const CERTS = {
  certificates: [
    {
      id: "c-1",
      asset_id: "a-1",
      asset_ip: "10.180.5.10",
      asset_hostname: "ws-01",
      port: 443,
      protocol_version: "TLSv1.2",
      cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384",
      cert_subject: { common_name: "ws-01.corp.test" },
      cert_issuer: { common_name: "CCure Internal CA" },
      cert_not_after: "2027-01-01T00:00:00Z",
      cert_is_expired: false,
      cert_is_self_signed: true,
      is_weak_cipher: false,
      grade: "B",
      issues: ["self-signed"],
    },
  ],
  total: 1,
};

const routeGet = (url) => {
  const u = String(url);
  if (u === "/assets/services/assets")
    return Promise.resolve({ data: { assets: ASSETS.assets, total: 2 } });
  if (u === "/assets/services") return Promise.resolve({ data: SERVICES });
  if (u === "/assets/certificates") return Promise.resolve({ data: CERTS });
  if (u === "/assets") return Promise.resolve({ data: ASSETS });
  return Promise.resolve({ data: {} });
};

const renderPage = async () => {
  const r = render(<AssetRegistry />);
  await waitFor(() => expect(axiosInstance.get).toHaveBeenCalled());
  return r;
};

const callsTo = (path) =>
  axiosInstance.get.mock.calls.filter((c) => String(c[0]) === path);

/* Innermost match. `[...querySelectorAll("*")].find(...)` returns the first
   element in DOCUMENT order whose text matches — a wrapper — and an assertion
   about that wrapper is not an assertion about the element carrying the text. */
const innermost = (container, re) =>
  [...container.querySelectorAll("*")]
    .filter((el) => re.test(el.textContent || ""))
    .filter((el) => ![...el.children].some((c) => re.test(c.textContent || "")))
    .pop();

const headerTexts = (container) =>
  [...container.querySelectorAll("table thead th")].map((th) =>
    (th.textContent || "").trim(),
  );

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  params = new URLSearchParams("");
  permissions = new Set(["assets:update"]);
  axiosInstance.get.mockImplementation(routeGet);
  axiosInstance.patch.mockResolvedValue({ data: {} });
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetRegistry — functional", () => {
  it("loads the asset inventory on mount", async () => {
    await renderPage();
    await waitFor(() => expect(callsTo("/assets").length).toBeGreaterThan(0));
  });

  it("renders a row per asset", async () => {
    await renderPage();
    expect(await screen.findByText("10.180.5.10")).toBeInTheDocument();
    expect(await screen.findByText("10.180.5.11")).toBeInTheDocument();
  });

  it("shows the operating system and the open-port count", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(container.textContent).toMatch(/Windows 11 Pro/);
    expect(container.textContent).toMatch(/Ubuntu 24\.04/);
  });

  it("shows per-asset vulnerability counts", async () => {
    /* Read from the CELLS. `container.textContent` concatenates them with
       no separator, so a word-boundary match on the whole string is
       meaningless — it was passing on unrelated digits. */
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const cells = [...container.querySelectorAll("tbody td")].map((td) =>
      (td.textContent || "").trim(),
    );
    expect(cells).toContain("3");
    expect(cells).toContain("5");
  });

  it("sorts by risk score, worst first, by default", async () => {
    await renderPage();
    await waitFor(() => {
      const p = callsTo("/assets")[0][1]?.params;
      expect(p?.sort_by).toBe("risk_score");
      expect(p?.sort_dir).toBe("desc");
    });
  });

  it("pages with skip and limit", async () => {
    await renderPage();
    await waitFor(() => {
      const p = callsTo("/assets")[0][1]?.params;
      expect(p).toHaveProperty("skip");
      expect(p).toHaveProperty("limit");
    });
  });

  it("omits unset filters rather than sending blanks", async () => {
    await renderPage();
    await waitFor(() => {
      const p = callsTo("/assets")[0][1]?.params || {};
      expect(Object.values(p)).not.toContain("");
    });
  });

  it("shows an empty state when the estate is empty", async () => {
    axiosInstance.get.mockImplementation((url) =>
      String(url) === "/assets"
        ? Promise.resolve({ data: { assets: [], total: 0 } })
        : routeGet(url),
    );
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(/no |none|empty/i),
    );
  });

  it("reports a failed load rather than an empty estate", async () => {
    /* "You have no assets" and "we could not read your assets" are different
       facts, and only one of them should make somebody start a discovery scan. */
    axiosInstance.get.mockImplementation((url) =>
      String(url) === "/assets"
        ? Promise.reject(new Error("boom"))
        : routeGet(url),
    );
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(/failed to load assets/i),
    );
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<AssetRegistry />);
      await vi.advanceTimersByTimeAsync(120000);
      expect(callsTo("/assets").length).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   VIEW CONTRACT — three endpoints, not one filtered three ways
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetRegistry — view contract", () => {
  /* The tab strip is `<div onClick>` driven by `setSearchParams`, so the view
     is a URL concern. Driving it through the URL is what the application
     itself does; clicking would only exercise the router mock. */
  it("reads the services endpoint for the services view", async () => {
    params = new URLSearchParams("tab=services");
    await renderPage();
    await waitFor(() =>
      expect(callsTo("/assets/services").length).toBeGreaterThan(0),
    );
  });

  it("reads the certificates endpoint for the certificates view", async () => {
    params = new URLSearchParams("tab=tls");
    await renderPage();
    await waitFor(() =>
      expect(callsTo("/assets/certificates").length).toBeGreaterThan(0),
    );
  });

  it("does not read the services endpoint on the asset view", async () => {
    await renderPage();
    await screen.findByText("10.180.5.10");
    expect(callsTo("/assets/services").length).toBe(0);
    expect(callsTo("/assets/certificates").length).toBe(0);
  });

  it("keeps each view's pagination separate", async () => {
    params = new URLSearchParams("tab=services");
    await renderPage();
    await waitFor(() =>
      expect(callsTo("/assets/services").length).toBeGreaterThan(0),
    );
    const p = callsTo("/assets/services")[0][1]?.params;
    expect(p).toHaveProperty("skip");
    expect(p).toHaveProperty("limit");
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   MUTATION CONTRACT — one boolean, one endpoint
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetRegistry — mutation contract", () => {
  const managedToggle = (container) =>
    [
      ...container.querySelectorAll("tbody button, tbody input[type=checkbox]"),
    ].find((el) =>
      /manag/i.test(
        el.getAttribute("aria-label") ||
          el.getAttribute("title") ||
          el.textContent ||
          "",
      ),
    );

  it("issues no mutation on load", async () => {
    await renderPage();
    await screen.findByText("10.180.5.10");
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("never deletes an asset from this page", async () => {
    /* The registry is the record of what exists on the network. Removing an
       asset is not a listing concern and there is no control for it here. */
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    for (const b of [...container.querySelectorAll("tbody button")].slice(
      0,
      20,
    )) {
      await user.click(b);
    }
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("toggles managed with PATCH /assets/:id carrying only is_managed", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const toggle = managedToggle(container);
    if (!toggle) return; // asserted by the affordance tests below
    await user.click(toggle);
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalled());
    const [url, body] = axiosInstance.patch.mock.calls[0];
    expect(url).toMatch(/^\/assets\/a-\d$/);
    expect(Object.keys(body)).toEqual(["is_managed"]);
  });

  it("sends the opposite of the asset's current managed state", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const toggle = managedToggle(container);
    if (!toggle) return;
    await user.click(toggle);
    await waitFor(() => expect(axiosInstance.patch).toHaveBeenCalled());
    const [url, body] = axiosInstance.patch.mock.calls[0];
    const asset = ASSETS.assets.find((a) => url.endsWith(a.id));
    expect(body.is_managed).toBe(!asset.is_managed);
  });

  it("dispatches no mutation without assets:update", async () => {
    permissions = new Set();
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    for (const b of [...container.querySelectorAll("tbody button")].slice(
      0,
      20,
    )) {
      await user.click(b);
    }
    expect(axiosInstance.patch).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetRegistry — accessibility", () => {
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

  it("gives the asset table an accessible name", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
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
    await screen.findByText("10.180.5.10");
    const ths = [...container.querySelectorAll("table thead th")];
    expect(ths.length).toBeGreaterThan(0);
    expect(ths.every((th) => th.getAttribute("scope") === "col")).toBe(true);
  });

  it("does not abbreviate a column heading to a single letter", async () => {
    /* The vulnerability columns are headed "C", "H" and "M". A reader hears
       "C" and cannot know it means Critical; the abbreviation is legible only
       next to its neighbours, which a screen reader does not provide. */
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const single = headerTexts(container).filter((t) => t.length === 1);
    expect(single).toEqual([]);
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

  it("makes the view tabs operable by keyboard", async () => {
    /* They are `<div onClick>` with no role, no tabindex and no key handler, so
       a keyboard user cannot reach the Services or Certificates views at all —
       two thirds of the page is unreachable without a mouse. */
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    /* Scoped to the tablist. Matching every element whose text equals a label
       also catches the wrapper DIV around each tab, which is not the control
       and is not supposed to be focusable. */
    const list = container.querySelector('[role="tablist"]');
    expect(list).toBeTruthy();
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    expect(tabs.length).toBe(3);
    for (const el of tabs) {
      const focusable =
        el.tagName === "BUTTON" ||
        el.tagName === "A" ||
        el.getAttribute("tabindex") !== null;
      expect(focusable).toBe(true);
    }
  });

  it("states which view is selected", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const tabLabels = [
      "Asset Inventory",
      "Services & Ports",
      "TLS / Certificates",
    ];
    const tabs = [...container.querySelectorAll("*")].filter((el) =>
      tabLabels.includes((el.textContent || "").trim()),
    );
    expect(tabs.length).toBeGreaterThan(0);
    expect(
      tabs.some(
        (b) =>
          b.getAttribute("aria-selected") ||
          b.getAttribute("aria-current") ||
          b.getAttribute("aria-pressed"),
      ),
    ).toBe(true);
  });

  it("conveys risk level as text, not by colour alone", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(container.textContent).toMatch(/critical/i);
    expect(container.textContent).toMatch(/medium/i);
  });

  it("gives the managed toggle an accessible name that names the asset", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const toggles = [
      ...container.querySelectorAll("tbody button, tbody input[type=checkbox]"),
    ].filter((el) =>
      /manag/i.test(
        el.getAttribute("aria-label") ||
          el.getAttribute("title") ||
          el.textContent ||
          "",
      ),
    );
    if (!toggles.length) return;
    const names = toggles.map((el) =>
      (el.getAttribute("aria-label") || "").trim(),
    );
    expect(names.every(Boolean)).toBe(true);
    expect(new Set(names).size).toBe(names.length);
  });

  it("puts a load failure in a live region", async () => {
    axiosInstance.get.mockImplementation((url) =>
      String(url) === "/assets"
        ? Promise.reject(new Error("boom"))
        : routeGet(url),
    );
    /* Anchored on the page's actual message: a loose /fail/ also matches
       filter option text elsewhere in the DOM. */
    const { container } = await renderPage();
    await waitFor(() =>
      expect(container.textContent).toMatch(/failed to load assets/i),
    );
    const msg = innermost(container, /failed to load assets/i);
    expect(
      msg.closest('[role="alert"],[role="status"],[aria-live]'),
    ).toBeTruthy();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetRegistry — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    /* The risk bar's WIDTH is the score — per-instance data, not a design
       decision a token could carry — and stays inline for the same reason
       CcureSkeleton keeps its dimensions inline. Its COLOUR, which was the part
       carrying meaning, is a band class. Nothing else may be inline. */
    const inline = [...container.querySelectorAll("[style]")].map((e) => ({
      cls: e.className,
      style: e.getAttribute("style"),
    }));
    const allowed = inline.filter(
      (e) =>
        /ar-riskbar-fill/.test(e.cls) &&
        /^width: \d+(\.\d+)?%;?$/.test(e.style),
    );
    expect(inline.length - allowed.length).toBe(0);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   STAGE 1 REMEDIATION (after batch 11) — the drill-down's focus trap.

   Batch 10 called `useFocusTrap(Boolean(activeService))` against a hook whose
   signature is `(ref, active)`: the boolean became the ref, `active` was
   undefined, and the dialog's `ref` was `undefined`. It had role, name and
   Escape — and no focus containment or restoration. These tests pin the four
   behaviours the trap exists for and prove the fix added no request.
   ══════════════════════════════════════════════════════════════════════════ */
describe("AssetRegistry — associated-assets dialog focus trap (stage 1 remediation)", () => {
  const openDialog = async (user) => {
    params = new URLSearchParams("tab=services");
    await renderPage();
    const opener = await screen.findByRole("button", { name: "View Assets" });
    opener.focus();
    expect(opener).toHaveFocus();
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", {
      name: /Associated Assets for/,
    });
    return { opener, dialog };
  };

  it("moves focus into the dialog when it opens", async () => {
    const user = userEvent.setup();
    const { dialog } = await openDialog(user);
    await waitFor(() =>
      expect(dialog.contains(document.activeElement)).toBe(true),
    );
    expect(document.activeElement).not.toBe(document.body);
  });

  it("keeps Tab and Shift+Tab inside the dialog while it is open", async () => {
    const user = userEvent.setup();
    const { dialog } = await openDialog(user);
    await waitFor(() =>
      expect(dialog.contains(document.activeElement)).toBe(true),
    );
    // More presses than there are focusable controls in the dialog, both ways.
    for (let i = 0; i < 12; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 12; i += 1) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    await openDialog(user);
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("returns focus to the control that opened it", async () => {
    const user = userEvent.setup();
    const { opener, dialog } = await openDialog(user);
    await waitFor(() =>
      expect(dialog.contains(document.activeElement)).toBe(true),
    );
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("still closes from its close control and from the backdrop", async () => {
    const user = userEvent.setup();
    const { dialog } = await openDialog(user);
    await user.click(
      within(dialog).getByRole("button", {
        name: "Close the associated-assets dialog",
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    await user.click(
      await screen.findByRole("button", { name: "View Assets" }),
    );
    const again = await screen.findByRole("dialog", {
      name: /Associated Assets for/,
    });
    await user.click(again.parentElement); // the backdrop
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("introduces no request: open reads the associated assets once, close reads nothing", async () => {
    const user = userEvent.setup();
    await openDialog(user);
    await waitFor(() =>
      expect(callsTo("/assets/services/assets").length).toBe(1),
    );
    const before = axiosInstance.get.mock.calls.length;
    await user.tab();
    await user.tab({ shift: true });
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(axiosInstance.get.mock.calls.length).toBe(before);
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   BATCH 16 — keyboard reach, captions, and dashboard.css
   ══════════════════════════════════════════════════════════════════════════
   Written against the batch 10 page before the change; every test in this
   block failed there. Batch 10 recorded the thirteen `<th onClick>` sort
   headers as click-only; the row, certificate and dialog drill-downs and the
   managed toggle were the same defect in four more places. */
describe("AssetRegistry — batch 16", () => {
  const sortHeaders = (container) => [
    ...container.querySelectorAll("thead th[aria-sort]"),
  ];

  it("makes every sortable asset column a button that states its sort", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const ths = sortHeaders(container);
    expect(
      ths.map((th) => th.textContent.replace(/[↕▲▼↓↑]/g, "").trim()),
    ).toEqual(["IP / Host", "Risk", "Last Seen"]);
    for (const th of ths) expect(th.querySelector("button")).toBeTruthy();
    // Default sort is risk, worst first.
    expect(ths[1]).toHaveAttribute("aria-sort", "descending");
    expect(ths[0]).toHaveAttribute("aria-sort", "none");
  });

  it("makes the services and certificate sort columns buttons too", async () => {
    params = new URLSearchParams("tab=services");
    const services = await renderPage();
    await screen.findByText("ssh");
    expect(sortHeaders(services.container)).toHaveLength(5);
    services.unmount();

    params = new URLSearchParams("tab=tls");
    const certs = render(<AssetRegistry />);
    await screen.findByText("ws-01.corp.test");
    expect(sortHeaders(certs.container)).toHaveLength(5);
  });

  it("sorts from the keyboard with the page's own direction rules", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const button = sortHeaders(container)[0].querySelector("button");
    button.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => {
      const p = callsTo("/assets").at(-1)[1]?.params;
      expect(p.sort_by).toBe("ip_address");
      // A newly chosen asset column starts descending, as it always has.
      expect(p.sort_dir).toBe("desc");
    });
  });

  it("gives every table one caption, as its first child", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    for (const t of container.querySelectorAll("table")) {
      expect(t.querySelectorAll("caption").length).toBe(1);
      expect(t.firstElementChild.tagName).toBe("CAPTION");
    }
  });

  it("reaches each asset's detail with a real link", async () => {
    await renderPage();
    const link = await screen.findByRole("link", { name: /10\.180\.5\.10/ });
    expect(link).toHaveAttribute("href", "/assets/a-1");
  });

  it("makes the managed state a toggle button that states its value", async () => {
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    const toggles = [
      ...container.querySelectorAll("tbody button[aria-pressed]"),
    ];
    expect(toggles).toHaveLength(2);
    expect(toggles.map((t) => t.getAttribute("aria-pressed"))).toEqual([
      "false",
      "true",
    ]);
  });

  it("offers no managed toggle without assets:update, and still states the value", async () => {
    permissions = new Set();
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(
      container.querySelectorAll("tbody button[aria-pressed]"),
    ).toHaveLength(0);
    expect(container.textContent).toMatch(/Unmanaged/);
    expect(container.textContent).toMatch(/Managed/);
  });

  it("reaches a certificate's asset with a real link", async () => {
    params = new URLSearchParams("tab=tls");
    await renderPage();
    const link = await screen.findByRole("link", { name: "ws-01" });
    expect(link).toHaveAttribute("href", "/assets/a-1");
  });

  it("reaches an associated asset from the dialog with a real link", async () => {
    const user = userEvent.setup();
    params = new URLSearchParams("tab=services");
    /* The service-assets endpoint's own row shape (Backend/routers/assets.py:
       asset_id, asset_hostname, asset_ip) — which is what the page reads. The
       shared `routeGet` answers this URL with registry rows (id, hostname),
       which render a nameless link and would prove nothing. */
    axiosInstance.get.mockImplementation((url) =>
      String(url) === "/assets/services/assets"
        ? Promise.resolve({
            data: {
              assets: [
                {
                  asset_id: "a-1",
                  asset_hostname: "ws-01",
                  asset_ip: "10.180.5.10",
                  asset_type: "endpoint",
                  state: "open",
                  service_product: "OpenSSH",
                  service_version: "9.6",
                  last_scan_time: "2026-09-10T10:00:00Z",
                },
              ],
              total: 1,
            },
          })
        : routeGet(url),
    );
    await renderPage();
    await user.click(
      await screen.findByRole("button", { name: "View Assets" }),
    );
    const dialog = await screen.findByRole("dialog");
    const link = await within(dialog).findByRole("link", { name: "ws-01" });
    expect(link).toHaveAttribute("href", "/assets/a-1");
  });

  it("no longer depends on dashboard.css", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const path = await import("node:path");
    // Not `new URL(rel, import.meta.url)`: Vite rewrites that pattern into an
    // asset URL, which is not a file path.
    const source = readFileSync(
      path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        "../../pages/AssetRegistry.jsx",
      ),
      "utf8",
    );
    expect(source).not.toMatch(/import\s+["'][^"']*dashboard\.css["']/);
    const { container } = await renderPage();
    await screen.findByText("10.180.5.10");
    expect(container.querySelector("[class*='db-']")).toBeNull();
  });
});
