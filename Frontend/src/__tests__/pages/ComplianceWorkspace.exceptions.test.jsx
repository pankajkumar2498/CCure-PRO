/**
 * ComplianceWorkspace (`/compliance`) — the Exceptions tab. Checkpoint 3C
 * batch 26A baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 26A block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The Exceptions tab is read-only. Opening it — and changing the framework or
 * a scoping filter while it is open — reads
 * `GET /compliance/findings?status=pending&limit=10000`, with the header's
 * framework and scoping filters appended. The list pages on the client, 25 at
 * a time, and returns to page 1 when fresh data arrives or the page size
 * changes. A failed read shows the workspace's error and logs it. Nothing on
 * the tab writes.
 *
 * Only the axios instance, the shell and the signed-in user are replaced.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ComplianceWorkspace from "../../pages/ComplianceWorkspace";
import api from "@shell/api/axiosInstance";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let user;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user }),
}));

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const ANALYST = {
  id: 1,
  username: "analyst",
  role: { name: "analyst", permissions: ["compliance:read"] },
};
const ORG_ADMIN = {
  id: 2,
  username: "admin",
  role: {
    name: "Org Admin",
    permissions: ["compliance:read", "compliance:attest"],
  },
};

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const EXCEPTIONS_URL = "/compliance/findings?status=pending&limit=10000";
const SUMMARY = {
  score_pct: 72,
  weighted_score_pct: 70,
  kpis: {
    passed: 40,
    failed: 10,
    exceptions: 2,
    manual_review: 5,
    not_assessed: 3,
    total_controls: 60,
  },
};
const EXCEPTIONS = [
  {
    id: "exc-1",
    control_id: "A.5.1",
    asset_id: "asset-7",
    status: "pending",
    evidence: { note: "Compensating control documented" },
    reason: "not shown when a note exists",
  },
  {
    id: "exc-2",
    control_id: "A.8.2",
    asset_id: null,
    status: "pending",
    reason: "Legacy system, retired in Q4",
  },
  { id: "exc-3", control_id: "A.8.8", status: "pending" },
];
const many = (n) =>
  Array.from({ length: n }, (_, i) => ({
    id: `exc-${i + 1}`,
    control_id: `EX-${String(i + 1).padStart(2, "0")}`,
    asset_id: `asset-${i + 1}`,
    status: "pending",
    reason: `Waiver ${i + 1}`,
  }));
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};

/* ── Harness ────────────────────────────────────────────────────────────── */
let getReply;
let consoleError;
let scrolled;

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const mount = async () => {
  const view = render(<ComplianceWorkspace />);
  await flush();
  return view;
};
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);

// The tab bar is eight unnamed <div>s; it is found by its contents.
const tabBar = () =>
  [...document.querySelectorAll("div")].find(
    (d) =>
      /* Nine since P3-2 added the Schedules tab. The identity of the bar is
         the two labels below; the count is incidental and is kept exact so a
         wrapper cannot satisfy it. */
      d.children.length === 9 &&
      /Approvals Queue/.test(d.textContent || "") &&
      /Marketplace/.test(d.textContent || ""),
  );
const openTab = async (label) => {
  const tab = [...tabBar().children].find(
    (c) => (c.textContent || "").trim() === label,
  );
  fireEvent.click(tab);
  await flush();
};
const openExceptions = () => openTab("Exceptions");

const exceptionReads = () =>
  api.get.mock.calls.filter(([u]) => u.startsWith("/compliance/findings"));
const table = () => document.querySelector("table");
const rows = () =>
  [...table().querySelectorAll("tbody tr")].map((tr) =>
    [...tr.querySelectorAll("td, th")].map(squash),
  );
const firstColumn = () => rows().map((r) => r[0]);
const pageStatus = () => bodyText().match(/Page (\d+) of (\d+)/)?.[0];
const selectWith = (values) =>
  [...document.querySelectorAll("select")].find(
    (s) => [...s.options].map((o) => o.value).join(",") === values,
  );
const sizeSelect = () => selectWith("10,25,50,100");
const frameworkSelect = () =>
  [...document.querySelectorAll("select")].find((s) =>
    [...s.options].some(
      (o) => o.value === "all" && o.textContent === "All Frameworks",
    ),
  );
const buttonNamed = (...patterns) => {
  for (const name of patterns) {
    const found = screen.queryAllByRole("button", { name });
    if (found.length === 1) return found[0];
  }
  throw new Error(`no single button named ${patterns.join(" or ")}`);
};
const nextButton = () => buttonNamed(/^Next$/);
const previousButton = () => buttonNamed(/^Prev$/, /^Previous$/);
const firstButton = () => buttonNamed(/^«$/, /^First page$/);
const lastButton = () => buttonNamed(/^»$/, /^Last page$/);

beforeEach(() => {
  user = ANALYST;
  scrolled = [];
  Element.prototype.scrollIntoView = vi.fn(function (options) {
    scrolled.push({ element: this, options });
  });
  getReply = (url) => {
    if (url.startsWith("/compliance/findings"))
      return { data: { data: EXCEPTIONS } };
    if (url.startsWith("/compliance/summary")) return { data: SUMMARY };
    if (url === "/compliance/marketplace") return { data: { data: [] } };
    return { data: { data: [] } };
  };
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url, config) => {
    const r = getReply(url, config);
    return r instanceof Promise ? r : Promise.resolve(r);
  });
  consoleError = vi.spyOn(console, "error");
});

afterEach(() => {
  cleanup();
  // Read-only: nothing is ever written, and every read is the marketplace, a
  // summary, or pending findings.
  expect(api.post).not.toHaveBeenCalled();
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const [url] of api.get.mock.calls) {
    expect(url).toMatch(
      /^\/compliance\/(marketplace|summary(\?[a-z0-9_=&]+)?|findings\?status=pending&limit=10000(&[a-z0-9_]+=[a-z0-9_]+)*)$/,
    );
  }
  consoleError.mockRestore();
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace Exceptions — contract", () => {
  describe("reading", () => {
    it("reads pending findings when the tab opens, and not before", async () => {
      await mount();
      expect(exceptionReads()).toHaveLength(0);
      await openExceptions();
      expect(exceptionReads()).toEqual([[EXCEPTIONS_URL]]);
    });

    it("reads again each time the tab is opened", async () => {
      await mount();
      await openExceptions();
      await openTab("Dashboard");
      await openExceptions();
      expect(exceptionReads()).toEqual([[EXCEPTIONS_URL], [EXCEPTIONS_URL]]);
    });

    it("a selected framework narrows the read, and changing it while open reads again", async () => {
      await mount();
      fireEvent.change(frameworkSelect(), {
        target: { value: "cfw_nist_csf_v2" },
      });
      await flush();
      await openExceptions();
      expect(exceptionReads().at(-1)).toEqual([
        `${EXCEPTIONS_URL}&framework_id=cfw_nist_csf_v2`,
      ]);
      fireEvent.change(frameworkSelect(), { target: { value: "all" } });
      await flush();
      expect(exceptionReads().at(-1)).toEqual([EXCEPTIONS_URL]);
      expect(exceptionReads()).toHaveLength(2);
    });

    it("a framework's scoping filter is carried into the read", async () => {
      getReply = (url) => {
        if (url.startsWith("/compliance/findings"))
          return { data: { data: EXCEPTIONS } };
        if (url.startsWith("/compliance/summary")) return { data: SUMMARY };
        if (url === "/compliance/marketplace")
          return {
            data: {
              data: [],
              active_framework_ids: ["cfw_iso27001_2022", "cfw_pci_dss_v4"],
            },
          };
        return { data: { data: [] } };
      };
      await mount();
      fireEvent.change(frameworkSelect(), {
        target: { value: "cfw_pci_dss_v4" },
      });
      await flush();
      await openExceptions();
      fireEvent.click(screen.getByRole("checkbox", { name: /CDE Scope Only/ }));
      await flush();
      expect(exceptionReads().at(-1)).toEqual([
        `${EXCEPTIONS_URL}&framework_id=cfw_pci_dss_v4&cde_scope_only=true`,
      ]);
    });
  });

  describe("the list", () => {
    it("lists each pending finding: control, asset or Global, the note before the reason, else a dash, and status", async () => {
      await mount();
      await openExceptions();
      /* P3-2 added "Decided by": a waiver is an accepted risk and the record
         of who accepted it is the point of the workflow. These fixtures carry
         no `approved_by`, so it renders as a dash — the decision has not been
         taken, which is not the same as nobody being named. The "Decision"
         column is permission-gated and absent here. */
      expect(rows()).toEqual([
        ["A.5.1", "asset-7", "Compensating control documented", "pending", "—"],
        ["A.8.2", "Global", "Legacy system, retired in Q4", "pending", "—"],
        ["A.8.8", "Global", "—", "pending", "—"],
      ]);
      const headers = [...table().querySelectorAll("thead th")].map(squash);
      expect(headers).toEqual([
        "Control ID",
        "Asset ID",
        "Waiver Reason",
        "Status",
        "Decided by",
      ]);
    });

    it.each([
      ["an empty list", { data: { data: [] } }],
      ["no list at all", { data: {} }],
    ])("with %s it says nothing is pending", async (_, reply) => {
      getReply = (url) =>
        url.startsWith("/compliance/findings")
          ? reply
          : url.startsWith("/compliance/summary")
            ? { data: SUMMARY }
            : { data: { data: [] } };
      await mount();
      await openExceptions();
      expect(bodyText()).toContain(
        "No pending exceptions or waivers recorded.",
      );
      expect(pageStatus()).toBe("Page 1 of 1");
    });

    it("the list is the same for an analyst and an organisation admin", async () => {
      await mount();
      await openExceptions();
      const asAnalyst = rows();
      cleanup();
      user = ORG_ADMIN;
      await mount();
      await openExceptions();
      expect(rows()).toEqual(asAnalyst);
    });
  });

  describe("paging", () => {
    beforeEach(() => {
      getReply = (url) =>
        url.startsWith("/compliance/findings")
          ? { data: { data: many(60) } }
          : url.startsWith("/compliance/summary")
            ? { data: SUMMARY }
            : { data: { data: [] } };
    });

    it("shows 25 at a time, and Next, Previous, first and last move between pages", async () => {
      await mount();
      await openExceptions();
      expect(firstColumn()).toHaveLength(25);
      expect(firstColumn()[0]).toBe("EX-01");
      expect(firstColumn()[24]).toBe("EX-25");
      expect(pageStatus()).toBe("Page 1 of 3");
      expect(bodyText()).toContain("Showing 1–25 of 60 waivers");
      expect(previousButton()).toBeDisabled();
      expect(firstButton()).toBeDisabled();

      fireEvent.click(nextButton());
      await flush();
      expect(pageStatus()).toBe("Page 2 of 3");
      expect(firstColumn()[0]).toBe("EX-26");
      expect(bodyText()).toContain("Showing 26–50 of 60 waivers");

      fireEvent.click(lastButton());
      await flush();
      expect(pageStatus()).toBe("Page 3 of 3");
      expect(firstColumn()).toEqual(
        many(60)
          .slice(50)
          .map((e) => e.control_id),
      );
      expect(nextButton()).toBeDisabled();
      expect(lastButton()).toBeDisabled();

      fireEvent.click(previousButton());
      await flush();
      expect(pageStatus()).toBe("Page 2 of 3");

      fireEvent.click(firstButton());
      await flush();
      expect(pageStatus()).toBe("Page 1 of 3");
      expect(firstColumn()[0]).toBe("EX-01");
    });

    it("offers 10, 25, 50 or 100 per page, and a change returns to page 1", async () => {
      await mount();
      await openExceptions();
      expect(sizeSelect()).toBeTruthy();
      expect(sizeSelect().value).toBe("25");
      fireEvent.click(nextButton());
      await flush();
      fireEvent.change(sizeSelect(), { target: { value: "10" } });
      await flush();
      expect(pageStatus()).toBe("Page 1 of 6");
      expect(firstColumn()).toHaveLength(10);
      expect(firstColumn()[0]).toBe("EX-01");
      fireEvent.change(sizeSelect(), { target: { value: "100" } });
      await flush();
      expect(pageStatus()).toBe("Page 1 of 1");
      expect(firstColumn()).toHaveLength(60);
    });

    it("a page change scrolls the list back into view", async () => {
      await mount();
      await openExceptions();
      expect(scrolled).toHaveLength(0);
      fireEvent.click(nextButton());
      await flush();
      expect(scrolled).toHaveLength(1);
      expect(scrolled[0].options).toEqual({
        behavior: "smooth",
        block: "start",
      });
      expect(scrolled[0].element.contains(table())).toBe(true);
    });

    it("fresh data returns the list to page 1", async () => {
      await mount();
      await openExceptions();
      fireEvent.click(nextButton());
      await flush();
      await openTab("Dashboard");
      await openExceptions();
      expect(pageStatus()).toBe("Page 1 of 3");
      expect(firstColumn()[0]).toBe("EX-01");
    });

    it("paging is disabled while the list reloads", async () => {
      await mount();
      await openExceptions();
      await openTab("Dashboard");
      const pending = deferred();
      getReply = (url) =>
        url.startsWith("/compliance/findings")
          ? pending.promise
          : url.startsWith("/compliance/summary")
            ? { data: SUMMARY }
            : { data: { data: [] } };
      await openExceptions();
      expect(nextButton()).toBeDisabled();
      expect(lastButton()).toBeDisabled();
      await act(async () => pending.resolve({ data: { data: many(60) } }));
      await flush();
      expect(nextButton()).toBeEnabled();
      expect(lastButton()).toBeEnabled();
    });
  });

  describe("a failed read", () => {
    it("shows the workspace's error, logs it, and lists nothing", async () => {
      const failure = {
        response: { data: { detail: "Findings store unavailable" } },
        message: "Request failed",
      };
      getReply = (url) =>
        url.startsWith("/compliance/findings")
          ? Promise.reject(failure)
          : url.startsWith("/compliance/summary")
            ? { data: SUMMARY }
            : { data: { data: [] } };
      consoleError.mockImplementation(() => {});
      await mount();
      await openExceptions();
      expect(bodyText()).toContain(
        "Connection or Database Error: Findings store unavailable",
      );
      expect(console.error).toHaveBeenCalledWith(
        "Failed to load compliance data",
        failure,
      );
      expect(bodyText()).toContain(
        "No pending exceptions or waivers recorded.",
      );
    });
  });

  describe("routes", () => {
    it("App.jsx mounts /compliance behind the base sign-in check only", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const baseAt = app.indexOf("<Route element={<PrivateRoute />}>");
      const firstGate = app.indexOf("requiredPermission", baseAt);
      const at = app.search(
        /<Route path="\/compliance" element=\{<ComplianceWorkspace \/>\} \/>/,
      );
      expect(at).toBeGreaterThan(baseAt);
      expect(at).toBeLessThan(firstGate);
      expect(app.match(/<ComplianceWorkspace\b/g)).toHaveLength(1);
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 26A — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const panel = () =>
  screen
    .getByRole("heading", { level: 2, name: "Exceptions" })
    .closest("section");

describe("ComplianceWorkspace Exceptions — batch 26a", () => {
  it("is a section headed Exceptions, listing a captioned table with scoped column headers and a row header per waiver", async () => {
    await mount();
    await openExceptions();
    const heading = screen.getByRole("heading", {
      level: 2,
      name: "Exceptions",
    });
    const section = panel();
    expect(section.getAttribute("aria-labelledby")).toBe(heading.id);
    expect(squash(table().querySelector("caption"))).toBe(
      "Pending exceptions and waivers",
    );
    for (const th of table().querySelectorAll("thead th"))
      expect(th.getAttribute("scope")).toBe("col");
    expect(
      [...table().querySelectorAll("tbody th[scope=row]")].map(squash),
    ).toEqual(["A.5.1", "A.8.2", "A.8.8"]);
  });

  it("shows each status as a badge", async () => {
    await mount();
    await openExceptions();
    const badges = [...panel().querySelectorAll(".cc-badge")].map(squash);
    expect(badges).toEqual(["pending", "pending", "pending"]);
  });

  it("pages through a named navigation with a live page status, a labelled page size and named first and last page buttons", async () => {
    getReply = (url) =>
      url.startsWith("/compliance/findings")
        ? { data: { data: many(60) } }
        : url.startsWith("/compliance/summary")
          ? { data: SUMMARY }
          : { data: { data: [] } };
    await mount();
    await openExceptions();
    const nav = screen.getByRole("navigation", {
      name: "Exceptions pagination",
    });
    expect(squash(within(nav).getByRole("status"))).toBe("Page 1 of 3");
    const size = within(panel()).getByLabelText("Rows per page");
    expect([...size.options].map((o) => o.value)).toEqual([
      "10",
      "25",
      "50",
      "100",
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Last page" }));
    await flush();
    expect(squash(within(nav).getByRole("status"))).toBe("Page 3 of 3");
    expect(screen.getByRole("button", { name: "First page" })).toBeEnabled();
  });

  it("while reloading, shows placeholder rows and announces loading rather than claiming nothing is pending", async () => {
    await mount();
    await openExceptions();
    await openTab("Dashboard");
    const pending = deferred();
    getReply = (url) =>
      url.startsWith("/compliance/findings")
        ? pending.promise
        : url.startsWith("/compliance/summary")
          ? { data: SUMMARY }
          : { data: { data: [] } };
    await openExceptions();
    expect(panel().querySelectorAll(".cc-skeleton").length).toBeGreaterThan(0);
    expect(squash(panel())).not.toContain("No pending exceptions");
    expect(within(panel()).getAllByRole("status").map(squash)).toContain(
      "Loading results",
    );
    await act(async () => pending.resolve({ data: { data: EXCEPTIONS } }));
    await flush();
  });

  it("renders no inline style and no legacy class inside the tab", async () => {
    await mount();
    await openExceptions();
    const section = panel();
    expect([...section.querySelectorAll("[style]")]).toEqual([]);
    const classes = [...section.querySelectorAll("[class]")].flatMap((el) => [
      ...el.classList,
    ]);
    expect(
      classes.filter((c) => /^(db-|cw-pagination|mono$|loading-bar)/.test(c)),
    ).toEqual([]);
  });

  it("the tab's source uses design-system parts and its stylesheet is token-only", () => {
    const source = readFileSync(
      path.join(SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-exceptions\.css["']/,
    );
    expect(source).toMatch(/from\s+["']\.\.\/design-system["']/);
    const start = source.indexOf("function ExceptionsPanel(");
    expect(start).toBeGreaterThan(-1);
    const block = source.slice(start, source.indexOf("\n}\n", start));
    expect(block).not.toMatch(/style=\{/);
    expect(block.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(block).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
    expect(block).not.toMatch(/className="(db-|cw-pagination|mono\b)/);
    expect(block).toMatch(/<CcureTable\b/);
    expect(block).toMatch(/<CcurePagination\b/);
    const render = source.slice(
      source.indexOf('{activeTab === "exceptions" && ('),
      source.indexOf('{activeTab === "credentials" && ('),
    );
    expect(render).toMatch(/<ExceptionsPanel\b/);
    expect(render).not.toMatch(/style=\{|<table\b|<PaginationBar\b/);

    const cssPath = path.join(SRC, "styles/compliance-exceptions.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)[a-z0-9-]+/g) || []).toEqual([]);
    expect(css).not.toMatch(/prefers-color-scheme|ux4g/i);
    expect(css).toMatch(/@media \(max-width: 640px\)/);
    // Scoped: every selector names the tab's own prefix.
    const selectors = css
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .split("{")
      .slice(0, -1)
      .map((s) => s.split("}").pop().trim())
      .filter((s) => s && !s.startsWith("@"));
    for (const s of selectors) expect(s).toMatch(/\.cwx-/);
  });
});
