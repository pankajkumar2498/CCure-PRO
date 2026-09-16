/**
 * AMTIntegration (`/admin/amt`) — Checkpoint 3C batch 20 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 20 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The page reads coverage statistics (GET /assets/coverage-stats) and, for a
 * selected category, a paged reconciliation drilldown
 * (GET /assets/reconciliation/drilldown). The same endpoint with
 * `export: true` returns a CSV blob that the page saves as
 * `amt_${category}_export.csv`.
 *
 * Its one write is the inventory import: POST /assets/import-amt with a single
 * multipart field, `file`. The server REPLACES the organisation's AMT
 * inventory with the file's contents, so everything that decides whether and
 * what is sent is pinned here: the client-side checks and their exact
 * messages, that nothing is sent until the form is submitted, the request
 * shape, and what follows success (the file clears; statistics reload
 * 1.5 seconds later) and failure. There is no confirmation step.
 *
 * The API wrappers in `api/assets.js` are real and only the axios instance is
 * mocked, so endpoints, parameters, `responseType` and headers are asserted as
 * they leave the application.
 *
 * The route is gated on `assets:update` in App.jsx; the page itself checks no
 * permission.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import AMTIntegration from "../../../pages/admin/AMTIntegration";
import PrivateRoute from "../../../components/auth/PrivateRoute";
import AuthContext from "../../../context/AuthContext";
import api from "../../../api/axiosInstance";

vi.mock("../../../api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

const STATS_PATH = "/assets/coverage-stats";
const DRILL_PATH = "/assets/reconciliation/drilldown";
const IMPORT_PATH = "/assets/import-amt";

/* Field names are the page's reads, checked against the backend:
   `/assets/coverage-stats` returns these seven keys, and the drilldown returns
   `{ data, total }` with Asset rows for scanned / matched / shadow_it and AMT
   inventory records for inventory / coverage_gap. */
const STATS = {
  configured: true,
  total_scanned: 40,
  total_inventory: 50,
  fully_audited: 36,
  shadow_it: 4,
  coverage_gap: 14,
  coverage_percentage: 72,
};

const UNCONFIGURED = {
  configured: false,
  total_scanned: 40,
  total_inventory: 0,
  fully_audited: 0,
  shadow_it: 40,
  coverage_gap: 0,
  coverage_percentage: 0,
};

const ASSET_ROWS = [
  {
    id: "a-1",
    hostname: "files-01",
    ip_address: "10.20.0.11",
    mac_address: "00:1A:2B:3C:4D:11",
    first_seen_at: "2026-08-01T09:00:00Z",
    risk_score: 82,
    risk_level: "high",
    owner: "alice",
  },
  {
    id: "a-2",
    hostname: null,
    ip_address: null,
    mac_address: null,
    first_seen_at: null,
    risk_score: 12,
    risk_level: "low",
    owner: null,
  },
];

const INVENTORY_ROWS = [
  {
    id: "i-1",
    asset_tag: "TAG-001",
    asset_name: "Finance Laptop",
    serial: "SN-001",
    vendor: "Dell",
    asset_type: "Laptop",
    asset_user: "bob",
    status: "In Use",
    location: "Pune",
    company_name: "Finance",
  },
  {
    id: "i-2",
    asset_tag: null,
    asset_name: null,
    serial: null,
    vendor: null,
    asset_type: null,
    asset_user: null,
    status: null,
    location: null,
    company_name: null,
  },
];

const INVENTORY_CATEGORIES = ["inventory", "coverage_gap"];

let statsReply;
let drillReply;
let exportReply;
let importReply;
let saved;
let downloads;
let realCreateObjectURL;
let realRevokeObjectURL;

beforeEach(() => {
  vi.clearAllMocks();
  statsReply = () => Promise.resolve({ data: STATS });
  drillReply = (config) =>
    Promise.resolve({
      data: {
        data: INVENTORY_CATEGORIES.includes(config.params.category)
          ? INVENTORY_ROWS
          : ASSET_ROWS,
        total: 23,
      },
    });
  exportReply = () => Promise.resolve({ data: "ID,Hostname\na-1,files-01\n" });
  importReply = () => Promise.resolve({ data: { success: true } });

  api.get.mockImplementation((url, config) => {
    if (url === STATS_PATH) return statsReply(config);
    if (url === DRILL_PATH) {
      return config?.params?.export ? exportReply(config) : drillReply(config);
    }
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
  api.post.mockImplementation((url, body, config) =>
    url === IMPORT_PATH
      ? importReply(body, config)
      : Promise.reject(new Error(`unexpected POST ${url}`)),
  );

  saved = [];
  downloads = [];
  realCreateObjectURL = window.URL.createObjectURL;
  realRevokeObjectURL = window.URL.revokeObjectURL;
  window.URL.createObjectURL = vi.fn((blob) => {
    saved.push(blob);
    return "blob:harness/amt-export";
  });
  window.URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
    function click() {
      downloads.push({
        href: this.getAttribute("href"),
        download: this.getAttribute("download"),
        attached: document.body.contains(this),
      });
    },
  );
});

afterEach(() => {
  // The import is the page's only write, and only ever to its own endpoint.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls) expect(url).toBe(IMPORT_PATH);
  vi.useRealTimers();
  vi.restoreAllMocks();
  window.URL.createObjectURL = realCreateObjectURL;
  window.URL.revokeObjectURL = realRevokeObjectURL;
});

/* ── Helpers ──────────────────────────────────────────────────────────────── */

const statsCalls = () => api.get.mock.calls.filter(([u]) => u === STATS_PATH);
const drillCalls = () =>
  api.get.mock.calls.filter(([u, c]) => u === DRILL_PATH && !c?.params?.export);
const exportCalls = () =>
  api.get.mock.calls.filter(([u, c]) => u === DRILL_PATH && c?.params?.export);
const lastDrill = () => drillCalls().at(-1);

// Resolves pending promise chains without depending on real or fake timers.
const settle = () =>
  act(async () => {
    for (let i = 0; i < 6; i += 1) await Promise.resolve();
  });

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/admin/amt"]}>
      <AMTIntegration />
    </MemoryRouter>,
  );

const refreshButton = () =>
  screen.getByRole("button", { name: /Refresh Stats/ });

const loaded = async () => {
  renderPage();
  await settle();
  expect(refreshButton()).toBeEnabled();
};

// The visible label of each category control, legacy markup and migrated
// alike: the click lands on the label and bubbles to whatever owns it.
const CATEGORY = {
  scanned: /^Total Scanned Devices:?$/,
  inventory: /^AMT Inventory Records:?$/,
  matched: /^Fully Audited \(Scanned & Configured\):?$/,
  shadow_it: /^Shadow IT \(Unmanaged Rogue\):?$/,
  coverage_gap: /^Coverage Gap \(Offline \/ Firewall\):?$/,
};

const HEADINGS = {
  scanned: [
    "Total Scanned Devices",
    "Devices discovered during active network scanning.",
  ],
  inventory: [
    "AMT Inventory Records",
    "All records imported from the corporate inventory file.",
  ],
  matched: [
    "Fully Audited Assets",
    "Assets verified in both active scans and corporate inventory reference.",
  ],
  shadow_it: [
    "Shadow IT Devices",
    "Unmanaged rogue devices found in scans but missing from AMT inventory.",
  ],
  coverage_gap: [
    "Coverage Gap Assets",
    "Official inventory devices that have not been detected in any active scans.",
  ],
};

const ASSET_HEADERS = [
  "Hostname",
  "IP Address",
  "MAC Address",
  "First Seen",
  "Risk Score",
  "Owner",
];
const INVENTORY_HEADERS = [
  "Asset Tag",
  "Asset Name",
  "Serial",
  "Vendor",
  "Asset Type",
  "Owner/User",
  "Status",
  "Location",
  "Department",
];

const choose = async (u, category) => {
  await u.click(screen.getByText(CATEGORY[category]));
  await settle();
};

const coverageSummary = () => screen.getByText(/inventory assets\s+matched\./);

const searchBox = () =>
  screen.getByPlaceholderText("Search Hostname, IP, MAC, Serial...");
const ownerBox = () => screen.getByPlaceholderText("Filter by Owner...");
const deptBox = () => screen.getByPlaceholderText("Filter by Department...");
const locBox = () => screen.getByPlaceholderText("Filter by Location...");

const exportButton = () => screen.getByRole("button", { name: /Export CSV/ });
const previousButton = () => screen.getByRole("button", { name: /Previous/ });
const nextButton = () => screen.getByRole("button", { name: /Next/ });

const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const textShown = (text) =>
  screen.queryAllByText(
    (_, el) =>
      squash(el) === text &&
      ![...(el?.children || [])].some((c) => squash(c) === text),
  ).length > 0;

const headerTexts = () =>
  screen.getAllByRole("columnheader").map((th) => squash(th));
const bodyRows = () => {
  const table = screen.getByRole("table");
  return within(table)
    .getAllByRole("row")
    .filter((r) => !r.closest("thead"));
};

const MB = 1024 * 1024;
const jsonFile = (name = "assets.json", size) => {
  const file = new File(['{"data":[]}'], name, { type: "application/json" });
  if (size !== undefined) Object.defineProperty(file, "size", { value: size });
  return file;
};
const fileInput = () => document.querySelector('input[type="file"]');
const pick = (file) =>
  fireEvent.change(fileInput(), { target: { files: [file] } });
// The drop target owns the file input in both markups.
const dropZone = () => fileInput().parentElement;
const drop = (file) =>
  fireEvent.drop(dropZone(), { dataTransfer: { files: [file] } });
const submitButton = () =>
  screen.getByRole("button", {
    name: /Upload & Sync Inventory|Uploading & Syncing/,
  });

/* ════════════════════════════════════════════════════════════════════════════
   Contract — must pass on the legacy page and after migration.
   ════════════════════════════════════════════════════════════════════════════ */

describe("AMTIntegration — contract", () => {
  describe("statistics", () => {
    it("loads coverage statistics once on mount and writes nothing", async () => {
      await loaded();
      expect(api.get.mock.calls).toEqual([[STATS_PATH, { params: {} }]]);
      expect(api.post).not.toHaveBeenCalled();
    });

    it("disables Refresh Stats while loading, and reloads the same statistics on request", async () => {
      let release;
      statsReply = () =>
        new Promise((resolve) => {
          release = () => resolve({ data: STATS });
        });
      renderPage();
      await settle();
      expect(refreshButton()).toBeDisabled();
      await act(async () => release());
      await settle();
      expect(refreshButton()).toBeEnabled();

      statsReply = () => Promise.resolve({ data: STATS });
      await userEvent.setup().click(refreshButton());
      await settle();
      expect(statsCalls()).toEqual([
        [STATS_PATH, { params: {} }],
        [STATS_PATH, { params: {} }],
      ]);
    });

    it("summarises a linked inventory", async () => {
      await loaded();
      expect(
        screen.getByText("Inventory linked successfully"),
      ).toBeInTheDocument();
      expect(screen.getByText("Linked & Active")).toBeInTheDocument();
      expect(screen.getByText("72%")).toBeInTheDocument();
      expect(textShown("36 of 50 inventory assets matched.")).toBe(true);
      for (const value of ["40", "50", "4", "14"]) {
        expect(screen.getAllByText(value).length).toBeGreaterThan(0);
      }
      for (const re of Object.values(CATEGORY)) {
        expect(screen.getByText(re)).toBeInTheDocument();
      }
    });

    it("offers no categories while no inventory is linked", async () => {
      statsReply = () => Promise.resolve({ data: UNCONFIGURED });
      await loaded();
      expect(
        screen.getByText("No active inventory file linked"),
      ).toBeInTheDocument();
      expect(screen.getByText("CMDB Integration Inactive")).toBeInTheDocument();
      expect(screen.queryByText("Linked & Active")).toBeNull();
      for (const re of Object.values(CATEGORY)) {
        expect(screen.queryByText(re)).toBeNull();
      }
      expect(drillCalls()).toHaveLength(0);
    });

    it("reports a failed load", async () => {
      statsReply = () => Promise.reject(new Error("boom"));
      await loaded();
      expect(
        screen.getByText("Failed to load inventory coverage statistics."),
      ).toBeInTheDocument();
      expect(screen.getByText("CMDB Integration Inactive")).toBeInTheDocument();
    });
  });

  describe("categories and the drilldown", () => {
    it("selecting a category requests its first page, ten rows, with no optional filters", async () => {
      const u = userEvent.setup();
      await loaded();
      await choose(u, "shadow_it");
      expect(drillCalls()).toEqual([
        [DRILL_PATH, { params: { category: "shadow_it", skip: 0, limit: 10 } }],
      ]);
    });

    it("each category control, and the coverage summary, selects its own category", async () => {
      const u = userEvent.setup();
      await loaded();
      for (const category of [
        "scanned",
        "inventory",
        "matched",
        "shadow_it",
        "coverage_gap",
      ]) {
        await choose(u, category);
        expect(lastDrill()[1].params.category).toBe(category);
      }
      await u.click(coverageSummary());
      await settle();
      expect(lastDrill()[1].params.category).toBe("matched");
      expect(drillCalls()).toHaveLength(6);
    });

    it("selecting the open category again closes the drilldown without a request", async () => {
      const u = userEvent.setup();
      await loaded();
      await choose(u, "scanned");
      expect(
        screen.getByRole("heading", { name: "Total Scanned Devices (23)" }),
      ).toBeInTheDocument();
      await choose(u, "scanned");
      expect(
        screen.queryByRole("heading", { name: /Total Scanned Devices \(/ }),
      ).toBeNull();
      expect(screen.queryByRole("button", { name: /Export CSV/ })).toBeNull();
      expect(drillCalls()).toHaveLength(1);
    });

    it("titles and describes each category with its total", async () => {
      const u = userEvent.setup();
      await loaded();
      for (const [category, [title, description]] of Object.entries(HEADINGS)) {
        await choose(u, category);
        expect(
          screen.getByRole("heading", { name: `${title} (23)` }),
        ).toBeInTheDocument();
        expect(screen.getByText(description)).toBeInTheDocument();
      }
    });

    it("sends each filter as typed, only when it is set, one request per keystroke, from page one", async () => {
      const u = userEvent.setup();
      await loaded();
      await choose(u, "scanned");
      await u.click(nextButton());
      await settle();
      expect(lastDrill()[1].params.skip).toBe(10);

      const before = drillCalls().length;
      await u.type(searchBox(), "fi");
      await settle();
      expect(drillCalls()).toHaveLength(before + 2);
      expect(lastDrill()).toEqual([
        DRILL_PATH,
        { params: { category: "scanned", search: "fi", skip: 0, limit: 10 } },
      ]);

      await u.type(ownerBox(), " a");
      await u.type(deptBox(), "IT");
      await u.type(locBox(), "Pune");
      await settle();
      expect(lastDrill()).toEqual([
        DRILL_PATH,
        {
          params: {
            category: "scanned",
            search: "fi",
            owner: " a",
            department: "IT",
            location: "Pune",
            skip: 0,
            limit: 10,
          },
        },
      ]);

      await u.clear(searchBox());
      await u.clear(ownerBox());
      await settle();
      expect(lastDrill()).toEqual([
        DRILL_PATH,
        {
          params: {
            category: "scanned",
            department: "IT",
            location: "Pune",
            skip: 0,
            limit: 10,
          },
        },
      ]);
    });

    it("changing category returns to page one and clears every filter", async () => {
      const u = userEvent.setup();
      await loaded();
      await choose(u, "scanned");
      await u.type(searchBox(), "x");
      await u.type(ownerBox(), "o");
      await u.type(deptBox(), "d");
      await u.type(locBox(), "l");
      await u.click(nextButton());
      await settle();
      expect(lastDrill()[1].params).toMatchObject({ skip: 10, search: "x" });

      const before = drillCalls().length;
      await choose(u, "inventory");
      expect(drillCalls()).toHaveLength(before + 1);
      expect(lastDrill()).toEqual([
        DRILL_PATH,
        { params: { category: "inventory", skip: 0, limit: 10 } },
      ]);
      for (const box of [searchBox(), ownerBox(), deptBox(), locBox()]) {
        expect(box).toHaveValue("");
      }
    });

    it("pages through the results ten at a time", async () => {
      const u = userEvent.setup();
      await loaded();
      await choose(u, "matched");
      expect(textShown("Showing 1 to 10 of 23 entries")).toBe(true);
      expect(previousButton()).toBeDisabled();

      await u.click(nextButton());
      await settle();
      expect(lastDrill()[1].params).toEqual({
        category: "matched",
        skip: 10,
        limit: 10,
      });
      expect(textShown("Showing 11 to 20 of 23 entries")).toBe(true);

      await u.click(nextButton());
      await settle();
      expect(lastDrill()[1].params.skip).toBe(20);
      expect(textShown("Showing 21 to 23 of 23 entries")).toBe(true);
      expect(nextButton()).toBeDisabled();

      await u.click(previousButton());
      await settle();
      expect(lastDrill()[1].params.skip).toBe(10);
    });

    it("shows no page controls when every result fits on one page", async () => {
      drillReply = () =>
        Promise.resolve({ data: { data: ASSET_ROWS, total: 2 } });
      const u = userEvent.setup();
      await loaded();
      await choose(u, "scanned");
      expect(screen.queryByRole("button", { name: /Next/ })).toBeNull();
      expect(screen.queryByText(/^Showing/)).toBeNull();
    });

    it("lists assets with links to the asset, and inventory records without links", async () => {
      const u = userEvent.setup();
      await loaded();

      for (const category of ["scanned", "matched", "shadow_it"]) {
        await choose(u, category);
        expect(headerTexts()).toEqual(ASSET_HEADERS);
      }
      const [first, second] = bodyRows();
      const cells = within(first).getAllByRole("cell");
      expect(cells.map(squash)).toEqual([
        "files-01",
        "10.20.0.11",
        "00:1A:2B:3C:4D:11",
        new Date("2026-08-01T09:00:00Z").toLocaleDateString(),
        "82 (high)",
        "alice",
      ]);
      expect(
        within(first)
          .getAllByRole("link")
          .map((a) => [squash(a), a.getAttribute("href")]),
      ).toEqual([
        ["files-01", "/assets/a-1"],
        ["10.20.0.11", "/assets/a-1"],
      ]);
      expect(within(second).getAllByRole("cell").map(squash)).toEqual([
        "—",
        "—",
        "—",
        "—",
        "12 (low)",
        "—",
      ]);
      expect(
        within(second)
          .getAllByRole("link")
          .map((a) => a.getAttribute("href")),
      ).toEqual(["/assets/a-2", "/assets/a-2"]);

      for (const category of ["inventory", "coverage_gap"]) {
        await choose(u, category);
        expect(headerTexts()).toEqual(INVENTORY_HEADERS);
      }
      const [record, blank] = bodyRows();
      // "Department" shows the record's company_name.
      expect(within(record).getAllByRole("cell").map(squash)).toEqual([
        "TAG-001",
        "Finance Laptop",
        "SN-001",
        "Dell",
        "Laptop",
        "bob",
        "In Use",
        "Pune",
        "Finance",
      ]);
      expect(within(blank).getAllByRole("cell").map(squash)).toEqual(
        Array(9).fill("—"),
      );
      expect(within(screen.getByRole("table")).queryAllByRole("link")).toEqual(
        [],
      );
    });

    it("shows loading, failure and empty drilldowns", async () => {
      const u = userEvent.setup();
      drillReply = () => new Promise(() => {});
      await loaded();
      await choose(u, "scanned");
      expect(screen.getByText("Loading asset details...")).toBeInTheDocument();
      expect(exportButton()).toBeDisabled();

      drillReply = () => Promise.reject(new Error("boom"));
      await choose(u, "inventory");
      expect(
        screen.getByText("Failed to load drilldown details."),
      ).toBeInTheDocument();

      drillReply = () => Promise.resolve({ data: { data: [], total: 0 } });
      await choose(u, "shadow_it");
      expect(
        screen.getByText("No assets match the current filters."),
      ).toBeInTheDocument();
      expect(exportButton()).toBeDisabled();
    });
  });

  describe("export", () => {
    it("offers no export, and requests none, until a category is selected", async () => {
      await loaded();
      expect(screen.queryByRole("button", { name: /Export CSV/ })).toBeNull();
      expect(exportCalls()).toHaveLength(0);
    });

    it("exports the category with its filters, never its page, as a CSV blob named amt_{category}_export.csv", async () => {
      const u = userEvent.setup();
      await loaded();
      await choose(u, "shadow_it");
      await u.type(searchBox(), "q");
      await u.type(deptBox(), "IT");
      await u.click(nextButton());
      await settle();

      await u.click(exportButton());
      await settle();

      expect(exportCalls()).toEqual([
        [
          DRILL_PATH,
          {
            params: {
              category: "shadow_it",
              search: "q",
              department: "IT",
              export: true,
            },
            responseType: "blob",
          },
        ],
      ]);
      expect(window.URL.createObjectURL).toHaveBeenCalledTimes(1);
      expect(saved[0]).toBeInstanceOf(Blob);
      expect(saved[0].type).toBe("text/csv");
      const content = await new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.readAsText(saved[0]);
      });
      expect(content).toBe("ID,Hostname\na-1,files-01\n");
      expect(downloads).toEqual([
        {
          href: "blob:harness/amt-export",
          download: "amt_shadow_it_export.csv",
          attached: true,
        },
      ]);
      expect(document.querySelectorAll("a[download]")).toHaveLength(0);
      // As found: the object URL is never revoked.
      expect(window.URL.revokeObjectURL).not.toHaveBeenCalled();
      expect(exportButton()).toBeEnabled();
    });

    it("disables export while exporting", async () => {
      let release;
      exportReply = () =>
        new Promise((resolve) => {
          release = () => resolve({ data: "x" });
        });
      const u = userEvent.setup();
      await loaded();
      await choose(u, "scanned");
      await u.click(exportButton());
      await settle();
      const busy = screen.getByRole("button", { name: /Exporting CSV/ });
      expect(busy).toBeDisabled();
      await act(async () => release());
      await settle();
      expect(exportButton()).toBeEnabled();
    });

    it("logs a failed export and shows nothing", async () => {
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      exportReply = () => Promise.reject(new Error("export boom"));
      const u = userEvent.setup();
      await loaded();
      await choose(u, "scanned");
      await u.click(exportButton());
      await settle();
      expect(error).toHaveBeenCalledWith("Export failed:", expect.any(Error));
      expect(downloads).toEqual([]);
      expect(
        screen.queryByText(/export/i, { selector: "[role=alert]" }),
      ).toBeNull();
      expect(exportButton()).toBeEnabled();
    });
  });

  describe("import", () => {
    it("accepts a .json file of up to 16 MB, in any letter case, and sends nothing on selection", async () => {
      await loaded();
      expect(submitButton()).toBeDisabled();
      const file = jsonFile("INVENTORY.JSON", 16 * MB);
      pick(file);
      await settle();
      expect(screen.getByText("INVENTORY.JSON")).toBeInTheDocument();
      expect(screen.getByText("16384.0 KB")).toBeInTheDocument();
      expect(submitButton()).toBeEnabled();
      expect(api.post).not.toHaveBeenCalled();
      expect(api.get.mock.calls).toHaveLength(1);
    });

    it("refuses a file that is not .json, with the exact message, and clears the selection", async () => {
      await loaded();
      pick(jsonFile());
      await settle();
      expect(screen.getByText("assets.json")).toBeInTheDocument();

      pick(jsonFile("assets.csv"));
      await settle();
      expect(
        screen.getByText(
          "Unsupported file format: assets.csv. The AMT inventory must be a .json export.",
        ),
      ).toBeInTheDocument();
      expect(screen.queryByText("assets.json")).toBeNull();
      expect(
        screen.getByText("Drag & Drop assets.json here"),
      ).toBeInTheDocument();
      expect(submitButton()).toBeDisabled();
    });

    it("refuses an empty file", async () => {
      await loaded();
      pick(jsonFile("empty.json", 0));
      await settle();
      expect(screen.getByText("empty.json is empty.")).toBeInTheDocument();
      expect(submitButton()).toBeDisabled();
    });

    it("refuses a file above 16 MB", async () => {
      await loaded();
      pick(jsonFile("big.json", 16 * MB + 1));
      await settle();
      expect(
        screen.getByText("big.json is 16.0 MB, above the 16 MB limit."),
      ).toBeInTheDocument();
      expect(submitButton()).toBeDisabled();
    });

    it("applies the same checks to a dropped file, and a drop sends nothing", async () => {
      await loaded();
      expect(fireEvent.dragOver(dropZone())).toBe(false);

      drop(jsonFile("notes.txt"));
      await settle();
      expect(
        screen.getByText(
          "Unsupported file format: notes.txt. The AMT inventory must be a .json export.",
        ),
      ).toBeInTheDocument();

      drop(jsonFile("dropped.json"));
      await settle();
      expect(screen.getByText("dropped.json")).toBeInTheDocument();
      expect(screen.queryByText(/Unsupported file format/)).toBeNull();
      expect(submitButton()).toBeEnabled();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("submits the file as the multipart field `file` to POST /assets/import-amt, once, on submit", async () => {
      await loaded();
      const file = jsonFile();
      pick(file);
      await settle();
      expect(api.post).not.toHaveBeenCalled();

      fireEvent.click(submitButton());
      await settle();

      expect(api.post).toHaveBeenCalledTimes(1);
      const [url, body, config] = api.post.mock.calls[0];
      expect(url).toBe(IMPORT_PATH);
      expect(body).toBeInstanceOf(FormData);
      expect([...body.keys()]).toEqual(["file"]);
      expect(body.get("file")).toBe(file);
      expect(config).toEqual({
        headers: { "Content-Type": "multipart/form-data" },
        params: {},
      });
    });

    it("shows the upload in progress and cannot be submitted twice", async () => {
      let release;
      importReply = () =>
        new Promise((resolve) => {
          release = () => resolve({ data: { success: true } });
        });
      await loaded();
      pick(jsonFile());
      await settle();
      fireEvent.click(submitButton());
      await settle();
      expect(submitButton()).toBeDisabled();
      expect(submitButton()).toHaveTextContent("Uploading & Syncing...");
      fireEvent.click(submitButton());
      await settle();
      expect(api.post).toHaveBeenCalledTimes(1);
      await act(async () => release());
      await settle();
    });

    it("after success, clears the file, confirms, and reloads statistics 1.5 seconds later", async () => {
      await loaded();
      vi.useFakeTimers();
      pick(jsonFile());
      await settle();
      fireEvent.click(submitButton());
      await settle();

      expect(
        screen.getByText(
          /Inventory file successfully uploaded! Reconciliation is running in the background\./,
        ),
      ).toBeInTheDocument();
      expect(
        screen.getByText("Drag & Drop assets.json here"),
      ).toBeInTheDocument();
      expect(submitButton()).toBeDisabled();
      expect(submitButton()).toHaveTextContent("Upload & Sync Inventory");
      expect(statsCalls()).toHaveLength(1);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(1499);
      });
      expect(statsCalls()).toHaveLength(1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1);
      });
      await settle();
      expect(statsCalls()).toEqual([
        [STATS_PATH, { params: {} }],
        [STATS_PATH, { params: {} }],
      ]);
      expect(api.post).toHaveBeenCalledTimes(1);
    });

    it("a response without success shows its detail or a default, keeps the file and reloads nothing", async () => {
      await loaded();
      vi.useFakeTimers();

      importReply = () =>
        Promise.resolve({ data: { success: false, detail: "No usable MAC." } });
      pick(jsonFile());
      await settle();
      fireEvent.click(submitButton());
      await settle();
      expect(screen.getByText("No usable MAC.")).toBeInTheDocument();
      expect(screen.getByText("assets.json")).toBeInTheDocument();
      expect(submitButton()).toBeEnabled();

      importReply = () => Promise.resolve({ data: {} });
      fireEvent.click(submitButton());
      await settle();
      expect(screen.getByText("Import failed.")).toBeInTheDocument();

      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
      expect(statsCalls()).toHaveLength(1);
      expect(
        screen.queryByText(/Inventory file successfully uploaded/),
      ).toBeNull();
    });

    it("a rejected upload shows the API's detail or a default", async () => {
      await loaded();
      importReply = () =>
        Promise.reject({ response: { data: { detail: "File too large." } } });
      pick(jsonFile());
      await settle();
      fireEvent.click(submitButton());
      await settle();
      expect(screen.getByText("File too large.")).toBeInTheDocument();

      importReply = () => Promise.reject(new Error("network"));
      fireEvent.click(submitButton());
      await settle();
      expect(
        screen.getByText("An error occurred during file upload."),
      ).toBeInTheDocument();
      expect(screen.getByText("assets.json")).toBeInTheDocument();
      expect(statsCalls()).toHaveLength(1);
    });

    it("choosing another file hides an earlier confirmation or error", async () => {
      await loaded();
      pick(jsonFile());
      await settle();
      fireEvent.click(submitButton());
      await settle();
      expect(
        screen.getByText(/Inventory file successfully uploaded/),
      ).toBeInTheDocument();

      pick(jsonFile("next.json"));
      await settle();
      expect(
        screen.queryByText(/Inventory file successfully uploaded/),
      ).toBeNull();

      pick(jsonFile("bad.xml"));
      await settle();
      expect(
        screen.getByText(/Unsupported file format: bad\.xml/),
      ).toBeInTheDocument();
      pick(jsonFile("good.json"));
      await settle();
      expect(screen.queryByText(/Unsupported file format/)).toBeNull();
    });
  });

  describe("route permission", () => {
    it("App.jsx mounts the page once, behind assets:update", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const gate = app.match(
        /<Route\s+element=\{\s*<PrivateRoute\s+requiredPermission=\{\{\s*resource:\s*"([a-z_]+)",\s*action:\s*"([a-z_]+)",?\s*\}\}\s*\/>\s*\}\s*>\s*<Route\s+path="\/admin\/amt"\s+element=\{<AMTIntegration\s*\/>\}\s*\/>\s*<\/Route>/,
      );
      expect(gate?.slice(1)).toEqual(["assets", "update"]);
      expect(app.match(/<AMTIntegration\b/g)).toHaveLength(1);
    });

    const guarded = (permissions) =>
      render(
        <AuthContext.Provider
          value={{
            loading: false,
            authState: "authenticated",
            user: { role: { name: "analyst", permissions } },
          }}
        >
          <MemoryRouter initialEntries={["/admin/amt"]}>
            <Routes>
              <Route
                element={
                  <PrivateRoute
                    requiredPermission={{
                      resource: "assets",
                      action: "update",
                    }}
                  />
                }
              >
                <Route path="/admin/amt" element={<AMTIntegration />} />
              </Route>
              <Route path="/dashboard" element={<div>Fallback page</div>} />
              <Route path="/login" element={<div>Login page</div>} />
            </Routes>
          </MemoryRouter>
        </AuthContext.Provider>,
      );

    it("without assets:update the page never mounts and nothing is requested", async () => {
      guarded(["assets:read", "scans:execute"]);
      await settle();
      expect(screen.getByText("Fallback page")).toBeInTheDocument();
      expect(api.get).not.toHaveBeenCalled();
    });

    it("with assets:update the page mounts and loads its statistics", async () => {
      guarded(["assets:read", "assets:update"]);
      await settle();
      expect(screen.queryByText("Fallback page")).toBeNull();
      expect(statsCalls()).toHaveLength(1);
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 20 — the specification. Every test here fails on the legacy page.
   ════════════════════════════════════════════════════════════════════════════ */

describe("AMTIntegration — batch 20", () => {
  it("has one level-one heading", async () => {
    await loaded();
    const h1 = screen.getAllByRole("heading", { level: 1 });
    expect(h1).toHaveLength(1);
    expect(h1[0]).toHaveTextContent("AMT Integration & Reconciliation");
  });

  it("makes every category a button that states whether it is selected", async () => {
    const u = userEvent.setup();
    await loaded();
    const button = (category) =>
      screen.getByRole("button", {
        name: new RegExp(CATEGORY[category].source.replace(/:\?\$$/, "")),
      });
    for (const category of Object.keys(CATEGORY)) {
      expect(button(category)).toHaveAttribute("aria-pressed", "false");
    }
    await u.click(button("shadow_it"));
    await settle();
    expect(button("shadow_it")).toHaveAttribute("aria-pressed", "true");
    expect(button("scanned")).toHaveAttribute("aria-pressed", "false");
  });

  it("describes Shadow IT and Coverage Gap to assistive technology, not only in a tooltip", async () => {
    await loaded();
    expect(
      screen.getByRole("button", { name: /^Shadow IT \(Unmanaged Rogue\)/ }),
    ).toHaveAccessibleDescription(
      "Discovered during active scans, but not present in your official AMT inventory file.",
    );
    expect(
      screen.getByRole("button", {
        name: /^Coverage Gap \(Offline \/ Firewall\)/,
      }),
    ).toHaveAccessibleDescription(
      "Listed in your AMT inventory records, but never successfully detected during active network scans.",
    );
  });

  it("makes the coverage summary a button whose name carries the coverage as text", async () => {
    const u = userEvent.setup();
    await loaded();
    const summary = screen.getByRole("button", { name: /72%\s*coverage/i });
    expect(summary).toHaveAttribute("aria-pressed", "false");
    expect(summary.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    await u.click(summary);
    await settle();
    expect(lastDrill()[1].params.category).toBe("matched");
  });

  it("labels the drilldown filters", async () => {
    const u = userEvent.setup();
    await loaded();
    await choose(u, "scanned");
    expect(screen.getByLabelText("Search hostname, IP, MAC or serial")).toBe(
      searchBox(),
    );
    expect(screen.getByLabelText("Owner")).toBe(ownerBox());
    expect(screen.getByLabelText("Department")).toBe(deptBox());
    expect(screen.getByLabelText("Location")).toBe(locBox());
  });

  it("names the file input and keeps it reachable by keyboard, with the drop zone as its label", async () => {
    await loaded();
    const input = screen.getByLabelText("AMT inventory file (.json)");
    expect(input).toBe(fileInput());
    expect(input).toHaveAttribute("accept", ".json");
    expect(input).not.toHaveAttribute("style");
    expect(input).not.toHaveAttribute("hidden");
    expect(input.tabIndex).toBe(0);
    const zone = document.querySelector(`label[for="${input.id}"]`);
    expect(zone).toHaveTextContent("Drag & Drop assets.json here");
  });

  it("announces a statistics failure as an alert", async () => {
    statsReply = () => Promise.reject(new Error("boom"));
    await loaded();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load inventory coverage statistics.",
    );
  });

  it("announces the upload outcome", async () => {
    await loaded();
    pick(jsonFile("assets.csv"));
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Unsupported file format: assets.csv.",
    );
    pick(jsonFile());
    await settle();
    fireEvent.click(submitButton());
    await settle();
    expect(
      screen
        .getAllByRole("status")
        .some((s) =>
          /Inventory file successfully uploaded/.test(s.textContent),
        ),
    ).toBe(true);
  });

  it("announces drilldown loading and failure", async () => {
    const u = userEvent.setup();
    drillReply = () => new Promise(() => {});
    await loaded();
    await choose(u, "scanned");
    expect(
      screen
        .getAllByRole("status")
        .some((s) => /Loading asset details/.test(s.textContent)),
    ).toBe(true);
    drillReply = () => Promise.reject(new Error("boom"));
    await choose(u, "inventory");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load drilldown details.",
    );
  });

  it("gives the drilldown table a caption and scoped column headers", async () => {
    const u = userEvent.setup();
    await loaded();
    await choose(u, "shadow_it");
    const table = screen.getByRole("table", { name: /Shadow IT Devices/ });
    const headers = within(table).getAllByRole("columnheader");
    expect(headers.map(squash)).toEqual(ASSET_HEADERS);
    for (const th of headers) expect(th).toHaveAttribute("scope", "col");
  });

  it("names the page controls without their arrow glyphs", async () => {
    const u = userEvent.setup();
    await loaded();
    await choose(u, "matched");
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Export CSV" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Refresh Stats" })).toBeEnabled();
  });

  it("hides decorative glyphs from assistive technology", async () => {
    const u = userEvent.setup();
    await loaded();
    await choose(u, "matched");
    const glyphs = /[📁↻📥🛡ℹ◀▶🔌⚠✔]/u;
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
    );
    const exposed = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (
        glyphs.test(n.textContent) &&
        !n.parentElement.closest("[aria-hidden=true]")
      ) {
        exposed.push(n.textContent.trim());
      }
    }
    expect(exposed).toEqual([]);
  });

  it("renders no inline style", async () => {
    const u = userEvent.setup();
    await loaded();
    await choose(u, "matched");
    expect(
      screen.getByTestId("app-layout").querySelectorAll("[style]"),
    ).toHaveLength(0);
  });

  it("styles the page from its own token stylesheet, without colour literals or legacy classes", () => {
    const source = readFileSync(
      path.join(SRC, "pages/admin/AMTIntegration.jsx"),
      "utf8",
    );
    expect(source).toMatch(
      /import\s+["']\.\.\/\.\.\/styles\/amt-integration\.css["']/,
    );
    expect(source).not.toMatch(/style=\{\{/);
    expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(source).not.toMatch(/\brgba?\(/);
    const classes = [
      ...source.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g),
    ].flatMap((m) => (m[1] ?? m[2]).split(/\s+/));
    expect(
      classes.filter(
        (c) => /^db-/.test(c) || ["data-table", "mono"].includes(c),
      ),
    ).toEqual([]);

    const cssPath = path.join(SRC, "styles/amt-integration.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\brgba?\(/);
    expect(css.match(/var\(--(?!ccure-)/g) || []).toEqual([]);
    expect(css).toMatch(/var\(--ccure-/);
  });
});
