/**
 * ComplianceWorkspace (`/compliance`) — the page shell: the header and its
 * filters, Gap Analysis, Run Compliance Scan and Create Baseline Policy, the
 * tab bar, the error banner, the loading bar, the dialog container and its
 * titles, and the Marketplace's uninstall question. Checkpoint 3C batch 32.
 *
 * Written against the page BEFORE migration. The contract block passes on the
 * legacy page and must keep passing; the batch 32 block is the specification,
 * and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Run Compliance Scan reads the policies afresh. With none it says to create
 * one and sends nothing; otherwise it starts one scan per policy of the chosen
 * framework — every policy with All Frameworks chosen — with the policy's
 * framework and no asset scope.
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
  waitFor,
  within,
} from "@testing-library/react";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

import ComplianceWorkspace from "@audit/pages/ComplianceWorkspace";
import api from "@shell/api/axiosInstance";
import { AUDIT_SRC } from "../../../testPaths";
import { personaFrom } from "../../../fixtures/authorization";

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

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let user;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(user) }),
}));

const ADMIN = personaFrom({
  id: 7,
  username: "operator",
  role: { name: "Org Admin" },
  permissionKeys: [
    "audit.compliance.read",
    "audit.compliance.manage_frameworks",
  ],
});

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const ISO = "cfw_iso27001_2022";
const NIST = "cfw_nist_csf_v2";
const PCI = "cfw_pci_dss_v4";
const ACTIVE = [ISO, NIST, PCI];
const MARKETPLACE = [
  {
    framework_id: ISO,
    name: "ISO/IEC 27001:2022",
    code: "ISO27001",
    version: "2022",
    controls_count: 93,
    is_installed: true,
  },
];
const POLICIES = [
  { id: "pol-iso", name: "ISO baseline", framework_id: ISO, status: "active" },
  {
    id: "pol-nist",
    name: "NIST baseline",
    framework_id: NIST,
    status: "active",
  },
];
const FINDINGS = [
  {
    id: "f-1",
    control_id: "A.8.8",
    control_title: "Management of technical vulnerabilities",
    rule_id: "rule-1",
    rule_name: "ccure.linux.sshd.permit_root_login",
    severity: "HIGH",
    asset_id: "asset-1",
    asset_hostname: "web-01",
    asset_ip: "10.70.0.11",
    source: "credentialed",
    status: "fail",
    fix_command: "sed -i s/PermitRootLogin.yes/PermitRootLogin.no/ sshd_config",
    recommendation_text: "Disable direct root login over SSH.",
  },
];
const GAP = {
  source_framework: { id: ISO, name: "ISO/IEC 27001:2022", code: "ISO27001" },
  target_framework: { id: "cfw_nis2", name: "EU NIS 2", code: "NIS2" },
  summary: {
    total_target_controls: 0,
    mapped_controls: 0,
    estimated_pass: 0,
    estimated_fail: 0,
    pending_manual: 0,
    estimated_score_pct: 0,
  },
  controls: [],
};
const UNINSTALL_QUESTION =
  "Are you sure you want to uninstall this compliance framework? This will hide its policies, findings, approvals, and dashboard averages.";
const deferred = () => {
  let resolve;
  const promise = new Promise((a) => {
    resolve = a;
  });
  return { promise, resolve };
};

/* ── Harness ────────────────────────────────────────────────────────────── */
let policies;
let policiesReply;
let credentialsReply;
let confirmSpy;
let consoleError;

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
// The focus trap places focus in an animation frame, so anything asserting
// where focus landed waits one out.
const frame = async () => {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 40));
  });
  await flush();
};
const mount = async () => {
  const view = render(<ComplianceWorkspace />);
  await flush();
  return view;
};
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);
const click = async (el) => {
  fireEvent.click(el);
  await flush();
};
const change = async (el, value) => {
  fireEvent.change(el, { target: { value } });
  await flush();
};
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
  await click(tab);
};
const frameworkSelect = () =>
  [...document.querySelectorAll("select")].find((s) =>
    [...s.options].some(
      (o) => o.value === "all" && o.textContent === "All Frameworks",
    ),
  );
const buttonWithText = (re) =>
  [...document.querySelectorAll("button")].find((b) => re.test(squash(b)));
const findingRow = (controlId) =>
  [...document.querySelectorAll("tbody tr")].find(
    (r) => r.cells.length > 1 && squash(r.cells[0]) === controlId,
  );
const cardOf = (name) => {
  let el = [...document.querySelectorAll("h1, h2, h3, h4")].find(
    (h) => squash(h) === name,
  );
  while (el && !el.querySelector("button")) el = el.parentElement;
  return el;
};

beforeEach(() => {
  user = ADMIN;
  policies = POLICIES;
  policiesReply = null;
  credentialsReply = () => Promise.resolve({ data: [] });
  Element.prototype.scrollIntoView = vi.fn();
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url) => {
    if (url === "/compliance/marketplace")
      return Promise.resolve({
        data: { data: MARKETPLACE, active_framework_ids: ACTIVE },
      });
    if (url === "/compliance/policies" && policiesReply) return policiesReply();
    if (url.startsWith("/compliance/policies"))
      return Promise.resolve({ data: { data: policies } });
    if (url.startsWith("/compliance/findings"))
      return Promise.resolve({ data: { data: FINDINGS } });
    if (url.startsWith("/compliance/gap-analysis"))
      return Promise.resolve({ data: GAP });
    if (url === "/compliance/credentials") return credentialsReply();
    if (url.startsWith("/compliance/summary"))
      return Promise.resolve({
        data: { score_pct: 70, weighted_score_pct: 60, kpis: {} },
      });
    return Promise.resolve({ data: { data: [] } });
  });
  api.post.mockImplementation((url) =>
    Promise.resolve({
      data: url === "/compliance/scans" ? { scan_run_id: "run-1" } : {},
    }),
  );
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
  consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  // The shell starts scans and uninstalls frameworks, and nothing else.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls)
    expect(url).toMatch(
      /^\/compliance\/(scans|marketplace\/[a-z0-9_]+\/uninstall)$/,
    );
  confirmSpy.mockRestore();
  consoleError.mockRestore();
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace shell — contract", () => {
  it("Run Compliance Scan with no policies says to create one and starts nothing", async () => {
    policies = [];
    await mount();
    await click(buttonWithText(/Run Compliance Scan/));
    expect(api.get.mock.calls.map(([u]) => u)).toContain(
      "/compliance/policies",
    );
    expect(bodyText()).toContain(
      "Please create a policy baseline first under the 'Policies' tab before running a compliance scan.",
    );
    expect(api.post).not.toHaveBeenCalled();
  });

  it("with All Frameworks chosen it starts one scan per policy, in order, with no asset scope", async () => {
    await mount();
    await click(buttonWithText(/Run Compliance Scan/));
    expect(api.post.mock.calls).toEqual([
      [
        "/compliance/scans",
        {
          framework_id: ISO,
          policy_id: "pol-iso",
          asset_ids: [],
          asset_tags: [],
        },
      ],
      [
        "/compliance/scans",
        {
          framework_id: NIST,
          policy_id: "pol-nist",
          asset_ids: [],
          asset_tags: [],
        },
      ],
    ]);
    expect(bodyText()).toContain(
      "Compliance scan triggered successfully for all active policies! Re-evaluating rules...",
    );
  });

  it("with a framework chosen it scans only that framework's policies", async () => {
    await mount();
    await change(frameworkSelect(), NIST);
    await click(buttonWithText(/Run Compliance Scan/));
    expect(api.post.mock.calls).toEqual([
      [
        "/compliance/scans",
        {
          framework_id: NIST,
          policy_id: "pol-nist",
          asset_ids: [],
          asset_tags: [],
        },
      ],
    ]);
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 32 — the specification. Each fails on the legacy page.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace shell — batch 32", () => {
  it("the header is a level-one heading, and every filter is a labelled control", async () => {
    await mount();
    expect(
      screen.getByRole("heading", { level: 1, name: "Policy Compliance" }),
    ).toBeTruthy();
    expect([...frameworkSelect().labels].map((l) => squash(l))).toEqual([
      "Framework",
    ]);
    expect(screen.getByLabelText("Gap Source").tagName).toBe("SELECT");
    await change(frameworkSelect(), PCI);
    expect(screen.getByLabelText("SAQ Profile").tagName).toBe("SELECT");
    expect(
      screen.getByRole("checkbox", { name: "CDE Scope Only" }),
    ).toBeTruthy();
  });

  it("the header's actions are design-system buttons named without their decorations", async () => {
    await mount();
    for (const name of ["Gap Analysis", "Run Compliance Scan"]) {
      expect(screen.getByRole("button", { name })).toHaveClass("cc-btn");
    }
    await openTab("Policies");
    expect(
      screen.getByRole("button", { name: "Create Baseline Policy" }),
    ).toHaveClass("cc-btn");
  });

  it("the tab bar is a named tab list: one tab chosen and tabbable, arrow keys move focus without choosing, and the chosen tab labels its panel", async () => {
    await mount();
    const list = screen.getByRole("tablist", {
      name: "Compliance workspace sections",
    });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((t) => squash(t))).toEqual([
      "Dashboard",
      "Marketplace",
      "Policies",
      "Controls",
      "Findings",
      "Exceptions",
      // P3-2: recurring compliance scans, which beat has run every sixty
      // seconds since the first compliance migration with no screen to
      // create one.
      "Schedules",
      "Credentials Manager",
      "Approvals Queue",
    ]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs.filter((t) => t.getAttribute("tabindex") === "0")).toEqual([
      tabs[0],
    ]);
    tabs[0].focus();
    fireEvent.keyDown(tabs[0], { key: "ArrowRight" });
    expect(document.activeElement).toBe(tabs[1]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    await click(tabs[1]);
    expect(tabs[1]).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel", { name: "Marketplace" })).toBeTruthy();
  });

  it("a read that fails is an alert naming the error", async () => {
    credentialsReply = () => Promise.reject(new Error("Network Error"));
    await mount();
    await openTab("Credentials Manager");
    const alert = screen
      .getAllByRole("alert")
      .find((a) => /Connection or Database Error/.test(squash(a)));
    expect(squash(alert)).toContain(
      "Connection or Database Error: Network Error",
    );
  });

  it("while the workspace loads, a progress bar is named for it", async () => {
    await mount();
    const pending = deferred();
    policiesReply = () => pending.promise;
    await click(buttonWithText(/Run Compliance Scan/));
    expect(
      screen.getByRole("progressbar", { name: "Loading compliance data" }),
    ).toBeTruthy();
    await act(async () => pending.resolve({ data: { data: [] } }));
    await flush();
    expect(
      screen.queryByRole("progressbar", { name: "Loading compliance data" }),
    ).toBeNull();
  });

  it("dialogs are titled for people, and close with a named button", async () => {
    await mount();
    await click(buttonWithText(/Gap Analysis/));
    expect(screen.getByRole("dialog", { name: "Gap Analysis" })).toBeTruthy();
    await click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await openTab("Findings");
    await click(
      within(findingRow("A.8.8")).getByRole("button", { name: "Remediate" }),
    );
    expect(
      screen.getByRole("dialog", { name: "Remediate Finding" }),
    ).toBeTruthy();
  });

  it("uninstalling a framework asks in a dialog with Cancel focused; Cancel and Escape send nothing, and confirming sends one POST", async () => {
    await mount();
    await openTab("Marketplace");
    const uninstall = () =>
      within(cardOf("ISO/IEC 27001:2022")).getByRole("button", {
        name: "Uninstall",
      });

    // A browser focuses the button a click lands on; jsdom does not, so the
    // opener is focused the way a person's click would leave it.
    uninstall().focus();
    await click(uninstall());
    await frame();
    let box = screen.getByRole("dialog", { name: "Uninstall framework" });
    expect(squash(box)).toContain(UNINSTALL_QUESTION);
    expect(within(box).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await click(within(box).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();

    await click(uninstall());
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.post).not.toHaveBeenCalled();

    await click(uninstall());
    box = screen.getByRole("dialog", { name: "Uninstall framework" });
    await click(within(box).getByRole("button", { name: "Uninstall" }));
    expect(api.post.mock.calls).toEqual([
      [`/compliance/marketplace/${ISO}/uninstall`],
    ]);
    expect(bodyText()).toContain("Framework uninstalled successfully.");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(confirmSpy).not.toHaveBeenCalled();
  });

  it("the migrated source keeps no inline style, legacy class, hand-built control, native confirm or legacy dialog container, and its stylesheet is token-only", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/ComplianceWorkspace.jsx"),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(source).toMatch(
      /import\s+["']\.\.\/styles\/compliance-workspace\.css["']/,
    );
    expect(source).not.toMatch(/components\/layout\/Modal/);
    expect(source).not.toMatch(/<Modal\b|<\/Modal>/);
    expect(source).not.toMatch(/modalType\.toUpperCase\(\)/);
    expect(source).not.toMatch(/window\.confirm/);
    expect(source).not.toMatch(/style=\{/);
    expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(source).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
    expect(source).not.toMatch(
      /className=["{`][^"}`]*(\bdb-|\bcw-pagination|\bloading-bar\b)/,
    );
    expect(source).not.toMatch(/<(button|select|table)\b/);
    for (const part of [
      "CcureTabs",
      "CcureTabPanel",
      "CcureModal",
      "CcureProgress",
      "CcureAlert",
    ])
      expect(source).toMatch(new RegExp(`<${part}\\b`));

    const complianceCss = readFileSync(
      path.join(AUDIT_SRC, "styles/compliance.css"),
      "utf8",
    );
    expect(complianceCss).not.toMatch(
      /\.loading-bar|loading-slide|\.cw-pagination/,
    );

    const cssPath = path.join(AUDIT_SRC, "styles/compliance-workspace.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)[a-z0-9-]+/g) || []).toEqual([]);
    expect(css).not.toMatch(/prefers-color-scheme|ux4g|!important|url\(/i);
    expect(css).toMatch(/@media \(max-width: 640px\)/);
    const selectors = css
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .split("{")
      .slice(0, -1)
      .map((s) => s.split("}").pop().trim())
      .filter((s) => s && !s.startsWith("@"));
    for (const s of selectors) expect(s).toMatch(/\.cwh-/);
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Phase 1, finding F6 — a run over zero assets is "not assessed", not done.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace shell — a run that assessed nothing", () => {
  it("stops polling and says nothing was assessed, instead of announcing a completed scan", async () => {
    const base = api.get.getMockImplementation();
    api.get.mockImplementation((url) =>
      url === "/compliance/scans/run-1"
        ? Promise.resolve({
            data: {
              id: "run-1",
              status: "not_assessed",
              error_message: "No assets matched this scan's scope.",
            },
          })
        : base(url),
    );
    await mount();
    await change(frameworkSelect(), NIST);
    await click(buttonWithText(/Run Compliance Scan/));
    await waitFor(() =>
      expect(bodyText()).toContain(
        "Nothing was assessed: No assets matched this scan's scope. Previous results are unchanged.",
      ),
    );
    expect(bodyText()).not.toContain("Compliance scan completed.");
    const polls = api.get.mock.calls.filter(
      ([u]) => u === "/compliance/scans/run-1",
    ).length;
    await new Promise((r) => setTimeout(r, 50));
    expect(
      api.get.mock.calls.filter(([u]) => u === "/compliance/scans/run-1"),
    ).toHaveLength(polls);
  });
});
