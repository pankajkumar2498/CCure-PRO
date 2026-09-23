/**
 * ComplianceWorkspace (`/compliance`) — the Dashboard, Controls, Policies and
 * Findings tabs. Checkpoint 3C batch 26B baseline.
 *
 * Written against the page BEFORE migration. The contract blocks are the gate
 * every later change must keep passing; the batch 26B blocks are the
 * specification, and every test in them fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * All four tabs only read. The Dashboard reads the workspace summary and, for
 * All Frameworks, each active framework's; it downloads reports as array
 * buffers and computes the NIS 2 fine ceiling in the browser. Controls reads a
 * framework's register — search on Enter, status at once. Policies reads the
 * baselines and, on expansion, a baseline's rules. Findings reads every
 * finding, filters and pages them in the browser, and polls every 5 seconds
 * while any finding is re-checking. Their buttons that lead to a write only
 * open the workspace's existing dialogs; no test here submits one.
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
import api from "../../api/axiosInstance";

vi.mock("../../api/axiosInstance", () => ({
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

vi.mock("../../context/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: 1,
      username: "analyst",
      role: { name: "analyst", permissions: ["compliance:read"] },
    },
  }),
}));

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const ISO = "cfw_iso27001_2022";
const NIST = "cfw_nist_csf_v2";

const SUMMARY = {
  score_pct: 86,
  weighted_score_pct: 41,
  kpis: {
    passed: 40,
    failed: 10,
    exceptions: 2,
    manual_review: 5,
    not_assessed: 3,
    total_controls: 60,
  },
  quadrant_scores: { GV: 55, ID: 70, PR: 82, DE: 48, RS: 61, RC: 90 },
};

const CONTROLS = {
  data: [
    {
      control_id: "cct_iso_5_1",
      control_number: "A.5.1",
      title: "Policies for information security",
      description: "Information security policy defined and approved.",
      theme: "ORG",
      scannability: "manual",
      status: "pass",
      evidence_file_count: 2,
      reviewed_at: "2026-08-01T10:00:00Z",
    },
    {
      control_id: "cct_iso_8_8",
      control_number: "A.8.8",
      title: "Management of technical vulnerabilities",
      theme: "TECH",
      scannability: "auto",
      status: "fail",
      evidence_file_count: 0,
      reviewed_at: null,
    },
    {
      control_id: "cct_csf_gv_oc_01",
      control_number: "GV.OC-01",
      title: "Organizational mission is understood",
      theme: "GV",
      function: "Govern",
      category: "GV.OC",
      category_name: "Organizational Context",
      scannability: "semi_auto",
      status: "manual_review",
      evidence_file_count: 1,
      reviewed_at: null,
    },
    {
      control_id: "cct_iso_7_4",
      control_number: "A.7.4",
      title: "Physical security monitoring",
      theme: "PHY",
      scannability: "manual",
      status: "not_assessed",
      evidence_file_count: 0,
      reviewed_at: null,
    },
    {
      control_id: "cct_iso_6_7",
      control_number: "A.6.7",
      title: "Remote working",
      theme: "PPL",
      scannability: "manual",
      status: "not_applicable",
      evidence_file_count: 0,
      reviewed_at: "2026-07-15T09:30:00Z",
    },
  ],
  summary: {
    passed: 1,
    failed: 1,
    awaiting_review: 1,
    not_assessed: 1,
    not_applicable: 1,
  },
};

const policy = (i) => ({
  id: `pol-${i}`,
  name: `Baseline ${String(i).padStart(2, "0")}`,
  target_platform: "linux",
  version_number: 1,
  rules_count: 1,
  status: "active",
});
const POLICIES = [
  {
    id: "pol-1",
    name: "ISO 27001 Linux baseline",
    target_platform: "linux",
    version_number: 3,
    rules_count: 4,
    status: "active",
  },
  {
    id: "pol-2",
    name: "NIST CSF Windows baseline",
    target_platform: "windows",
    version_number: 1,
    rules_count: 1,
    status: "draft",
  },
];
const RULES = [
  {
    id: "rule-1",
    control_number: "A.8.8",
    control_title: "Management of technical vulnerabilities",
    rule_name: "ccure.linux.sshd.permit_root_login",
    severity: "HIGH",
    evidence_source: "credentialed_config",
    check_definition: {
      key: "sshd.permit_root_login",
      operator: "equals",
      expected: "no",
    },
  },
  {
    id: "rule-2",
    control_id: "cct_nist_csf_v2_PR_AA_05",
    control_title: "Access permissions and authorizations",
    rule_name: "manual.pr_aa_05",
    severity: null,
    evidence_source: "manual",
  },
  {
    id: "rule-3",
    control_id: "cct_iso_5_1",
    control_title: "Policies for information security",
    rule_name: "ccure.policy.present",
    severity: "LOW",
    evidence_source: "network",
  },
  {
    id: "rule-4",
    control_title: "Unmapped check",
    rule_name: "ccure.unmapped",
    severity: "CRITICAL",
    evidence_source: "network",
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
    asset_reboot_pending: true,
    source: "credentialed",
    status: "fail",
  },
  {
    id: "f-2",
    control_id: "A.5.24",
    control_title: "Incident management planning",
    severity: "MEDIUM",
    source: "manual",
    status: "manual_review",
    status_reason: "No credential was in scope for this host.",
  },
  {
    id: "f-3",
    control_id: "A.8.2",
    control_title: "Privileged access rights",
    rule_id: "rule-3",
    rule_name: "ccure.win.local_admins",
    severity: "CRITICAL",
    asset_id: "asset-2",
    asset_hostname: "Unknown",
    asset_ip: "10.70.0.12",
    source: "network",
    status: "pass",
    control_tags: ["ig1"],
  },
  {
    id: "f-4",
    control_id: "A.8.9",
    control_title: "Configuration management",
    severity: "LOW",
    asset_id: "asset-3",
    asset_hostname: "db-01",
    asset_ip: "10.70.0.13",
    source: "credentialed",
    status: "fail",
    evidence: { observed: "PermitRootLogin yes" },
    control_tags: ["ig2"],
  },
];
const manyFindings = (n) =>
  Array.from({ length: n }, (_, i) => ({
    id: `m-${i + 1}`,
    control_id: `EX-${String(i + 1).padStart(2, "0")}`,
    control_title: `Finding ${i + 1}`,
    severity: "LOW",
    source: "network",
    status: i % 2 ? "pass" : "fail",
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
let routes;
let activeIds;
let allowCredentials;
let downloads;
let consoleError;

// A route answers every GET it matches: a value, a promise, or a function of
// the URL and config returning either.
const on = (match, reply) => {
  const test =
    typeof match === "string"
      ? (u) => u === match
      : match instanceof RegExp
        ? (u) => match.test(u)
        : match;
  routes.unshift([test, reply]);
};
const answer = (url, config) => {
  for (const [test, reply] of routes) {
    if (test(url, config))
      return typeof reply === "function" ? reply(url, config) : reply;
  }
  if (url === "/compliance/marketplace")
    return {
      data: activeIds
        ? { data: [], active_framework_ids: activeIds }
        : { data: [] },
    };
  if (url.startsWith("/compliance/summary")) return { data: SUMMARY };
  if (url.startsWith("/compliance/frameworks/")) return { data: CONTROLS };
  if (/^\/compliance\/policies\/[^/?]+\/rules$/.test(url))
    return { data: { data: RULES } };
  if (url.startsWith("/compliance/policies"))
    return { data: { data: POLICIES } };
  if (url.startsWith("/compliance/findings"))
    return { data: { data: FINDINGS } };
  if (url === "/compliance/credentials") return { data: [] };
  if (/^\/compliance\/controls\/[^/]+\/evidence$/.test(url))
    return { data: { data: [] } };
  if (url.startsWith("/compliance/reports/"))
    return {
      data: new ArrayBuffer(8),
      headers: { "content-type": "application/pdf" },
    };
  return { data: { data: [] } };
};

const ALLOWED_READS =
  /^\/compliance\/(marketplace|summary(\?[a-z0-9_=&]+)?|frameworks\/[a-z0-9_]+\/controls(\?[A-Za-z0-9_=&%.-]+)?|policies(\?[a-z0-9_=&]+)?|policies\/[a-z0-9-]+\/rules|findings\?limit=10000(&[a-z0-9_]+=[a-z0-9_]+)*|credentials|controls\/[A-Za-z0-9_.-]+\/evidence|reports\/[a-z0-9_]+(\?[a-z0-9_=&]+)?)$/;

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const tick = async () => {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
  await flush();
};
const mount = async () => {
  const view = render(<ComplianceWorkspace />);
  await flush();
  return view;
};
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
// Comparable text: no whitespace, no colons, no disclosure chevrons, lower case.
const norm = (value) =>
  (typeof value === "string" ? value : value?.textContent || "")
    .replace(/[\s:▶▼]/g, "")
    .toLowerCase();
const bodyText = () => squash(document.body);
const calls = () => api.get.mock.calls.length;
const since = (n) => api.get.mock.calls.slice(n);
const lastGet = () => api.get.mock.calls.at(-1);

// Some element reads exactly the label and the value, in either order.
const hasPair = (label, value) => {
  const a = norm(label) + norm(value);
  const b = norm(value) + norm(label);
  return [...document.body.querySelectorAll("*")].some((el) => {
    const t = norm(el);
    return t === a || t === b;
  });
};

// The tab bar is eight unnamed <div>s; it is found by its contents.
const tabBar = () =>
  [...document.querySelectorAll("div")].find(
    (d) =>
      d.children.length === 8 &&
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
const selectWith = (values) =>
  [...document.querySelectorAll("select")].find(
    (s) => [...s.options].map((o) => o.value).join(",") === values,
  );
const frameworkSelect = () =>
  [...document.querySelectorAll("select")].find((s) =>
    [...s.options].some(
      (o) => o.value === "all" && o.textContent === "All Frameworks",
    ),
  );
const choose = async (select, value) => {
  fireEvent.change(select, { target: { value } });
  await flush();
};
const chooseFramework = (id) => choose(frameworkSelect(), id);

// The first table in the tab is its main one; a policy's rules nest inside.
const mainTable = () => document.querySelector("table");
const bodyRows = (table = mainTable()) => [...table.tBodies[0].rows];
const rowCells = (row) => [...row.cells].map(norm);
const rowOf = (first, table = mainTable()) =>
  bodyRows(table).find(
    (r) => r.cells.length > 1 && norm(r.cells[0]) === norm(first),
  );
const firstColumn = (table = mainTable()) =>
  bodyRows(table)
    .filter((r) => r.cells.length > 1)
    .map((r) => norm(r.cells[0]));
const headingNamed = (text) =>
  [...document.querySelectorAll("h1, h2, h3, h4, h5, h6")].find(
    (h) => squash(h).replace(/^\W+/u, "") === text,
  );
const pageStatus = () => bodyText().match(/Page (\d+) of (\d+)/)?.[0];
const buttonNamed = (...patterns) => {
  for (const name of patterns) {
    const found = screen.queryAllByRole("button", { name });
    if (found.length === 1) return found[0];
  }
  throw new Error(`no single button named ${patterns.join(" or ")}`);
};
const nextButton = () => buttonNamed(/^Next$/);
const expectDialog = (name) =>
  expect(screen.getByRole("dialog", { name })).toBeInTheDocument();

beforeEach(() => {
  routes = [];
  activeIds = null;
  allowCredentials = false;
  downloads = [];
  Element.prototype.scrollIntoView = vi.fn();
  URL.createObjectURL = vi.fn(() => "blob:views");
  URL.revokeObjectURL = vi.fn();
  HTMLAnchorElement.prototype.click = function click() {
    downloads.push({
      href: this.getAttribute("href"),
      name: this.getAttribute("download"),
    });
  };
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url, config) => {
    const r = answer(url, config);
    return r instanceof Promise ? r : Promise.resolve(r);
  });
  consoleError = vi.spyOn(console, "error");
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  // Nothing on these tabs writes, and every read is one they are known to
  // make; the stored credentials are read only by the remediation dialog.
  expect(api.post).not.toHaveBeenCalled();
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const [url] of api.get.mock.calls) {
    expect(url).toMatch(ALLOWED_READS);
    if (url === "/compliance/credentials") expect(allowCredentials).toBe(true);
  }
  consoleError.mockRestore();
  delete HTMLAnchorElement.prototype.click;
  delete Element.prototype.scrollIntoView;
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("ComplianceWorkspace views — contract", () => {
  describe("Dashboard", () => {
    it("reads the workspace summary, then each active framework's, on opening", async () => {
      await mount();
      expect(api.get.mock.calls).toEqual([
        ["/compliance/marketplace"],
        ["/compliance/summary"],
        [`/compliance/summary?framework_id=${ISO}`],
        [`/compliance/summary?framework_id=${NIST}`],
      ]);
    });

    it("shows the two scores, the KPIs and each framework's score", async () => {
      await mount();
      expect(hasPair("Overall Score", "86%")).toBe(true);
      expect(hasPair("Risk-Weighted Score", "41%")).toBe(true);
      expect(headingNamed("All Frameworks")).toBeTruthy();
      expect(hasPair("Passed", "40")).toBe(true);
      expect(hasPair("Failed", "10")).toBe(true);
      expect(hasPair("Active Waivers", "2")).toBe(true);
      expect(headingNamed("Compliance Score by Framework")).toBeTruthy();
      expect(hasPair("ISO/IEC 27001:2022", "86%")).toBe(true);
      expect(hasPair("NIST CSF v2.0", "86%")).toBe(true);
    });

    it("a chosen framework reads only its own summary and shows its themes", async () => {
      await mount();
      const n = calls();
      await chooseFramework(NIST);
      expect(since(n)).toEqual([[`/compliance/summary?framework_id=${NIST}`]]);
      expect(headingNamed("NIST CSF Controls")).toBeTruthy();
      expect(
        headingNamed("NIST CSF 2.0 Core Functions Breakdown"),
      ).toBeTruthy();
      expect(headingNamed("Compliance Score by Framework")).toBeFalsy();
      for (const [label, value] of [
        ["Govern (GV)", 55],
        ["Identify (ID)", 70],
        ["Protect (PR)", 82],
        ["Detect (DE)", 48],
        ["Respond (RS)", 61],
        ["Recover (RC)", 90],
      ])
        expect(hasPair(label, `${value}%`)).toBe(true);
    });

    it("says when no framework has a score yet", async () => {
      on(
        (u) => u.startsWith("/compliance/summary?framework_id="),
        () => Promise.reject(new Error("unscored")),
      );
      await mount();
      expect(bodyText()).toContain(
        "No enabled frameworks with scored controls yet.",
      );
    });

    it("shows nothing until the summary arrives", async () => {
      const pending = deferred();
      on("/compliance/summary", pending.promise);
      await mount();
      expect(bodyText()).not.toMatch(/Overall Score|Executive Compliance/);
      await act(async () => pending.resolve({ data: SUMMARY }));
      await flush();
      expect(hasPair("Overall Score", "86%")).toBe(true);
    });
  });

  describe("Dashboard reports", () => {
    const reportSelect = () =>
      [...document.querySelectorAll("select")].find((s) =>
        [...s.options].some((o) => o.value === "executive"),
      );
    const download = async (name) => {
      fireEvent.click(screen.getByRole("button", { name }));
      await flush();
    };
    const expectDownload = (url, filename, type = "application/pdf") => {
      expect(lastGet()).toEqual([url, { responseType: "arraybuffer" }]);
      expect(downloads.at(-1)).toEqual({ href: "blob:views", name: filename });
      expect(URL.createObjectURL.mock.calls.at(-1)[0].type).toBe(type);
      expect(URL.revokeObjectURL).toHaveBeenLastCalledWith("blob:views");
    };

    it("offers each active framework's report and the executive briefing, and downloads the Statement of Applicability as PDF", async () => {
      await mount();
      expect([...reportSelect().options].map((o) => o.textContent)).toEqual([
        "Statement of Applicability (SoA — ISO 27001)",
        "NIST CSF v2.0 Current Profile",
        "Multi-Framework Executive Briefing",
      ]);
      expect(reportSelect().value).toBe("soa");
      await download(/Download PDF Report/);
      expectDownload(
        `/compliance/reports/soa?fmt=pdf&framework_id=${ISO}`,
        `soa_${ISO}.pdf`,
      );
    });

    it("Word format, for the chosen framework, falls back to the Word type when the server names none", async () => {
      on(/^\/compliance\/reports\//, { data: new ArrayBuffer(8), headers: {} });
      await mount();
      await chooseFramework(NIST);
      fireEvent.click(screen.getByRole("button", { name: "Word (.docx)" }));
      await flush();
      await download(/Download DOCX Report/);
      expectDownload(
        `/compliance/reports/soa?fmt=docx&framework_id=${NIST}`,
        `soa_${NIST}.docx`,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      );
    });

    it("downloads the NIST CSF profile and the executive briefing", async () => {
      await mount();
      await choose(reportSelect(), "nist_csf");
      await download(/Download PDF Report/);
      expectDownload(
        "/compliance/reports/nist_csf?fmt=pdf",
        "nist_csf_report.pdf",
      );
      await choose(reportSelect(), "executive");
      await download(/Download PDF Report/);
      expectDownload(
        "/compliance/reports/executive",
        "executive_compliance_report.pdf",
      );
    });

    it("carries a framework's scoping filters into its report", async () => {
      activeIds = [ISO, NIST, "cfw_pci_dss_v4", "cfw_nis2"];
      await mount();
      await chooseFramework("cfw_pci_dss_v4");
      fireEvent.click(screen.getByRole("checkbox", { name: /CDE Scope Only/ }));
      await flush();
      await choose(reportSelect(), "pci_dss_v4");
      await download(/Download PDF Report/);
      expectDownload(
        "/compliance/reports/pci_dss_v4?fmt=pdf&cde_scope_only=true",
        "pci_dss_v4_report.pdf",
      );
      await chooseFramework("cfw_nis2");
      await choose(selectWith("all,essential,important"), "important");
      await choose(reportSelect(), "nis2");
      await download(/Download PDF Report/);
      expectDownload(
        "/compliance/reports/nis2?fmt=pdf&nis2_entity_type=important",
        "nis2_report.pdf",
      );
    });

    it("quick downloads fetch their fixed reports", async () => {
      await mount();
      for (const [name, url, file] of [
        [
          "SoA PDF",
          "/compliance/reports/soa?fmt=pdf",
          "statement_of_applicability.pdf",
        ],
        [
          "SoA Word",
          "/compliance/reports/soa?fmt=docx",
          "statement_of_applicability.docx",
        ],
        [
          "Executive Brief (PDF)",
          "/compliance/reports/executive",
          "executive_compliance_report.pdf",
        ],
        [
          "NIST CSF PDF",
          "/compliance/reports/nist_csf?fmt=pdf",
          "nist_csf_v2_report.pdf",
        ],
      ]) {
        await download(name);
        expectDownload(url, file);
      }
      expect(downloads).toHaveLength(4);
    });

    it("says Generating while a report is prepared, and reports a failure", async () => {
      const pending = deferred();
      on(/^\/compliance\/reports\//, pending.promise);
      consoleError.mockImplementation(() => {});
      await mount();
      await download(/Download PDF Report/);
      expect(screen.getByRole("button", { name: /Generating/ })).toBeDisabled();
      await act(async () =>
        pending.reject({
          response: { data: { detail: "Report renderer unavailable" } },
          message: "Request failed",
        }),
      );
      await flush();
      expect(bodyText()).toContain(
        "Failed to download report: Report renderer unavailable",
      );
      expect(
        screen.getByRole("button", { name: /Download PDF Report/ }),
      ).toBeEnabled();
      expect(downloads).toHaveLength(0);
    });
  });

  describe("Dashboard — NIS 2", () => {
    const calculator = () => {
      let el = [...document.querySelectorAll("h1, h2, h3, h4, h5, h6")].find(
        (h) => /Fine Risk Exposure Calculator/.test(h.textContent || ""),
      );
      while (el && !/Statutory Fine Ceiling/.test(el.textContent || ""))
        el = el.parentElement;
      return el;
    };
    const euro = (n) => `€${n.toLocaleString()}`;

    it("computes the fine ceiling from turnover and entity type, in the browser", async () => {
      activeIds = [ISO, NIST, "cfw_nis2"];
      await mount();
      expect(calculator()).toBeFalsy();
      await chooseFramework("cfw_nis2");
      expect(bodyText()).toMatch(
        /Article 23 CSIRT Mandatory Incident Reporting SLA/,
      );
      const n = calls();
      expect(squash(calculator())).toContain("Essential Entity (Art. 3.1)");
      expect(squash(calculator())).toContain(euro(10000000));
      const turnover = calculator().querySelector('input[type="number"]');
      expect(turnover.value).toBe("50000000");
      await choose(turnover, "1000000000");
      expect(squash(calculator())).toContain(euro(20000000));
      await choose(selectWith("all,essential,important"), "important");
      expect(squash(calculator())).toContain("Important Entity (Art. 3.2)");
      expect(squash(calculator())).toContain(euro(14000000));
      await choose(
        calculator().querySelector('input[type="number"]'),
        "100000000",
      );
      expect(squash(calculator())).toContain(euro(7000000));
      expect(since(n)).toEqual([]);
    });
  });

  describe("Controls", () => {
    const statusFilter = () =>
      selectWith(
        "all,pass,fail,manual_review,not_assessed,not_applicable,exception",
      );
    const register = (query = "") =>
      `/compliance/frameworks/${ISO}/controls${query}`;

    it("opens by reading the ISO 27001 register, or the chosen framework's", async () => {
      await mount();
      await openTab("Controls");
      expect(lastGet()).toEqual([register()]);
      const n = calls();
      await chooseFramework(NIST);
      expect(since(n)).toEqual([[`/compliance/frameworks/${NIST}/controls`]]);
    });

    it("searches on Enter only, with the trimmed text encoded", async () => {
      await mount();
      await openTab("Controls");
      const n = calls();
      const search = document.querySelector('input[type="search"]');
      await choose(search, "  A.5 & x ");
      fireEvent.keyDown(search, { key: "a" });
      await flush();
      expect(since(n)).toEqual([]);
      fireEvent.keyDown(search, { key: "Enter" });
      await flush();
      expect(since(n)).toEqual([[register("?search=A.5%20%26%20x")]]);
    });

    it("a status choice reads the register at once, with the status chosen before it", async () => {
      await mount();
      await openTab("Controls");
      let n = calls();
      await choose(statusFilter(), "fail");
      await tick();
      expect(since(n)).toEqual([[register()]]);
      n = calls();
      await choose(statusFilter(), "pass");
      await tick();
      expect(since(n)).toEqual([[register("?status=fail")]]);
      n = calls();
      fireEvent.keyDown(document.querySelector('input[type="search"]'), {
        key: "Enter",
      });
      await flush();
      expect(since(n)).toEqual([[register("?status=pass")]]);
    });

    it("lists each control and the register's summary", async () => {
      await mount();
      await openTab("Controls");
      const date = (iso) => norm(new Date(iso).toLocaleDateString());
      expect(bodyRows().map(rowCells)).toEqual([
        [
          "a.5.1",
          norm(
            "Policies for information securityInformation security policy defined and approved.",
          ),
          norm("Organizational Controls (ORG)"),
          "manual",
          "pass",
          norm("📎 2"),
          date("2026-08-01T10:00:00Z"),
          "attest",
        ],
        [
          "a.8.8",
          norm("Management of technical vulnerabilities"),
          norm("Technological Controls (TECH)"),
          "auto",
          "fail",
          "—",
          "—",
          "attest",
        ],
        [
          "gv.oc-01",
          norm("Organizational mission is understood"),
          norm("GovernGV.OC · Organizational Context"),
          "semi_auto",
          "manualreview",
          norm("📎 1"),
          "—",
          "attest",
        ],
        [
          "a.7.4",
          norm("Physical security monitoring"),
          norm("Physical Controls (PHY)"),
          "manual",
          "notassessed",
          "—",
          "—",
          "attest",
        ],
        [
          "a.6.7",
          norm("Remote working"),
          norm("People Controls (PPL)"),
          "manual",
          "notapplicable",
          "—",
          date("2026-07-15T09:30:00Z"),
          "attest",
        ],
      ]);
      expect(
        [...mainTable().tHead.rows[0].cells].map((c) => squash(c)),
      ).toEqual([
        "Ref",
        "Control",
        "Theme",
        "Mode",
        "Status",
        "Evidence",
        "Reviewed",
        "Actions",
      ]);
      for (const label of [
        "Implemented",
        "Not implemented",
        "Awaiting review",
        "Not assessed",
        "Excluded",
      ])
        expect(hasPair(label, "1")).toBe(true);
      expect(headingNamed("Control Register")).toBeTruthy();
    });

    it("says when nothing matches, and not while the register is loading", async () => {
      const pending = deferred();
      on(/^\/compliance\/frameworks\//, pending.promise);
      await mount();
      await openTab("Controls");
      expect(bodyText()).not.toContain("No controls match the current filter.");
      await act(async () => pending.resolve({ data: { data: [] } }));
      await flush();
      expect(bodyText()).toContain("No controls match the current filter.");
    });

    it("Attest opens the attestation dialog and reads only that control's evidence", async () => {
      await mount();
      await openTab("Controls");
      const n = calls();
      fireEvent.click(
        within(rowOf("A.5.1")).getByRole("button", { name: "Attest" }),
      );
      await flush();
      expectDialog("Control Manual Attestation");
      expect(since(n)).toEqual([["/compliance/controls/cct_iso_5_1/evidence"]]);
    });
  });

  describe("Policies", () => {
    const toggle = async (name) => {
      const row = bodyRows().find((r) => norm(r).includes(norm(name)));
      fireEvent.click(row.querySelector("[aria-expanded]") || row);
      await flush();
    };
    const rulesTable = () => mainTable().querySelector("table");

    it("opens by reading the baselines, narrowed by a chosen framework", async () => {
      await mount();
      await openTab("Policies");
      expect(lastGet()).toEqual(["/compliance/policies"]);
      const n = calls();
      await chooseFramework(NIST);
      expect(since(n)).toEqual([[`/compliance/policies?framework_id=${NIST}`]]);
    });

    it("lists each baseline, or says there are none", async () => {
      await mount();
      await openTab("Policies");
      expect(bodyRows().map(rowCells)).toEqual([
        [norm("ISO 27001 Linux baseline"), "linux", "v3", "4", "active"],
        [norm("NIST CSF Windows baseline"), "windows", "v1", "1", "draft"],
      ]);
      expect(
        [...mainTable().tHead.rows[0].cells].map((c) => squash(c)),
      ).toEqual([
        "Baseline Name",
        "Platform",
        "Version",
        "Rules Count",
        "Status",
      ]);
      cleanup();
      on("/compliance/policies", { data: { data: [] } });
      await mount();
      await openTab("Policies");
      expect(bodyText()).toContain(
        'No baseline policies defined. Click "Create Baseline Policy" to define one.',
      );
    });

    it("expanding a baseline reads its rules once and lists them; collapsing reads nothing", async () => {
      await mount();
      await openTab("Policies");
      let n = calls();
      await toggle("ISO 27001 Linux baseline");
      expect(since(n)).toEqual([["/compliance/policies/pol-1/rules"]]);
      expect(bodyText()).toContain("Policy Rules & Check Parameters");
      expect(bodyRows(rulesTable()).map(rowCells)).toEqual([
        [
          "a.8.8",
          norm(
            "Management of technical vulnerabilitiesRule Code: ccure.linux.sshd.permit_root_login",
          ),
          "high",
          norm("credentialed_config sshd.permit_root_login equals no"),
          "configure",
        ],
        [
          "pr.aa.05",
          norm(
            "Access permissions and authorizationsRule Code: manual.pr_aa_05",
          ),
          "medium",
          "manualreview",
          "configure",
        ],
        [
          "a.5.1",
          norm(
            "Policies for information securityRule Code: ccure.policy.present",
          ),
          "low",
          "network",
          "configure",
        ],
        [
          "n/a",
          norm("Unmapped checkRule Code: ccure.unmapped"),
          "critical",
          "network",
          "configure",
        ],
      ]);
      n = calls();
      await toggle("ISO 27001 Linux baseline");
      expect(rulesTable()).toBeNull();
      expect(since(n)).toEqual([]);
      await toggle("ISO 27001 Linux baseline");
      await toggle("NIST CSF Windows baseline");
      expect(since(n)).toEqual([
        ["/compliance/policies/pol-1/rules"],
        ["/compliance/policies/pol-2/rules"],
      ]);
      expect(mainTable().querySelectorAll("table")).toHaveLength(1);
    });

    it("says while rules load and when there are none", async () => {
      const pending = deferred();
      on(/\/rules$/, pending.promise);
      await mount();
      await openTab("Policies");
      await toggle("ISO 27001 Linux baseline");
      expect(bodyText()).toContain("Loading policy rules...");
      await act(async () => pending.resolve({ data: { data: [] } }));
      await flush();
      expect(bodyText()).toContain("No rules linked to this policy.");
    });

    it("reports rules that failed to load", async () => {
      on(/\/rules$/, () =>
        Promise.reject({
          response: { data: { detail: "Rules store unavailable" } },
          message: "Request failed",
        }),
      );
      await mount();
      await openTab("Policies");
      await toggle("ISO 27001 Linux baseline");
      expect(bodyText()).toContain(
        "Failed to load policy rules: Rules store unavailable",
      );
    });

    it("Configure opens the rule dialog without collapsing the baseline or reading anything", async () => {
      await mount();
      await openTab("Policies");
      await toggle("ISO 27001 Linux baseline");
      const n = calls();
      fireEvent.click(
        within(rowOf("A.8.8", rulesTable())).getByRole("button", {
          name: "Configure",
        }),
      );
      await flush();
      expectDialog("Configure Rule Parameters");
      expect(rulesTable()).not.toBeNull();
      expect(since(n)).toEqual([]);
    });

    it("pages the baselines 25 at a time", async () => {
      on("/compliance/policies", {
        data: { data: Array.from({ length: 60 }, (_, i) => policy(i + 1)) },
      });
      await mount();
      await openTab("Policies");
      expect(firstColumn()).toHaveLength(25);
      expect(pageStatus()).toBe("Page 1 of 3");
      expect(
        [...selectWith("10,25,50,100").options].map((o) => o.value),
      ).toEqual(["10", "25", "50", "100"]);
      fireEvent.click(nextButton());
      await flush();
      expect(pageStatus()).toBe("Page 2 of 3");
      expect(firstColumn()[0]).toBe(norm("Baseline 26"));
      await choose(selectWith("10,25,50,100"), "10");
      expect(pageStatus()).toBe("Page 1 of 6");
    });
  });

  describe("Findings", () => {
    const statusFilter = () => selectWith("all,pass,fail,manual_review");
    const severityFilter = () => selectWith("all,CRITICAL,HIGH,MEDIUM,LOW");
    const assetFilter = () =>
      [...document.querySelectorAll("select")].find((s) =>
        [...s.options].some((o) => o.value === "asset-1"),
      );
    const searchBox = () =>
      document.querySelector('input[placeholder="Search by Control, Rule..."]');
    const actionNames = (row) =>
      within(row)
        .queryAllByRole("button")
        .map((b) => squash(b));
    const findingsRead = (query = "") =>
      `/compliance/findings?limit=10000${query}`;

    it("opens by reading every finding, narrowed by a chosen framework", async () => {
      await mount();
      await openTab("Findings");
      expect(lastGet()).toEqual([findingsRead()]);
      const n = calls();
      await chooseFramework(NIST);
      expect(since(n)).toEqual([[findingsRead(`&framework_id=${NIST}`)]]);
    });

    it("lists each finding", async () => {
      await mount();
      await openTab("Findings");
      expect(bodyRows().map(rowCells)).toEqual([
        [
          "a.8.8",
          norm(
            "Management of technical vulnerabilitiesRule Code: ccure.linux.sshd.permit_root_login",
          ),
          "high",
          norm("web-01Reboot Required10.70.0.11"),
          "credentialed",
          "fail",
          norm("EvidenceRemediateWaiverEdit Rule"),
        ],
        [
          "a.5.24",
          norm("Incident management planning"),
          "medium",
          "global",
          "manual",
          norm("manual_reviewNo credential was in scope for this host."),
          norm("Evidenceverify"),
        ],
        [
          "a.8.2",
          norm("Privileged access rightsRule Code: ccure.win.local_admins"),
          "critical",
          "10.70.0.12",
          "network",
          "pass",
          norm("EvidenceEdit Rule"),
        ],
        [
          "a.8.9",
          norm("Configuration management"),
          "low",
          norm("db-0110.70.0.13"),
          "credentialed",
          "fail",
          norm("EvidenceRemediateWaiver"),
        ],
      ]);
      expect(
        [...mainTable().tHead.rows[0].cells].map((c) => squash(c)),
      ).toEqual([
        "Control ID",
        "Rule / Control Title",
        "Severity",
        "Asset Name / IP",
        "Scan Mode",
        "Status",
        "Actions",
      ]);
    });

    it("Remediate and Waiver for a failure, Verify for manual review, Edit Rule wherever there is a rule", async () => {
      await mount();
      await openTab("Findings");
      /* P1-3 added Evidence to every row, before the status-dependent
         controls. What this test protects is unchanged: which *status*
         earns Remediate, Waiver, Verify and Edit Rule. Evidence is offered
         on every verdict because what a pass rested on is as much a
         reviewer's question as what a failure did. */
      expect(actionNames(rowOf("A.8.8"))).toEqual([
        "Evidence",
        "Remediate",
        "Waiver",
        "Edit Rule",
      ]);
      expect(actionNames(rowOf("A.5.24"))).toEqual(["Evidence", "Verify"]);
      expect(actionNames(rowOf("A.8.2"))).toEqual(["Evidence", "Edit Rule"]);
      expect(actionNames(rowOf("A.8.9"))).toEqual([
        "Evidence",
        "Remediate",
        "Waiver",
      ]);
    });

    it("filters in the browser, without reading again", async () => {
      await mount();
      await openTab("Findings");
      const n = calls();
      expect(
        [...assetFilter().options].map((o) => [o.value, o.textContent]),
      ).toEqual([
        ["all", "All Assets"],
        ["asset-1", "web-01 (10.70.0.11)"],
        ["asset-2", "10.70.0.12"],
        ["asset-3", "db-01 (10.70.0.13)"],
      ]);
      expect(
        screen.queryByRole("button", { name: "Clear Filters" }),
      ).toBeNull();

      await choose(assetFilter(), "asset-1");
      expect(firstColumn()).toEqual(["a.8.8"]);
      expect(bodyText()).toContain(
        "Showing 1–1 of 1 findings (filtered from 4 total)",
      );
      fireEvent.click(screen.getByRole("button", { name: "Clear Filters" }));
      await flush();
      expect(firstColumn()).toHaveLength(4);
      expect(bodyText()).toContain("Showing 1–4 of 4 findings");
      expect(bodyText()).not.toContain("filtered from");

      await choose(statusFilter(), "fail");
      expect(firstColumn()).toEqual(["a.8.8", "a.8.9"]);
      await choose(statusFilter(), "all");
      await choose(severityFilter(), "CRITICAL");
      expect(firstColumn()).toEqual(["a.8.2"]);
      await choose(severityFilter(), "all");
      await choose(searchBox(), "PermitRootLogin YES");
      expect(firstColumn()).toEqual(["a.8.9"]);
      await choose(searchBox(), "web-01");
      expect(firstColumn()).toEqual(["a.8.8"]);
      await choose(searchBox(), "no such finding");
      expect(bodyText()).toContain(
        "No matching compliance findings discovered.",
      );
      expect(since(n)).toEqual([]);
    });

    it("offers the implementation-group filter for CIS Controls only, without Clear Filters", async () => {
      activeIds = [ISO, NIST, "cfw_cis_v8_1"];
      await mount();
      await openTab("Findings");
      expect(selectWith("all,ig1,ig2,ig3")).toBeFalsy();
      await chooseFramework("cfw_cis_v8_1");
      await choose(selectWith("all,ig1,ig2,ig3"), "ig2");
      expect(firstColumn()).toEqual(["a.8.9"]);
      expect(
        screen.queryByRole("button", { name: "Clear Filters" }),
      ).toBeNull();
    });

    it("shows no rows and no empty message while the findings load", async () => {
      const pending = deferred();
      on(/^\/compliance\/findings/, pending.promise);
      await mount();
      await openTab("Findings");
      expect(bodyText()).not.toContain(
        "Management of technical vulnerabilities",
      );
      expect(bodyText()).not.toContain("No matching compliance findings");
      await act(async () => pending.resolve({ data: { data: FINDINGS } }));
      await flush();
      expect(firstColumn()).toHaveLength(4);
    });

    it("pages 50 at a time and returns to page 1 when a filter changes", async () => {
      on(/^\/compliance\/findings/, { data: { data: manyFindings(60) } });
      await mount();
      await openTab("Findings");
      expect(firstColumn()).toHaveLength(50);
      expect(pageStatus()).toBe("Page 1 of 2");
      expect(
        [...selectWith("25,50,100,250").options].map((o) => o.value),
      ).toEqual(["25", "50", "100", "250"]);
      fireEvent.click(nextButton());
      await flush();
      expect(pageStatus()).toBe("Page 2 of 2");
      expect(bodyText()).toContain("Showing 51–60 of 60 findings");
      await choose(statusFilter(), "fail");
      expect(pageStatus()).toBe("Page 1 of 1");
      expect(firstColumn()).toHaveLength(30);
    });

    it("Remediate opens the remediation dialog, which reads the stored credentials and nothing else", async () => {
      allowCredentials = true;
      await mount();
      await openTab("Findings");
      const n = calls();
      fireEvent.click(
        within(rowOf("A.8.8")).getByRole("button", { name: "Remediate" }),
      );
      await flush();
      expectDialog("Remediate Finding");
      expect(since(n)).toEqual([["/compliance/credentials"]]);
    });

    it("Waiver opens the waiver dialog and reads nothing", async () => {
      await mount();
      await openTab("Findings");
      const n = calls();
      fireEvent.click(
        within(rowOf("A.8.9")).getByRole("button", { name: "Waiver" }),
      );
      await flush();
      expectDialog("Request Exception Waiver");
      expect(since(n)).toEqual([]);
    });

    it("Verify opens the attestation dialog and reads that control's evidence", async () => {
      await mount();
      await openTab("Findings");
      const n = calls();
      fireEvent.click(
        within(rowOf("A.5.24")).getByRole("button", { name: "Verify" }),
      );
      await flush();
      expectDialog("Control Manual Attestation");
      expect(since(n)).toEqual([["/compliance/controls/A.5.24/evidence"]]);
    });

    it("Edit Rule opens the rule dialog and reads nothing", async () => {
      await mount();
      await openTab("Findings");
      const n = calls();
      fireEvent.click(
        within(rowOf("A.8.2")).getByRole("button", { name: "Edit Rule" }),
      );
      await flush();
      expectDialog("Configure Rule Parameters");
      expect(since(n)).toEqual([]);
    });

    describe("polling", () => {
      const advance = async (ms) => {
        await act(async () => {
          vi.advanceTimersByTime(ms);
        });
        await flush();
      };
      const findingsReads = () =>
        api.get.mock.calls.filter(([u]) => u.startsWith("/compliance/findings"))
          .length;

      it.each(["pending_reverify", "queued", "running"])(
        "reads quietly every 5 seconds while a finding is %s, and stops on leaving the tab",
        async (status) => {
          vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
          on(/^\/compliance\/findings/, {
            data: {
              data: [...FINDINGS, { ...FINDINGS[3], id: "f-5", status }],
            },
          });
          await mount();
          await openTab("Findings");
          expect(findingsReads()).toBe(1);
          await advance(4999);
          expect(findingsReads()).toBe(1);
          await advance(1);
          expect(findingsReads()).toBe(2);
          expect(lastGet()).toEqual([findingsRead()]);
          expect(
            document.querySelector(".loading-bar, .cwh-loading"),
          ).toBeNull();
          expect(firstColumn()).toHaveLength(5);
          await advance(5000);
          expect(findingsReads()).toBe(3);
          await openTab("Dashboard");
          await advance(20000);
          expect(findingsReads()).toBe(3);
        },
      );

      it("does not poll when no finding is re-checking", async () => {
        vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
        await mount();
        await openTab("Findings");
        await advance(20000);
        expect(findingsReads()).toBe(1);
      });
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 26B — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const view = (name) => document.querySelector(`.cwv-${name}`);

describe("ComplianceWorkspace views — batch 26b", () => {
  describe("Dashboard", () => {
    it("names each card by its heading and lists the KPIs as terms", async () => {
      await mount();
      for (const name of [
        "Overall Score",
        "Risk-Weighted Score",
        "All Frameworks",
        "Executive Compliance Reports & SoA Hub",
        "Compliance Score by Framework",
      ])
        expect(
          screen.getByRole("heading", { level: 2, name }),
        ).toBeInTheDocument();
      expect([...view("dashboard").querySelectorAll("dt")].map(squash)).toEqual(
        ["Passed", "Failed", "Active Waivers"],
      );
      expect([...view("dashboard").querySelectorAll("dd")].map(squash)).toEqual(
        ["40", "10", "2"],
      );
    });

    it("labels the report menu, groups the formats as pressed buttons, and groups the quick downloads", async () => {
      await mount();
      const menu = within(view("dashboard")).getByLabelText("Report");
      expect(menu.tagName).toBe("SELECT");
      const formats = screen.getByRole("group", { name: "Report format" });
      const pdf = within(formats).getByRole("button", { name: "PDF" });
      const word = within(formats).getByRole("button", {
        name: "Word (.docx)",
      });
      expect(pdf).toHaveAttribute("aria-pressed", "true");
      expect(word).toHaveAttribute("aria-pressed", "false");
      fireEvent.click(word);
      await flush();
      expect(pdf).toHaveAttribute("aria-pressed", "false");
      expect(word).toHaveAttribute("aria-pressed", "true");
      const quick = screen.getByRole("group", { name: "Quick downloads" });
      expect(within(quick).getAllByRole("button").map(squash)).toEqual([
        "SoA PDF",
        "SoA Word",
        "Executive Brief (PDF)",
        "NIST CSF PDF",
      ]);
    });

    it("draws each framework's score as a named progress bar", async () => {
      await mount();
      for (const name of ["ISO/IEC 27001:2022", "NIST CSF v2.0"]) {
        const bar = screen.getByRole("progressbar", { name });
        expect(bar).toHaveAttribute("aria-valuenow", "86");
      }
    });

    it("labels the NIS 2 turnover field", async () => {
      activeIds = [ISO, NIST, "cfw_nis2"];
      await mount();
      await chooseFramework("cfw_nis2");
      const field = screen.getByLabelText("Annual Global Turnover (EUR €)");
      expect(field).toHaveAttribute("type", "number");
    });
  });

  describe("Controls", () => {
    it("labels search and status, captions the register and scopes its headers", async () => {
      await mount();
      await openTab("Controls");
      const section = view("controls");
      expect(within(section).getByLabelText("Search controls")).toHaveAttribute(
        "type",
        "search",
      );
      expect(within(section).getByLabelText("Status").tagName).toBe("SELECT");
      expect(squash(mainTable().caption)).toBe("Control register");
      for (const th of mainTable().tHead.querySelectorAll("th"))
        expect(th).toHaveAttribute("scope", "col");
      expect(
        [...mainTable().querySelectorAll("tbody th[scope=row]")].map(squash),
      ).toEqual(["A.5.1", "A.8.8", "GV.OC-01", "A.7.4", "A.6.7"]);
      expect(
        [...section.querySelectorAll("tbody .cc-badge")].map(squash),
      ).toEqual([
        "PASS",
        "FAIL",
        "MANUAL REVIEW",
        "NOT ASSESSED",
        "NOT APPLICABLE",
      ]);
    });

    it("announces loading instead of claiming nothing matches", async () => {
      const pending = deferred();
      on(/^\/compliance\/frameworks\//, pending.promise);
      await mount();
      await openTab("Controls");
      const section = view("controls");
      expect(within(section).getAllByRole("status").map(squash)).toContain(
        "Loading results",
      );
      expect(section.querySelectorAll(".cc-skeleton").length).toBeGreaterThan(
        0,
      );
      await act(async () => pending.resolve({ data: CONTROLS }));
      await flush();
    });
  });

  describe("Policies", () => {
    it("expands a baseline from a named button that reports its state and controls its rules", async () => {
      await mount();
      await openTab("Policies");
      expect(
        screen.getByRole("heading", { level: 2, name: "Policies" }),
      ).toBeInTheDocument();
      expect(squash(mainTable().caption)).toBe("Baseline policies");
      const button = screen.getByRole("button", {
        name: /ISO 27001 Linux baseline/,
      });
      expect(button).toHaveAttribute("type", "button");
      expect(button).toHaveAttribute("aria-expanded", "false");
      fireEvent.click(button);
      await flush();
      expect(button).toHaveAttribute("aria-expanded", "true");
      const region = document.getElementById(
        button.getAttribute("aria-controls"),
      );
      const rules = region.querySelector("table");
      expect(squash(rules.caption)).toBe("Rules in ISO 27001 Linux baseline");
      for (const th of rules.tHead.querySelectorAll("th"))
        expect(th).toHaveAttribute("scope", "col");
      expect(
        [...rules.querySelectorAll("tbody th[scope=row]")].map(squash),
      ).toEqual(["A.8.8", "PR.AA.05", "A.5.1", "N/A"]);
      fireEvent.click(button);
      await flush();
      expect(button).toHaveAttribute("aria-expanded", "false");
    });

    it("pages through a named navigation with a live page status", async () => {
      await mount();
      await openTab("Policies");
      const nav = screen.getByRole("navigation", {
        name: "Policies pagination",
      });
      expect(squash(within(nav).getByRole("status"))).toBe("Page 1 of 1");
      expect(
        within(view("policies")).getByRole("button", { name: "Last page" }),
      ).toBeDisabled();
    });
  });

  describe("Findings", () => {
    it("labels every filter, captions the findings, scopes the headers and badges severity", async () => {
      await mount();
      await openTab("Findings");
      const section = view("findings");
      expect(
        screen.getByRole("heading", { level: 2, name: "Findings" }),
      ).toBeInTheDocument();
      for (const label of ["Search findings", "Asset", "Status", "Severity"])
        expect(within(section).getByLabelText(label)).toBeInTheDocument();
      expect(squash(mainTable().caption)).toBe("Compliance findings");
      for (const th of mainTable().tHead.querySelectorAll("th"))
        expect(th).toHaveAttribute("scope", "col");
      expect(
        [...mainTable().querySelectorAll("tbody th[scope=row]")].map(squash),
      ).toEqual(["A.8.8", "A.5.24", "A.8.2", "A.8.9"]);
      expect(
        bodyRows().map((r) => squash(r.cells[2].querySelector(".cc-badge"))),
      ).toEqual(["High", "Medium", "Critical", "Low"]);
      expect(
        screen.getByRole("navigation", { name: "Findings pagination" }),
      ).toBeInTheDocument();
    });

    it("while loading, shows placeholder rows and announces it", async () => {
      const pending = deferred();
      on(/^\/compliance\/findings/, pending.promise);
      await mount();
      await openTab("Findings");
      const section = view("findings");
      expect(section.querySelectorAll(".cc-skeleton").length).toBeGreaterThan(
        0,
      );
      expect(within(section).getAllByRole("status").map(squash)).toContain(
        "Loading results",
      );
      await act(async () => pending.resolve({ data: { data: FINDINGS } }));
      await flush();
    });
  });

  describe("presentation", () => {
    const LEGACY =
      /^(db-|cw-pagination|mono$|metric-card|metrics-grid|radial-score|kpis-list|quad|progress-container|comp-progress-fill|nist-badge|dashboard-view|danger$|info$|actions-cell$)/;
    const expectClean = (root) => {
      expect(root).toBeTruthy();
      const styled = [...root.querySelectorAll("[style]")].filter(
        (el) => !el.classList.contains("cc-progress__bar"),
      );
      expect(styled).toEqual([]);
      const classes = [...root.querySelectorAll("[class]")].flatMap((el) => [
        ...el.classList,
      ]);
      expect(classes.filter((c) => LEGACY.test(c))).toEqual([]);
    };

    it("renders no inline style and no legacy class inside the four views", async () => {
      activeIds = [ISO, NIST, "cfw_nis2"];
      await mount();
      expectClean(view("dashboard"));
      await chooseFramework("cfw_nis2");
      expectClean(view("dashboard"));
      await chooseFramework("all");
      await openTab("Controls");
      expectClean(view("controls"));
      await openTab("Policies");
      fireEvent.click(
        screen.getByRole("button", { name: /ISO 27001 Linux baseline/ }),
      );
      await flush();
      expectClean(view("policies"));
      await openTab("Findings");
      expectClean(view("findings"));
    });

    it("the views' source uses design-system parts and the stylesheet is token-only", () => {
      const source = readFileSync(
        path.join(SRC, "pages/ComplianceWorkspace.jsx"),
        "utf8",
      ).replace(/\r\n/g, "\n");
      expect(source).toMatch(
        /import\s+["']\.\.\/styles\/compliance-views\.css["']/,
      );
      const at = (needle, from = 0) => {
        const i = source.indexOf(needle, from);
        expect(i).toBeGreaterThan(-1);
        return i;
      };
      const dashboard = at('{activeTab === "dashboard" && summary && (');
      const marketplace = at('{activeTab === "marketplace" && (');
      const policies = at('{activeTab === "policies" && (', marketplace);
      const controls = at('{activeTab === "controls" && (');
      const findings = at('{activeTab === "findings" &&');
      const exceptions = at('{activeTab === "exceptions" && (');
      for (const block of [
        source.slice(dashboard, marketplace),
        source.slice(policies, controls),
        source.slice(controls, findings),
        source.slice(findings, exceptions),
      ]) {
        expect(block).not.toMatch(/style=\{/);
        expect(block.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
        expect(block).not.toMatch(/\b(?:rgba?|hsla?)\(|var\(--/);
        expect(block).not.toMatch(/className=["{`][^"}`]*\bdb-/);
        expect(block).not.toMatch(
          /<(table|select|input|button|PaginationBar|Skeleton)\b/,
        );
        expect(block).toMatch(/<Ccure[A-Z]/);
      }

      const cssPath = path.join(SRC, "styles/compliance-views.css");
      expect(existsSync(cssPath)).toBe(true);
      const css = readFileSync(cssPath, "utf8");
      expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
      expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
      expect(css.match(/var\(--(?!ccure-)[a-z0-9-]+/g) || []).toEqual([]);
      expect(css).not.toMatch(/prefers-color-scheme|ux4g|!important/i);
      expect(css).toMatch(/@media \(max-width: 640px\)/);
      const selectors = css
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .split("{")
        .slice(0, -1)
        .map((s) => s.split("}").pop().trim())
        .filter((s) => s && !s.startsWith("@"));
      for (const s of selectors) expect(s).toMatch(/\.cwv-/);
    });
  });
});
