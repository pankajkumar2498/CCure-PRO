/**
 * The state catalogue.
 *
 *   ready    — expression that must hold before anything is measured
 *   actions  — clicks and waits that put the page into the state
 *   probes   — keyboard checks run after the capture, with real key events:
 *              `tabTo` is an expression over `el` (the focused element) that
 *              Tab is pressed until it holds; `press`, `expect`,
 *              `expectRequest` and `then` describe what must follow
 *   tracked  — selectors whose computed style and geometry are recorded
 *
 * States measure what a page does, never what a build is expected to do: the
 * same catalogue runs against the build before a change and after it.
 */
import {
  ANALYST,
  ASSETS_READONLY,
  FINDINGS_READONLY,
  AR_ASSETS,
  AR_SERVICES,
  AR_SERVICE_ASSETS,
  AR_CERTS,
  VB_GROUPS,
  VB_FINDINGS,
  VB_FINDINGS_NULL_CVSS,
  VB_FINDING_DETAIL,
  SD_STUBS,
  SD_STUBS_EMPTY,
  SD_STUBS_ERROR,
  SD_STUBS_NULL_CVSS,
  DASHBOARD_ADMIN,
  DASHBOARD_RESTRICTED,
  NO_DASHBOARD,
  CW_STUBS,
  CW26A_WAIVERS,
  CW26A_MANY,
  CW26B_SUMMARY,
  CW26B_SUMMARY_NIS2,
  CW26B_MARKETPLACE_NIS2,
  CW26B_CONTROLS,
  CW26B_POLICIES,
  CW26B_POLICY_RULES,
  CW26B_FINDINGS,
  CW27_ORG_ADMIN,
  CW27_MARKETPLACE,
  CW28_CONTROLS,
  CW28_EVIDENCE,
  CW29_CREDENTIALS,
  CW30_REQUESTS,
  CW30_FINDINGS,
  CW31_GAP,
  CW31_GAP_LONG,
  CW31_GAP_EMPTY,
  CW31_CREDENTIALS,
  SCANS_READONLY,
  P2_STUBS,
  P2_RUNNING_SESSION,
  P1_STUBS,
  P1_INTERACTIVE_SESSION,
  P1_SCOPE_SESSION,
  P1_DONE_SESSION,
  AMT_STUBS,
  AMT_STATS_UNLINKED,
  NO_SCANS_READ,
  NM_STUBS,
  NM_EMPTY,
  SCANS_ADMIN,
  SH_STUBS,
  SH_STUBS_EMPTY,
  CR_STUBS,
  CR_TICKET,
  CR_SECRETS,
  CR_FRAMES,
  crSocketScript,
  P3_STUBS,
  P3_REPORT_SESSION,
  P3_RUNNING_SESSION,
  P3_ERROR_SESSION,
  P3_CANCELLED_SESSION,
  P3_UNREACHABLE_SESSION,
  p3StartSession,
  P3_TICKET,
  P3_SECRET,
  P3_WRITES,
  p3SocketScript,
  NS_STUBS,
  NS_TICKET,
  NS_SECRET,
  NS_WRITES,
  NS_TARGET_FILE,
  NS_RUNNING_FRAMES,
  NS_COMPLETE_FRAMES,
  nsSession,
  nsSocketScript,
  PLATFORM_MODULES,
  PH_ORG_ADMIN,
  PH_SUPERADMIN,
  PH_ORGS,
} from "./fixtures.mjs";

const BOTH = ["light", "dark"];
const LIGHT = ["light"];

const byText = (tag, re) =>
  `[...document.querySelectorAll(${JSON.stringify(tag)})].find((e) => ${re}.test((e.textContent || "").trim()))`;
const hasText = (re) => `${re}.test(document.body.innerText)`;
const dialogOpen = `!!document.querySelector('[role=dialog], .vb-drawer')`;

const PAGE_TRACKED = [
  "h1",
  "table thead th",
  "table tbody td",
  "[role=tablist] [role=tab]",
  "[role=dialog]",
];

/* ── AssetRegistry ────────────────────────────────────────────────────────── */
const AR_BASE = {
  persona: ANALYST,
  stubs: {
    "/assets": AR_ASSETS,
    "/assets/services": AR_SERVICES,
    "/assets/services/assets": AR_SERVICE_ASSETS,
    "/assets/certificates": AR_CERTS,
  },
  tracked: PAGE_TRACKED,
};

const AR_STATES = [
  {
    ...AR_BASE,
    id: "ar-assets",
    route: "/assets",
    themes: BOTH,
    ready: "document.querySelectorAll('table tbody tr').length >= 3",
    probes: [
      { id: "tab-focus-ring", tabTo: "el.getAttribute('role') === 'tab'" },
      {
        id: "sort-ip-by-keyboard",
        tabTo:
          "!!el.closest('th') && /IP \\/ Host/.test(el.closest('th').textContent)",
        press: "Enter",
        wait: 600,
        expectRequest: {
          path: "/api/assets",
          query: { sort_by: "ip_address" },
        },
      },
      // Scoped to the table body: the "Managed state" filter select above the
      // table matches the same word.
      {
        id: "managed-toggle-reachable",
        tabTo:
          "!!el.closest('tbody') && /managed/i.test(el.getAttribute('aria-label') || el.textContent || '')",
      },
      {
        id: "row-drilldown-by-keyboard",
        tabTo:
          "el.tagName === 'A' && /\\/assets\\/a-1$/.test(el.getAttribute('href') || '')",
        press: "Enter",
        wait: 800,
        expect: "location.pathname === '/assets/a-1'",
      },
    ],
  },
  {
    ...AR_BASE,
    id: "ar-assets-readonly",
    route: "/assets",
    themes: LIGHT,
    persona: ASSETS_READONLY,
    ready: "document.querySelectorAll('table tbody tr').length >= 3",
  },
  {
    ...AR_BASE,
    id: "ar-assets-empty",
    route: "/assets",
    themes: LIGHT,
    stubs: { ...AR_BASE.stubs, "/assets": { assets: [], total: 0 } },
    ready: hasText("/No assets discovered/"),
  },
  {
    ...AR_BASE,
    id: "ar-assets-error",
    route: "/assets",
    themes: BOTH,
    stubs: { ...AR_BASE.stubs, "/assets": { __status: 500 } },
    ready: hasText("/Failed to load assets/"),
  },
  {
    ...AR_BASE,
    id: "ar-services",
    route: "/assets?tab=services",
    themes: BOTH,
    ready: hasText("/snmp/"),
    probes: [
      {
        id: "sort-port-by-keyboard",
        tabTo:
          "!!el.closest('th') && /^Port/.test(el.closest('th').textContent.trim())",
        press: "Enter",
        wait: 600,
        expectRequest: {
          path: "/api/assets/services",
          query: { sort_by: "port" },
        },
      },
      {
        id: "view-assets-dialog-by-keyboard",
        tabTo: "/View Assets/.test(el.textContent || '')",
        press: "Enter",
        wait: 600,
        expect: dialogOpen,
        then: [
          {
            press: "Escape",
            wait: 400,
            expect: "!document.querySelector('[role=dialog]')",
          },
        ],
      },
    ],
  },
  {
    ...AR_BASE,
    id: "ar-services-dialog",
    route: "/assets?tab=services",
    themes: BOTH,
    ready: hasText("/snmp/"),
    actions: [
      { click: byText("button", "/View Assets/") },
      { waitFor: hasText("/Associated Assets for/") },
    ],
  },
  {
    ...AR_BASE,
    id: "ar-tls",
    route: "/assets?tab=tls",
    themes: BOTH,
    ready: hasText("/srv-02\\.corp\\.test/"),
    probes: [
      {
        id: "cert-asset-link-reachable",
        tabTo:
          "el.tagName === 'A' && /\\/assets\\/a-1$/.test(el.getAttribute('href') || '')",
      },
    ],
  },
  {
    ...AR_BASE,
    id: "ar-assets-mobile",
    route: "/assets",
    themes: LIGHT,
    viewport: [390, 1400],
    ready: "document.querySelectorAll('table tbody tr').length >= 3",
  },
];

/* ── VulnerabilityBrowser ─────────────────────────────────────────────────── */
const VB_BASE = {
  persona: ANALYST,
  stubs: {
    "/findings/grouped/by-component": VB_GROUPS,
    "/findings": VB_FINDINGS,
    "/findings/f-1": VB_FINDING_DETAIL,
  },
  tracked: PAGE_TRACKED,
};

const OPEN_DRAWER_BY_KEYBOARD = {
  id: "open-drawer-by-keyboard",
  // Any control in the first finding row other than the NVD link.
  tabTo:
    "!!el.closest('tbody tr') && el.closest('tbody tr') === document.querySelector('tbody tr') && !/nvd\\.nist\\.gov/.test(el.getAttribute('href') || '')",
  press: "Enter",
  wait: 700,
  expect: dialogOpen,
  then: [
    {
      press: "Escape",
      wait: 400,
      expect: "!document.querySelector('[role=dialog], .vb-drawer')",
    },
  ],
};

const VB_STATES = [
  {
    ...VB_BASE,
    id: "vb-grouped",
    route: "/vulnerabilities",
    themes: BOTH,
    ready: hasText("/google-chrome/"),
    probes: [
      {
        id: "view-toggle-focus-ring",
        tabTo: "el.hasAttribute('aria-pressed')",
      },
      {
        id: "group-drilldown-by-keyboard",
        tabTo:
          "!!el.closest('tbody tr') && /google-chrome/.test(el.textContent || '')",
        press: "Enter",
        wait: 900,
        expectRequest: {
          path: "/api/findings",
          query: { search: "google-chrome" },
        },
      },
    ],
  },
  {
    ...VB_BASE,
    id: "vb-cve",
    route: "/vulnerabilities?view=cve",
    themes: BOTH,
    ready: hasText("/CVE-2026-1111/"),
    probes: [
      {
        id: "view-toggle-focus-ring",
        tabTo: "el.hasAttribute('aria-pressed')",
      },
      OPEN_DRAWER_BY_KEYBOARD,
    ],
  },
  {
    ...VB_BASE,
    id: "vb-cve-readonly",
    route: "/vulnerabilities?view=cve",
    themes: LIGHT,
    persona: FINDINGS_READONLY,
    ready: hasText("/CVE-2026-1111/"),
    probes: [OPEN_DRAWER_BY_KEYBOARD],
  },
  {
    ...VB_BASE,
    id: "vb-cve-nullcvss",
    route: "/vulnerabilities?view=cve",
    themes: LIGHT,
    stubs: { ...VB_BASE.stubs, "/findings": VB_FINDINGS_NULL_CVSS },
    ready: hasText("/CVE-2026-4444/"),
    readyTimeout: 8000,
  },
  {
    ...VB_BASE,
    id: "vb-drawer",
    route: "/vulnerabilities?view=cve",
    themes: BOTH,
    ready: hasText("/CVE-2026-1111/"),
    actions: [
      { click: "document.querySelector('tbody tr')" },
      { waitFor: hasText("/A crafted page executes code/") },
    ],
  },
  {
    ...VB_BASE,
    id: "vb-drawer-accept",
    route: "/vulnerabilities?view=cve",
    themes: LIGHT,
    ready: hasText("/CVE-2026-1111/"),
    actions: [
      { click: "document.querySelector('tbody tr')" },
      { waitFor: hasText("/A crafted page executes code/") },
      { click: byText("button", "/Accept Risk/") },
      { waitFor: "!!document.querySelector('textarea')" },
    ],
  },
  {
    ...VB_BASE,
    id: "vb-empty",
    route: "/vulnerabilities?view=cve",
    themes: LIGHT,
    stubs: { ...VB_BASE.stubs, "/findings": { findings: [], total: 0 } },
    ready: hasText("/No vulnerabilities or findings identified/"),
  },
  {
    ...VB_BASE,
    id: "vb-error",
    route: "/vulnerabilities",
    themes: LIGHT,
    stubs: {
      ...VB_BASE.stubs,
      "/findings/grouped/by-component": { __status: 500 },
    },
    ready: hasText("/Failed to load findings/"),
  },
  {
    ...VB_BASE,
    id: "vb-cve-mobile",
    route: "/vulnerabilities?view=cve",
    themes: LIGHT,
    viewport: [390, 1400],
    ready: hasText("/CVE-2026-1111/"),
  },
];

/* ── Shared selectors for pages still on dashboard.css ────────────────────── */
const SHARED_TRACKED = [
  "h1",
  ".db-page-header",
  ".db-card",
  ".db-card-title",
  ".db-btn",
  ".db-btn--primary",
  ".db-table th",
  ".db-table td",
  ".db-sev-badge",
  ".db-tag",
];

/* ── SecurityDashboard (batch 17) ─────────────────────────────────────────── */
const SD_BASE = {
  // Audit's dashboard address since Phase 12.2; /dashboard redirects here.
  route: "/audit-dashboard",
  persona: ANALYST,
  stubs: SD_STUBS,
  tracked: [...PAGE_TRACKED, "h2"],
};

const sdReady = hasText("/CVE-2026-1111/");

// Section titles are upper-cased by CSS on the legacy page and innerText
// reports the rendered case, so text readiness checks are case-insensitive.
const sdText = (source) => hasText(`/${source}/i`);

// The date-range control was a <div> before batch 17. The innermost element
// carrying the text is clicked and the click bubbles to whichever owns it.
const sdDateToggle = `[...document.querySelectorAll("button, div, span")].filter((e) => /^(📅\\s*)?Last 30 days/.test((e.textContent || "").trim())).pop()`;

// React Router reads navigation state from history.state.usr; seeded before
// the app boots, this is exactly what the registration flow hands the page.
const SD_WELCOME_INIT = `(() => { try { if (!history.state || !history.state.usr) history.replaceState({ usr: { isNewRegistration: true }, key: "harness", idx: 0 }, ""); } catch (e) {} })();`;

const SD_PROBES = {
  dateMenu: {
    id: "date-range-menu-by-keyboard",
    tabTo:
      "el.tagName === 'BUTTON' && /Last 30 days/.test(el.textContent || '')",
    press: "Enter",
    wait: 400,
    expect: "/Year to date/.test(document.body.innerText)",
    then: [
      {
        press: "Escape",
        wait: 400,
        expect: "!/Year to date/.test(document.body.innerText)",
      },
    ],
  },
  metricCard: {
    id: "metric-card-by-keyboard",
    tabTo:
      "(el.tagName === 'A' || el.tagName === 'BUTTON') && /Critical Findings/.test(el.textContent || '')",
    press: "Enter",
    wait: 800,
    expect:
      "location.pathname === '/vulnerabilities' && location.search === '?severity=Critical'",
  },
  assetRow: {
    id: "top-asset-row-by-keyboard",
    tabTo:
      "el.tagName === 'A' && /\\/assets\\/a-1$/.test(el.getAttribute('href') || '')",
    press: "Enter",
    wait: 800,
    expect: "location.pathname === '/assets/a-1'",
  },
  cveRow: {
    id: "top-cve-row-by-keyboard",
    tabTo:
      "el.tagName === 'A' && /search=CVE-2026-1111/.test(el.getAttribute('href') || '')",
    press: "Enter",
    wait: 800,
    expect: "location.search === '?search=CVE-2026-1111'",
  },
  tabs: {
    id: "tabs-by-keyboard",
    tabTo: "el.getAttribute('role') === 'tab'",
    press: "ArrowRight",
    wait: 400,
    expect:
      "((document.querySelector('[role=tab][aria-selected=true]') || {}).textContent || '').trim() === 'Assets'",
  },
  welcomeEscape: {
    id: "welcome-dialog-escape",
    tabTo:
      "el.tagName === 'BUTTON' && !!el.closest('[role=dialog], .modal-panel')",
    press: "Escape",
    wait: 500,
    expect: "!/Welcome to CCure Audit PRO/i.test(document.body.innerText)",
  },
};

const SD_TABS = [
  ["assets", "Assets", "Asset Registry — Quick View"],
  ["vulns", "Vulnerabilities", "Vulnerability Intelligence — Quick View"],
  ["scans", "Scans", "Scan Activity & History"],
  ["compliance", "Compliance", "Compliance & Security Posture"],
];

const SD_STATES = [
  {
    ...SD_BASE,
    id: "sd-default",
    themes: BOTH,
    ready: sdReady,
    probes: [SD_PROBES.dateMenu, SD_PROBES.metricCard],
  },
  {
    ...SD_BASE,
    id: "sd-asset-row-keyboard",
    themes: LIGHT,
    ready: sdReady,
    probes: [SD_PROBES.assetRow],
  },
  {
    ...SD_BASE,
    id: "sd-cve-row-keyboard",
    themes: LIGHT,
    ready: sdReady,
    probes: [SD_PROBES.cveRow],
  },
  {
    ...SD_BASE,
    id: "sd-tabs-keyboard",
    themes: LIGHT,
    ready: sdReady,
    probes: [SD_PROBES.tabs],
  },
  {
    ...SD_BASE,
    id: "sd-date-menu",
    themes: LIGHT,
    ready: sdReady,
    actions: [{ click: sdDateToggle }, { waitFor: hasText("/Year to date/") }],
  },
  {
    ...SD_BASE,
    id: "sd-admin",
    themes: BOTH,
    persona: DASHBOARD_ADMIN,
    ready: `${sdReady} && ${sdText("scan started")}`,
  },
  {
    ...SD_BASE,
    id: "sd-restricted",
    themes: LIGHT,
    persona: DASHBOARD_RESTRICTED,
    ready: hasText("/Informational only/"),
  },
  {
    ...SD_BASE,
    id: "sd-noaccess",
    themes: LIGHT,
    persona: NO_DASHBOARD,
    ready: "location.pathname === '/scan'",
    readyTimeout: 10000,
  },
  {
    ...SD_BASE,
    id: "sd-empty",
    themes: LIGHT,
    stubs: SD_STUBS_EMPTY,
    ready: hasText("/No assets found/"),
  },
  {
    ...SD_BASE,
    id: "sd-error",
    themes: LIGHT,
    stubs: SD_STUBS_ERROR,
    ready: hasText("/No assets found/"),
  },
  {
    ...SD_BASE,
    id: "sd-nullcvss",
    themes: LIGHT,
    stubs: SD_STUBS_NULL_CVSS,
    ready: hasText("/CVE-2026-4444/"),
    readyTimeout: 8000,
  },
  {
    ...SD_BASE,
    id: "sd-welcome",
    themes: BOTH,
    init: SD_WELCOME_INIT,
    ready: `${sdText("Welcome to CCure Audit PRO")} && ${sdReady}`,
    probes: [SD_PROBES.welcomeEscape],
  },
  {
    ...SD_BASE,
    id: "sd-mobile",
    themes: LIGHT,
    viewport: [390, 1600],
    ready: sdReady,
  },
  ...SD_TABS.map(([id, label, heading]) => ({
    ...SD_BASE,
    id: `sd-tab-${id}`,
    themes: LIGHT,
    ready: sdReady,
    actions: [
      { click: byText("button", `/^${label}$/`) },
      { waitFor: sdText(heading) },
    ],
  })),
  {
    ...SD_BASE,
    id: "sd-tab-audit",
    themes: LIGHT,
    persona: DASHBOARD_ADMIN,
    ready: sdReady,
    actions: [{ click: byText("button", "/^Audit$/") }, { waitFor: "true" }],
  },
];

const CW_TABS = [
  ["dashboard", "Dashboard"],
  ["marketplace", "Marketplace"],
  ["policies", "Policies"],
  ["controls", "Controls"],
  ["findings", "Findings"],
  ["exceptions", "Exceptions"],
  ["credentials", "Credentials Manager"],
  ["approvals", "Approvals Queue"],
];

// The workspace's tabs are not buttons and its title is not a heading, so the
// state finds the tab bar by its contents and clicks the label inside it.
const cwTabClick = (label) => `(() => {
  const bar = [...document.querySelectorAll("div")].find(
    (d) => d.children.length >= 8 && /Approvals Queue/.test(d.textContent || "") && /Marketplace/.test(d.textContent || "") && (d.textContent || "").length < 400,
  );
  if (!bar) return null;
  return [...bar.querySelectorAll("*")].find(
    (e) => (e.textContent || "").trim() === ${JSON.stringify(label)} && ![...e.children].some((c) => (c.textContent || "").trim() === ${JSON.stringify(label)}),
  );
})()`;

const CW_STATES = CW_TABS.map(([id, label]) => ({
  id: `cw-${id}`,
  route: "/compliance",
  themes: BOTH,
  persona: ANALYST,
  stubs: CW_STUBS,
  tracked: SHARED_TRACKED,
  ready: hasText("/Policy Compliance/"),
  actions:
    id === "dashboard"
      ? []
      : [{ click: cwTabClick(label) }, { waitFor: "true" }],
}));

/* ── ComplianceWorkspace Exceptions (batch 26a) ───────────────────────────── */
/* The Exceptions tab: one read of pending findings, paged in the browser.
   Nothing here presses a control that writes. There is no failed-read state:
   the workspace reports a failed read through console.error on every build,
   which the harness would count as a console error, so the unit tests pin
   that path instead. */
const CW26A_BASE = {
  route: "/compliance",
  persona: ANALYST,
  stubs: { ...CW_STUBS, "/compliance/findings": CW26A_WAIVERS },
  tracked: [...PAGE_TRACKED, "h2", "nav", "table"],
  ready: hasText("/Policy Compliance/i"),
};
const CW26A_OPEN = [
  { click: cwTabClick("Exceptions") },
  { waitFor: hasText("/Compensating control documented/") },
];
const cw26aButton = (name) =>
  `[...document.querySelectorAll("button")].find((b) => /^${name}$/.test((b.textContent || "").trim()))`;
// Chooses a framework in the header's selector the way a person's choice
// would reach React, and returns the selector (a script click opens nothing).
const cwChooseFramework = (id) => `(() => {
  const select = [...document.querySelectorAll("select")].find((s) => [...s.options].some((o) => o.value === "all"));
  if (!select) return null;
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(select, ${JSON.stringify(id)});
  select.dispatchEvent(new Event("change", { bubbles: true }));
  return select;
})()`;

const CW26A_STATES = [
  {
    ...CW26A_BASE,
    id: "cw26a-populated",
    themes: BOTH,
    actions: CW26A_OPEN,
    probes: [
      {
        id: "page-size-focus",
        tabTo:
          "el.tagName === 'SELECT' && [...el.options].map((o) => o.value).join(',') === '10,25,50,100'",
      },
    ],
  },
  {
    ...CW26A_BASE,
    id: "cw26a-paged",
    themes: BOTH,
    stubs: { ...CW_STUBS, "/compliance/findings": CW26A_MANY },
    actions: [
      { click: cwTabClick("Exceptions") },
      { waitFor: hasText("/CTRL-25/") },
      { click: cw26aButton("Next") },
      { waitFor: hasText("/Page 2 of 3/i") },
    ],
    probes: [
      {
        id: "next-by-keyboard",
        tabTo:
          "el.tagName === 'BUTTON' && /^Next$/.test((el.textContent || '').trim())",
        press: "Enter",
        expect: hasText("/Page 3 of 3/i"),
      },
    ],
  },
  {
    ...CW26A_BASE,
    id: "cw26a-loading",
    themes: BOTH,
    stubs: { ...CW_STUBS, "/compliance/findings": { __pending: true } },
    actions: [{ click: cwTabClick("Exceptions") }, { waitFor: "true" }],
  },
  {
    ...CW26A_BASE,
    id: "cw26a-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    actions: CW26A_OPEN,
  },
  {
    ...CW26A_BASE,
    id: "cw26a-framework",
    themes: LIGHT,
    actions: [
      { click: cwChooseFramework("cfw_nist_csf_v2") },
      {
        waitFor:
          "[...document.querySelectorAll('select')].some((s) => s.value === 'cfw_nist_csf_v2')",
      },
      ...CW26A_OPEN,
    ],
  },
];

/* ── ComplianceWorkspace read-only views (batch 26b) ──────────────────────── */
/* Dashboard, Controls, Policies and Findings, populated. Nothing here clicks a
   download, submits or opens a dialog, or touches Marketplace, Approvals or
   Credentials. No finding is re-checking, so the Findings tab never starts its
   5-second poll. Every action works on the build before and after the batch. */
const CW26B_BASE = {
  route: "/compliance",
  persona: ANALYST,
  tracked: [...PAGE_TRACKED, "h2", "h3", "table", "[role=progressbar]"],
  ready: hasText("/Policy Compliance/i"),
};
const CW26B_DASHBOARD_STUBS = {
  ...CW_STUBS,
  "/compliance/summary": CW26B_SUMMARY,
};
// The workspace score and both framework rows all read 86%.
const CW26B_DASHBOARD_LOADED = {
  waitFor: "(document.body.innerText.match(/86%/g) || []).length >= 3",
};
const CW26B_CONTROLS_STUBS = {
  ...CW_STUBS,
  "/compliance/frameworks/cfw_iso27001_2022/controls": CW26B_CONTROLS,
};
const CW26B_CONTROLS_OPEN = [
  { click: cwTabClick("Controls") },
  { waitFor: hasText("/Policies for information security/") },
];
const CW26B_POLICIES_STUBS = {
  ...CW_STUBS,
  "/compliance/policies": CW26B_POLICIES,
  "/compliance/policies/pol-1/rules": CW26B_POLICY_RULES,
};
const CW26B_POLICIES_OPEN = [
  { click: cwTabClick("Policies") },
  { waitFor: hasText("/ISO 27001 Linux baseline/") },
];
const CW26B_FINDINGS_STUBS = {
  ...CW_STUBS,
  "/compliance/findings": CW26B_FINDINGS,
};
const CW26B_FINDINGS_OPEN = [
  { click: cwTabClick("Findings") },
  { waitFor: hasText("/Management of technical vulnerabilities/") },
];
// The policy's own row, or the control inside it that expands it.
const cw26bPolicyToggle = (name) => `(() => {
  const row = [...document.querySelectorAll("tbody tr")].find((r) => (r.textContent || "").includes(${JSON.stringify(name)}));
  return row ? row.querySelector("[aria-expanded]") || row : null;
})()`;
// Chooses a value in the select offering exactly these options, the way a
// person's choice reaches React.
const cw26bChoose = (values, value) => `(() => {
  const select = [...document.querySelectorAll("select")].find((s) => [...s.options].map((o) => o.value).join(",") === ${JSON.stringify(values)});
  if (!select) return null;
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(select, ${JSON.stringify(value)});
  select.dispatchEvent(new Event("change", { bubbles: true }));
  return select;
})()`;

const CW26B_STATES = [
  {
    ...CW26B_BASE,
    id: "cw26b-dashboard",
    themes: BOTH,
    stubs: CW26B_DASHBOARD_STUBS,
    actions: [CW26B_DASHBOARD_LOADED],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-dashboard-framework",
    themes: BOTH,
    stubs: CW26B_DASHBOARD_STUBS,
    actions: [
      CW26B_DASHBOARD_LOADED,
      { click: cwChooseFramework("cfw_nist_csf_v2") },
      { waitFor: hasText("/Core Functions Breakdown/i") },
    ],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-dashboard-nis2",
    themes: LIGHT,
    stubs: {
      ...CW26B_DASHBOARD_STUBS,
      "/compliance/marketplace": CW26B_MARKETPLACE_NIS2,
      "/compliance/summary": CW26B_SUMMARY_NIS2,
    },
    ready: `${hasText("/Policy Compliance/i")} && [...document.querySelectorAll("option")].some((o) => o.value === "cfw_nis2")`,
    actions: [
      { click: cwChooseFramework("cfw_nis2") },
      { waitFor: hasText("/Fine Risk Exposure Calculator/i") },
    ],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-dashboard-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW26B_DASHBOARD_STUBS,
    actions: [CW26B_DASHBOARD_LOADED],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-controls",
    themes: BOTH,
    stubs: CW26B_CONTROLS_STUBS,
    actions: CW26B_CONTROLS_OPEN,
  },
  {
    ...CW26B_BASE,
    id: "cw26b-controls-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW26B_CONTROLS_STUBS,
    actions: CW26B_CONTROLS_OPEN,
  },
  {
    ...CW26B_BASE,
    id: "cw26b-policies",
    themes: BOTH,
    stubs: CW26B_POLICIES_STUBS,
    actions: [
      ...CW26B_POLICIES_OPEN,
      { click: cw26bPolicyToggle("ISO 27001 Linux baseline") },
      { waitFor: hasText("/sshd\\.permit_root_login/") },
    ],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-policies-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW26B_POLICIES_STUBS,
    actions: CW26B_POLICIES_OPEN,
    probes: [
      {
        id: "expand-by-keyboard",
        tabTo:
          "el.getAttribute('aria-expanded') === 'false' && /ISO 27001 Linux baseline/.test(el.textContent || '')",
        press: "Enter",
        expect: hasText("/sshd\\.permit_root_login/"),
      },
    ],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-findings",
    themes: BOTH,
    stubs: CW26B_FINDINGS_STUBS,
    actions: CW26B_FINDINGS_OPEN,
  },
  {
    ...CW26B_BASE,
    id: "cw26b-findings-filtered",
    themes: LIGHT,
    stubs: CW26B_FINDINGS_STUBS,
    actions: [
      ...CW26B_FINDINGS_OPEN,
      { click: cw26bChoose("all,pass,fail,manual_review", "fail") },
      { waitFor: hasText("/filtered from 4 total/") },
    ],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-findings-loading",
    themes: LIGHT,
    stubs: { ...CW_STUBS, "/compliance/findings": { __pending: true } },
    actions: [{ click: cwTabClick("Findings") }, { waitFor: "true" }],
  },
  {
    ...CW26B_BASE,
    id: "cw26b-findings-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW26B_FINDINGS_STUBS,
    actions: CW26B_FINDINGS_OPEN,
  },
];

/* ── ComplianceWorkspace ordinary writes (batch 27) ────────────────────────── */
/* Marketplace, and the three ordinary-write dialogs opened and left open. No
   state installs, uninstalls, submits a dialog, approves, or opens anything
   that carries credentials or evidence: opening these dialogs sends nothing. */
const CW27_BASE = {
  route: "/compliance",
  persona: ANALYST,
  tracked: [...PAGE_TRACKED, "h2", "h3", "form", "[role=dialog] label"],
  ready: hasText("/Policy Compliance/i"),
};
const CW27_MARKETPLACE_STUBS = {
  ...CW_STUBS,
  "/compliance/marketplace": CW27_MARKETPLACE,
};
const CW27_MARKETPLACE_OPEN = [
  { click: cwTabClick("Marketplace") },
  { waitFor: hasText("/SOC 2 Type II/") },
];
const cw27DialogOpen = (button) =>
  `!!document.querySelector("[role=dialog]") && ${hasText(button)}`;
const CW27_POLICY_DIALOG_OPEN = [
  { click: cwTabClick("Policies") },
  { waitFor: hasText("/Create Baseline Policy/") },
  { click: byText("button", "/Create Baseline Policy/") },
  { waitFor: cw27DialogOpen("/Publish Baseline/") },
];
const CW27_WAIVER_DIALOG_OPEN = [
  ...CW26B_FINDINGS_OPEN,
  { click: byText("button", "/^Waiver$/") },
  { waitFor: cw27DialogOpen("/Request Waiver/") },
];
// Tab from inside the open dialog to its first text field.
const CW27_DIALOG_FIELD_FOCUS = {
  id: "dialog-field-focus",
  tabTo:
    "!!el.closest('[role=dialog]') && (el.tagName === 'TEXTAREA' || (el.tagName === 'INPUT' && el.type === 'text'))",
};

const CW27_STATES = [
  {
    ...CW27_BASE,
    id: "cw27-marketplace-admin",
    themes: BOTH,
    persona: CW27_ORG_ADMIN,
    stubs: CW27_MARKETPLACE_STUBS,
    actions: CW27_MARKETPLACE_OPEN,
  },
  {
    ...CW27_BASE,
    id: "cw27-marketplace-analyst",
    themes: LIGHT,
    stubs: CW27_MARKETPLACE_STUBS,
    actions: CW27_MARKETPLACE_OPEN,
  },
  {
    ...CW27_BASE,
    id: "cw27-marketplace-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    persona: CW27_ORG_ADMIN,
    stubs: CW27_MARKETPLACE_STUBS,
    actions: CW27_MARKETPLACE_OPEN,
  },
  {
    ...CW27_BASE,
    id: "cw27-policy-dialog",
    themes: BOTH,
    stubs: CW_STUBS,
    actions: CW27_POLICY_DIALOG_OPEN,
    probes: [CW27_DIALOG_FIELD_FOCUS],
  },
  {
    ...CW27_BASE,
    id: "cw27-rule-dialog",
    themes: BOTH,
    stubs: CW26B_POLICIES_STUBS,
    actions: [
      ...CW26B_POLICIES_OPEN,
      { click: cw26bPolicyToggle("ISO 27001 Linux baseline") },
      { waitFor: hasText("/sshd\\.permit_root_login/") },
      { click: byText("button", "/^Configure$/") },
      { waitFor: cw27DialogOpen("/Save Rule Configuration/") },
    ],
    probes: [CW27_DIALOG_FIELD_FOCUS],
  },
  {
    ...CW27_BASE,
    id: "cw27-waiver-dialog",
    themes: BOTH,
    stubs: CW26B_FINDINGS_STUBS,
    actions: CW27_WAIVER_DIALOG_OPEN,
    probes: [CW27_DIALOG_FIELD_FOCUS],
  },
  {
    ...CW27_BASE,
    id: "cw27-waiver-dialog-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW26B_FINDINGS_STUBS,
    actions: CW27_WAIVER_DIALOG_OPEN,
  },
];

/* ── ComplianceWorkspace attestation and evidence (batch 28) ──────────────── */
/* The Control Manual Attestation dialog opened from Controls and from Findings
   and left open. No state chooses a file, saves an attestation, downloads or
   removes evidence: the picker is never opened and Save is never pressed. The
   two states that show the removal question press Remove only where Remove
   asks first — the migrated build, whose Remove is named for its file. On the
   legacy build Remove is the delete itself, so there the same step clicks the
   dialog's title instead. The router refuses every write regardless, and the
   batch report counts them. */
const CW28_BASE = {
  route: "/compliance",
  persona: ANALYST,
  tracked: [
    ...PAGE_TRACKED,
    "h2",
    "h3",
    "form",
    "[role=dialog] label",
    "[role=dialog] li",
  ],
  ready: hasText("/Policy Compliance/i"),
};
const CW28_CONTROLS_STUBS = {
  ...CW_STUBS,
  "/compliance/frameworks/cfw_iso27001_2022/controls": CW28_CONTROLS,
  "/compliance/controls/cct_iso_5_1/evidence": CW28_EVIDENCE,
  "/compliance/controls/cct_iso_6_7/evidence": { data: [] },
};
const CW28_FINDINGS_STUBS = {
  ...CW26B_FINDINGS_STUBS,
  "/compliance/controls/A.5.24/evidence": { data: [] },
};
// The Attest button in a control's row of the register.
const cw28Attest = (controlNumber) => `(() => {
  const row = [...document.querySelectorAll("tbody tr")].find((r) => r.cells.length > 1 && (r.cells[0].textContent || "").trim() === ${JSON.stringify(controlNumber)});
  return row ? [...row.querySelectorAll("button")].find((b) => (b.textContent || "").trim() === "Attest") : null;
})()`;
const CW28_ATTEST_OPEN = [
  ...CW26B_CONTROLS_OPEN,
  { click: cw28Attest("A.5.1") },
  {
    waitFor: `${cw27DialogOpen("/Save Attestation/")} && ${hasText("/board-minutes\\.docx/")}`,
  },
];
const CW28_EXCLUDED_OPEN = [
  ...CW26B_CONTROLS_OPEN,
  { click: cw28Attest("A.6.7") },
  {
    waitFor: `${cw27DialogOpen("/Save Attestation/")} && ${hasText("/6\\.1\\.3\\(d\\)/")}`,
  },
];
const CW28_VERIFY_OPEN = [
  ...CW26B_FINDINGS_OPEN,
  { click: byText("button", "/^Verify$/") },
  { waitFor: cw27DialogOpen("/Save Attestation/") },
];
const CW28_LONG_NAME = CW28_EVIDENCE.data[0].filename;
// Remove on the migrated build asks and sends nothing; on the legacy build it
// is the delete, so the click goes to the dialog's title.
const CW28_REMOVE_OR_TITLE = `(document.querySelector(${JSON.stringify(`[role=dialog] button[aria-label="Remove ${CW28_LONG_NAME}"]`)}) || document.querySelector("[role=dialog] h2"))`;
const CW28_QUESTION_OPEN = [
  ...CW28_ATTEST_OPEN,
  { click: CW28_REMOVE_OR_TITLE },
  {
    waitFor: `!document.querySelector('[role=dialog] button[aria-label^="Remove "]') || /Delete Information-Security-Policy/.test(document.body.innerText)`,
  },
];
// Tab from inside the open dialog to its file picker.
const CW28_FILE_FOCUS = {
  id: "dialog-file-focus",
  tabTo:
    "!!el.closest('[role=dialog]') && el.tagName === 'INPUT' && el.type === 'file'",
};

const CW28_STATES = [
  {
    ...CW28_BASE,
    id: "cw28-attest",
    themes: BOTH,
    stubs: CW28_CONTROLS_STUBS,
    actions: CW28_ATTEST_OPEN,
    probes: [CW28_FILE_FOCUS],
  },
  {
    ...CW28_BASE,
    id: "cw28-attest-excluded",
    themes: BOTH,
    stubs: CW28_CONTROLS_STUBS,
    actions: CW28_EXCLUDED_OPEN,
    probes: [CW27_DIALOG_FIELD_FOCUS],
  },
  {
    ...CW28_BASE,
    id: "cw28-attest-verify",
    themes: LIGHT,
    stubs: CW28_FINDINGS_STUBS,
    actions: CW28_VERIFY_OPEN,
  },
  {
    ...CW28_BASE,
    id: "cw28-attest-question",
    themes: BOTH,
    stubs: CW28_CONTROLS_STUBS,
    actions: CW28_QUESTION_OPEN,
  },
  {
    ...CW28_BASE,
    id: "cw28-attest-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW28_CONTROLS_STUBS,
    actions: CW28_QUESTION_OPEN,
  },
];

/* ── ComplianceWorkspace Credentials Manager (batch 29) ───────────────────── */
/* The Credentials Manager tab: the saved list for an organisation admin and for
   an analyst, empty, with the key field chosen, on a phone, and with the
   deletion question open. No state types into a field, saves a credential or
   deletes one: Save is never pressed and no password or key is entered. The
   two states that show the deletion question press Delete only where Delete
   asks in a dialog — the migrated build, whose Delete is named for its
   credential. On the legacy build Delete opens the browser's confirm, which the
   runner does not answer and a confirmation would turn into a DELETE, so there
   the same step clicks the list's title instead. The router refuses every
   write regardless, and the batch report counts them. */
const CW29_BASE = {
  route: "/compliance",
  persona: CW27_ORG_ADMIN,
  tracked: [...PAGE_TRACKED, "h2", "form", "label", "[role=dialog]"],
  ready: hasText("/Policy Compliance/i"),
};
const CW29_STUBS = {
  ...CW_STUBS,
  "/compliance/credentials": CW29_CREDENTIALS,
};
const CW29_OPEN = [
  { click: cwTabClick("Credentials Manager") },
  { waitFor: hasText("/Bastion keys/") },
];
// Delete on the migrated build opens a dialog and sends nothing; on the legacy
// build it is the browser's confirm, so the click goes to the list's title.
const CW29_DELETE_OR_TITLE = `(document.querySelector('button[aria-label="Delete Linux fleet"]') || [...document.querySelectorAll("h2, div")].find((e) => e.children.length === 0 && (e.textContent || "").trim() === "Saved Credentials"))`;
const CW29_DELETE_OPEN = [
  ...CW29_OPEN,
  { click: CW29_DELETE_OR_TITLE },
  {
    waitFor: `!document.querySelector('button[aria-label^="Delete "]') || !!document.querySelector("[role=dialog]")`,
  },
];
// Tab to the register form's password field, and to its key field.
const CW29_PASSWORD_FOCUS = {
  id: "password-field-focus",
  tabTo: "el.tagName === 'INPUT' && el.type === 'password'",
};
const CW29_KEY_FOCUS = {
  id: "key-field-focus",
  tabTo: "el.tagName === 'TEXTAREA'",
};

const CW29_STATES = [
  {
    ...CW29_BASE,
    id: "cw29-credentials-admin",
    themes: BOTH,
    stubs: CW29_STUBS,
    actions: CW29_OPEN,
    probes: [CW29_PASSWORD_FOCUS],
  },
  {
    ...CW29_BASE,
    id: "cw29-credentials-analyst",
    themes: LIGHT,
    persona: ANALYST,
    stubs: CW29_STUBS,
    actions: CW29_OPEN,
  },
  {
    ...CW29_BASE,
    id: "cw29-credentials-empty",
    themes: LIGHT,
    stubs: { ...CW_STUBS, "/compliance/credentials": [] },
    actions: [
      { click: cwTabClick("Credentials Manager") },
      { waitFor: hasText("/Save Target Credential/") },
    ],
  },
  {
    ...CW29_BASE,
    id: "cw29-credentials-key",
    themes: LIGHT,
    stubs: CW29_STUBS,
    actions: [
      ...CW29_OPEN,
      { click: cw26bChoose("password,key", "key") },
      { waitFor: `!!document.querySelector("form textarea")` },
    ],
    probes: [CW29_KEY_FOCUS],
  },
  {
    ...CW29_BASE,
    id: "cw29-credentials-delete",
    themes: BOTH,
    stubs: CW29_STUBS,
    actions: CW29_DELETE_OPEN,
  },
  {
    ...CW29_BASE,
    id: "cw29-credentials-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW29_STUBS,
    actions: CW29_OPEN,
  },
];

/* ── ComplianceWorkspace credential-bearing execution (batch 30) ──────────── */
/* The Approvals Queue, the execution log, and the remediation and rollback
   dialog opened and left open. No state approves, rejects, cancels, dispatches,
   copies or types: nothing is sent but reads, and no credential is entered.
   View Logs, Rollback and Remediate only open a dialog on either build. The
   two states that show a queue question press Approve or Cancel only where it
   asks in a dialog — the migrated build, whose action is named for its ticket.
   On the legacy build Approve posts at once and Cancel opens the browser's
   confirm, so there the same step clicks the queue's title instead. The router
   refuses every write regardless, and the batch report counts them. */
const CW30_BASE = {
  route: "/compliance",
  persona: CW27_ORG_ADMIN,
  tracked: [
    ...PAGE_TRACKED,
    "h2",
    "h3",
    "h4",
    "table",
    "fieldset",
    "[role=dialog]",
  ],
  ready: hasText("/Policy Compliance/i"),
};
const CW30_QUEUE_STUBS = {
  ...CW_STUBS,
  "/compliance/remediations/requests": CW30_REQUESTS,
  "/compliance/credentials": CW29_CREDENTIALS,
};
const CW30_FINDINGS_STUBS = {
  ...CW26B_FINDINGS_STUBS,
  "/compliance/findings": CW30_FINDINGS,
  "/compliance/credentials": CW29_CREDENTIALS,
};
const CW30_QUEUE_OPEN = [
  { click: cwTabClick("Approvals Queue") },
  { waitFor: hasText("/crrq_cw30pending/") },
];
// A ticket's action by its visible label, in the ticket's own row.
const cw30Action = (ticket, label) => `(() => {
  const row = [...document.querySelectorAll("tbody tr")].find((r) => r.cells.length > 1 && (r.cells[0].textContent || "").trim() === ${JSON.stringify(ticket)});
  return row ? [...row.querySelectorAll("button")].find((b) => (b.textContent || "").trim() === ${JSON.stringify(label)}) : null;
})()`;
// A decision asks in a dialog on the migrated build; on the legacy build the
// click goes to the queue's title.
const cw30AskOrTitle = (name) =>
  `(document.querySelector(${JSON.stringify(`button[aria-label="${name}"]`)}) || [...document.querySelectorAll("h2, div")].find((e) => e.children.length === 0 && (e.textContent || "").trim() === "Remediation Approvals Queue"))`;
const CW30_ASKED = `!document.querySelector('button[aria-haspopup="dialog"]') || !!document.querySelector("[role=dialog]")`;
const CW30_REMEDIATE_OPEN = [
  ...CW26B_FINDINGS_OPEN,
  { click: byText("button", "/^Remediate$/") },
  { waitFor: cw27DialogOpen("/Close Guide/") },
];
// Tab from inside the open dialog to the one-time password field, and to the
// console output.
const CW30_PASSWORD_FOCUS = {
  id: "jit-password-focus",
  tabTo:
    "!!el.closest('[role=dialog]') && el.tagName === 'INPUT' && el.type === 'password'",
};
const CW30_CONSOLE_FOCUS = {
  id: "console-focus",
  tabTo: "!!el.closest('[role=dialog]') && el.tagName === 'PRE'",
};

const CW30_STATES = [
  {
    ...CW30_BASE,
    id: "cw30-queue-admin",
    themes: BOTH,
    stubs: CW30_QUEUE_STUBS,
    actions: CW30_QUEUE_OPEN,
  },
  {
    ...CW30_BASE,
    id: "cw30-queue-analyst",
    themes: LIGHT,
    persona: ANALYST,
    stubs: CW30_QUEUE_STUBS,
    actions: CW30_QUEUE_OPEN,
  },
  {
    ...CW30_BASE,
    id: "cw30-queue-empty",
    themes: LIGHT,
    stubs: { ...CW_STUBS, "/compliance/remediations/requests": { data: [] } },
    actions: [
      { click: cwTabClick("Approvals Queue") },
      { waitFor: hasText("/No approval tickets in this status/") },
    ],
  },
  {
    ...CW30_BASE,
    id: "cw30-queue-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW30_QUEUE_STUBS,
    actions: CW30_QUEUE_OPEN,
  },
  {
    ...CW30_BASE,
    id: "cw30-approve-ask",
    themes: BOTH,
    stubs: CW30_QUEUE_STUBS,
    actions: [
      ...CW30_QUEUE_OPEN,
      { click: cw30AskOrTitle("Approve crrq_cw30pending") },
      { waitFor: CW30_ASKED },
    ],
  },
  {
    ...CW30_BASE,
    id: "cw30-cancel-ask",
    themes: LIGHT,
    stubs: CW30_QUEUE_STUBS,
    actions: [
      ...CW30_QUEUE_OPEN,
      { click: cw30AskOrTitle("Cancel Rollback crrq_rollback_cw30own") },
      { waitFor: CW30_ASKED },
    ],
  },
  {
    ...CW30_BASE,
    id: "cw30-log-viewer",
    themes: BOTH,
    stubs: CW30_QUEUE_STUBS,
    actions: [
      ...CW30_QUEUE_OPEN,
      { click: cw30Action("crrq_cw30executed", "View Logs") },
      { waitFor: cw27DialogOpen("/Close Logs/") },
    ],
    probes: [CW30_CONSOLE_FOCUS],
  },
  {
    ...CW30_BASE,
    id: "cw30-rollback-dialog",
    themes: BOTH,
    stubs: CW30_QUEUE_STUBS,
    actions: [
      ...CW30_QUEUE_OPEN,
      { click: cw30Action("crrq_cw30executed", "Rollback") },
      { waitFor: cw27DialogOpen("/Close Guide/") },
    ],
  },
  {
    ...CW30_BASE,
    id: "cw30-remediate-dialog",
    themes: BOTH,
    stubs: CW30_FINDINGS_STUBS,
    actions: [
      ...CW30_REMEDIATE_OPEN,
      {
        click: `document.querySelector("[role=dialog] input[type=checkbox]")`,
      },
      {
        waitFor: `!!document.querySelector("[role=dialog] input[type=checkbox]:checked")`,
      },
    ],
    probes: [CW30_PASSWORD_FOCUS],
  },
  {
    ...CW30_BASE,
    id: "cw30-remediate-key",
    themes: LIGHT,
    stubs: CW30_FINDINGS_STUBS,
    actions: [
      ...CW30_REMEDIATE_OPEN,
      { click: cw26bChoose("password,key", "key") },
      { waitFor: `!!document.querySelector("[role=dialog] textarea")` },
    ],
  },
  {
    ...CW30_BASE,
    id: "cw30-remediate-stored",
    themes: LIGHT,
    stubs: CW30_FINDINGS_STUBS,
    actions: [
      ...CW30_REMEDIATE_OPEN,
      {
        click: `[...document.querySelectorAll("[role=dialog] input[type=radio]")][1]`,
      },
      { waitFor: hasText("/Choose Credential/") },
    ],
  },
  {
    ...CW30_BASE,
    id: "cw30-remediate-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW30_FINDINGS_STUBS,
    actions: CW30_REMEDIATE_OPEN,
  },
];

/* ── ComplianceWorkspace gap analysis and pagination (batch 31) ───────────── */
/* The gap-analysis dialog, opened from the header's Gap Analysis, and the
   Credentials Manager's pager. Every request is a read: Gap Analysis reads the
   gap analysis, and paging reads nothing. The router stubs the gap analysis by
   path, so any pair returns the stubbed result. No state recalculates, types
   or writes. */
const CW31_BASE = {
  route: "/compliance",
  persona: CW27_ORG_ADMIN,
  tracked: [...PAGE_TRACKED, "h2", "h3", "dl", "table", "nav", "[role=dialog]"],
  ready: hasText("/Policy Compliance/i"),
};
const cw31GapStubs = (gap) => ({
  ...CW_STUBS,
  "/compliance/gap-analysis": gap,
});
const CW31_GAP_OPEN = [
  { click: byText("button", "/Gap Analysis/") },
  { waitFor: cw27DialogOpen("/Recalculate Gap/") },
];
const CW31_CREDENTIAL_STUBS = {
  ...CW_STUBS,
  "/compliance/credentials": CW31_CREDENTIALS,
};
const CW31_CREDENTIALS_OPEN = [
  { click: cwTabClick("Credentials Manager") },
  { waitFor: hasText("/Fleet 25/") },
];
// Tab from inside the open dialog to its first framework choice, and to the
// breakdown's scroll region.
const CW31_SOURCE_FOCUS = {
  id: "gap-source-focus",
  tabTo: "!!el.closest('[role=dialog]') && el.tagName === 'SELECT'",
};
const CW31_RESULTS_FOCUS = {
  id: "gap-results-focus",
  tabTo:
    "!!el.closest('[role=dialog]') && el.getAttribute('role') === 'region'",
};

const CW31_STATES = [
  {
    ...CW31_BASE,
    id: "cw31-gap-dialog",
    themes: BOTH,
    stubs: cw31GapStubs(CW31_GAP),
    actions: CW31_GAP_OPEN,
    probes: [CW31_SOURCE_FOCUS],
  },
  {
    ...CW31_BASE,
    id: "cw31-gap-long",
    themes: LIGHT,
    stubs: cw31GapStubs(CW31_GAP_LONG),
    actions: CW31_GAP_OPEN,
    probes: [CW31_RESULTS_FOCUS],
  },
  {
    ...CW31_BASE,
    id: "cw31-gap-empty",
    themes: LIGHT,
    stubs: cw31GapStubs(CW31_GAP_EMPTY),
    actions: CW31_GAP_OPEN,
  },
  {
    ...CW31_BASE,
    id: "cw31-gap-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: cw31GapStubs(CW31_GAP),
    actions: CW31_GAP_OPEN,
  },
  {
    ...CW31_BASE,
    id: "cw31-credentials-pages",
    themes: BOTH,
    stubs: CW31_CREDENTIAL_STUBS,
    actions: CW31_CREDENTIALS_OPEN,
  },
  {
    ...CW31_BASE,
    id: "cw31-credentials-page2",
    themes: LIGHT,
    stubs: CW31_CREDENTIAL_STUBS,
    actions: [
      ...CW31_CREDENTIALS_OPEN,
      { click: byText("button", "/^Next$/") },
      { waitFor: hasText("/Page 2 of 2/") },
    ],
  },
  {
    ...CW31_BASE,
    id: "cw31-credentials-size",
    themes: LIGHT,
    stubs: CW31_CREDENTIAL_STUBS,
    actions: [
      ...CW31_CREDENTIALS_OPEN,
      { click: cw26bChoose("10,25,50,100", "10") },
      { waitFor: hasText("/Page 1 of 3/") },
    ],
  },
  {
    ...CW31_BASE,
    id: "cw31-credentials-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    stubs: CW31_CREDENTIAL_STUBS,
    actions: CW31_CREDENTIALS_OPEN,
  },
];

/* ── Phase2Results (batch 18) ─────────────────────────────────────────────── */
/* Phase 3 starts scans from an effect on mount, and Phase 2 hands off to it in
   automatic mode whenever the pipeline has a phase 3. So no state here pairs
   automatic mode with such a pipeline: scans that include phase 3 are only
   loaded with interactive mode seeded, and no probe ever presses "Run
   Vulnerability Audit". guard.mjs makes a Phase 3 mount impossible regardless. */
const P2_BASE = {
  persona: ANALYST,
  stubs: P2_STUBS,
  tracked: [...PAGE_TRACKED, "h2", "h3", "input[type=checkbox]", "code"],
};

const P2_INTERACTIVE = { cc_executionMode: "interactive" };

const p2Ready = `${hasText("/Hosts scanned/")} && ${hasText("/10\\.20\\.0\\.11/")}`;

// The legacy card header and the migrated disclosure button both toggle.
const p2Toggles = `[...document.querySelectorAll(".host-card-header, .p2-host__toggle")]`;
const P2_EXPAND = [
  { click: `${p2Toggles}[0]` },
  { waitFor: hasText("/Target OS Fingerprint/i") },
  { click: `${p2Toggles}[1]` },
  { waitFor: hasText("/UDP Services/i") },
];

const P2_PROBES = {
  hostDetails: {
    id: "host-details-by-keyboard",
    tabTo:
      "el.tagName === 'BUTTON' && /10\\.20\\.0\\.11(?!\\d)/.test((el.closest('.host-card, .p2-host') || {}).textContent || '')",
    press: "Enter",
    wait: 500,
    expect: "/Target OS Fingerprint/i.test(document.body.innerText)",
    then: [
      {
        press: "Enter",
        wait: 400,
        expect: "!/Target OS Fingerprint/i.test(document.body.innerText)",
      },
    ],
  },
  // Space on the table's checkbox for 10.20.0.11 drops it from the queue.
  selectHost: {
    id: "select-host-by-keyboard",
    tabTo:
      "el.type === 'checkbox' && !!el.closest('tr') && /10\\.20\\.0\\.11(?!\\d)/.test(el.closest('tr').textContent || '')",
    press: "Space",
    wait: 400,
    expect:
      "/2 hosts queued for vulnerability audit/.test(document.body.innerText)",
  },
  auditProfile: {
    id: "audit-profile-by-keyboard",
    tabTo:
      "el.tagName === 'BUTTON' && (el.textContent || '').trim() === 'Deep'",
    press: "Enter",
    wait: 400,
    expect:
      "((b) => !!b && (b.getAttribute('aria-pressed') === 'true' || b.classList.contains('filter-tab--active')))([...document.querySelectorAll('button')].find((b) => (b.textContent || '').trim() === 'Deep'))",
  },
};

const P2_STATES = [
  {
    ...P2_BASE,
    id: "p2-results",
    route: "/scan/p2-asset/phase2",
    themes: BOTH,
    ready: p2Ready,
    probes: [P2_PROBES.hostDetails],
  },
  {
    ...P2_BASE,
    id: "p2-expanded",
    route: "/scan/p2-asset/phase2",
    themes: BOTH,
    ready: p2Ready,
    actions: P2_EXPAND,
  },
  {
    ...P2_BASE,
    id: "p2-expanded-mobile",
    route: "/scan/p2-asset/phase2",
    themes: LIGHT,
    viewport: [390, 2600],
    ready: p2Ready,
    actions: P2_EXPAND,
  },
  {
    ...P2_BASE,
    id: "p2-interactive",
    route: "/scan/p2-audit/phase2",
    themes: BOTH,
    session: P2_INTERACTIVE,
    ready: hasText("/3 hosts queued for vulnerability audit/"),
    probes: [P2_PROBES.selectHost, P2_PROBES.auditProfile],
  },
  {
    ...P2_BASE,
    id: "p2-readonly",
    route: "/scan/p2-audit/phase2",
    themes: LIGHT,
    persona: SCANS_READONLY,
    session: P2_INTERACTIVE,
    ready: hasText("/3 hosts queued for vulnerability audit/"),
  },
  {
    ...P2_BASE,
    id: "p2-unreachable",
    route: "/scan/p2-unreachable/phase2",
    themes: BOTH,
    ready: hasText("/Host is unavailable/"),
  },
  {
    ...P2_BASE,
    id: "p2-no-results",
    route: "/scan/p2-no-results/phase2",
    themes: LIGHT,
    ready: hasText("/scanner worker was stopped/"),
  },
  {
    ...P2_BASE,
    id: "p2-load-error",
    route: "/scan/p2-missing/phase2",
    themes: LIGHT,
    ready: hasText("/Scan not found/"),
  },
  {
    ...P2_BASE,
    id: "p2-running",
    route: "/scan/asset-discovery",
    themes: BOTH,
    session: P2_RUNNING_SESSION,
    ready: hasText("/Port Scan Running/i"),
    // GET /scans/{id} every 4 s until results arrive (compare.mjs).
    repeatable: ["^GET /api/scans/p2-running -> "],
  },
];

/* ── Phase1Results (batch 19) ─────────────────────────────────────────────── */
/* "Run Port Scan" starts a port scan, and "View Port Scan Results" and
   "Continue to Port Scan" lead to Phase 2, which can hand off to Phase 3. No
   action or probe here touches any of the three: probes only select a host,
   change the port-scan mode, toggle an exclusion and change the host filter.
   Phase 1 itself never navigates on its own; every capture must end on a
   Phase 1 route. */
const P1_BASE = {
  persona: ANALYST,
  stubs: P1_STUBS,
  tracked: [
    ...PAGE_TRACKED,
    "h2",
    "input[type=checkbox]",
    "input[type=text]",
    "code",
  ],
};

const p1Hosts = hasText("/10\\.20\\.0\\.11/");

// The nearest ancestor naming the exclusion, legacy markup and migrated alike.
const p1Near = (label, other) =>
  `(() => { let n = el; for (let i = 0; i < 6 && n; i += 1, n = n.parentElement) { const t = n.textContent || ''; if (${label}.test(t)) return !${other}.test(t); } return false; })()`;

const P1_PROBES = {
  // Space on the table's checkbox for 10.20.0.11 drops it from the selection.
  selectHost: {
    id: "select-host-by-keyboard",
    tabTo:
      "el.type === 'checkbox' && !!el.closest('tr') && /10\\.20\\.0\\.11(?!\\d)/.test(el.closest('tr').textContent || '')",
    press: "Space",
    wait: 400,
    expect: "/\\b3 hosts selected/.test(document.body.innerText)",
  },
  customMode: {
    id: "custom-ports-mode-by-keyboard",
    tabTo:
      "el.tagName === 'BUTTON' && (el.textContent || '').trim() === 'Custom Ports'",
    press: "Enter",
    wait: 400,
    expect: "!!document.querySelector('input[placeholder^=\"e.g. 22,80\"]')",
  },
  excludePorts: {
    id: "exclude-ports-switch-by-keyboard",
    tabTo: `el.type === 'checkbox' && !el.closest('tr') && ${p1Near("/Exclude Specific Ports/", "/Exclude Specific IPs/")}`,
    press: "Space",
    wait: 400,
    expect: "!!document.querySelector('input[placeholder^=\"e.g. 2375\"]')",
  },
  filterAll: {
    id: "host-filter-by-keyboard",
    tabTo:
      "el.tagName === 'BUTTON' && /^All \\(5\\)$/.test((el.textContent || '').trim())",
    press: "Enter",
    wait: 400,
    expect: "/10\\.20\\.0\\.14/.test(document.body.innerText)",
  },
};

const P1_STATES = [
  {
    ...P1_BASE,
    id: "p1-basic",
    route: "/scan/p1-basic/phase1",
    themes: BOTH,
    ready: `${hasText("/Scan completed/")} && ${p1Hosts}`,
    probes: [P1_PROBES.filterAll],
  },
  {
    ...P1_BASE,
    id: "p1-asset-running",
    route: "/scan/p1-asset/phase1",
    themes: BOTH,
    ready: `${hasText("/Port Scan Running/i")} && ${p1Hosts}`,
    // Loaded once, then polled every 4 s while the port scan runs.
    repeatable: ["^GET /api/scans/p1-asset -> "],
  },
  {
    ...P1_BASE,
    id: "p1-audit-running",
    route: "/scan/p1-audit/phase1",
    themes: LIGHT,
    ready: `${hasText("/Port Scan Running/i")} && ${p1Hosts}`,
    repeatable: ["^GET /api/scans/p1-audit -> "],
  },
  {
    ...P1_BASE,
    id: "p1-phase2-done",
    route: "/scan/host-discovery",
    themes: BOTH,
    session: P1_DONE_SESSION,
    ready: `${hasText("/Port Scan Complete/")} && ${p1Hosts}`,
  },
  {
    ...P1_BASE,
    id: "p1-interactive",
    route: "/scan/host-discovery",
    themes: BOTH,
    session: P1_INTERACTIVE_SESSION,
    ready: `${hasText("/Configure & Run Port Scan/")} && ${hasText("/\\b4 hosts selected/")}`,
    probes: [
      P1_PROBES.selectHost,
      P1_PROBES.customMode,
      P1_PROBES.excludePorts,
    ],
  },
  {
    ...P1_BASE,
    id: "p1-scope",
    route: "/scan/host-discovery",
    themes: BOTH,
    session: P1_SCOPE_SESSION,
    ready: `${hasText("/Sensitive Ports Detected/")} && ${hasText("/Invalid IP, range, or CIDR format/")}`,
  },
  {
    ...P1_BASE,
    id: "p1-scope-mobile",
    route: "/scan/host-discovery",
    themes: LIGHT,
    viewport: [390, 2400],
    session: P1_SCOPE_SESSION,
    ready: `${hasText("/Sensitive Ports Detected/")} && ${hasText("/Invalid IP, range, or CIDR format/")}`,
  },
  {
    ...P1_BASE,
    id: "p1-readonly",
    route: "/scan/host-discovery",
    themes: LIGHT,
    persona: SCANS_READONLY,
    session: P1_INTERACTIVE_SESSION,
    ready: `${hasText("/Configure & Run Port Scan/")} && ${p1Hosts}`,
  },
  {
    ...P1_BASE,
    id: "p1-unreachable",
    route: "/scan/p1-unreachable/phase1",
    themes: BOTH,
    ready: hasText("/Host is unavailable/"),
  },
  {
    ...P1_BASE,
    id: "p1-no-results",
    route: "/scan/p1-no-results/phase1",
    themes: LIGHT,
    ready: hasText("/scanner worker was stopped/"),
  },
  {
    ...P1_BASE,
    id: "p1-load-error",
    route: "/scan/p1-missing/phase1",
    themes: LIGHT,
    ready: hasText("/Scan not found/"),
  },
];

/* ── AMTIntegration (batch 20) ────────────────────────────────────────────── */
/* The import replaces the organisation's AMT inventory, and the drop zone and
   the file input both open the native file chooser. No action or probe here
   activates either of them, Upload & Sync or Export CSV: probes only Tab to
   the file input, to Export and to an asset link. Opening a category and
   turning a page are reads. A persona without assets:update never reaches the
   page: the route sends it to /dashboard. */
const AMT_BASE = {
  route: "/admin/amt",
  persona: ANALYST,
  stubs: AMT_STUBS,
  tracked: [
    ...PAGE_TRACKED,
    "h2",
    "h3",
    "button",
    "input",
    "a[href^='/assets/']",
  ],
};

// Statistics have settled: Refresh Stats is disabled while they load.
const amtLoaded = `[...document.querySelectorAll("button")].some((b) => /Refresh Stats/.test(b.textContent || "") && !b.disabled)`;
const amtReady = `${amtLoaded} && ${hasText("/Linked & Active/")}`;

// The first element in document order carrying the Shadow IT label. The click
// bubbles to whichever element owns it (a <div> before batch 20).
const amtShadowIt = `[...document.querySelectorAll("span")].find((e) => /^Shadow IT \\(Unmanaged Rogue\\)/.test((e.textContent || "").trim()))`;

const amtOpenShadowIt = (until) => [
  { click: amtShadowIt },
  { waitFor: hasText(until) },
];

const AMT_DRILLDOWN_PATH = "/api/assets/reconciliation/drilldown";

const AMT_PROBES = {
  // Tab only. Enter or Space here would open the file chooser.
  fileInput: {
    id: "file-input-reachable",
    tabTo: "el.tagName === 'INPUT' && el.type === 'file'",
  },
  category: {
    id: "category-by-keyboard",
    tabTo:
      "el.tagName === 'BUTTON' && /^Shadow IT \\(Unmanaged Rogue\\)/.test((el.textContent || '').trim())",
    press: "Enter",
    wait: 600,
    expectRequest: {
      path: AMT_DRILLDOWN_PATH,
      query: { category: "shadow_it" },
    },
  },
  // Tab only. Enter would leave the page.
  assetLink: {
    id: "asset-link-reachable",
    tabTo:
      "el.tagName === 'A' && /\\/assets\\/amt-a-1$/.test(el.getAttribute('href') || '')",
  },
  // Tab only. Enter would start a download.
  exportButton: {
    id: "export-reachable",
    tabTo: "el.tagName === 'BUTTON' && /Export CSV/.test(el.textContent || '')",
  },
  nextPage: {
    id: "next-page-by-keyboard",
    tabTo: "el.tagName === 'BUTTON' && /Next/.test(el.textContent || '')",
    press: "Enter",
    wait: 600,
    expectRequest: { path: AMT_DRILLDOWN_PATH, query: { skip: "10" } },
  },
};

const AMT_STATES = [
  {
    ...AMT_BASE,
    id: "amt-overview",
    themes: BOTH,
    ready: amtReady,
    probes: [AMT_PROBES.fileInput, AMT_PROBES.category],
  },
  {
    ...AMT_BASE,
    id: "amt-drilldown",
    themes: BOTH,
    ready: amtReady,
    actions: amtOpenShadowIt("/kiosk-lobby-02/"),
    probes: [
      AMT_PROBES.assetLink,
      AMT_PROBES.exportButton,
      AMT_PROBES.nextPage,
    ],
  },
  {
    ...AMT_BASE,
    id: "amt-drilldown-mobile",
    themes: LIGHT,
    viewport: [390, 2400],
    ready: amtReady,
    actions: amtOpenShadowIt("/kiosk-lobby-02/"),
  },
  {
    ...AMT_BASE,
    id: "amt-drilldown-empty",
    themes: LIGHT,
    stubs: {
      ...AMT_STUBS,
      "/assets/reconciliation/drilldown": {
        total: 0,
        skip: 0,
        limit: 10,
        data: [],
      },
    },
    ready: amtReady,
    actions: amtOpenShadowIt("/No assets match the current filters/"),
  },
  {
    ...AMT_BASE,
    id: "amt-drilldown-error",
    themes: LIGHT,
    stubs: {
      ...AMT_STUBS,
      "/assets/reconciliation/drilldown": { __status: 500 },
    },
    ready: amtReady,
    actions: amtOpenShadowIt("/Failed to load drilldown details/"),
  },
  {
    ...AMT_BASE,
    id: "amt-unlinked",
    themes: LIGHT,
    stubs: { ...AMT_STUBS, "/assets/coverage-stats": AMT_STATS_UNLINKED },
    ready: `${amtLoaded} && ${hasText("/CMDB Integration Inactive/")}`,
  },
  {
    ...AMT_BASE,
    id: "amt-error",
    themes: BOTH,
    stubs: { ...AMT_STUBS, "/assets/coverage-stats": { __status: 500 } },
    ready: `${amtLoaded} && ${hasText("/Failed to load inventory coverage statistics/")}`,
  },
  {
    ...AMT_BASE,
    id: "amt-denied",
    themes: LIGHT,
    persona: ASSETS_READONLY,
    stubs: SD_STUBS,
    ready: `location.pathname === "/audit-dashboard" && ${sdReady}`,
  },
];

/* ── NetworkMap (batch 21) ────────────────────────────────────────────────── */
/* The map is a vis-network canvas, and two things follow from that.

   Drawing on a canvas is not a DOM mutation, so the runner's settle cannot
   see it. The page fits the view 300 ms after building the graph and animates
   the fit for 400 ms, which ends about when a capture would otherwise be
   taken. A canvas state is therefore ready only once the canvas has existed
   for 1.5 s and three consecutive readings of its pixels, 200 ms apart, are
   identical. The readings are taken from outside, like every other ready
   expression; the page carries no hook. Should the canvas ever refuse to be
   read, the state falls back to waiting 2.5 s.

   No state or probe touches the canvas itself. Node selection, the endpoint
   evidence and guidance dialogs and asset navigation all start from a click
   on a node, and are covered by the unit tests. The probes press only
   controls that read or redraw: Refresh, Fit Screen, Expand All, Collapse
   All, a subnet checkbox, the freshness window and the mask. */
const NM_BASE = {
  route: "/topology",
  persona: ANALYST,
  stubs: NM_STUBS,
  tracked: [
    ...PAGE_TRACKED,
    "h2",
    "h3",
    "button",
    "select",
    "input",
    "canvas",
    "[role=status]",
  ],
};

const nmCanvasReady = `(() => {
  const w = window;
  const canvas = document.querySelector("canvas");
  if (!canvas || /Loading topology nodes/.test(document.body.innerText)) return false;
  const now = performance.now();
  if (!w.__nmCanvasSince) w.__nmCanvasSince = now;
  let frame;
  try {
    frame = canvas.toDataURL();
  } catch (e) {
    return now - w.__nmCanvasSince > 2500;
  }
  w.__nmCanvasSteady = frame === w.__nmCanvasFrame ? (w.__nmCanvasSteady || 0) + 1 : 0;
  w.__nmCanvasFrame = frame;
  return now - w.__nmCanvasSince > 1500 && w.__nmCanvasSteady >= 3;
})()`;

const NM_PATH = "/api/topology/map";
const nmButton = (re) =>
  `el.tagName === 'BUTTON' && ${re}.test(el.textContent || '')`;
const nmSelectWith = (option) =>
  `el.tagName === 'SELECT' && [...el.options].some((o) => o.textContent === ${JSON.stringify(option)})`;

const NM_PROBES = [
  {
    id: "refresh-by-keyboard",
    tabTo: nmButton("/Refresh/"),
    press: "Enter",
    wait: 600,
    expectRequest: {
      path: NM_PATH,
      query: { subnet_mask: "24", active_within_days: "30" },
    },
  },
  // Enter redraws the view and requests nothing.
  {
    id: "fit-by-keyboard",
    tabTo: nmButton("/Fit Screen/"),
    press: "Enter",
    wait: 600,
  },
  {
    id: "expand-all-by-keyboard",
    tabTo: nmButton("/Expand All/"),
    press: "Enter",
    wait: 400,
    expect: hasText("/\\b14 Visible Nodes/"),
  },
  {
    id: "collapse-all-by-keyboard",
    tabTo: nmButton("/Collapse All/"),
    press: "Enter",
    wait: 400,
    expect: hasText("/\\b7 Visible Nodes/"),
  },
  {
    id: "subnet-checkbox-by-keyboard",
    tabTo: "el.tagName === 'INPUT' && el.type === 'checkbox'",
    press: "Space",
    wait: 300,
    expect: `document.querySelector("input[type=checkbox]") && !document.querySelector("input[type=checkbox]").checked`,
  },
  // On a closed <select>, the arrow keys step to the next or previous option.
  {
    id: "window-by-keyboard",
    tabTo: nmSelectWith("Last 30 days"),
    press: "ArrowRight",
    wait: 600,
    expectRequest: { path: NM_PATH, query: { active_within_days: "90" } },
  },
  {
    id: "mask-by-keyboard",
    tabTo: nmSelectWith("Class C (/24)"),
    press: "ArrowLeft",
    wait: 600,
    expectRequest: { path: NM_PATH, query: { subnet_mask: "23" } },
  },
];

const NM_STATES = [
  {
    ...NM_BASE,
    id: "nm-org",
    themes: BOTH,
    ready: nmCanvasReady,
    probes: NM_PROBES,
  },
  {
    ...NM_BASE,
    id: "nm-scan",
    themes: LIGHT,
    route: "/scan/nm-scan-7/topology-map",
    ready: `${hasText("/Scan ID: nm-scan-7/")} && ${nmCanvasReady}`,
  },
  {
    ...NM_BASE,
    id: "nm-mobile",
    themes: LIGHT,
    viewport: [390, 2400],
    ready: nmCanvasReady,
  },
  {
    ...NM_BASE,
    id: "nm-empty",
    themes: LIGHT,
    stubs: { "/topology/map": NM_EMPTY },
    ready: hasText("/No Network Nodes Discovered/"),
  },
  {
    ...NM_BASE,
    id: "nm-error",
    themes: LIGHT,
    stubs: {
      "/topology/map": {
        __status: 500,
        body: { detail: "Topology engine unavailable" },
      },
    },
    ready: hasText("/Topology engine unavailable/"),
  },
  {
    ...NM_BASE,
    id: "nm-denied",
    themes: LIGHT,
    persona: NO_SCANS_READ,
    stubs: {
      "/topology/map": {
        __status: 403,
        body: {
          detail:
            "Insufficient privileges. Your role 'analyst' does not have 'scans:read' permission.",
        },
      },
    },
    ready: hasText("/does not have 'scans:read' permission/"),
  },
];

/* ── ScanHistory (batch 22) ───────────────────────────────────────────────── */
/* The live stream is a finite replay (fixtures.mjs), so every state waits for
   the page's own fallback to settle on "Live sync polling". From then on the
   list is fetched every 5 s and the stream was opened twice before that, so
   both requests repeat for as long as a capture runs.

   Archive and Delete send their request on the first press, with no
   confirmation, and confirming Re-run or Stop would send one too. Probes only
   Tab to those controls; the states that open the re-run and stop
   confirmations send nothing, and the harness refuses every write anyway. */
const SH_TRACKED = [
  ...PAGE_TRACKED,
  "h2",
  "button",
  "input",
  "[role=status]",
  "[role=progressbar]",
];

const SH_BASE = {
  route: "/history",
  persona: SCANS_ADMIN,
  stubs: SH_STUBS,
  tracked: SH_TRACKED,
  repeatable: ["^GET /api/scans\\?", "^GET /api/scans/events\\?"],
};

const shPolling = hasText("/Live sync polling/");
const shRows = `document.querySelectorAll("table tbody tr").length > 0`;
const shHistoryReady = `${shPolling} && ${shRows}`;
// innerText follows text-transform, and the legacy card label is uppercased.
const shMonitorReady = `${shPolling} && ${hasText("/Overall Progress/i")}`;
const shButton = (re) =>
  `el.tagName === 'BUTTON' && ${re}.test((el.textContent || '').trim())`;
const shRowButton = (re) =>
  `[...document.querySelectorAll("table tbody tr button")].find((b) => ${re}.test((b.textContent || "").trim()))`;
const shDialogOpen = `!!document.querySelector("[role=dialog]")`;

const SH_PROBES = {
  // Tab only: each of these sends a write, or opens a confirmation, on Enter.
  rerun: { id: "rerun-reachable", tabTo: shButton("/^Re-run/") },
  archive: { id: "archive-reachable", tabTo: shButton("/^Archive/") },
  remove: { id: "delete-reachable", tabTo: shButton("/^Delete/") },
  stop: { id: "stop-reachable", tabTo: shButton("/^Stop Scan/") },
  nextPage: {
    id: "next-page-by-keyboard",
    tabTo: shButton("/^Next$/"),
    press: "Enter",
    wait: 400,
    expect: hasText("/Page 2 of 2/"),
  },
  sortTarget: {
    id: "sort-target-by-keyboard",
    tabTo: shButton("/^Target/"),
    press: "Enter",
    wait: 400,
    expect: `!!document.querySelector('[aria-sort="ascending"]')`,
  },
  statusFailed: {
    id: "status-failed-by-keyboard",
    tabTo: shButton("/^Failed$/"),
    press: "Enter",
    wait: 400,
    expect: `[...document.querySelectorAll("table tbody tr")].every((r) => /Failed/.test(r.textContent || ""))`,
  },
  ownerMine: {
    id: "owner-mine-by-keyboard",
    tabTo: shButton("/^My scans$/"),
    press: "Enter",
    wait: 800,
    expectRequest: {
      path: "/api/scans",
      query: { scope: "active", created_by: "me" },
    },
  },
  syncNow: {
    id: "sync-now-by-keyboard",
    tabTo: shButton("/Sync now/"),
    press: "Enter",
    wait: 800,
    expectRequest: { path: "/api/scans", query: { scope: "active" } },
  },
  escapeDialog: {
    id: "confirmation-escape",
    tabTo: `el.tagName === 'BUTTON' && /^Cancel$/.test((el.textContent || '').trim()) && !!el.closest("[role=dialog]")`,
    press: "Escape",
    wait: 400,
    expect: `!document.querySelector("[role=dialog]")`,
  },
};

const SH_STATES = [
  {
    ...SH_BASE,
    id: "sh-history",
    themes: BOTH,
    ready: shHistoryReady,
    probes: [
      SH_PROBES.rerun,
      SH_PROBES.archive,
      SH_PROBES.remove,
      SH_PROBES.nextPage,
      SH_PROBES.sortTarget,
      SH_PROBES.statusFailed,
      SH_PROBES.ownerMine,
      SH_PROBES.syncNow,
    ],
  },
  {
    ...SH_BASE,
    id: "sh-completed",
    themes: LIGHT,
    route: "/history?status=complete",
    ready: shHistoryReady,
  },
  {
    ...SH_BASE,
    id: "sh-monitor",
    themes: BOTH,
    route: "/monitor",
    ready: shMonitorReady,
    probes: [SH_PROBES.stop],
  },
  {
    ...SH_BASE,
    id: "sh-mobile",
    themes: LIGHT,
    viewport: [390, 2400],
    ready: shHistoryReady,
  },
  {
    ...SH_BASE,
    id: "sh-loading",
    themes: LIGHT,
    stubs: {
      "/scans": { __pending: true },
      "/scans/events": { __pending: true },
    },
    ready: `${hasText("/Live sync connecting/")} && !document.querySelector("table")`,
  },
  {
    ...SH_BASE,
    id: "sh-empty",
    themes: LIGHT,
    stubs: SH_STUBS_EMPTY,
    ready: `${shPolling} && ${hasText("/No scans yet/")}`,
  },
  {
    ...SH_BASE,
    id: "sh-error",
    themes: LIGHT,
    stubs: {
      "/scans": { __status: 500 },
      "/scans/events": { __status: 500 },
    },
    ready: `${shPolling} && ${hasText("/Failed to load scan history/")}`,
  },
  {
    ...SH_BASE,
    id: "sh-readonly",
    themes: LIGHT,
    persona: DASHBOARD_RESTRICTED,
    ready: shHistoryReady,
  },
  {
    ...SH_BASE,
    id: "sh-denied",
    themes: LIGHT,
    persona: NO_SCANS_READ,
    stubs: {
      "/scans": {
        __status: 403,
        body: {
          detail:
            "Insufficient privileges. Your role 'analyst' does not have 'scans:read' permission.",
        },
      },
      "/scans/events": { __status: 403 },
    },
    ready: `${shPolling} && ${hasText("/Failed to load scan history/")}`,
  },
  {
    ...SH_BASE,
    id: "sh-detail",
    themes: LIGHT,
    ready: shHistoryReady,
    actions: [
      { click: shRowButton("/^View/") },
      { waitFor: hasText("/Discovery Results/i") },
    ],
  },
  {
    ...SH_BASE,
    id: "sh-rerun-confirm",
    themes: LIGHT,
    ready: shHistoryReady,
    actions: [{ click: shRowButton("/^Re-run/") }, { waitFor: shDialogOpen }],
    probes: [SH_PROBES.escapeDialog],
  },
  {
    ...SH_BASE,
    id: "sh-stop-confirm",
    themes: LIGHT,
    route: "/monitor",
    ready: shMonitorReady,
    actions: [
      {
        click: `[...document.querySelectorAll("button")].find((b) => /^Stop Scan/.test((b.textContent || "").trim()))`,
      },
      { waitFor: shDialogOpen },
    ],
    probes: [SH_PROBES.escapeDialog],
  },
];

/* ── CredentialedResults (batch 23) ───────────────────────────────────────── */
/* Every state reads the report through `?scan_id=`, so the page's own request
   is what the fixtures answer. A finished report needs nothing more. The
   running states answer the ticket (router.mjs) and script the socket
   (fixtures.mjs); `cr-fallback` drops it after two frames, and from then on
   the page reads the record every 3 s for as long as the capture runs.

   The expanded states open every section — the audit evidence, and with it the
   masked environment variables, included — and wait until the masked form is
   present and no unmasked value is anywhere in the document. */
const CR_TRACKED = [
  ...PAGE_TRACKED,
  "h2",
  "button",
  "input",
  "pre",
  "[role=progressbar]",
  "[role=log]",
];

const CR_BASE = { persona: ANALYST, stubs: CR_STUBS, tracked: CR_TRACKED };
const crRoute = (id) => `/scan/credentialed/results?scan_id=${id}`;
const crReport = `${hasText("/Credentialed Scan Results/")} && ${hasText("/System Information/i")}`;
const crProgress = hasText("/Credentialed Scan In Progress/");
const crSocket = (id) =>
  `(window.__harnessSockets || []).length === 1 && /^\\/api\\/scans\\/${id}\\/progress\\?ticket=${CR_TICKET}$/.test(window.__harnessSockets[0])`;
const crButton = (re) =>
  `el.tagName === 'BUTTON' && ${re}.test((el.textContent || '').trim())`;
// Clicks every collapsed section. Its chevron is the last character of the
// toggle's text in both builds.
const crExpandAll = {
  click: `(() => { const toggles = [...document.querySelectorAll("button")].filter((b) => /▼\\s*$/.test(b.textContent || "")); toggles.slice(1).forEach((b) => b.click()); return toggles[0]; })()`,
};
const crMasked = `document.documentElement.outerHTML.includes("AWS_SECRET_ACCESS_KEY=********") && ${JSON.stringify(CR_SECRETS)}.every((s) => !document.documentElement.outerHTML.includes(s))`;

const CR_PROBES = {
  severityHigh: {
    id: "severity-filter-by-keyboard",
    tabTo: crButton("/^High/"),
    press: "Enter",
    wait: 400,
    expect: `(() => { const ids = [...document.querySelectorAll("a")].map((a) => (a.textContent || "").trim()).filter((t) => /^CVE-/.test(t)); return ids.length === 1 && ids[0] === "CVE-2023-0286"; })()`,
  },
  openServices: {
    id: "open-section-by-keyboard",
    tabTo: crButton("/Running Services \\(2\\)/"),
    press: "Enter",
    wait: 400,
    expect: hasText("/ssh\\.service/"),
  },
  // Last: it leaves the Windows host on screen.
  switchHost: {
    id: "switch-host-by-keyboard",
    tabTo: crButton("/^10\\.40\\.2\\.30/"),
    press: "Enter",
    wait: 400,
    expect: hasText("/Build 26200\\.6584/"),
  },
  // Tab only: Enter navigates to a new credentialed scan.
  tryAgain: { id: "try-again-reachable", tabTo: crButton("/^Try Again$/") },
};

const CR_STATES = [
  {
    ...CR_BASE,
    id: "cr-report",
    route: crRoute("cr-report"),
    themes: BOTH,
    ready: crReport,
    probes: [
      CR_PROBES.severityHigh,
      CR_PROBES.openServices,
      CR_PROBES.switchHost,
    ],
  },
  {
    ...CR_BASE,
    id: "cr-expanded",
    route: crRoute("cr-report"),
    themes: LIGHT,
    ready: crReport,
    actions: [crExpandAll, { waitFor: crMasked }],
  },
  {
    ...CR_BASE,
    id: "cr-windows",
    route: crRoute("cr-windows"),
    themes: LIGHT,
    ready: crReport,
    actions: [crExpandAll, { waitFor: hasText("/VendorUpdater/") }],
  },
  {
    ...CR_BASE,
    id: "cr-mobile",
    route: crRoute("cr-report"),
    themes: LIGHT,
    viewport: [390, 2400],
    ready: crReport,
    actions: [crExpandAll, { waitFor: crMasked }],
  },
  {
    ...CR_BASE,
    id: "cr-empty",
    route: crRoute("cr-empty"),
    themes: LIGHT,
    ready: `${crReport} && ${hasText("/0 CVEs/")}`,
  },
  {
    ...CR_BASE,
    id: "cr-running",
    route: crRoute("cr-run"),
    themes: BOTH,
    ticket: CR_TICKET,
    init: crSocketScript({ frames: CR_FRAMES }),
    ready: `${crProgress} && ${hasText("/Collected 1,284 installed packages/")} && ${crSocket("cr-run")}`,
  },
  {
    ...CR_BASE,
    id: "cr-fallback",
    route: crRoute("cr-fallback"),
    themes: LIGHT,
    ticket: CR_TICKET,
    init: crSocketScript({ frames: CR_FRAMES.slice(0, 2), close: true }),
    // Ready once the page has read the record again after the socket dropped:
    // the first read, then the first 3-second poll.
    ready: `${crProgress} && ${hasText("/Detected Ubuntu 22\\.04\\.4 LTS/")} && ${crSocket("cr-fallback")} && window.__harnessSocketClosed === true && performance.getEntriesByType("resource").filter((e) => /\\/api\\/scans\\/cr-fallback\\?/.test(e.name)).length >= 2`,
    repeatable: ["^GET /api/scans/cr-fallback\\?"],
  },
  {
    ...CR_BASE,
    id: "cr-loading",
    route: crRoute("cr-load"),
    themes: LIGHT,
    ready: `${crProgress} && ${hasText("/Waiting for activity/")}`,
  },
  {
    ...CR_BASE,
    id: "cr-failed",
    route: crRoute("cr-failed"),
    themes: LIGHT,
    ready: hasText("/Authentication failed for user auditor/"),
    probes: [CR_PROBES.tryAgain],
  },
  {
    ...CR_BASE,
    id: "cr-unreachable",
    route: crRoute("cr-unreachable"),
    themes: BOTH,
    ready: hasText("/Host is unavailable\\/down\\/unreachable/"),
  },
  {
    ...CR_BASE,
    id: "cr-error",
    route: crRoute("cr-error"),
    themes: LIGHT,
    ready: hasText("/harness stub failure/"),
  },
  {
    ...CR_BASE,
    id: "cr-denied",
    route: crRoute("cr-denied"),
    themes: LIGHT,
    persona: NO_SCANS_READ,
    ready: hasText("/does not have 'scans:read' permission/"),
  },
];

/* ── Phase3Results (batch 24) ─────────────────────────────────────────────── */
/* Every p3- state opts out of the Phase 3 route block (guard.mjs) and nothing
   else. The seeded states hold the scan context where the page's own guards
   keep it from starting: a finished report, a running, failed or cancelled
   pipeline, discovery with no live host, or an operator without
   `scans:execute`. They send no write at all.

   The three pipeline states let the page start on mount. The router answers
   exactly the declared dispatch triggers and the ticket; any other write —
   Cancel's stop, for instance — is refused. The progress socket is scripted:
   `p3-pipeline` completes both phases, `p3-pipeline-running` stays open, and
   `p3-pipeline-failed` reports phase 2 failed. Readiness asserts each socket's
   URL and whether the page closed it, and waits for the save indicator's
   4-second clear so the capture does not race it.

   Cancel, Retry and Restart are reached by Tab only: each would send a write. */
const P3_TRACKED = [
  ...PAGE_TRACKED,
  "h2",
  "h3",
  "button",
  "[role=progressbar]",
  "[role=status]",
  "[role=alert]",
];

const P3_BASE = {
  persona: ANALYST,
  stubs: P3_STUBS,
  tracked: P3_TRACKED,
  allowPhase3: true,
};
const P3_ROUTE = "/scan/vulnerability-audit";
const p3Report = `${hasText("/3\\. Vulnerability Results/i")} && ${hasText("/View Risk Report/i")}`;
const p3Sockets = (id, n, closed) =>
  `(window.__harnessSockets || []).length === ${n} && window.__harnessSockets.every((s) => /^\\/api\\/scans\\/${id}\\/progress\\?ticket=${P3_TICKET}$/.test(s.url) && s.closed === ${closed})`;
const p3Quiet = `((el) => !!el && el.textContent === "")(document.querySelector(".sh-savestatus"))`;
const p3Masked = `document.body.innerText.includes("ftpuser/********") && !document.documentElement.outerHTML.includes(${JSON.stringify(P3_SECRET)})`;
const p3Button = (re) =>
  `el.tagName === 'BUTTON' && ${re}.test((el.textContent || '').trim())`;
const P3_OPEN_REPORT = [
  {
    click: `[...document.querySelectorAll("button")].find((b) => /View Risk Report/.test(b.textContent || ""))`,
  },
  { waitFor: `!!document.querySelector("[role=dialog]") && ${p3Masked}` },
];
const P3_PIPELINE = {
  route: P3_ROUTE,
  themes: LIGHT,
  ticket: P3_TICKET,
  writes: P3_WRITES,
  readyTimeout: 30000,
};

const P3_PROBES = {
  filterAll: {
    id: "discovery-filter-by-keyboard",
    tabTo: p3Button("/^All \\(4\\)$/"),
    press: "Enter",
    wait: 400,
    expect: `document.querySelectorAll("table")[0].querySelectorAll("tbody tr").length === 4`,
  },
  openReport: {
    id: "risk-report-by-keyboard",
    tabTo: p3Button("/View Risk Report/"),
    press: "Enter",
    wait: 500,
    expect: `!!document.querySelector("[role=dialog]")`,
    then: [
      {
        press: "Escape",
        wait: 400,
        expect: `!document.querySelector("[role=dialog]")`,
      },
    ],
  },
  // Tab only: Enter posts /scans/{id}/stop.
  cancel: { id: "cancel-reachable", tabTo: p3Button("/Cancel Scan/") },
  // Tab only: Enter starts the audit again.
  retry: { id: "retry-reachable", tabTo: p3Button("/Retry from/") },
};

const P3_STATES = [
  {
    ...P3_BASE,
    id: "p3-report",
    route: "/scan/p3-report/phase3",
    themes: BOTH,
    session: P3_REPORT_SESSION,
    ready: p3Report,
    probes: [P3_PROBES.filterAll, P3_PROBES.openReport],
  },
  {
    ...P3_BASE,
    id: "p3-report-modal",
    route: P3_ROUTE,
    themes: LIGHT,
    session: P3_REPORT_SESSION,
    ready: p3Report,
    actions: P3_OPEN_REPORT,
  },
  {
    ...P3_BASE,
    id: "p3-report-mobile",
    route: P3_ROUTE,
    themes: LIGHT,
    viewport: [390, 2400],
    session: P3_REPORT_SESSION,
    ready: p3Report,
  },
  {
    ...P3_BASE,
    id: "p3-modal-mobile",
    route: P3_ROUTE,
    themes: LIGHT,
    viewport: [390, 2400],
    session: P3_REPORT_SESSION,
    ready: p3Report,
    actions: P3_OPEN_REPORT,
  },
  {
    ...P3_BASE,
    id: "p3-running",
    route: P3_ROUTE,
    themes: BOTH,
    session: P3_RUNNING_SESSION,
    ready: hasText("/Running Vulnerability Audit/i"),
    probes: [P3_PROBES.cancel],
  },
  {
    ...P3_BASE,
    id: "p3-error",
    route: P3_ROUTE,
    themes: LIGHT,
    session: P3_ERROR_SESSION,
    ready: hasText("/Pipeline failed at Vulnerability Audit/i"),
    probes: [P3_PROBES.retry],
  },
  {
    ...P3_BASE,
    id: "p3-cancelled",
    route: P3_ROUTE,
    themes: LIGHT,
    session: P3_CANCELLED_SESSION,
    ready: hasText("/Scan Cancelled/i"),
  },
  {
    ...P3_BASE,
    id: "p3-unreachable",
    route: P3_ROUTE,
    themes: LIGHT,
    session: P3_UNREACHABLE_SESSION,
    ready: hasText("/Host is unavailable/i"),
  },
  {
    ...P3_BASE,
    id: "p3-denied",
    route: P3_ROUTE,
    themes: LIGHT,
    persona: SCANS_READONLY,
    session: p3StartSession("p3-denied"),
    ready: `${hasText("/You do not have permission to perform this action/")} && ${p3Quiet}`,
  },
  {
    ...P3_BASE,
    ...P3_PIPELINE,
    id: "p3-pipeline",
    session: p3StartSession("p3-live"),
    init: p3SocketScript([
      { phase: 2, progress: { status: "complete", percentage: 100 } },
      { phase: 3, progress: { status: "complete", percentage: 100 } },
    ]),
    ready: `${p3Report} && ${p3Sockets("p3-live", 2, true)} && ${p3Quiet}`,
  },
  {
    ...P3_BASE,
    ...P3_PIPELINE,
    id: "p3-pipeline-running",
    session: p3StartSession("p3-stall"),
    init: p3SocketScript([]),
    ready: `${hasText("/Running Port Scan/i")} && ${p3Sockets("p3-stall", 1, false)}`,
  },
  {
    ...P3_BASE,
    ...P3_PIPELINE,
    id: "p3-pipeline-failed",
    session: p3StartSession("p3-fail"),
    init: p3SocketScript([{ phase: 2, progress: { status: "failed" } }]),
    ready: `${hasText("/Port scan background task failed/i")} && ${p3Sockets("p3-fail", 1, true)} && ${p3Quiet}`,
  },
];

/* ── NewScan (batch 25) ───────────────────────────────────────────────────── */
/* Setup states open /scan/new with the scan context seeded and send no write.
   `ns-dispatch` presses Start: the router answers exactly the declared
   POST /scan/host-discovery and the ticket, and the page then follows the scan
   it started at /scan/active/ns-live. The mission states open that route
   directly. Every progress socket is scripted (fixtures.mjs): its frames arrive
   40 ms apart, readiness asserts the socket's URL and whether the page closed
   it, and the states that list hosts wait for the new-host highlight's
   3-second clear.

   The Phase 3 hand-off is not captured: the route guard throws on a Phase 3
   navigation, and the page would report the throw as an exception. The unit
   tests pin that target; `ns-handoff` captures the interactive hand-off to
   host discovery instead.

   Stop Scan and Try Again are reached by Tab only: Stop would send a write. */
const NS_TRACKED = [
  ...PAGE_TRACKED,
  "h2",
  "button",
  "input[type=checkbox]",
  "[role=progressbar]",
  "[role=alert]",
  "[role=dialog]",
  "table",
];
const NS_BASE = { persona: ANALYST, stubs: NS_STUBS, tracked: NS_TRACKED };
const NS_MISSION = { themes: LIGHT, ticket: NS_TICKET, readyTimeout: 30000 };

const nsButton = (re) =>
  `[...document.querySelectorAll("button")].find((b) => ${re}.test((b.textContent || "").trim()))`;
const nsSettingsOpen = `!!document.querySelector(".ns-drawer--open, [role=dialog]")`;
const nsTargetField = `document.querySelector('input[placeholder*="10.180.6.0/24"]')`;
const nsSetupReady = (re) =>
  `${hasText(re)} && !!${nsButton("/Start (Scan|Discovery)/")}`;
const nsSockets = (id, n, closed) =>
  `(window.__harnessSockets || []).length === ${n} && window.__harnessSockets.every((s) => s.url === "/api/scans/${id}/progress?ticket=${NS_TICKET}" && s.closed === ${closed})`;
const nsSettled = `!document.querySelector(".am-host-card--new, .ns-host--new")`;
// The one checkbox whose nearest ancestors, holding no other checkbox, name it.
const nsSwitch = (re) =>
  `[...document.querySelectorAll('input[type="checkbox"]')].find((el) => { for (let n = el.parentElement; n && n.querySelectorAll('input[type="checkbox"]').length === 1; n = n.parentElement) { if (${re}.test(n.textContent || "")) return true; } return false; })`;
const nsSelectWith = (value) =>
  `[...document.querySelectorAll("select")].find((s) => [...s.options].some((o) => o.value === ${JSON.stringify(value)}))`;
// Sets a controlled field the way typing would, and hands back the element.
const nsSetValue = (selector, value) =>
  `((el) => { if (!el) return null; const proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, "value").set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event(el.tagName === "SELECT" ? "change" : "input", { bubbles: true })); return el; })(${selector})`;
// Drops a synthetic text file on the target field. Nothing is uploaded: the
// page reads the file in the browser and keeps only the target strings.
const nsDrop = (name, content) =>
  `((input) => { if (!input) return null; const dt = new DataTransfer(); dt.items.add(new File([${JSON.stringify(content)}], ${JSON.stringify(name)}, { type: "text/plain" })); input.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt })); return input; })(${nsTargetField})`;
const NS_OPEN_SETTINGS = { click: nsButton("/Configure Advanced Settings/") };

const NS_PROBES = {
  quickTarget: {
    id: "quick-target-by-keyboard",
    tabTo: `el.tagName === 'BUTTON' && (el.textContent || '').trim() === '10.180.4.1'`,
    press: "Enter",
    wait: 300,
    expect: `${nsTargetField}.value === "10.180.4.1"`,
  },
  settings: {
    id: "settings-by-keyboard",
    tabTo: `el.tagName === 'BUTTON' && /Configure Advanced Settings/.test(el.textContent || '')`,
    press: "Enter",
    wait: 500,
    expect: nsSettingsOpen,
    then: [{ press: "Escape", wait: 400, expect: `!${nsSettingsOpen}` }],
  },
  // Tab only: Enter posts /scans/{id}/stop.
  stop: {
    id: "stop-reachable",
    tabTo: `el.tagName === 'BUTTON' && /Stop Scan/.test(el.textContent || '')`,
  },
  retry: {
    id: "try-again-reachable",
    tabTo: `el.tagName === 'BUTTON' && /Try Again/.test(el.textContent || '')`,
  },
};

const NS_STATES = [
  {
    ...NS_BASE,
    id: "ns-setup",
    route: "/scan/new",
    themes: BOTH,
    session: nsSession({ cc_target: "" }),
    ready: nsSetupReady("/Basic Network Scan/"),
    probes: [NS_PROBES.quickTarget, NS_PROBES.settings],
  },
  {
    ...NS_BASE,
    id: "ns-setup-asset",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({ cc_pipelineMode: "asset" }),
    ready: nsSetupReady("/Fast-first with coverage fallback/"),
  },
  {
    ...NS_BASE,
    id: "ns-setup-audit",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({ cc_pipelineMode: "vulnerability_audit" }),
    ready: nsSetupReady("/Balanced port coverage/"),
  },
  {
    ...NS_BASE,
    id: "ns-settings",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({
      cc_pipelineMode: "asset",
      cc_portScanMode: "port",
      cc_portProfile: "it",
      cc_excludePorts: "2375, 2376",
    }),
    ready: nsSetupReady("/Asset Discovery/"),
    actions: [
      NS_OPEN_SETTINGS,
      {
        waitFor: `${nsSettingsOpen} && ${hasText("/Sensitive Ports Detected/")}`,
      },
    ],
  },
  {
    ...NS_BASE,
    id: "ns-validation",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({
      cc_pipelineMode: "asset",
      cc_portScanMode: "port",
      cc_portProfile: "custom",
      cc_customPorts: "22,22",
      cc_excludePorts: "80,abc",
      cc_excludeIps: "bad!",
    }),
    ready: nsSetupReady("/Asset Discovery/"),
    actions: [
      NS_OPEN_SETTINGS,
      {
        waitFor: `${nsSettingsOpen} && ${hasText("/Duplicate port detected: 22/")}`,
      },
    ],
  },
  {
    ...NS_BASE,
    id: "ns-settings-audit",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({ cc_pipelineMode: "vulnerability_audit" }),
    ready: nsSetupReady("/Balanced port coverage/"),
    actions: [
      NS_OPEN_SETTINGS,
      { waitFor: nsSettingsOpen },
      { click: nsSwitch("/Authenticated Checks/") },
      { waitFor: hasText("/Linux fleet/") },
      { click: nsSwitch("/Network Topology \\(SNMP\\)/") },
      { waitFor: `!!${nsSelectWith("v3")}` },
      { click: nsSetValue(nsSelectWith("v3"), "v3") },
      {
        waitFor: `!!document.querySelector('input[placeholder="Auth passphrase"]')`,
      },
      { click: nsSetValue(nsSelectWith("AES128"), "AES128") },
      {
        waitFor: `!!document.querySelector('input[placeholder="Privacy passphrase"]')`,
      },
      {
        click: nsSetValue(
          `document.querySelector('input[placeholder="Auth passphrase"]')`,
          NS_SECRET,
        ),
      },
      {
        waitFor: `document.querySelector('input[placeholder="Auth passphrase"]').value === ${JSON.stringify(NS_SECRET)}`,
      },
    ],
  },
  {
    ...NS_BASE,
    id: "ns-targets",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({ cc_target: "" }),
    ready: nsSetupReady("/Basic Network Scan/"),
    actions: [
      { click: nsDrop("targets.txt", NS_TARGET_FILE) },
      {
        waitFor: `!!document.querySelector("table") && ${hasText("/Valid:\\s*3/")}`,
      },
    ],
  },
  {
    ...NS_BASE,
    id: "ns-file-error",
    route: "/scan/new",
    themes: LIGHT,
    session: nsSession({ cc_target: "" }),
    ready: nsSetupReady("/Basic Network Scan/"),
    actions: [
      { click: nsDrop("targets.zip", "10.70.0.10\n") },
      { waitFor: hasText("/Unsupported file format/") },
    ],
  },
  {
    ...NS_BASE,
    id: "ns-denied",
    route: "/scan/new",
    themes: LIGHT,
    persona: SCANS_READONLY,
    session: nsSession(),
    ready: nsSetupReady("/Basic Network Scan/"),
  },
  {
    ...NS_BASE,
    id: "ns-setup-mobile",
    route: "/scan/new",
    themes: LIGHT,
    viewport: [390, 1600],
    session: nsSession(),
    ready: nsSetupReady("/Basic Network Scan/"),
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-dispatch",
    route: "/scan/new",
    session: nsSession(),
    writes: NS_WRITES,
    init: nsSocketScript(NS_COMPLETE_FRAMES),
    ready: nsSetupReady("/Basic Network Scan/"),
    actions: [
      { click: nsButton("/Start Scan/") },
      {
        waitFor: `location.pathname === "/scan/active/ns-live" && ${hasText("/Scan complete/")} && ${nsSockets("ns-live", 1, true)} && ${nsSettled}`,
        timeout: 20000,
      },
    ],
    repeatable: ["^GET /api/scans/ns-live -> "],
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-running",
    route: "/scan/active/ns-run",
    themes: BOTH,
    session: nsSession(),
    init: nsSocketScript(NS_RUNNING_FRAMES),
    // Case-insensitive: the legacy badge is uppercased by CSS, and innerText
    // reports the rendered case.
    ready: `${hasText("/Live Scanning/i")} && ${hasText("/10\\.70\\.0\\.11/")} && ${nsSockets("ns-run", 1, false)} && ${nsSettled}`,
    repeatable: ["^GET /api/scans/ns-run -> "],
    probes: [NS_PROBES.stop],
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-failed",
    route: "/scan/active/ns-fail",
    session: nsSession(),
    init: nsSocketScript([{ phase: 1, progress: { status: "failed" } }]),
    ready: `${hasText("/The scanner worker stopped responding/")} && ${nsSockets("ns-fail", 1, true)}`,
    probes: [NS_PROBES.retry],
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-unreachable",
    route: "/scan/active/ns-none",
    session: nsSession(),
    init: nsSocketScript([
      {
        phase: 1,
        progress: { status: "complete", total_ips: 16, discovered: 0 },
      },
    ]),
    ready: `${hasText("/Target Unreachable/")} && ${nsSockets("ns-none", 1, true)}`,
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-cancelled",
    route: "/scan/active/ns-stop",
    session: nsSession(),
    init: nsSocketScript([]),
    ready: `${hasText("/Scan cancelled/")} && ${nsSockets("ns-stop", 1, false)}`,
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-handoff",
    route: "/scan/active/ns-hand",
    session: nsSession({
      cc_pipelineMode: "asset",
      cc_executionMode: "interactive",
    }),
    init: nsSocketScript(NS_COMPLETE_FRAMES),
    ready: `location.pathname === "/scan/host-discovery" && ${hasText("/10\\.70\\.0\\.11/")} && ${nsSockets("ns-hand", 1, true)}`,
    repeatable: ["^GET /api/scans/ns-hand -> "],
  },
  {
    ...NS_BASE,
    ...NS_MISSION,
    id: "ns-mission-mobile",
    route: "/scan/active/ns-run",
    viewport: [390, 1400],
    session: nsSession(),
    init: nsSocketScript(NS_RUNNING_FRAMES),
    ready: `${hasText("/Live Scanning/i")} && ${hasText("/10\\.70\\.0\\.11/")} && ${nsSockets("ns-run", 1, false)} && ${nsSettled}`,
    repeatable: ["^GET /api/scans/ns-run -> "],
  },
];

/* ── Platform Home (after sign-in) ───────────────────────────────────────────
   CCurePRO Home at /, the three product entry pages, and the platform header's
   shared navigation: Administration, organisation switcher, notifications,
   settings and the account menu. Added with the platform header, so the page a
   person lands on after sign-in is captured like every other screen. */
const PH_TRACKED = ["h1", "h2", "[role=menu]", "[role=dialog]", ".pl-header"];
const PH_BASE = {
  route: "/",
  persona: ANALYST,
  stubs: {
    "/platform/modules": PLATFORM_MODULES,
    // GET /notifications answers a bare list (response_model=list[...]), which
    // is what the panel reads. The shared stub's object shape is left alone:
    // the dashboard states request it and their captures must not change.
    "/notifications": [],
  },
  tracked: PH_TRACKED,
};
const phReady = `document.querySelectorAll('ul[aria-label="CCurePRO products"] > li').length === 4`;
const PH_STATES = [
  { ...PH_BASE, id: "ph-home", themes: BOTH, ready: phReady },
  {
    ...PH_BASE,
    id: "ph-home-mobile",
    themes: LIGHT,
    viewport: [390, 1400],
    ready: phReady,
  },
  {
    ...PH_BASE,
    id: "ph-admin-menu",
    themes: LIGHT,
    persona: PH_ORG_ADMIN,
    ready: phReady,
    actions: [
      { click: byText("button", "/Administration/") },
      {
        waitFor: `!!document.querySelector('[role=menu][aria-label="Administration"]')`,
      },
    ],
  },
  {
    ...PH_BASE,
    id: "ph-superadmin",
    themes: LIGHT,
    persona: PH_SUPERADMIN,
    stubs: { ...PH_BASE.stubs, "/admin/organizations/": PH_ORGS },
    ready: `${phReady} && /Harness Org/.test(document.body.innerText)`,
    actions: [
      {
        click: `document.querySelector('button[aria-label^="Switch organization"]')`,
      },
      {
        waitFor: `!!document.querySelector('[role=menu][aria-label="Switch Organization"]')`,
      },
    ],
  },
  {
    ...PH_BASE,
    id: "ph-notifications",
    themes: LIGHT,
    ready: phReady,
    actions: [
      {
        click: `document.querySelector('button[aria-label^="Notifications"]')`,
      },
      { waitFor: `!!document.getElementById("sh-notifications")` },
    ],
  },
  {
    ...PH_BASE,
    id: "ph-settings",
    themes: BOTH,
    ready: phReady,
    actions: [
      { click: `document.querySelector('button[aria-label="Settings"]')` },
      { waitFor: hasText("/Rows per page/") },
    ],
  },
  {
    ...PH_BASE,
    id: "ph-account-menu",
    themes: LIGHT,
    ready: phReady,
    actions: [
      {
        click: `document.querySelector('button[aria-label^="Account menu for"]')`,
      },
      {
        waitFor: `!!document.querySelector('[role=menu][aria-label="Account"]')`,
      },
    ],
  },
  ...[
    ["ph-entry-policy", "/policy-dashboard", "CCure Policy Pro"],
    ["ph-entry-rank", "/rank-dashboard", "CCure Rank"],
    ["ph-entry-ir", "/ir-dashboard", "CCure IR"],
  ].map(([id, route, title]) => ({
    ...PH_BASE,
    id,
    route,
    themes: LIGHT,
    ready: `document.querySelector("h1")?.textContent === ${JSON.stringify(title)} && /is not available yet/.test(document.body.innerText)`,
  })),
];

export const STATES = [
  ...AR_STATES,
  ...VB_STATES,
  ...SD_STATES,
  ...CW_STATES,
  ...P2_STATES,
  ...P1_STATES,
  ...AMT_STATES,
  ...NM_STATES,
  ...SH_STATES,
  ...CR_STATES,
  ...P3_STATES,
  ...NS_STATES,
  ...CW26A_STATES,
  ...CW26B_STATES,
  ...CW27_STATES,
  ...CW28_STATES,
  ...CW29_STATES,
  ...CW30_STATES,
  ...CW31_STATES,
  ...PH_STATES,
];

/** States whose output Batch 31 must leave byte-for-byte unchanged: every page
 *  migrated so far (batches 16 to 30) and ComplianceWorkspace outside the
 *  gap-analysis dialog and the Credentials Manager's pager. Under these
 *  prefixes `cw-credentials` and the `cw29-credentials-` states are the ones
 *  it is expected to change; the regression gate names the rest individually. */
export const REGRESSION_PREFIXES = [
  "cw26a-",
  "cw26b-",
  "cw27-",
  "cw28-",
  "cw29-",
  "cw30-",
  "ar-",
  "vb-",
  "cw-",
  "sd-",
  "p2-",
  "p1-",
  "amt-",
  "nm-",
  "sh-",
  "cr-",
  "p3-",
  "ns-",
  // Platform Home and the platform header, captured since they gained the
  // shared navigation.
  "ph-",
];

/** States the sensitivity gate injects into. */
export const SENSITIVITY_STATES = ["ar-assets", "vb-cve"];
