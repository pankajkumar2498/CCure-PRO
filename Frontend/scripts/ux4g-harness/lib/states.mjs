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
  route: "/dashboard",
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

export const STATES = [...AR_STATES, ...VB_STATES, ...SD_STATES, ...CW_STATES];

/** States whose output Batch 17 must leave byte-for-byte unchanged. Batch 16
 *  gated `sd-` and `cw-`; batch 17 changes the dashboard, so the gate is the
 *  pages batch 16 migrated plus the one page still importing dashboard.css. */
export const REGRESSION_PREFIXES = ["ar-", "vb-", "cw-"];

/** States the sensitivity gate injects into. */
export const SENSITIVITY_STATES = ["ar-assets", "vb-cve"];
