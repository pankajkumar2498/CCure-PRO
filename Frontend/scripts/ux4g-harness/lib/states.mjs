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

/* ── Regression sweep: pages Batch 16 must not change ─────────────────────── */
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

const SD_STATES = [
  {
    id: "sd-default",
    route: "/dashboard",
    themes: BOTH,
    persona: ANALYST,
    stubs: SD_STUBS,
    tracked: SHARED_TRACKED,
    ready: hasText("/CVE-2026-1111/"),
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

/** States whose output Batch 16 must leave byte-for-byte unchanged. */
export const REGRESSION_PREFIXES = ["sd-", "cw-"];

/** States the sensitivity gate injects into. */
export const SENSITIVITY_STATES = ["ar-assets", "vb-cve"];
