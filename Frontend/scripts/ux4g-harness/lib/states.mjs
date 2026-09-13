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
    ready: `location.pathname === "/dashboard" && ${sdReady}`,
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
];

/** States whose output Batch 22 must leave byte-for-byte unchanged: every page
 *  migrated so far (batches 16 to 21) and the one page still importing
 *  dashboard.css. Batch 22 changes ScanHistory only. */
export const REGRESSION_PREFIXES = [
  "ar-",
  "vb-",
  "cw-",
  "sd-",
  "p2-",
  "p1-",
  "amt-",
  "nm-",
];

/** States the sensitivity gate injects into. */
export const SENSITIVITY_STATES = ["ar-assets", "vb-cve"];
