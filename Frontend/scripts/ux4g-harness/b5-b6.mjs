#!/usr/bin/env node
/** Scoped B.5/B.6 regressions. All API writes are synthetic declared responses. */
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { runCapture, parseArgs } from "./run.mjs";
import { STATES } from "./lib/states.mjs";
import {
  AR_ASSETS,
  VB_FINDINGS,
  VB_FINDING_DETAIL,
  VB_GROUPS,
  PLATFORM_MODULES,
} from "./lib/fixtures.mjs";

const vocabulary = JSON.parse(
  readFileSync(
    new URL(
      "../../src/__tests__/fixtures/authorizationVocabulary.json",
      import.meta.url,
    ),
  ),
).keys;
const allKeys = Object.keys(vocabulary);
export function nativePersona(keys = allKeys) {
  return {
    id: "b5-user",
    username: "harness",
    full_name: "Harness Operator",
    email: "harness@example.test",
    org_id: "o-1",
    organization_name: "Harness Org",
    role: { name: "Analyst", permissions: [] },
    is_active: true,
    is_verified: true,
    mfa_enabled: false,
    authorization: {
      contract: 1,
      home_org_id: "o-1",
      active_org_id: "o-1",
      can_switch_organisation: false,
      assignments: [],
      permissions: {
        platform: keys.filter((k) => vocabulary[k] === "platform"),
        organization: keys.filter((k) => vocabulary[k] !== "platform"),
      },
    },
  };
}
const persona = nativePersona();
const stubs = {
  "/platform/modules": PLATFORM_MODULES,
  "/auth/config": { self_registration_enabled: true },
  "/auth/check-email": { available: true, domain_allowed: true },
  "/auth/check-username": { available: true },
  "/notifications/stream": {
    __status: 404,
    body: { detail: "Synthetic SSE fallback" },
  },
};
Object.assign(stubs, {
  "/remediation/findings/f-1": {
    finding_id: "f-1",
    vuln_id: "CVE-2026-1111",
    asset_id: "a-1",
    severity: "Critical",
    remediation: { state: "open" },
    sla: { state: "within_sla" },
    verification: {},
    exception: {},
  },
  "/remediation/findings/f-1/history": { events: [] },
  "/scans/cr-report/policy": { policy: { recorded: false } },
});
const fallbackStubs = {
  "/assets/a-1": { ...AR_ASSETS.assets[0], notes_history: [] },
  "/assets/a-1/services": { services: [] },
  "/assets/a-1/findings": VB_FINDINGS,
  "/assets/a-1/changelog": { timeline: [], raw_changelog: [], admin_logs: [] },
  "/findings/f-1": VB_FINDING_DETAIL,
  "/findings/grouped/by-component": VB_GROUPS,
};
const auditPersonaFor = (id) =>
  id === "sd-noaccess"
    ? nativePersona(allKeys.filter((k) => k !== "audit.dashboard.read"))
    : id === "sd-restricted"
      ? nativePersona(["audit.dashboard.read", "audit.scan.read"])
      : id.includes("readonly") || id === "cw30-queue-analyst"
        ? nativePersona(allKeys.filter((k) => k.endsWith(".read")))
        : persona;
const common = {
  persona,
  stubs,
  themes: ["light", "dark"],
  tabLimit: 28,
  tracked: [
    ".auth-split-wrapper",
    ".auth-card",
    ".cc-field",
    "[role=dialog]",
    ".cc-main",
    ".cc-page",
  ],
};
const byButton = (text) =>
  `Array.from(document.querySelectorAll('button')).find(el=>el.textContent.trim()===${JSON.stringify(text)})`;
const focusClick = (expression) =>
  `(()=>{const el=${expression};el?.focus();return el;})()`;
const fill = (values) => ({
  click: `(()=>{const values=${JSON.stringify(values)};let first;for(const [selector,value] of Object.entries(values)){const el=document.querySelector(selector);if(!el)return null;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));first ||= el;}return first;})()`,
});
const loginActions = [
  fill({
    "#emailOrUsername": "harness@example.test",
    "#password": "Harness!Passphrase1",
  }),
  { click: "document.querySelector('button[type=submit]')" },
  { waitFor: "!!document.querySelector('#mfaCode')" },
];
const mfaWrites = {
  "POST /auth/login": {
    status: "mfa_required",
    mfa_token: "synthetic-challenge",
  },
};
const pages = [
  ["login", "/login", "!!document.querySelector('#password')"],
  ["register", "/register", "!!document.querySelector('#fullName')"],
  [
    "forgot",
    "/forgot-password",
    "!!document.querySelector('#emailOrUsername')",
  ],
  [
    "reset",
    "/reset-password?token=synthetic-reset",
    "!!document.querySelector('#confirm')",
  ],
  [
    "verify",
    "/verify-email",
    "document.body.innerText.includes('This link is no longer valid')",
  ],
];
export const AUTH_STATES = pages.flatMap(([id, route, ready]) =>
  [320, 768, 1440].map((width) => ({
    ...common,
    id: `b5-${id}-${width}`,
    route,
    ready,
    viewport: [width, 1000],
  })),
);
const flows = [
  {
    id: "mfa",
    route: "/login",
    ready: "!!document.querySelector('#password')",
    writes: mfaWrites,
    actions: loginActions,
    probes: [
      {
        id: "code-name-focus",
        tabTo: "el.id === 'mfaCode'",
        press: "ArrowRight",
        expect:
          "document.activeElement.getAttribute('autocomplete') === 'one-time-code'",
      },
    ],
  },
  {
    id: "mfa-complete",
    route: "/login",
    ready: "!!document.querySelector('#password')",
    writes: {
      ...mfaWrites,
      "POST /auth/login/verify-mfa": {
        access_token: "harness-token",
        token_type: "bearer",
      },
    },
    actions: [
      ...loginActions,
      fill({ "#mfaCode": "123456" }),
      { click: "document.querySelector('button[type=submit]')" },
      { waitFor: "location.pathname === '/'" },
    ],
  },
  {
    id: "terms",
    route: "/register",
    ready: "!!document.querySelector('#fullName')",
    actions: [
      { click: focusClick(byButton("Terms of Service")) },
      { waitFor: "!!document.querySelector('[role=dialog]')" },
    ],
    probes: [
      {
        id: "terms-escape",
        tabTo: "!!el.closest('[role=dialog]')",
        press: "Escape",
        expect:
          "!document.querySelector('[role=dialog]') && document.activeElement.textContent.trim() === 'Terms of Service' && !document.querySelector('input[type=checkbox]').checked",
      },
    ],
  },
  {
    id: "register-complete",
    route: "/register",
    ready: "!!document.querySelector('#fullName')",
    writes: { "POST /auth/register": { status: "pending_verification" } },
    actions: [
      fill({
        "#fullName": "Harness Operator",
        "#username": "harness",
        "#email": "harness@example.test",
        "#password": "Harness!Passphrase1",
        "#confirm": "Harness!Passphrase1",
      }),
      { click: "document.querySelector('input[type=checkbox]')" },
      { click: "document.querySelector('button[type=submit]')" },
      { waitFor: "document.body.innerText.includes('Check your email')" },
    ],
  },
  {
    id: "forgot-complete",
    route: "/forgot-password",
    ready: "!!document.querySelector('#emailOrUsername')",
    writes: {
      "POST /auth/forgot-password": {
        detail:
          "If this account is registered, you will receive a reset link shortly.",
      },
    },
    actions: [
      fill({ "#emailOrUsername": "harness@example.test" }),
      { click: "document.querySelector('button[type=submit]')" },
      { waitFor: "!!document.querySelector('[role=status]')" },
    ],
  },
  {
    id: "verify-complete",
    route: "/verify-email?token=synthetic-verify",
    ready: "document.body.innerText.includes('Email verified')",
    writes: {
      "POST /auth/verify-email": {
        status: "pending_approval",
        detail: "Awaiting administrator approval",
      },
    },
  },
  {
    id: "reset-complete",
    route: "/reset-password?token=synthetic-reset",
    ready: "!!document.querySelector('#confirm')",
    writes: { "POST /auth/reset-password": {} },
    actions: [
      fill({
        "#password": "Harness!Passphrase1",
        "#confirm": "Harness!Passphrase1",
      }),
      { click: "document.querySelector('button[type=submit]')" },
      { waitFor: "location.pathname === '/login'" },
    ],
  },
];
AUTH_STATES.push(
  ...flows.flatMap((flow) =>
    [390, 1440].map((width) => ({
      ...common,
      ...flow,
      id: `b5-${flow.id}-${width}`,
      viewport: [width, 1000],
    })),
  ),
);

const selected = [
  "ar-assets",
  "ar-assets-readonly",
  "ar-services",
  "ar-services-dialog",
  "ar-tls",
  "sd-default",
  "sd-date-menu",
  "sd-tab-assets",
  "sd-tab-vulns",
  "sd-tab-scans",
  "sd-tab-compliance",
  "sd-tab-audit",
  "vb-cve",
  "vb-grouped",
  "p1-interactive",
  "p2-done",
  "ns-entry",
  "sh-list",
  "cr-results",
  "nm-default",
  "cw26b-controls",
  "cw27-policy-dialog",
  "cw29-credentials-admin",
  "cw30-remediate-dialog",
  "ph-home",
  "ar-assets-empty",
  "ar-assets-error",
  "vb-drawer",
  "vb-drawer-accept",
  "vb-empty",
  "vb-error",
  "sd-tabs-keyboard",
  "sd-empty",
  "sd-error",
  "sd-restricted",
  "sd-noaccess",
  "sd-welcome",
  "p1-basic",
  "p1-phase2-done",
  "p1-scope",
  "p1-unreachable",
  "p1-load-error",
  "p2-results",
  "p2-interactive",
  "p2-expanded",
  "p2-no-results",
  "p2-load-error",
  "p2-running",
  "ns-setup",
  "ns-setup-asset",
  "ns-settings",
  "ns-settings-audit",
  "ns-validation",
  "ns-targets",
  "ns-file-error",
  "ns-running",
  "ns-failed",
  "ns-unreachable",
  "sh-history",
  "sh-readonly",
  "sh-detail",
  "sh-rerun-confirm",
  "cr-report",
  "cr-expanded",
  "cr-unreachable",
  "cr-running",
  "p3-report",
  "p3-report-modal",
  "nm-org",
  "nm-scan",
  "cw30-queue-admin",
  "cw30-queue-analyst",
  "cw29-credentials-key",
];
export const AUDIT_STATES = STATES.filter((s) => selected.includes(s.id)).map(
  (state) => ({
    ...state,
    persona: auditPersonaFor(state.id),
    stubs: { ...fallbackStubs, ...state.stubs, ...stubs },
    probes: state.probes?.filter(
      (p) => !p.expectRequest || p.expectRequest.method !== "POST",
    ),
  }),
);
for (const id of ["ar-assets", "sd-default"])
  for (const width of [320, 375, 390, 414, 768, 1024, 1280, 1440, 1920]) {
    const original = STATES.find((s) => s.id === id);
    AUDIT_STATES.push({
      ...original,
      id: `b6-${id}-${width}`,
      persona,
      stubs: { ...fallbackStubs, ...original.stubs, ...stubs },
      themes: ["light"],
      viewport: [width, 1000],
      probes: [],
      tabLimit: 16,
    });
  }
const orgPersona = {
  ...persona,
  username: "superadmin",
  organization_name: "CCure Development",
  authorization: { ...persona.authorization, can_switch_organisation: true },
};
const orgStubs = {
  "/admin/organizations/": {
    organizations: [
      {
        id: "o-1",
        name: "CCure Development",
        slug: "development",
        is_active: true,
      },
      {
        id: "o-2",
        name: "Second Organization",
        slug: "second",
        is_active: true,
      },
    ],
  },
};
for (const id of ["ar-assets", "sd-default"])
  for (const width of [320, 375, 390, 414, 768, 1024, 1280, 1440, 1920]) {
    const original = STATES.find((s) => s.id === id);
    AUDIT_STATES.push({
      ...original,
      id: `b6-org-${id}-${width}`,
      persona: orgPersona,
      stubs: { ...original.stubs, ...stubs, ...orgStubs },
      themes: ["light"],
      viewport: [width, 1000],
      probes: [],
      tabLimit: 16,
    });
  }
for (const id of ["ar-assets", "sd-default"])
  for (const width of [390, 1440]) {
    const original = AUDIT_STATES.find((s) => s.id === `b6-org-${id}-${width}`);
    AUDIT_STATES.push({
      ...original,
      id: original.id + "-dark",
      themes: ["dark"],
    });
  }

// Account security uses the same real shell and nested shared dialogs.
const profileActions = [
  { click: "document.querySelector('[aria-label^=\"Account menu for\"]')" },
  { waitFor: "!!document.querySelector('[role=menuitem]')" },
  { click: byButton("My Account") },
  { waitFor: "!!document.querySelector('#ac-username')" },
  {
    click:
      "Array.from(document.querySelectorAll('[role=tab]')).find(el=>el.textContent==='Security')",
  },
  { waitFor: "document.body.innerText.includes('Change Password')" },
];
const profileStubs = {
  ...stubs,
  "/user/profile": { ...persona, mfa_enabled: false },
  "/user/sessions": [],
};
const accountFlows = [
  {
    id: "account-mfa",
    actions: [
      ...profileActions,
      { click: byButton("Set up MFA") },
      { waitFor: "!!document.querySelector('#ac-mfa-code')" },
    ],
    writes: {
      "POST /auth/mfa/enable": {
        secret: "SYNTHETIC-HARNESS-SECRET",
        qr_code:
          "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz4=",
      },
    },
  },
  {
    id: "account-password",
    actions: [
      ...profileActions,
      { click: focusClick(byButton("Change Password")) },
      { waitFor: "!!document.querySelector('#acp-current')" },
    ],
    probes: [
      {
        id: "nested-password-escape",
        tabTo: "el.id === 'acp-current'",
        press: "Escape",
        expect:
          "document.querySelectorAll('[role=dialog]').length === 1 && document.activeElement.textContent.trim() === 'Change Password'",
        then: [
          {
            press: "Escape",
            expect:
              "!document.querySelector('[role=dialog]') && document.activeElement.getAttribute('aria-label')?.startsWith('Account menu for')",
          },
        ],
      },
    ],
  },
];
for (const flow of accountFlows)
  for (const width of [390, 1440])
    AUTH_STATES.push({
      ...common,
      ...flow,
      id: `b5-${flow.id}-${width}`,
      route: "/",
      stubs: profileStubs,
      ready: "!!document.querySelector('[aria-label^=\"Account menu for\"]')",
      viewport: [width, 1000],
    });
// The web-scan scope is part of Audit; no scan is dispatched by these cases.
const webStubs = {
  ...stubs,
  "/web-scans": { items: [], total: 0 },
  "/dashboard/web-scan-summary": {
    scans: { total: 0, active: 0 },
    severity: {},
    endpoints: {},
  },
  "/dashboard/web-owasp-scorecard": { scorecard: [] },
  "/dashboard/web-scan-trends": { data: [] },
  "/dashboard/web-findings": { items: [], total: 0 },
  "/dashboard/web-endpoints": { items: [], total: 0 },
};
for (const [id, route, ready] of [
  ["web-new", "/web-scans/new", "!!document.querySelector('#webscan-target')"],
  [
    "web-dashboard",
    "/web-scans/dashboard",
    "document.body.innerText.includes('Application Security')",
  ],
  [
    "web-list",
    "/web-scans/list",
    "document.body.innerText.includes('No Web Scans Found')",
  ],
])
  for (const width of [320, 1440])
    AUDIT_STATES.push({
      ...common,
      id: `b6-${id}-${width}`,
      route,
      ready,
      stubs: webStubs,
      viewport: [width, 1000],
    });
const remediationStubs = {
  ...stubs,
  "/admin/users/": { users: [], total: 0 },
  "/assets": { assets: [], total: 0 },
  "/remediation/summary": {
    summary_line: "Synthetic remediation queue",
    by_state: { open: 0 },
    overdue: 0,
    within_sla: 0,
    no_sla: 0,
  },
  "/remediation/overdue": { findings: [], total: 0 },
  "/remediation/pending-verification": { findings: [], total: 0 },
  "/remediation/sla-policy": {
    days_by_severity: { critical: 7, high: 30, medium: 60, low: 90 },
    defaults: {},
    due_soon_window_days: 3,
    honour_kev_due_date: true,
  },
};
for (const width of [320, 1440])
  AUDIT_STATES.push({
    ...common,
    id: `b6-remediation-${width}`,
    route: "/remediation",
    ready: "document.body.innerText.includes('Synthetic remediation queue')",
    stubs: remediationStubs,
    viewport: [width, 1000],
  });
for (const id of [
  "ns-setup-mobile",
  "ns-mission-mobile",
  "p1-scope-mobile",
  "p2-expanded-mobile",
  "cr-mobile",
  "vb-cve-mobile",
  "cw30-remediate-mobile",
  "cw27-waiver-dialog-mobile",
]) {
  const original = STATES.find((st) => st.id === id);
  AUDIT_STATES.push({
    ...original,
    persona,
    stubs: { ...fallbackStubs, ...original.stubs, ...stubs },
  });
}

// Migrated overlays must reflow at phone widths with the same domain data.
for (const width of [320, 390, 768]) {
  const original = AUDIT_STATES.find((st) => st.id === "ns-settings");
  AUDIT_STATES.push({
    ...original,
    id: `b6-scan-settings-${width}`,
    viewport: [width, 1000],
    themes: ["light", "dark"],
  });
}
for (const state of AUDIT_STATES) {
  if (/^b6-(?:org-)?(?:ar-assets|sd-default)-\d+/.test(state.id))
    state.probes = [
      {
        id: "header-contained-above-page",
        tabTo: "!!el.closest('.cc-header')",
        press: "ArrowRight",
        expect:
          "(()=>{const header=document.querySelector('.cc-header');const main=document.querySelector('.cc-main');if(!header||!main)return false;const box=header.getBoundingClientRect();return main.getBoundingClientRect().top>=box.bottom-1&&Array.from(header.querySelectorAll('button,a,input')).filter(el=>el.getClientRects().length).every(el=>{const r=el.getBoundingClientRect();return r.top>=box.top-1&&r.bottom<=box.bottom+1;});})()",
      },
    ];
  if (state.id.startsWith("b6-org-"))
    state.probes.push({
      id: "search-text-clears-icon",
      tabTo: "el.id==='sh-global-search'",
      press: "ArrowRight",
      expect:
        "(()=>{const input=document.querySelector('#sh-global-search');const icon=document.querySelector('.sh-search-icon');return input&&icon&&input.getBoundingClientRect().left+parseFloat(getComputedStyle(input).paddingInlineStart)>=icon.getBoundingClientRect().right+4;})()",
    });
  if (state.id === "ns-settings" || state.id.startsWith("b6-scan-settings-"))
    state.tracked = [
      ".ns-model__title",
      ".ns-model__card--selected",
      ".ns-model__card--selected .ns-model__title",
    ];
  if (state.id === "ns-settings" || state.id.startsWith("b6-scan-settings-"))
    state.actions = [
      {
        click: focusClick(
          "Array.from(document.querySelectorAll('button')).find(el=>el.textContent.includes('Configure Advanced Settings'))",
        ),
      },
      ...state.actions.slice(1),
    ];
  if (state.id === "ns-settings" || state.id.startsWith("b6-scan-settings-"))
    state.probes = [
      {
        id: "profile-copy-wraps-and-settings-escape",
        tabTo: "!!el.closest('[role=dialog]')",
        press: "ArrowRight",
        expect:
          "Array.from(document.querySelectorAll('.ns-model__desc')).length===2&&Array.from(document.querySelectorAll('.ns-model__desc')).every(el=>el.scrollWidth<=el.clientWidth+1)",
        then: [
          {
            press: "Escape",
            expect:
              "!document.querySelector('[role=dialog]')&&document.activeElement.textContent.includes('Configure Advanced Settings')",
          },
        ],
      },
    ];
}
for (const id of ["ar-services-dialog", "vb-drawer"])
  for (const width of [320, 390]) {
    const original = AUDIT_STATES.find((st) => st.id === id);
    AUDIT_STATES.push({
      ...original,
      id: `b6-overlay-${id}-${width}`,
      viewport: [width, 1000],
      themes: ["light", "dark"],
      probes:
        id === "vb-drawer"
          ? [
              {
                id: "finding-actions-fit-without-overlap",
                tabTo:
                  "el.tagName==='BUTTON'&&el.textContent.includes('Accept Risk')",
                press: "ArrowRight",
                expect:
                  "(()=>{const buttons=Array.from(document.querySelectorAll('[role=dialog] button')).filter(el=>/Accept Risk|Mark Fixed/.test(el.textContent));if(buttons.length!==2)return false;const [a,b]=buttons.map(el=>el.getBoundingClientRect());const parent=buttons[0].parentElement.getBoundingClientRect();return a.right<=parent.right+1&&b.right<=parent.right+1&&(a.right+3<=b.left||a.bottom+3<=b.top);})()",
              },
            ]
          : original.probes,
    });
  }
// Deep is deliberately unavailable in the backend. The old catalogue expected
// it to become selected, which was already invalid before B.5/B.6.
for (const state of AUDIT_STATES)
  if (state.probes)
    state.probes = state.probes.map((probe) =>
      probe.id !== "audit-profile-by-keyboard"
        ? probe
        : {
            id: "unimplemented-audit-profile-disabled",
            tabTo:
              "el.tagName === 'BUTTON' && el.textContent.trim() === 'Recommended'",
            press: "Space",
            expect:
              "Array.from(document.querySelectorAll('button')).some(b=>b.textContent.trim()==='Deep' && b.disabled && b.getAttribute('aria-pressed')==='false')",
          },
    );

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const args = parseArgs(process.argv.slice(2));
  const states = args.phase === "auth" ? AUTH_STATES : AUDIT_STATES;
  const filters = String(args.states || "")
    .split(",")
    .filter(Boolean);
  await runCapture({
    base: args.base,
    label: args.label || args.phase,
    out: args.out,
    states: filters.length
      ? states.filter((s) => filters.some((prefix) => s.id.startsWith(prefix)))
      : states,
  });
}
