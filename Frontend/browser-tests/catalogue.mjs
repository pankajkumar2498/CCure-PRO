import {
  AUTH_STATES,
  AUDIT_STATES,
  nativePersona,
} from "../scripts/ux4g-harness/b5-b6.mjs";
import { PLATFORM_MODULES } from "../scripts/ux4g-harness/lib/fixtures.mjs";
import { STATES } from "../scripts/ux4g-harness/lib/states.mjs";
import { readFileSync } from "node:fs";
import {
  AR_ASSETS,
  VB_FINDINGS,
} from "../scripts/ux4g-harness/lib/fixtures.mjs";
const data = JSON.parse(
  readFileSync(new URL("./additional-fixtures.json", import.meta.url)),
);

const org = {
  id: "o-1",
  name: "CCure Development",
  slug: "development",
  plan: "enterprise",
  max_assets: 10000,
  max_users: 100,
  is_active: true,
  created_at: "2026-09-01T10:00:00Z",
};
const user = {
  id: "user-1",
  username: "analyst",
  full_name: "Security Analyst",
  email: "analyst@ccure.test",
  organization_id: org.id,
  org_id: org.id,
  organization_name: org.name,
  role_names: ["Analyst"],
  role: { name: "Analyst" },
  is_active: true,
  last_login_at: "2026-09-30T12:00:00Z",
};
const role = {
  id: "r1",
  key: "custom.reader",
  display_name: "Reader",
  description: "Read security assessments",
  kind: "custom",
  assignable_scope: "organization",
  org_id: org.id,
  state: "active",
  revision: 1,
  permission_count: 1,
  assignment_count: 1,
};
const permission = {
  key: "audit.scan.read",
  module: "audit",
  resource: "scan",
  action: "read",
  description: "Read scan results",
  scope: "organization",
  sensitivity: "normal",
  delegable: true,
  status: "active",
};
const log = {
  id: "event-1",
  action: "user.created",
  user_id: "b5-user",
  username: "harness",
  user_email: "harness@example.test",
  resource_type: "user",
  resource_id: user.id,
  status: "success",
  severity: "info",
  ip_address: "127.0.0.1",
  created_at: "2026-09-30T12:00:00Z",
  changes: { username: { old: null, new: "analyst" } },
};
export const COMMON_STUBS = {
  "/platform/modules": PLATFORM_MODULES,
  "/admin/organizations/": { organizations: [org] },
  "/admin/users/": { users: [user], total: 1 },
  "/admin/users/deleted": { users: [], total: 0 },
  "/admin/users/pending": { users: [], total: 0 },
  "/admin/registration-settings": {
    self_registration_enabled: false,
    deployment_default: false,
    administrator_approval_required: true,
    source: "deployment",
    revision: 0,
  },
  "/admin/email-domains": {
    rules: [
      {
        id: 1,
        domain: "ccure.test",
        verdict: "allow",
        source: "seed",
        reason: "Trusted domain",
      },
    ],
    total: 1,
    counts: { allow: 1, deny: 0 },
  },
  "/admin/email-domains/stats": {
    mode: "enforce",
    corpus_size: 76098,
    corpus_healthy: true,
    allow_rules: 1,
    deny_rules: 0,
    flagged_users: 0,
  },
  "/platform/rbac/roles": { roles: [role] },
  "/platform/rbac/roles/r1": {
    ...role,
    permissions: [permission.key],
    history: [],
    retirement_blockers: [],
    sensitive: false,
  },
  "/platform/rbac/permissions": { permissions: [permission] },
  "/platform/rbac/assignable-roles": {
    roles: [{ ...role, assignable: true, reasons: [] }],
    delegation: {},
  },
  "/platform/rbac/users/user-1/assignments": { assignments: [] },
  "/admin/audit-logs/": { logs: [log], total: 1 },
  "/admin/audit-logs": { logs: [log], total: 1 },
  "/admin/audit-logs/retention/preview": {
    installed: false,
    detail: "Retention is not installed",
  },
  "/admin/audit-logs/event-1": log,
  "/notifications": [],
  "/user/profile": { ...nativePersona(), mfa_enabled: false },
  "/user/sessions": [],
  "/notifications/stream": {
    __status: 404,
    body: { detail: "Synthetic SSE fallback" },
  },
};
const persona = nativePersona();
persona.authorization.can_switch_organisation = true;
export const COMMON_STATES = [
  ["home", "/", "CCurePRO Home"],
  ["users", "/admin/users", "User Management"],
  ["deleted", "/admin/users/deleted", "Deleted Users"],
  ["organizations", "/admin/organizations", "Organizations"],
  ["domains", "/admin/email-domains", "Email Domain Rules"],
  ["registration", "/admin/users?registration=settings", "User Management"],
  ["roles", "/admin/roles", "Roles & Permissions"],
  ["logs", "/admin/audit-logs", "Audit Logs"],
  ["policy", "/policy-dashboard", "CCure Policy Pro"],
  ["rank", "/rank-dashboard", "CCure Rank"],
  ["ir", "/ir-dashboard", "CCure IR"],
].map(([id, route, title]) => ({
  id: `common-${id}`,
  route,
  persona,
  stubs: COMMON_STUBS,
  ready:
    id === "registration"
      ? "!!document.querySelector('.registration-settings-form')"
      : `document.body.innerText.includes(${JSON.stringify(title)})`,
}));

// One settled representative of every implemented route, plus important states.
const seen = new Set();
const extraStubs = {
  ...COMMON_STUBS,
  "/config-audit/checks": data.configuration.CHECKS,
  "/config-audit/capabilities": {
    ...data.configuration.CAPS,
    check_types: ["registry", "command", "config_file"],
    operators: ["equals", "not_equals"],
    absence_policies: ["manual_review", "pass", "fail"],
  },
  "/credentials": { credentials: data.credentials.CREDS },
  "/credentials/types": { types: data.credentials.TYPES },
  "/scan-schedules": { schedules: data.schedules.SCHEDULES },
  "/scan-schedules/timezones": { timezones: ["UTC", "Asia/Kolkata"] },
  "/scan-schedules/credentials": { credentials: data.schedules.CREDENTIALS },
  "/scan-policies": { policies: [], total: 0 },
  "/scan-policies/settings": {
    scan_kinds: ["network", "credentialed", "any"],
    statuses: ["draft", "active", "archived"],
    config_keys: [],
    check_families: ["network_service", "host_configuration"],
    severities: ["info", "low", "medium", "high", "critical"],
  },
  "/scans": { scans: [], total: 0 },
  "/assets/a-1": { ...AR_ASSETS.assets[0], notes_history: [] },
  "/assets/a-1/services": { services: [] },
  "/assets/a-1/findings": VB_FINDINGS,
  "/assets/a-1/changelog": { timeline: [], raw_changelog: [], admin_logs: [] },
  "/compliance/credentials": { credentials: [] },
  "/web-scans/web-1": data.web.SCAN,
  "/web-scans/web-1/assets": {
    data: data.web.ASSETS,
    pagination: { total: data.web.ASSETS.length },
  },
  "/web-scans/web-1/findings": {
    data: data.web.FINDINGS,
    pagination: { total: data.web.FINDINGS.length },
  },
  "/web-scans/web-1/parameters": { data: [], pagination: { total: 0 } },
  "/web-scans/web-1/forms": { data: [], pagination: { total: 0 } },
  "/web-scans/web-1/api-operations": { data: [], pagination: { total: 0 } },
  "/dashboard/web-findings": {
    data: data.web.FINDINGS.map((item) => ({
      ...item,
      scan_id: "web-1",
      scan_name: "Corporate portal",
    })),
    pagination: { total: data.web.FINDINGS.length },
  },
  "/dashboard/web-endpoints": {
    data: data.web.ASSETS.map((item) => ({
      ...item,
      scan_id: "web-1",
      scan_name: "Corporate portal",
    })),
    pagination: { total: data.web.ASSETS.length },
  },
};
const EXTRAS = [
  ["launcher", "/scan", "Scan"],
  ["schedules", "/scan-schedules", "Scan Schedules"],
  ["credentials", "/scan-credentials", "Scan Credentials"],
  ["policies", "/scan-policies", "Scan Policies"],
  ["configuration", "/configuration-checks", "Configuration Checks"],
  ["validator", "/configuration-checks/validate", "Rule validator"],
  ["archived", "/archived", "Archived Scans"],
  ["recycle", "/recycle-bin", "Recycle Bin"],
  ["reports", "/reports", "Digital Report Cabinet"],
  ["asset-detail", "/assets/a-1", "Asset Information"],
  ["comparison", "/scan/comparison", "No scan selected"],
  ["credentialed", "/scan/credentialed", "Credentialed Scan"],
  ["web-assets", "/web-scans/web-1/assets", "Asset Inventory"],
  ["web-findings", "/web-scans/web-1/findings", "Findings Explorer"],
  ["web-detail", "/web-scans/web-1", "Corporate portal"],
  ["attack-surface", "/web-scans/web-1/attack-surface", "Attack Surface"],
  ["all-findings", "/web-scans/all-findings", "Findings"],
  ["all-endpoints", "/web-scans/all-endpoints", "Discovered Endpoints"],
].map(([id, route, title]) => ({
  id: `extra-${id}`,
  route,
  persona,
  stubs: extraStubs,
  ready: `document.body.innerText.includes(${JSON.stringify(title)}) && !document.querySelector('.cc-loader,.cc-skeleton')`,
}));
const amt = STATES.find((s) => s.id === "amt-overview");
const monitor = STATES.find((s) => s.id === "sh-monitor");
const webDetail = EXTRAS.find((s) => s.id === "extra-web-detail");
webDetail.ticket = "synthetic-web-ticket";
webDetail.init = `window.WebSocket = class {
  constructor() { this.readyState = 1; setTimeout(() => this.onopen?.({}), 0); }
  close() { this.readyState = 3; }
};`;
EXTRAS.push(
  { ...amt, persona, stubs: { ...amt.stubs, ...COMMON_STUBS } },
  { ...monitor, persona, stubs: { ...monitor.stubs, ...COMMON_STUBS } },
);
export const PAGE_STATES = [
  ...COMMON_STATES,
  ...AUTH_STATES,
  ...AUDIT_STATES,
  ...EXTRAS,
].filter((state) => {
  if (seen.has(state.route)) return false;
  seen.add(state.route);
  return true;
});
export const FLOW_STATES = [
  {
    ...COMMON_STATES.find((s) => s.id === "common-registration"),
    id: "registration-loading",
    stubs: {
      ...COMMON_STUBS,
      "/admin/registration-settings": { __pending: true },
    },
    ready: "document.body.innerText.includes('Loading registration settings')",
  },
  {
    ...COMMON_STATES.find((s) => s.id === "common-registration"),
    id: "registration-unavailable",
    stubs: {
      ...COMMON_STUBS,
      "/admin/registration-settings": { __status: 503 },
    },
    ready:
      "document.body.innerText.includes('Registration settings are unavailable')",
  },
  {
    ...COMMON_STATES.find((s) => s.id === "common-registration"),
    id: "registration-readonly",
    persona: nativePersona([
      "platform.user.read",
      "platform.registration.read",
    ]),
    ready: "document.body.innerText.includes('read-only access')",
  },
  {
    ...COMMON_STATES.find((s) => s.id === "common-registration"),
    id: "registration-enabled",
    stubs: {
      ...COMMON_STUBS,
      "/admin/registration-settings": {
        ...COMMON_STUBS["/admin/registration-settings"],
        self_registration_enabled: true,
        source: "administrator",
        revision: 1,
      },
    },
    ready:
      "document.body.innerText.includes('Using the saved administrator setting')",
  },
  {
    id: "auth-loading",
    route: "/",
    pendingRequests: ["POST /auth/refresh"],
    ready:
      "!!document.querySelector('main .cc-loader') && document.body.innerText.includes('Loading account')",
  },
  {
    ...COMMON_STATES.find((s) => s.id === "common-users"),
    id: "common-users-loading",
    stubs: { ...COMMON_STUBS, "/admin/users/": { __pending: true } },
    ready:
      "document.body.innerText.includes('User Management') && !!document.querySelector('.cc-loader')",
  },
  {
    ...COMMON_STATES.find((s) => s.id === "common-users"),
    id: "common-users-denied",
    persona: nativePersona([]),
    ready: "document.body.innerText.includes('Access denied')",
  },
  ...AUTH_STATES.filter(
    (s) => s.id.endsWith("-390") && !s.id.startsWith("b5-login"),
  ),
  ...AUDIT_STATES.filter((s) =>
    [
      "ar-assets-readonly",
      "ar-assets-empty",
      "ar-assets-error",
      "ar-services-dialog",
      "vb-drawer",
      "vb-drawer-accept",
      "sd-empty",
      "sd-error",
      "sd-noaccess",
      "ns-settings",
      "ns-validation",
      "ns-file-error",
      "ns-failed",
      "sh-rerun-confirm",
      "p1-load-error",
      "p2-load-error",
      "cw27-policy-dialog",
      "cw29-credentials-key",
      "cw30-remediate-dialog",
    ].includes(s.id),
  ),
];
