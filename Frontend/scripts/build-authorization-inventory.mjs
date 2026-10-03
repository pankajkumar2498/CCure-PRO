#!/usr/bin/env node
/**
 * Build (or check) the frontend authorization inventory — RBAC-6.
 *
 *   node scripts/build-authorization-inventory.mjs           # print a summary
 *   node scripts/build-authorization-inventory.mjs --write   # rewrite the JSON
 *   node scripts/build-authorization-inventory.mjs --check   # exit 1 on drift
 *
 * Every place the UI decides (or displays) something from a role or a permission,
 * with its classification: migrated · display-only · intentionally-retained ·
 * rbac7 · rbac8. Generated from source and deterministic; a vitest test fails when
 * the file and the code disagree, so a new role-name or atom check cannot appear
 * without a recorded decision.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "src");
export const INVENTORY = path.join(ROOT, "authorization-inventory.json");

/** What a line can be. Order matters: the first match names the line. */
const KINDS = [
  ["role_permissions_read", /role\??\.permissions\b/],
  ["role_name_read", /role\??\.name\b|\brole_name\b/],
  ["role_literal", /["'](superadmin|org_admin|analyst|viewer|scanner)["']/],
  ["active_org_hint", /\bactiveOrgId\b/],
  ["atom_check", /\b(can|canPermission|canAny|canAll)\(/],
  [
    "atom_config",
    /\b(requiredPermission|requiredAny|requiredAll)\b|permission:\s*\{|\bresource:\s*"/,
  ],
];

/** Explicit decisions (file prefix → kind → classification). The first rule that
 *  matches wins; `reason` is mandatory. */
const RULES = [
  // the helper itself
  [
    "src/shell/auth/authorization.js",
    "role_permissions_read",
    "intentionally-retained",
    "older-backend fallback: legacy atoms honoured as atoms only (no wildcard, no role rule); removed with the legacy model in RBAC-8",
  ],
  [
    "src/shell/auth/authorization.js",
    "role_name_read",
    "display-only",
    "assignmentLabels(): a label shown beside the user; never an input to a decision",
  ],
  [
    "src/shell/auth/",
    "*",
    "migrated",
    "the central, permission-based authorization layer",
  ],
  // display
  [
    "src/shell/navigation/UserCard.jsx",
    "role_name_read",
    "display-only",
    "the role label shown in the header",
  ],
  [
    "src/shell/account/ProfileModal.jsx",
    "role_name_read",
    "display-only",
    "the role badge on the profile",
  ],
  // platform administration (RBAC-7): permission keys from the backend's catalogue
  [
    "src/shell/admin/components/UserForm.jsx",
    "role_name_read",
    "display-only",
    "role option label in the user form; the roles offered are the ones the backend marks assignable",
  ],
  [
    "src/shell/admin/",
    "atom_check",
    "migrated",
    "platform-administration gate resolved by the central helper from platform permission keys",
  ],
  [
    "src/shell/admin/",
    "atom_config",
    "migrated",
    "platform-administration navigation/route gate naming a platform permission key",
  ],
  ["src/shell/admin/", "role_name_read", "display-only", "label only"],
  // the request hint
  [
    "src/shell/api/axiosInstance.js",
    "active_org_hint",
    "intentionally-retained",
    "the hint sent as org_id on every request; the backend validates it (RBAC-5) and it is never evidence",
  ],
  [
    "src/modules/audit/api/scans.js",
    "active_org_hint",
    "intentionally-retained",
    "the same request hint on a streaming URL; validated by the backend",
  ],
  [
    "src/shell/navigation/",
    "active_org_hint",
    "display-only",
    "comment describing the hint",
  ],
  // strings that look like a role but are data
  [
    "src/modules/audit/components/scan/AssessmentContext.jsx",
    "role_literal",
    "display-only",
    "a scan-summary field named 'scanner' (the scanning engine), not a role",
  ],
  [
    "src/modules/audit/pages/AssetDetail.jsx",
    "role_literal",
    "display-only",
    "a provenance source value ('analyst' edited the owner), a label, not a role check",
  ],
  // the app
  [
    "src/App.jsx",
    "atom_config",
    "migrated",
    "route guards resolve through the central helper; the platform-wide route names its key",
  ],
  // product code
  [
    "src/modules/audit/",
    "atom_check",
    "migrated",
    "Audit action gate resolved by the central helper from the backend's permission keys",
  ],
  [
    "src/modules/audit/",
    "atom_config",
    "migrated",
    "Audit navigation/route gate resolved by the central helper",
  ],
  ["src/modules/audit/", "role_name_read", "display-only", "label only"],
];

const walk = (dir) =>
  fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) return e.name === "__tests__" ? [] : walk(p);
      return /\.(js|jsx)$/.test(e.name) ? [p] : [];
    })
    .sort();

const classify = (file, kind) => {
  for (const [prefix, k, status, reason] of RULES) {
    if (file.startsWith(prefix) && (k === "*" || k === kind))
      return { status, reason };
  }
  return { status: "unclassified", reason: "" };
};

const isComment = (line) => /^\s*(\{?\/\/|\{?\/\*|\*)/.test(line);

export function build() {
  const sites = [];
  for (const abs of walk(SRC)) {
    const file = path.relative(ROOT, abs).split(path.sep).join("/");
    const lines = fs.readFileSync(abs, "utf8").split("\n");
    lines.forEach((text, i) => {
      for (const [kind, re] of KINDS) {
        if (re.test(text)) {
          const comment = isComment(text);
          const { status, reason } = comment
            ? { status: "display-only", reason: "documentation comment" }
            : classify(file, kind);
          sites.push({ file, line: i + 1, kind, status, reason });
          break;
        }
      }
    });
  }
  const counts = {};
  for (const s of sites) counts[s.status] = (counts[s.status] || 0) + 1;
  return {
    schema_version: 1,
    description:
      "Every frontend authorization decision or display of a role/permission, classified. Generated by scripts/build-authorization-inventory.mjs; do not edit by hand.",
    summary: {
      total: sites.length,
      ...Object.fromEntries(Object.entries(counts).sort()),
    },
    sites,
  };
}

export const render = (inv) => JSON.stringify(inv, null, 2) + "\n";

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = render(build());
  if (process.argv.includes("--write")) {
    fs.writeFileSync(INVENTORY, text);
    console.log(`wrote ${INVENTORY}`);
  } else if (process.argv.includes("--check")) {
    const ok =
      fs.existsSync(INVENTORY) && fs.readFileSync(INVENTORY, "utf8") === text;
    console.log(
      ok ? "inventory is current" : "inventory is out of date: run --write",
    );
    process.exit(ok ? 0 : 1);
  } else {
    console.log(JSON.parse(text).summary);
  }
}
