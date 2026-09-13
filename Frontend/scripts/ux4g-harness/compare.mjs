#!/usr/bin/env node
/**
 * Compare two capture reports.
 *
 *   node compare.mjs A/report.json B/report.json --mode determinism
 *     Every state in both reports must be identical in every category.
 *
 *   node compare.mjs PRE/report.json POST/report.json --mode diff [--identical sd-,cw-]
 *     Prints every named delta. States matching --identical must have none.
 *
 * Exit code 1 when a gate fails.
 */
import { existsSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { pixelDelta } from "./lib/png.mjs";

/* Two captures of an unchanged build differed by 1/255 in one channel on 44
   anti-aliased pixels at a card's rounded corners (cw-findings, light). That is
   rasteriser noise, not a rendering change, so screenshots are compared pixel
   by pixel and a pixel counts as changed only when some channel moves by more
   than this. Every sensitivity injection that expects a screenshot delta
   changes pixels by far more. Differences inside the tolerance are still
   reported, as notes, never silently absorbed. */
export const SCREENSHOT_TOLERANCE = 2;

function screenshotDelta(a, b) {
  if (a.screenshot === b.screenshot) return null;
  if (
    !a.screenshotFile ||
    !b.screenshotFile ||
    !existsSync(a.screenshotFile) ||
    !existsSync(b.screenshotFile)
  ) {
    return {
      changed: true,
      detail: { from: a.screenshot, to: b.screenshot, compared: "hash" },
    };
  }
  const d = pixelDelta(
    readFileSync(a.screenshotFile),
    readFileSync(b.screenshotFile),
    SCREENSHOT_TOLERANCE,
  );
  return {
    changed: d.beyond > 0,
    detail: { compared: "pixels", tolerance: SCREENSHOT_TOLERANCE, ...d },
  };
}

/* The shell's notification stream (SSE) is answered 404 and the shell retries
   it on a backoff timer, so how many attempts a capture logs depends on how
   long the capture ran — measured at 1, 2 or 3 across 62 captures of one
   unchanged build (batch 17). Repeated attempts compare as one; the raw log in
   report.json keeps every attempt. */
const RETRIED_STREAMS = [/^GET \/api\/notifications\/stream(?:\?\S*)? -> /];

export const comparableRequests = (lines) => {
  const seen = new Set();
  return lines.filter((line) => {
    if (!RETRIED_STREAMS.some((re) => re.test(line))) return true;
    if (seen.has(line)) return false;
    seen.add(line);
    return true;
  });
};

export const CATEGORIES = {
  names: (r) => r.names,
  headings: (r) => r.headings,
  roles: (r) => r.roles,
  ariaStates: (r) => r.ariaStates,
  dialogs: (r) => r.dialogs,
  live: (r) => r.live,
  tables: (r) => r.tables,
  inline: (r) => r.inline,
  classes: (r) => r.classes,
  clickable: (r) => r.clickable,
  contrast: (r) => r.contrast,
  tabOrder: (r) => r.tabOrder,
  probes: (r) => r.probes,
  overflow: (r) => r.overflowX,
  errorBoundary: (r) => r.errorBoundary,
  text: (r) => r.text,
  url: (r) => r.url,
  theme: (r) => r.theme,
  styles: (r) => r.styles,
  rects: (r) => r.rects,
  requests: (r) => comparableRequests(r.log.requests),
  writes: (r) => r.log.refusedWrites,
  offOrigin: (r) => r.log.offOrigin,
  csp: (r) => r.log.csp,
  runtime: (r) => ({
    ready: r.ready,
    actions: r.actions,
    exceptions: r.log.exceptions,
    consoleErrors: r.log.consoleErrors,
    unstubbed: r.log.unstubbed,
  }),
  screenshot: (r) => r.screenshot,
};

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function detail(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    const sa = a.map((x) => JSON.stringify(x));
    const sb = b.map((x) => JSON.stringify(x));
    const setA = new Set(sa);
    const setB = new Set(sb);
    return {
      count: [a.length, b.length],
      removed: sa
        .filter((x) => !setB.has(x))
        .slice(0, 12)
        .map((x) => JSON.parse(x)),
      added: sb
        .filter((x) => !setA.has(x))
        .slice(0, 12)
        .map((x) => JSON.parse(x)),
    };
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const changed = {};
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!same(a[k], b[k])) changed[k] = { from: a[k], to: b[k] };
    }
    return { changed };
  }
  return { from: a, to: b };
}

export function diffState(a, b, notes) {
  const deltas = [];
  for (const [name, pick] of Object.entries(CATEGORIES)) {
    if (name === "screenshot") {
      const s = screenshotDelta(a, b);
      if (s?.changed) deltas.push({ category: name, detail: s.detail });
      else if (s && notes) notes.push({ category: name, detail: s.detail });
      continue;
    }
    const va = pick(a);
    const vb = pick(b);
    if (!same(va, vb)) deltas.push({ category: name, detail: detail(va, vb) });
  }
  return deltas;
}

export function compareReports(A, B, { prefixes } = {}) {
  const keys = [
    ...new Set([...Object.keys(A.states), ...Object.keys(B.states)]),
  ]
    .filter((k) => !prefixes || prefixes.some((p) => k.startsWith(p)))
    .sort();
  const out = {};
  const notes = {};
  const missing = [];
  for (const k of keys) {
    if (!A.states[k] || !B.states[k]) {
      missing.push(k);
      continue;
    }
    notes[k] = [];
    out[k] = diffState(A.states[k], B.states[k], notes[k]);
  }
  return { states: out, notes, missing };
}

const clip = (v, n = 400) => {
  const s = JSON.stringify(v);
  return s.length > n ? `${s.slice(0, n)}…` : s;
};

// `process.argv[1]` is absent when the module is imported from `node -e`.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const [fileA, fileB, ...rest] = process.argv.slice(2);
  const opt = {};
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i].startsWith("--")) {
      opt[rest[i].slice(2)] = rest[i + 1];
      i += 1;
    }
  }
  if (!fileA || !fileB) {
    console.error(
      "usage: compare.mjs A.json B.json --mode determinism|diff [--identical p1,p2] [--states p1,p2] [--verbose true]",
    );
    process.exit(2);
  }
  const A = JSON.parse(readFileSync(fileA, "utf8"));
  const B = JSON.parse(readFileSync(fileB, "utf8"));
  const prefixes = opt.states ? opt.states.split(",") : undefined;
  const { states, notes, missing } = compareReports(A, B, { prefixes });
  const identical = opt.identical ? opt.identical.split(",") : [];
  const verbose = opt.verbose === "true" || opt.mode === "diff";
  let failed = false;

  for (const [k, deltas] of Object.entries(states)) {
    const noise = (notes[k] || []).map(
      (n) =>
        `${n.category} within tolerance: ${n.detail.within} px, max channel delta ${n.detail.maxDelta}`,
    );
    if (!deltas.length) {
      console.log(
        `${k}: IDENTICAL${noise.length ? ` (${noise.join("; ")})` : ""}`,
      );
      continue;
    }
    const mustMatch =
      opt.mode === "determinism" || identical.some((p) => k.startsWith(p));
    if (mustMatch) failed = true;
    console.log(
      `${k}: ${mustMatch ? "FAIL " : ""}${deltas.map((d) => d.category).join(", ")}`,
    );
    if (verbose || mustMatch) {
      for (const d of deltas)
        console.log(`    ${d.category}: ${clip(d.detail)}`);
    }
  }
  if (missing.length) {
    console.log(`missing from one report: ${missing.join(", ")}`);
    if (opt.mode === "determinism") failed = true;
  }
  const total = Object.keys(states).length;
  const same = Object.values(states).filter((d) => !d.length).length;
  console.log(
    `\n${same}/${total} states identical${failed ? " — GATE FAILED" : ""}`,
  );
  process.exit(failed ? 1 : 0);
}
