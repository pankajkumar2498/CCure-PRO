/**
 * Scans and credentialed results meet only in Audit's shared layer (F2,
 * docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).
 *
 * Before F2 the shared layout folder held `ScanStepper`, which reads
 * `ScanContext`, and `components/scan/` held the credentialed results' own
 * sections, so each feature reached into the other's folder. Now:
 *
 * - `components/layout/` imports no scan state and no feature component;
 * - the credentialed screens and `components/credentialed/` import nothing of
 *   the scan screens or `components/scan/`;
 * - the scan screens and `components/scan/` import nothing of the credentialed
 *   screens or `components/credentialed/`.
 *
 * What both use lives in `components/common/`. Both may call the backend's
 * scan APIs through `api/`, which is the HTTP boundary, not either feature.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { AUDIT_SRC } from "../../testPaths";

function sources(dir = AUDIT_SRC, out = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) sources(p, out);
    else if (/\.(js|jsx)$/.test(name)) out.push(p);
  }
  return out;
}

// Each Audit file's imports, as paths relative to the Audit folder.
function importsOf(file) {
  const out = [];
  for (const [, spec] of readFileSync(file, "utf8").matchAll(
    /(?:from|import)\s*\(?\s*["']([^"']+)["']/g,
  )) {
    let base;
    if (spec.startsWith("@audit/")) base = path.join(AUDIT_SRC, spec.slice(7));
    else if (spec.startsWith("."))
      base = path.resolve(path.dirname(file), spec);
    else continue;
    const hit = [base, `${base}.js`, `${base}.jsx`].find(
      (c) => existsSync(c) && statSync(c).isFile(),
    );
    if (hit) out.push(path.relative(AUDIT_SRC, hit).split(path.sep).join("/"));
  }
  return out;
}

const CREDENTIALED =
  /^pages\/scan\/(CredentialedResults|CredentialedScan|ScanCredentials)\.jsx$|^components\/credentialed\//;
const SCANS =
  /^pages\/scan\/(?!CredentialedResults|CredentialedScan|ScanCredentials)|^pages\/ScanHistory\.jsx$|^components\/scan\/|^context\/ScanContext/;

const all = sources().map((file) => ({
  file: path.relative(AUDIT_SRC, file).split(path.sep).join("/"),
  imports: importsOf(file),
}));
const crossings = (from, to) =>
  all
    .filter(({ file }) => from.test(file))
    .flatMap(({ file, imports }) =>
      imports.filter((i) => to.test(i)).map((i) => `${file} -> ${i}`),
    );

describe("Audit feature boundaries", () => {
  it("the shared layout imports no scan state and no feature component", () => {
    expect(
      crossings(
        /^components\/layout\//,
        /^context\/ScanContext|^components\/(scan|credentialed)\/|^pages\//,
      ),
    ).toEqual([]);
  });

  it("the credentialed screens import nothing of the scan screens", () => {
    expect(crossings(CREDENTIALED, SCANS)).toEqual([]);
  });

  it("the scan screens import nothing of the credentialed screens", () => {
    expect(crossings(SCANS, CREDENTIALED)).toEqual([]);
  });

  it("finds the files it is about", () => {
    const files = all.map(({ file }) => file);
    expect(files.filter((f) => CREDENTIALED.test(f)).length).toBeGreaterThan(5);
    expect(files.filter((f) => SCANS.test(f)).length).toBeGreaterThan(10);
    expect(files).toContain("components/layout/AppLayout.jsx");
  });
});
