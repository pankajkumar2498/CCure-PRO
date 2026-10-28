/**
 * The compliance workspace reaches `/compliance` only through
 * `api/compliance.js` (F1, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).
 *
 * The page made its 34 calls through the shared axios instance directly. The
 * tests beside this one assert each request on the wire; this one keeps a new
 * call from going back into the page or its tabs.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { AUDIT_SRC } from "../../../testPaths";

const PAGE = path.join(AUDIT_SRC, "pages/ComplianceWorkspace.jsx");
const PARTS = path.join(AUDIT_SRC, "components/compliance/workspace");

const workspaceSources = () => [
  PAGE,
  ...(existsSync(PARTS)
    ? readdirSync(PARTS)
        .filter((name) => name.endsWith(".jsx") || name.endsWith(".js"))
        .map((name) => path.join(PARTS, name))
    : []),
];

describe("ComplianceWorkspace API boundary", () => {
  it("neither the page nor its tabs import the HTTP client", () => {
    for (const file of workspaceSources()) {
      const source = readFileSync(file, "utf8");
      expect(source, path.relative(AUDIT_SRC, file)).not.toMatch(
        /@shell\/api\/axiosInstance|\baxios\b/,
      );
    }
  });

  it("the calls are the compliance API module's", () => {
    const source = readFileSync(PAGE, "utf8");
    expect(source).toMatch(/from\s+["']@audit\/api\/compliance["']/);
    const api = readFileSync(path.join(AUDIT_SRC, "api/compliance.js"), "utf8");
    expect(api).toMatch(/from\s+["']@shell\/api\/axiosInstance["']/);
  });
});
