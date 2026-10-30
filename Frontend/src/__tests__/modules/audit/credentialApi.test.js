/**
 * The credential screens use one API (F3, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).
 *
 * Stored credentials are the credential store's, `/credentials`, and the
 * application reaches it through `api/credentials.js`. Before F3 the scan
 * setup, the credentialed scan and the compliance workspace read and wrote
 * them through `/compliance/credentials`, an alias that always acted in the
 * user's home organisation, whichever organisation the page was in.
 *
 * `/scan-schedules/credentials` is the schedule picker's own list (S2b) and is
 * not this alias.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { SRC } from "../../testPaths";

function sources(dir = SRC, out = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (name === "__tests__") continue;
    if (statSync(p).isDirectory()) sources(p, out);
    else if (/\.(js|jsx)$/.test(name)) out.push(p);
  }
  return out;
}

const STORE_CLIENT = path.join(SRC, "modules/audit/api/credentials.js");
const rel = (file) => path.relative(SRC, file).split(path.sep).join("/");

describe("one credential API", () => {
  it("nothing calls the compliance alias of the credential store", () => {
    const callers = sources().filter((file) =>
      readFileSync(file, "utf8").includes("/compliance/credentials"),
    );
    expect(callers.map(rel)).toEqual([]);
  });

  it("only the credential store's client names its path", () => {
    const callers = sources().filter(
      (file) =>
        file !== STORE_CLIENT &&
        /["'`]\/credentials\b/.test(readFileSync(file, "utf8")),
    );
    expect(callers.map(rel)).toEqual([]);
    expect(readFileSync(STORE_CLIENT, "utf8")).toMatch(/["']\/credentials["']/);
  });
});
