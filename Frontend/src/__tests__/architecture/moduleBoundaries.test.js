/**
 * Module boundaries (Phase 12.3–12.4, docs/architecture/PHASE12_FRONTEND_SHELL.md
 * §3.6, §9, §10).
 *
 * Every source file must sit in a place modules.config.js names: the shell,
 * the design system, a product module, the composition root, the global
 * stylesheet, or a named pending group with its reason. Since 12.4 that is how
 * "Audit's code lives in src/modules/audit/" is enforced: a file anywhere else
 * is unclassified and fails.
 *
 * Every import is resolved to a file — relative, `@shell/…` and `@<module>/…`
 * alike — and checked:
 *
 *   design-system  imports only itself
 *   shell          imports only itself and the design system
 *   <module>       imports itself, the shell, the design system and the global
 *                  styles — never another product
 *   pending group  imports itself, the shell, the design system and the global
 *                  styles
 *   root           (main.jsx, App.jsx) composes everything; nothing else
 *                  imports it
 *
 * Tests are exempt from the layering — a test may render anything — but every
 * path a test imports or mocks must resolve to a real module. That is a move's
 * silent failure: a `vi.mock` whose path no longer names the module stops
 * mocking, and neither the build nor the test runner says so.
 *
 * The ESLint `no-restricted-imports` overrides repeat the alias half for an
 * editor; the last block checks they say what this file enforces.
 */
import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import {
  ALIASES,
  DESIGN_SYSTEM,
  GLOBAL_STYLES,
  MODULES,
  PENDING,
  ROOT_FILES,
  SHELL,
} from "../../../modules.config.js";

const FRONT = process.cwd();
const SRC = path.join(FRONT, "src");
const rel = (abs) => path.relative(FRONT, abs).split(path.sep).join("/");
const under = (p, dir) => p === dir || p.startsWith(`${dir}/`);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(jsx?|mjs|css)$/.test(name)) out.push(p);
  }
  return out;
}

const EXTS = ["", ".js", ".jsx", ".mjs", ".json", ".css"];
function resolveFile(base) {
  for (const ext of EXTS) {
    if (existsSync(base + ext) && statSync(base + ext).isFile())
      return base + ext;
  }
  for (const idx of ["index.js", "index.jsx"]) {
    const p = path.join(base, idx);
    if (existsSync(p)) return p;
  }
  return null;
}

/** null for a package import; a path, or `{ unresolved }`, otherwise. */
function resolveSpec(fromFile, spec) {
  if (spec.startsWith(".")) {
    return (
      resolveFile(path.resolve(path.dirname(fromFile), spec)) || {
        unresolved: spec,
      }
    );
  }
  const alias = Object.keys(ALIASES).find(
    (a) => spec === a || spec.startsWith(`${a}/`),
  );
  if (alias) {
    const target = path.join(FRONT, ALIASES[alias], spec.slice(alias.length));
    return resolveFile(target) || { unresolved: spec };
  }
  return null;
}

const IMPORT_RE =
  /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\(\s*|@import\s+)(["'])([^"'\n]+)\1/g;
const MOCK_RE =
  /vi\.(?:mock|doMock|unmock|doUnmock|importActual|importMock)\(\s*(["'])([^"'\n]+)\1/g;

const specsOf = (text, re) => [...text.matchAll(re)].map((m) => m[2]);

const PENDING_OWNER = Object.fromEntries(
  Object.entries(PENDING).flatMap(([group, { files }]) =>
    files.map((f) => [f, `pending:${group}`]),
  ),
);

/** Which part of the frontend a file belongs to. */
function ownerOf(relPath) {
  if (ROOT_FILES.includes(relPath)) return "root";
  if (GLOBAL_STYLES.includes(relPath)) return "global-styles";
  if (PENDING_OWNER[relPath]) return PENDING_OWNER[relPath];
  if (under(relPath, DESIGN_SYSTEM)) return "design-system";
  if (under(relPath, SHELL)) return "shell";
  for (const [key, dir] of Object.entries(MODULES))
    if (under(relPath, dir)) return key;
  return "unclassified";
}

const MODULE_KEYS = Object.keys(MODULES);
function allowed(from, to) {
  if (from === "root") return true;
  if (to === "root" || to === "unclassified" || from === "unclassified")
    return false;
  if (from === "design-system") return to === "design-system";
  if (from === "shell") return to === "shell" || to === "design-system";
  if (from === "global-styles") return to === "global-styles";
  const shared =
    to === "shell" || to === "design-system" || to === "global-styles";
  if (MODULE_KEYS.includes(from)) return to === from || shared;
  if (from.startsWith("pending:")) return to === from || shared;
  return false;
}

const sourceFiles = walk(SRC).filter((f) => !under(rel(f), "src/__tests__"));
const testFiles = walk(path.join(SRC, "__tests__"));

const edges = [];
const unresolvedImports = [];
for (const file of sourceFiles) {
  const text = readFileSync(file, "utf8");
  for (const spec of specsOf(text, IMPORT_RE)) {
    const target = resolveSpec(file, spec);
    if (target === null) continue;
    if (typeof target === "object") {
      unresolvedImports.push(`${rel(file)} → ${spec}`);
      continue;
    }
    edges.push({ from: rel(file), to: rel(target), spec });
  }
}

describe("the layout in modules.config.js", () => {
  it("names a shell and design system that exist", () => {
    expect(existsSync(path.join(FRONT, SHELL))).toBe(true);
    expect(existsSync(path.join(FRONT, DESIGN_SYSTEM))).toBe(true);
  });

  it("gives every product module an alias, and the shell one", () => {
    expect(ALIASES["@shell"]).toBe(SHELL);
    for (const [key, dir] of Object.entries(MODULES))
      expect(ALIASES[`@${key}`]).toBe(dir);
  });

  it("scanned a real import graph, not an empty one", () => {
    expect(sourceFiles.length).toBeGreaterThan(150);
    expect(edges.length).toBeGreaterThan(500);
    expect(
      edges.filter((e) => e.spec.startsWith("@shell/")).length,
    ).toBeGreaterThan(40);
  });
});

describe("every source file is in a classified place", () => {
  it("no file sits outside the shell, the design system, a module, the root, the global styles or a pending group", () => {
    const unclassified = sourceFiles
      .map(rel)
      .filter((f) => ownerOf(f) === "unclassified");
    expect(unclassified).toEqual([]);
  });

  it("every listed root, global-style and pending file exists — no stale entries", () => {
    const listed = [
      ...ROOT_FILES,
      ...GLOBAL_STYLES,
      ...Object.values(PENDING).flatMap((g) => g.files),
    ];
    expect(listed.filter((f) => !existsSync(path.join(FRONT, f)))).toEqual([]);
  });

  it("every pending group says why", () => {
    for (const g of Object.values(PENDING))
      expect(g.reason?.length).toBeGreaterThan(20);
  });

  it("Audit's code is in src/modules/audit/: the pre-12.4 locations hold none of it", () => {
    const legacy = sourceFiles
      .map(rel)
      .filter((f) =>
        /^src\/(api|auth|components|config|context|hooks|utils|pages|styles|modules\/web-scanning)\//.test(
          f,
        ),
      )
      .filter((f) => !GLOBAL_STYLES.includes(f) && !PENDING_OWNER[f]);
    expect(legacy).toEqual([]);
    expect(
      sourceFiles.filter((f) => ownerOf(rel(f)) === "audit").length,
    ).toBeGreaterThan(140);
  });
});

describe("imports respect the module boundaries", () => {
  it("every relative and alias import resolves to a file", () => {
    expect(unresolvedImports).toEqual([]);
  });

  it("no import crosses a boundary", () => {
    const crossings = edges
      .map((e) => ({ ...e, a: ownerOf(e.from), b: ownerOf(e.to) }))
      .filter((e) => !allowed(e.a, e.b))
      .map((e) => `${e.from} (${e.a}) → ${e.spec} (${e.b})`);
    expect(crossings).toEqual([]);
  });

  it("the shell depends on no product", () => {
    const shellDeps = new Set(
      edges
        .filter((e) => ownerOf(e.from) === "shell")
        .map((e) => ownerOf(e.to)),
    );
    expect([...shellDeps].sort()).toEqual(["design-system", "shell"]);
  });

  it("the design system depends on nothing in the application", () => {
    const deps = new Set(
      edges
        .filter((e) => ownerOf(e.from) === "design-system")
        .map((e) => ownerOf(e.to)),
    );
    expect([...deps]).toEqual(["design-system"]);
  });

  it("Audit reaches the shell and itself through their aliases", () => {
    const auditEdges = edges.filter((e) => ownerOf(e.from) === "audit");
    const intoShell = auditEdges.filter((e) => ownerOf(e.to) === "shell");
    expect(intoShell.length).toBeGreaterThan(40);
    expect(intoShell.every((e) => e.spec.startsWith("@shell/"))).toBe(true);
    const fromOutside = edges.filter(
      (e) => ownerOf(e.to) === "audit" && ownerOf(e.from) !== "audit",
    );
    expect(fromOutside.every((e) => e.spec.startsWith("@audit/"))).toBe(true);
  });

  it("the rule itself refuses what it should", () => {
    // Pinned so a loosened `allowed` cannot pass the checks above vacuously.
    expect(allowed("shell", "audit")).toBe(false);
    expect(allowed("design-system", "shell")).toBe(false);
    expect(allowed("policy", "audit")).toBe(false);
    expect(allowed("audit", "rank")).toBe(false);
    expect(allowed("audit", "root")).toBe(false);
    expect(allowed("audit", "shell")).toBe(true);
    expect(allowed("audit", "global-styles")).toBe(true);
    expect(allowed("shell", "global-styles")).toBe(false);
    expect(allowed("rank", "design-system")).toBe(true);
    expect(allowed("pending:sign-in", "audit")).toBe(false);
    expect(allowed("pending:sign-in", "shell")).toBe(true);
    expect(allowed("shell", "pending:sign-in")).toBe(false);
    expect(
      ownerOf("src/modules/audit/web-scanning/WebScanningRoutes.jsx"),
    ).toBe("audit");
    expect(ownerOf("src/pages/SecurityDashboard.jsx")).toBe("unclassified");
    expect(ownerOf("src/pages/Login.jsx")).toBe("pending:sign-in");
    expect(ownerOf("src/styles/global.css")).toBe("global-styles");
    expect(ownerOf("src/modules/rank/x.js")).toBe("rank");
    expect(ownerOf("src/shell/auth/PrivateRoute.jsx")).toBe("shell");
  });
});

describe("every path a test uses still names a module", () => {
  it("vi.mock / importActual specifiers all resolve", () => {
    const stale = [];
    let count = 0;
    for (const file of testFiles) {
      const text = readFileSync(file, "utf8");
      for (const spec of specsOf(text, MOCK_RE)) {
        const target = resolveSpec(file, spec);
        if (target === null) continue;
        count += 1;
        if (typeof target === "object") stale.push(`${rel(file)} → ${spec}`);
      }
    }
    expect(count).toBeGreaterThan(150);
    expect(stale).toEqual([]);
  });

  it("no test imports a module that does not exist", () => {
    const missing = [];
    for (const file of testFiles) {
      const text = readFileSync(file, "utf8");
      for (const spec of specsOf(text, IMPORT_RE)) {
        const target = resolveSpec(file, spec);
        if (target && typeof target === "object")
          missing.push(`${rel(file)} → ${spec}`);
      }
    }
    expect(missing).toEqual([]);
  });
});

describe("ESLint repeats the alias rules", () => {
  const eslint = JSON.parse(
    readFileSync(path.join(FRONT, ".eslintrc.json"), "utf8").replace(
      /^\s*\/\/.*$/gm,
      "",
    ),
  );
  const overrideFor = (files) =>
    (eslint.overrides || []).find(
      (x) =>
        JSON.stringify([...(x.files || [])].sort()) ===
        JSON.stringify([...files].sort()),
    );
  const forbidden = (files) => {
    const opt = overrideFor(files)?.rules?.["no-restricted-imports"]?.[1] || {};
    return new Set((opt.patterns || []).flatMap((p) => p.group || []));
  };
  const aliasGroup = (keys) => keys.flatMap((k) => [`@${k}`, `@${k}/*`]);

  it("the shell may import no product alias", () => {
    expect(forbidden([`${SHELL}/**`])).toEqual(
      new Set(aliasGroup(MODULE_KEYS)),
    );
  });

  it("the design system may import neither the shell nor a product", () => {
    expect(forbidden([`${DESIGN_SYSTEM}/**`])).toEqual(
      new Set(aliasGroup(["shell", ...MODULE_KEYS])),
    );
  });

  it.each(MODULE_KEYS)(
    "module %s may import no other product's alias",
    (key) => {
      expect(forbidden([`${MODULES[key]}/**`])).toEqual(
        new Set(aliasGroup(MODULE_KEYS.filter((k) => k !== key))),
      );
    },
  );

  it.each(Object.keys(PENDING))(
    "pending group %s may import no product alias",
    (group) => {
      const scripts = PENDING[group].files.filter((f) => /\.jsx?$/.test(f));
      expect(forbidden(scripts)).toEqual(new Set(aliasGroup(MODULE_KEYS)));
    },
  );

  it("no override remains for the retired pre-12.4 Audit locations", () => {
    expect(
      (eslint.overrides || []).some((x) => (x.files || []).includes("src/**")),
    ).toBe(false);
  });
});

describe("every tool resolves the aliases the same way (Phase 12.5)", () => {
  it("vite.config.js takes its aliases from modules.config.js and nowhere else", () => {
    const source = readFileSync(path.join(FRONT, "vite.config.js"), "utf8");
    expect(source).toMatch(
      /import \{ ALIASES \} from "\.\/modules\.config\.js";/,
    );
    expect(source).toMatch(/resolve: \{ alias \}/);
    // No alias is written out by hand beside the generated ones.
    expect(source).not.toMatch(/["']@(shell|audit|policy|rank|ir)["']\s*:/);
  });

  it("the aliases resolve to the very modules their folders hold", async () => {
    // Behavioural, not textual: the same module object through both routes.
    expect(await import("@shell/products/productList")).toBe(
      await import("../../shell/products/productList"),
    );
    expect(await import("@audit/config/scanConfig")).toBe(
      await import("../../modules/audit/config/scanConfig"),
    );
  });

  it("jsconfig.json gives the editor the same aliases", () => {
    const { paths } = JSON.parse(
      readFileSync(path.join(FRONT, "jsconfig.json"), "utf8"),
    ).compilerOptions;
    for (const [a, dir] of Object.entries(ALIASES))
      expect(paths[`${a}/*`]).toEqual([`${dir}/*`]);
  });
});

describe("every frontend part has an owner line (Phase 12.5)", () => {
  // The frontend twin of Backend/scripts/architecture/module_boundaries.py's
  // CODEOWNERS check. Skipped where the repository root is not present.
  const codeowners = path.join(FRONT, "..", ".github", "CODEOWNERS");
  const lines = existsSync(codeowners)
    ? readFileSync(codeowners, "utf8")
        .split("\n")
        .filter((l) => l.trim() && !l.trim().startsWith("#"))
    : null;
  const ownerOfPath = (p) =>
    lines
      .map((l) => l.trim().split(/\s+/))
      .filter(([pattern]) => pattern === `/Frontend/${p}/`)
      .map(([, ...owners]) => owners)
      .pop();

  it.skipIf(!lines).each([SHELL, DESIGN_SYSTEM, ...Object.values(MODULES)])(
    "%s has its own CODEOWNERS line naming an owner",
    (dir) => {
      expect(ownerOfPath(dir)?.length).toBeGreaterThan(0);
    },
  );
});
