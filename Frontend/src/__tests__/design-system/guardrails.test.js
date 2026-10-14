/**
 * Permanent guardrails for the UX4G foundation.
 *
 * Everything Phase 1 and Phase 2 established by measurement is asserted here,
 * so a later change that quietly undoes one fails CI rather than shipping. The
 * numbered list maps to docs/ux4g/02-dependency-strategy.md §11.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const SRC = path.join(ROOT, "src");
const DS = path.join(SRC, "design-system");

const baseline = JSON.parse(
  readFileSync(path.join(ROOT, "ux4g-baseline.json"), "utf8"),
);
const PINNED_UX4G = baseline.npm.version;

/** Every source file, minus generated output and the design system's own tokens. */
function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

let pkg;
let manifest;
let sources;

beforeAll(() => {
  pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const mPath = path.join(DS, "tokens", "ux4g.generated.manifest.json");
  manifest = existsSync(mPath) ? JSON.parse(readFileSync(mPath, "utf8")) : null;
  sources = walk(SRC).filter((p) => /\.(jsx?|css)$/.test(p));
});

/* ── 1. Version pinning ──────────────────────────────────────────────────── */

describe("UX4G version is pinned", () => {
  it("package.json names an exact version, not a range", () => {
    const spec = pkg.dependencies["ux4g-web-components"];
    // A caret would let `npm install` on a fresh clone pull a version none of
    // the Phase 1/2 measurements were made against — the class-collision set,
    // the reset shape, the token closure and every contrast figure are
    // properties of this exact build.
    expect(spec).toBe(PINNED_UX4G);
    expect(spec).not.toMatch(/^[\^~><*]/);
  });

  it("the installed package matches the pin", () => {
    const installed = JSON.parse(
      readFileSync(
        path.join(ROOT, "node_modules", "ux4g-web-components", "package.json"),
        "utf8",
      ),
    );
    expect(installed.version).toBe(PINNED_UX4G);
  });
});

/* ── 11. Generated assets correspond to the installed package ────────────── */

describe("generated assets correspond to the installed package", () => {
  it("a manifest was written", () => {
    // The generated CSS and fonts are gitignored, so the manifest is what makes
    // them auditable — it records which package version and mode produced the
    // bytes currently on disk.
    expect(manifest, "run `npm run ux4g:assets`").not.toBeNull();
  });

  it("the manifest names the pinned version", () => {
    expect(manifest.source.package).toBe("ux4g-web-components");
    expect(manifest.source.version).toBe(PINNED_UX4G);
  });

  it("every font in the manifest exists on disk at the recorded size", () => {
    for (const f of manifest.fonts) {
      const p = path.join(ROOT, "public", "assets", "fonts", "ux4g", f.file);
      expect(existsSync(p), `${f.file} missing`).toBe(true);
      expect(statSync(p).size, `${f.file} size drift`).toBe(f.bytes);
    }
  });

  it("no font file exists that the manifest does not name", () => {
    // A leftover from a previous run would be served by nginx and counted in
    // the image size while nothing referenced it.
    const dir = path.join(ROOT, "public", "assets", "fonts", "ux4g");
    const onDisk = readdirSync(dir)
      .filter((f) => f.endsWith(".woff2"))
      .sort();
    const named = manifest.fonts.map((f) => f.file).sort();
    expect(onDisk).toEqual(named);
  });

  it("retains the approved B.1 font set without changing typography", () => {
    // Proven in docs/ux4g/02-dependency-strategy.md §5 against four independent
    // sources: UX4G's own CSS, CCure components, the token graph, and what the
    // browser actually requested.
    expect(manifest.fonts.map((f) => f.family)).toEqual(
      baseline.assets.retainedFonts,
    );
    expect(manifest.droppedFonts.sort()).toEqual(
      [
        "Noto Sans Display",
        "UX4G Material Icons",
        "UX4G Material Icons Outlined",
        "UX4G Material Icons Round",
        "UX4G Material Icons Sharp",
        "UX4G Material Icons TwoTone",
      ].sort(),
    );
  });
});

/* ── Scoped dark surface completeness ────────────────────────────────────── */

describe(".cc-theme-dark is complete", () => {
  /**
   * `.cc-theme-dark` renders a container dark regardless of the root theme —
   * the fixed-dark auth surface needs it.
   *
   * A `--ccure-*` token whose light definition resolves through a UX4G
   * *semantic* token (`--ux4g-bg-error`, `--ux4g-text-neutral-primary`, …)
   * cannot follow a scoped container, because those flip only at
   * `:root[data-theme=dark]`. Every such token must be restated inside
   * `.cc-theme-dark` or it silently keeps its LIGHT value on a dark panel.
   *
   * This is not hypothetical. The first version of the block redefined the
   * severity text colours but not their tints, leaving #ffb3ae on #fff8f8 —
   * 1.63:1. Contrast caught it; this catches the next one at the source.
   */
  it("restates every token that would otherwise resolve light", () => {
    const tokensDir = path.join(DS, "tokens");
    const ccure = readFileSync(
      path.join(tokensDir, "ccure-tokens.css"),
      "utf8",
    );
    const themes = readFileSync(path.join(tokensDir, "themes.css"), "utf8");
    const ux4g = readFileSync(
      path.join(tokensDir, "ux4g.generated.css"),
      "utf8",
    );

    const darkBlock = ux4g.match(/:root\[data-theme=dark\]\{([\s\S]*?)\}/);
    expect(darkBlock, "UX4G dark block not found").not.toBeNull();
    const themeDependent = new Set(
      [...darkBlock[1].matchAll(/(--ux4g-[a-z0-9-]+):/g)].map((m) => m[1]),
    );
    expect(themeDependent.size).toBeGreaterThan(100);

    // Sliced rather than matched with a regex: the block spans many lines and
    // contains braces inside comments, which a non-greedy pattern stops at.
    const start = themes.indexOf(".cc-theme-dark");
    expect(start, ".cc-theme-dark block not found").toBeGreaterThan(-1);
    const scopedBlock = themes.slice(start);
    const scoped = new Set(
      [...scopedBlock.matchAll(/(--ccure-[a-z0-9-]+)\s*:/g)].map((m) => m[1]),
    );
    expect(scoped.size).toBeGreaterThan(30);

    const missing = [];
    for (const m of ccure.matchAll(/(--ccure-[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
      const [, name, value] = m;
      if (scoped.has(name)) continue;
      const refs = [...value.matchAll(/var\((--ux4g-[a-z0-9-]+)/g)].map(
        (r) => r[1],
      );
      if (refs.some((r) => themeDependent.has(r))) missing.push(name);
    }

    expect(
      missing,
      "these tokens keep their light value inside .cc-theme-dark",
    ).toEqual([]);
  });

  it("mirrors every token the root dark block overrides", () => {
    /**
     * The check above only catches tokens routed through a UX4G *semantic*
     * token. A token defined against a fixed palette step —
     * `--ccure-text-placeholder: var(--ux4g-color-neutral-600)` — does not
     * flip anywhere on its own, so ccure-tokens.css overrides it under
     * `:root[data-theme="dark"]`. That override is invisible to the first
     * check, and omitting the matching entry in `.cc-theme-dark` would leave a
     * light value on a dark panel with nothing to say so.
     *
     * Severity had already been handled by hand; the placeholder tier is the
     * second case, which is what made the gap worth closing rather than
     * remembering.
     */
    const tokensDir = path.join(DS, "tokens");
    const ccure = readFileSync(
      path.join(tokensDir, "ccure-tokens.css"),
      "utf8",
    );
    const themes = readFileSync(path.join(tokensDir, "themes.css"), "utf8");

    const rootDarkStart = ccure.indexOf(':root[data-theme="dark"]');
    expect(rootDarkStart, "root dark block not found").toBeGreaterThan(-1);
    const rootDark = new Set(
      [...ccure.slice(rootDarkStart).matchAll(/(--ccure-[a-z0-9-]+)\s*:/g)].map(
        (m) => m[1],
      ),
    );

    const scopedStart = themes.indexOf(".cc-theme-dark");
    const scoped = new Set(
      [...themes.slice(scopedStart).matchAll(/(--ccure-[a-z0-9-]+)\s*:/g)].map(
        (m) => m[1],
      ),
    );

    const missing = [...rootDark].filter((t) => !scoped.has(t));
    expect(
      missing,
      "overridden for the root dark theme but not for .cc-theme-dark",
    ).toEqual([]);
  });
});

/* ── 12. No unexpected third-party runtime dependency ────────────────────── */

describe("dependency surface", () => {
  it("runtime dependencies are exactly the approved set", () => {
    // A new runtime dependency is a new supply-chain entry and, for an
    // air-gapped product, a new thing that might reach the network. Adding one
    // should be a deliberate, reviewed act — which is what failing here makes
    // it.
    expect(Object.keys(pkg.dependencies).sort()).toEqual(
      [
        "axios",
        "react",
        "react-dom",
        "react-router-dom",
        "ux4g-web-components",
        "vis-data",
        "vis-network",
      ].sort(),
    );
  });

  it("the woff2 converter is a dev dependency, not a runtime one", () => {
    // It runs at build time only. Shipping it would put a WASM binary in the
    // runtime dependency tree for no reason.
    expect(pkg.devDependencies).toHaveProperty("wawoff2");
    expect(pkg.dependencies).not.toHaveProperty("wawoff2");
  });
});

/* ── 4. No unsafe-eval is introduced ─────────────────────────────────────── */

describe("no eval-shaped code enters the bundle", () => {
  it("application source contains no eval or Function constructor", () => {
    // `script-src 'self'` carries no 'unsafe-eval'. Anything here that needed
    // it would fail at runtime in production and pass every test in jsdom.
    const offenders = [];
    for (const f of sources) {
      if (!/\.jsx?$/.test(f)) continue;
      const text = readFileSync(f, "utf8");
      // Skip this file's own assertions.
      if (f.endsWith("guardrails.test.js")) continue;
      if (/\beval\s*\(/.test(text) || /new\s+Function\s*\(/.test(text)) {
        offenders.push(path.relative(ROOT, f));
      }
    }
    expect(offenders).toEqual([]);
  });
});

/* ── 13. Application code must not use ux4g-* classes directly ───────────── */

describe("UX4G class policy", () => {
  /**
   * The rule: application code addresses the design system, never UX4G.
   *
   *     <CcureButton />              yes
   *     <button class="ux4g-btn"/>   no   (written with `class` deliberately —
   *                                        the scan below matches className,
   *                                        and an anti-example should not trip
   *                                        the rule it illustrates)
   *
   * Two reasons, and the second is the load-bearing one:
   *
   *   * It is what lets the UX4G version underneath change — or be replaced —
   *     without editing pages. That is the entire premise of the layered
   *     architecture.
   *   * Production ships TOKENS ONLY. There is no `.ux4g-btn` rule in the
   *     bundle, so a `ux4g-` class silently styles nothing. It would look like
   *     a CSS bug, not a policy breach, and would be debugged as one.
   */
  it("only central design-system adapters use official ux4g- classes", () => {
    const offenders = [];
    for (const f of sources) {
      if (!/\.jsx?$/.test(f)) continue;
      if (f.startsWith(DS)) continue;
      const text = readFileSync(f, "utf8");

      // className="..." and className={`...`} — the two ways a class reaches
      // the DOM in this codebase.
      for (const m of text.matchAll(
        /className\s*=\s*(?:"([^"]*)"|'([^']*)'|\{`([^`]*)`\})/g,
      )) {
        const value = m[1] ?? m[2] ?? m[3] ?? "";
        if (/\bux4g-[a-z0-9-]+/.test(value)) {
          offenders.push(
            `${path.relative(ROOT, f)}: ${value.trim().slice(0, 70)}`,
          );
        }
      }
    }
    expect(
      offenders,
      "Use a central CCure adapter. Official classes belong only to the design system.",
    ).toEqual([]);
  });

  it("module styles cannot reference official ux4g- classes", () => {
    // The design system's components must be built on tokens, not on UX4G
    // classes — a `.cc-btn { composes: ux4g-btn }`-shaped dependency would
    // reintroduce the need for component CSS.
    const offenders = [];
    for (const f of sources) {
      if (!f.endsWith(".css")) continue;
      if (f.startsWith(DS)) continue;
      const text = readFileSync(f, "utf8");
      for (const m of text.matchAll(/\.ux4g-[a-z0-9-]+/g)) {
        offenders.push(`${path.relative(ROOT, f)}: ${m[0]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("only the design system may import the UX4G package", () => {
    // Application code imports from `@/design-system`, never from
    // `ux4g-web-components`. Enforcing the seam here is what keeps the
    // indirection real rather than conventional.
    const offenders = [];
    for (const f of sources) {
      if (f.startsWith(DS)) continue;
      if (f.includes(`__tests__${path.sep}design-system`)) continue;
      const text = readFileSync(f, "utf8");
      if (
        /from\s+["']ux4g-web-components|import\s+["']ux4g-web-components/.test(
          text,
        )
      ) {
        offenders.push(path.relative(ROOT, f));
      }
    }
    expect(offenders).toEqual([]);
  });
});

/* ── 3 + 5. Built output, when it exists ─────────────────────────────────── */

describe("built bundle", () => {
  const distAssets = path.join(ROOT, "dist", "assets");
  const built = existsSync(distAssets)
    ? readdirSync(distAssets).filter((f) => /\.(js|css)$/.test(f))
    : [];

  // These assert on `dist/`, which only exists after a build. `npm run build`
  // regenerates it and CI builds before testing; the guard reports the reason
  // rather than passing vacuously.
  it("a build exists to inspect", () => {
    expect(built.length, "run `npm run build` first").toBeGreaterThan(0);
  });

  it("carries no UX4G runtime marker", () => {
    for (const f of built.filter((f) => f.endsWith(".js"))) {
      const text = readFileSync(path.join(distAssets, f), "utf8");
      for (const marker of ["data-ux4g-runtime", "UX4G.js", "ux4g-backdrop"]) {
        expect(text.includes(marker), `${f} contains "${marker}"`).toBe(false);
      }
    }
  });

  it("carries no external origin in CSS", () => {
    for (const f of built.filter((f) => f.endsWith(".css"))) {
      const text = readFileSync(path.join(distAssets, f), "utf8");
      const external = text.match(/url\(\s*["']?https?:\/\/[^)]*\)/gi);
      expect(external, `${f} references an external origin`).toBeNull();
    }
  });

  it("carries no data: font URI in CSS", () => {
    for (const f of built.filter((f) => f.endsWith(".css"))) {
      const text = readFileSync(path.join(distAssets, f), "utf8");
      expect(text.match(/url\(\s*["']?data:font\//gi), f).toBeNull();
    }
  });

  it("excludes the development-only design-system showcase", () => {
    // /design-system is guarded by `import.meta.env.DEV`, which Rollup folds to
    // `false` in production, dropping the lazy import and the module behind it.
    // That is a claim about a bundler optimisation, so it is checked rather
    // than trusted: a refactor that makes the reference unconditional would
    // ship a route with no auth gate into production.
    for (const f of built) {
      const text = readFileSync(path.join(distAssets, f), "utf8");
      for (const marker of [
        "DesignSystemShowcase",
        "CCure design system",
        "CCure PRO design system",
      ]) {
        expect(text.includes(marker), `${f} contains "${marker}"`).toBe(false);
      }
    }
  });

  it("names no CDN, font host or analytics provider", () => {
    for (const f of built) {
      const text = readFileSync(path.join(distAssets, f), "utf8");
      for (const host of [
        "cdn.ux4g.gov.in",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "clarity.ms",
        "ux4g-analytics",
      ]) {
        expect(text.includes(host), `${f} references ${host}`).toBe(false);
      }
    }
  });
});
