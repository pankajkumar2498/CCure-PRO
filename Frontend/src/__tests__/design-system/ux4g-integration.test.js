/**
 * UX4G integration guarantees.
 *
 * Every assertion here corresponds to a claim in docs/ux4g/01-spike-report.md.
 * The point is that these are properties the build enforces rather than facts
 * someone measured once — a UX4G version bump that breaks any of them fails CI
 * instead of shipping.
 *
 * These read the GENERATED stylesheet, which `pretest` produces, so they are
 * testing what actually ships rather than what upstream published.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const DS = path.join(ROOT, "src", "design-system");

const GENERATED = path.join(DS, "tokens", "ux4g.generated.css");
const CCURE_TOKENS = path.join(DS, "tokens", "ccure-tokens.css");
const COMPONENTS_CSS = path.join(DS, "components", "components.css");
const FONT_DIR = path.join(ROOT, "public", "assets", "fonts", "ux4g");

let generated = "";
let ccureTokens = "";
let componentsCss = "";

beforeAll(() => {
  if (!existsSync(GENERATED)) {
    throw new Error(
      `${GENERATED} is missing. It is produced by scripts/build-ux4g-assets.mjs, ` +
        `which npm's pretest/prebuild hooks run. Run "npm run ux4g:assets".`,
    );
  }
  generated = readFileSync(GENERATED, "utf8");
  ccureTokens = readFileSync(CCURE_TOKENS, "utf8");
  componentsCss = readFileSync(COMPONENTS_CSS, "utf8");
});

describe("air-gap: the generated stylesheet reaches no network", () => {
  it("embeds no data: font URIs", () => {
    // These are what `font-src 'self'` blocks. Their absence is why no CSP
    // change was needed.
    expect(generated.match(/url\(\s*["']?data:font\//gi)).toBeNull();
  });

  it("references no external origin", () => {
    const external = generated.match(/url\(\s*["']?https?:\/\/[^)]*\)/gi);
    expect(external).toBeNull();
  });

  it("names no CDN, font host or analytics provider", () => {
    for (const host of [
      "cdn.ux4g.gov.in",
      "fonts.googleapis.com",
      "fonts.gstatic.com",
      "clarity.ms",
      "ux4g-analytics",
    ]) {
      expect(generated).not.toContain(host);
    }
  });
});

describe("fonts are self-hosted", () => {
  it("emits a WOFF2 file for every @font-face", () => {
    const faces = generated.match(/@font-face\{/g) ?? [];
    const files = readdirSync(FONT_DIR).filter((f) => f.endsWith(".woff2"));
    expect(faces.length).toBeGreaterThan(0);
    expect(files.length).toBe(faces.length);
  });

  it("points every face at a same-origin path under /assets/", () => {
    const urls = [
      ...generated.matchAll(/@font-face\{[^}]*url\(([^)]*)\)/g),
    ].map((m) => m[1].replace(/["']/g, ""));
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      // Leading slash = same origin. Under /assets/ so Frontend/nginx.conf's
      // immutable-cache location matches it.
      expect(url.startsWith("/assets/fonts/ux4g/")).toBe(true);
      expect(url.endsWith(".woff2")).toBe(true);
    }
  });
});

describe("the runtime is not adopted", () => {
  it("no source file imports the UX4G runtime", () => {
    // The runtime injects its library as an inline <script> via textContent,
    // which `script-src 'self'` blocks. Importing it would be a silent, total
    // failure of every UX4G behaviour — and an invitation to "fix" the CSP.
    const offenders = [];
    const walk = (dir) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === "node_modules") continue;
          walk(p);
        } else if (/\.(jsx?|css)$/.test(entry.name)) {
          const text = readFileSync(p, "utf8");
          if (
            /ux4g-web-components\/(runtime|design-system)/.test(text) ||
            /ux4g-web-components["']?\s*\)?\s*;?\s*$/m.test(
              text
                .split("\n")
                .find(
                  (l) =>
                    l.includes("import") && l.includes("ux4g-web-components"),
                ) ?? "",
            )
          ) {
            offenders.push(path.relative(ROOT, p));
          }
        }
      }
    };
    walk(path.join(ROOT, "src"));
    expect(offenders).toEqual([]);
  });
});

describe("dark mode rides the existing attribute", () => {
  it("UX4G themes on :root[data-theme=dark]", () => {
    // The same attribute PreferencesContext already writes from the
    // server-persisted preference. Upstream moved to `.dark` / `[data-mode]`
    // in 3.0.1; the generator re-emits that block under this attribute
    // (docs/ux4g/B11_UX4G_3_0_2_UPGRADE.md). A media query would still fail.
    expect(generated).toMatch(/:root\[data-theme=["']?dark["']?\]/);
  });

  it("never emits upstream's own dark selectors", () => {
    // A bare `.dark` would restyle any element carrying that class, and
    // nothing in the application sets `data-mode`.
    expect(generated).not.toMatch(/(^|[\s,{}])\.dark[\s,{]/);
    expect(generated).not.toContain("data-mode");
  });

  it("UX4G ships no prefers-color-scheme rule", () => {
    // One would silently override the user's stored account preference.
    expect(generated).not.toContain("prefers-color-scheme");
  });

  it("redefines a meaningful number of tokens under dark", () => {
    const block = generated.match(
      /:root\[data-theme=["']?dark["']?\]\{([^}]*)\}/,
    );
    expect(block).not.toBeNull();
    const count = (block[1].match(/--ux4g-[a-z0-9-]+:/g) ?? []).length;
    expect(count).toBeGreaterThan(100);
  });
});

describe("class collisions with existing CCure CSS", () => {
  it("has no bare rule for a class CCure also uses", () => {
    // Phase 0 found exactly three intersecting class tokens — active, muted,
    // is-muted — and every UX4G rule using them is compound-scoped to a
    // .ux4g-* class. A bare rule would restyle 148 CCure `active` call sites.
    for (const cls of ["active", "muted", "is-muted"]) {
      const bare = new RegExp(`(^|[},])\\.${cls}[,{]`, "g");
      expect(generated.match(bare)).toBeNull();
    }
  });

  it("ships no selector that can style a CCure element", () => {
    // The Phase 2 architecture makes collision structurally impossible rather
    // than merely checked: tokens mode emits comments, @font-face and :root
    // blocks, and nothing else. No class selector, no element selector, no
    // reset — so there is no rule that can match anything CCure renders.
    //
    // Strip the comment header, the @font-face rules and the :root blocks; a
    // conforming file has nothing left but whitespace.
    const remainder = generated
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/@font-face\{[^}]*\}/g, "")
      .replace(/:root(\[data-theme=dark\])?\{[^}]*\}/g, "")
      .trim();

    expect(
      remainder.slice(0, 400),
      "tokens mode emitted CSS beyond tokens and @font-face",
    ).toBe("");
  });

  it("carries no universal reset at all", () => {
    // In Phase 1 the reset had to be rescoped, because unscoped `border:0`
    // strips the UA default border from the 107 unclassed <input>/<select>/
    // <textarea> controls on this tree (the search boxes and filter dropdowns
    // on AssetRegistry, AssetDetail, ComplianceWorkspace and AppLayout's
    // global search), and `outline:0` removes the focus ring from anything
    // CCure does not explicitly focus-style.
    //
    // Not shipping component CSS removes the problem rather than containing
    // it. The build still asserts upstream's reset SHAPE (so a repackaging is
    // caught), and still rescopes it under UX4G_CSS_MODE=full.
    expect(generated).not.toContain(":where(");
    expect(generated.match(/(^|[},;])(body|html)\{/)).toBeNull();
  });
});

describe("the semantic layer does not leak", () => {
  it("components reference only --ccure-* tokens, never --ux4g-* directly", () => {
    // A component reaching past the semantic layer defeats the abstraction:
    // the UX4G version underneath could then no longer be changed without
    // editing components.
    const leaked = componentsCss.match(/--ux4g-[a-z0-9-]+/g);
    expect(leaked).toBeNull();
  });

  it("every --ux4g-* token the semantic layer references is defined", () => {
    // Catches a rename upstream. An undefined custom property silently
    // resolves to nothing, so the failure mode without this test is an
    // invisible colour rather than an error.
    const referenced = [
      ...new Set(
        [...ccureTokens.matchAll(/var\((--ux4g-[a-z0-9-]+)/g)].map((m) => m[1]),
      ),
    ];
    expect(referenced.length).toBeGreaterThan(50);

    const missing = referenced.filter((t) => !generated.includes(`${t}:`));
    expect(missing).toEqual([]);
  });

  it("defines severity tokens for both themes", () => {
    // Fixes the Phase 0 defect: --sev-* was declared once with no dark
    // override, so severity contrast was only ever verified in one theme.
    // Note the `\s*` — the authored CCure source is prettier-formatted with a
    // space before the brace, unlike the minified UX4G bundle above.
    const dark = ccureTokens.match(
      /:root\[data-theme=["']dark["']\]\s*\{[\s\S]*?\}/,
    );
    expect(dark).not.toBeNull();
    expect(dark[0]).toContain("--ccure-sev-critical");
  });
});

describe("legacy CCure tokens are untouched", () => {
  it("the semantic layer redefines no legacy token name", () => {
    // Phase 1 is additive. Re-pointing --accent/--text/--bg-app onto the new
    // layer would restyle all 79 pages through 2,155 var() call sites at once,
    // which is the big-bang this migration exists to avoid. That step is
    // Phase 3 and must be its own reviewable change.
    const legacy = [
      "--accent",
      "--bg-app",
      "--bg-white",
      "--text",
      "--text-muted",
      "--border",
      "--sidebar-bg",
      "--font",
    ];
    for (const name of legacy) {
      const declared = new RegExp(
        `^\\s*${name.replace(/-/g, "\\-")}\\s*:`,
        "m",
      );
      expect(ccureTokens).not.toMatch(declared);
    }
  });
});
