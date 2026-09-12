/**
 * WCAG contrast, computed from the actual token values, in both themes.
 *
 * This exists because Phase 0 found the pre-existing severity palette was
 * declared once with no dark override, so its contrast had only ever been
 * verified in one theme — and because the first pass of this layer shipped a
 * danger button at 4.38:1 in light mode, which looks perfectly fine and is
 * below the AA floor.
 *
 * Colour is the one part of a design system where "it looks right" is not
 * evidence. Every pair below is resolved through the real var() chain and
 * measured.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const TOKENS = path.join(ROOT, "src", "design-system", "tokens");

/** Parse `--name: value` pairs out of one CSS block. */
function declarations(block) {
  const out = {};
  for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+)/g)) {
    out[m[1]] = m[2].trim();
  }
  return out;
}

function blockFor(css, selector) {
  // `[\s\S]*?` rather than `[^}]*` — the CCure sources are formatted and their
  // blocks contain no nested braces, but comments inside them can.
  const re = new RegExp(
    `${selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\{([\\s\\S]*?)\\n?\\}`,
  );
  const m = css.match(re);
  return m ? m[1] : "";
}

let light = {};
let dark = {};
let scopedDark = {};

beforeAll(() => {
  const ux4g = readFileSync(path.join(TOKENS, "ux4g.generated.css"), "utf8");
  const ccure = readFileSync(path.join(TOKENS, "ccure-tokens.css"), "utf8");

  // Upstream ships SIX :root blocks, not one. Reading only the first drops 55
  // tokens — and it drops them silently, because an unresolved custom property
  // yields no colour rather than an error. Every block is merged.
  let uLight = {};
  for (const m of ux4g.matchAll(/:root\{([\s\S]*?)\}/g)) {
    uLight = { ...uLight, ...declarations(m[1]) };
  }
  let uDark = {};
  for (const m of ux4g.matchAll(/:root\[data-theme=dark\]\{([\s\S]*?)\}/g)) {
    uDark = { ...uDark, ...declarations(m[1]) };
  }
  if (Object.keys(uLight).length < 900) {
    throw new Error(
      `Only ${Object.keys(uLight).length} UX4G light tokens parsed; expected >900. ` +
        `The token blocks were not read correctly, so these ratios would be ` +
        `measured against defaults rather than the real palette.`,
    );
  }

  // CCure is authored across several :root blocks; merge them all.
  let cLight = {};
  for (const m of ccure.matchAll(/(?:^|\n):root\s*\{([\s\S]*?)\n\}/g)) {
    cLight = { ...cLight, ...declarations(m[1]) };
  }
  const cDark = declarations(blockFor(ccure, ':root[data-theme="dark"]'));

  light = { ...uLight, ...cLight };
  dark = { ...light, ...uDark, ...cDark };

  // `.cc-theme-dark` renders a container dark regardless of the root theme —
  // the fixed-dark auth surface needs it. It is a third palette and must be
  // measured like the other two: it was introduced precisely to avoid a
  // contrast failure, so shipping it unmeasured would be self-defeating.
  const themes = readFileSync(path.join(TOKENS, "themes.css"), "utf8");
  const scoped = declarations(blockFor(themes, ".cc-theme-dark"));
  scopedDark = { ...light, ...scoped };
});

/** Follow var() chains to a literal. Falls back to the light table, which is
 *  how the cascade behaves for a token the dark block does not redefine. */
function resolve(name, theme, depth = 0) {
  if (depth > 12) return null;
  const raw = theme[name] ?? light[name];
  if (!raw) return null;
  const m = raw.match(/^var\(\s*(--[a-z0-9-]+)/);
  return m ? resolve(m[1], theme, depth + 1) : raw;
}

function toRgb(value) {
  if (!value) return null;
  const hex = value.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hex) {
    const h =
      hex[1].length === 3
        ? hex[1]
            .split("")
            .map((c) => c + c)
            .join("")
        : hex[1];
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  }
  return null;
}

function luminance([r, g, b]) {
  const f = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

function contrast(fg, bg) {
  const a = toRgb(fg);
  const b = toRgb(bg);
  if (!a || !b) return null;
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** [label, foreground token, background token, floor] */
const PAIRS = [
  ["body text on page", "--ccure-text", "--ccure-bg", 4.5],
  ["body text on surface", "--ccure-text", "--ccure-surface", 4.5],
  [
    "secondary text on surface",
    "--ccure-text-secondary",
    "--ccure-surface",
    4.5,
  ],
  // The input's background is --ccure-surface, so this is the pairing that
  // actually ships on a placeholder.
  [
    "placeholder on input surface",
    "--ccure-text-placeholder",
    "--ccure-surface",
    4.5,
  ],
  ["link on surface", "--ccure-text-link", "--ccure-surface", 4.5],
  ["primary button label", "--ccure-on-primary", "--ccure-primary", 4.5],
  ["danger button label", "--ccure-on-primary", "--ccure-danger-solid", 4.5],
  [
    "error text on error surface",
    "--ccure-danger-text",
    "--ccure-danger-bg",
    4.5,
  ],
  [
    "warning text on warning surface",
    "--ccure-warning-text",
    "--ccure-warning-bg",
    4.5,
  ],
  [
    "success text on success surface",
    "--ccure-success-text",
    "--ccure-success-bg",
    4.5,
  ],
  ["info text on info surface", "--ccure-info-text", "--ccure-info-bg", 4.5],
  // Field labels. theme.css records that six CCure labels had drifted onto a
  // 2.6:1 token; the semantic layer exposes no such tier, and this pins it.
  ["field label on surface", "--ccure-text", "--ccure-surface", 4.5],
];

/** Severity is held to the full 4.5:1 text floor, not the 3.0 large-text one.
 *  Severity appears as small badge text and as inline labels in dense tables,
 *  so the large-text allowance does not apply to how it is actually used —
 *  and a severity a reader cannot make out is the one label in this product
 *  that most needs to be readable. */
const SEVERITY = [
  ["critical", "--ccure-sev-critical"],
  ["high", "--ccure-sev-high"],
  ["medium", "--ccure-sev-medium"],
  ["low", "--ccure-sev-low"],
  ["info", "--ccure-sev-info"],
];

for (const [themeName, getTheme] of [
  ["light", () => light],
  ["dark", () => dark],
  ["scoped dark (.cc-theme-dark)", () => scopedDark],
]) {
  describe(`contrast — ${themeName}`, () => {
    for (const [label, fg, bg, floor] of PAIRS) {
      it(`${label} meets ${floor}:1`, () => {
        const theme = getTheme();
        const f = resolve(fg, theme);
        const b = resolve(bg, theme);
        // A null here means a token stopped resolving — a rename upstream —
        // which must fail rather than silently skip the measurement.
        expect(f, `${fg} did not resolve`).toBeTruthy();
        expect(b, `${bg} did not resolve`).toBeTruthy();

        const ratio = contrast(f, b);
        expect(
          ratio,
          `${fg} (${f}) on ${bg} (${b}) did not compute`,
        ).toBeTruthy();
        expect(
          Number(ratio.toFixed(2)),
          `${label}: ${f} on ${b} = ${ratio?.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(floor);
      });
    }

    it("places the placeholder tier below the value tier", () => {
      // The ForgotPassword migration surfaced a placeholder at 15.72:1 against
      // a value at 18.97:1 — legible, but near enough that an empty field read
      // as a filled one. Contrast alone cannot express that; the ORDER of the
      // tiers is the property worth pinning.
      const theme = getTheme();
      const surface = resolve("--ccure-surface", theme);
      const value = contrast(resolve("--ccure-text", theme), surface);
      const placeholder = contrast(
        resolve("--ccure-text-placeholder", theme),
        surface,
      );
      const secondary = contrast(
        resolve("--ccure-text-secondary", theme),
        surface,
      );

      expect(placeholder, "placeholder did not resolve").toBeTruthy();
      // Subordinate to a real value, and to a hint.
      expect(
        placeholder,
        `placeholder ${placeholder?.toFixed(2)} should be below value ${value?.toFixed(2)}`,
      ).toBeLessThan(value);
      expect(placeholder).toBeLessThan(secondary);
      // ...but still comfortably readable. A placeholder is content.
      expect(Number(placeholder.toFixed(2))).toBeGreaterThanOrEqual(4.5);
    });

    it("keeps the placeholder visibly subordinate, not marginally", () => {
      // A tier one step below the value would satisfy "less than" while
      // looking identical. Measured targets: 0.44x in light, 0.40x in scoped
      // dark. The ceiling here is deliberately loose enough to allow a palette
      // renumber and tight enough to catch a collapse back onto secondary.
      const theme = getTheme();
      const surface = resolve("--ccure-surface", theme);
      const value = contrast(resolve("--ccure-text", theme), surface);
      const placeholder = contrast(
        resolve("--ccure-text-placeholder", theme),
        surface,
      );
      const share = placeholder / value;
      expect(
        Number(share.toFixed(2)),
        `placeholder is ${(share * 100).toFixed(0)}% of the value tier's contrast`,
      ).toBeLessThanOrEqual(0.6);
    });

    for (const [name, token] of SEVERITY) {
      it(`severity ${name} meets 4.5:1 on its own tint`, () => {
        // CcureSeverityBadge draws the severity colour on the matching
        // --ccure-sev-*-bg tint, not on the page surface. That pairing was
        // never measured before Checkpoint 3B, and it is the one that actually
        // ships on a badge.
        const theme = getTheme();
        const f = resolve(token, theme);
        const b = resolve(`${token}-bg`, theme);
        expect(f, `${token} did not resolve`).toBeTruthy();
        expect(b, `${token}-bg did not resolve`).toBeTruthy();
        const ratio = contrast(f, b);
        expect(
          Number(ratio.toFixed(2)),
          `severity ${name} on its tint: ${f} on ${b} = ${ratio?.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(4.5);
      });

      it(`severity ${name} meets 4.5:1 on the surface`, () => {
        const theme = getTheme();
        const f = resolve(token, theme);
        const b = resolve("--ccure-surface", theme);
        expect(f, `${token} did not resolve`).toBeTruthy();
        const ratio = contrast(f, b);
        expect(
          Number(ratio.toFixed(2)),
          `severity ${name}: ${f} on ${b} = ${ratio?.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(4.5);
      });
    }
  });
}
