/**
 * scripts/build-ux4g-assets.mjs
 * ─────────────────────────────────────────────────────────────────────────────
 * Derives CCure's UX4G foundation from the pinned `ux4g-web-components`
 * package. Runs as `prebuild` / `pretest`, and inside the Docker build.
 *
 * Two things upstream ships that this deployment cannot use as-is:
 *
 *   1. Every font is embedded as a `data:font/*;base64` URI — 91% of the 8.3 MB
 *      stylesheet, and blocked outright by CCure's `font-src 'self'`.
 *   2. 717 kB of component CSS for `.ux4g-*` classes that CCure never uses,
 *      carrying a universal reset that damages unmigrated pages (see RESET_RE).
 *
 * Neither is solved by relaxing the CSP. Both are solved here, at build time.
 *
 * ── Output modes ────────────────────────────────────────────────────────────
 *
 *   tokens (default) — the design foundation only: every `:root` block, the
 *                      dark-theme block, and the @font-face rules for fonts on
 *                      the allowlist. This is what production ships.
 *
 *   full             — the whole stylesheet with the reset rescoped and fonts
 *                      externalised. Kept so the decision is reversible: if
 *                      CCure ever adopts `.ux4g-*` classes directly, one env
 *                      var switches it back rather than a rewrite.
 *
 * Set with `UX4G_CSS_MODE`. The choice and its evidence are recorded in
 * docs/ux4g/02-dependency-strategy.md.
 *
 * ── Why the generated files are gitignored ──────────────────────────────────
 * They are a pure function of the pinned package: same version in, byte-
 * identical bytes out (asserted by `npm run ux4g:verify`). Committing ~3 MB of
 * derived bytes would put them under review on every bump and let the checked-in
 * copy drift from what the lockfile actually installs. Docker's `npm install`
 * supplies the input and `prebuild` regenerates them in-image, so the build
 * needs no network beyond the registry fetch it already performs.
 */

import { readFile, writeFile, mkdir, rm, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import wawoff2 from "wawoff2";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

const PKG_DIR = path.join(ROOT, "node_modules", "ux4g-web-components");
const SOURCE_CSS = path.join(PKG_DIR, "styles", "ux4g.css");

/**
 * The version every guarantee in docs/ux4g/ was measured against. A mismatch is
 * fatal, not a warning: the class-collision analysis, the reset shape, the
 * token closure and the contrast figures are all properties of this exact
 * build. Bumping it means re-running Phase 1's checks, deliberately.
 */
const PINNED_VERSION = "2.1.0";

const MODE = (process.env.UX4G_CSS_MODE ?? "tokens").toLowerCase();
if (!["tokens", "full"].includes(MODE)) {
  throw new Error(`UX4G_CSS_MODE must be "tokens" or "full", got "${MODE}"`);
}

/**
 * Fonts to keep, by the `font-family` its @font-face declares.
 *
 * Evidence for the exclusions, from docs/ux4g/02-dependency-strategy.md §5:
 *
 *   Noto Sans          — consumed by --ux4g-font-family-base, which
 *                        --ccure-font aliases, which every cc-* component
 *                        uses. The one face the browser actually fetched.
 *   Noto Sans Display  — no consumer in UX4G's CSS at all; reachable only via
 *                        --ccure-font-display, which nothing uses. The token
 *                        stays and falls back to the base family.
 *   Material Icons ×5  — consumed ONLY by .ux4g-icon / -outlined / -round /
 *                        -sharp / -twotone, which are component classes this
 *                        build does not ship and the class policy forbids.
 *                        CCure draws 63 inline <svg> icons and uses zero icon
 *                        fonts.
 *
 * A face not on this list has its @font-face dropped *and* its WOFF2 not
 * written, so nothing can reference a file that is absent.
 */
const KEEP_FONTS = new Set(["Noto Sans"]);

const FONT_OUT_DIR = path.join(ROOT, "public", "assets", "fonts", "ux4g");
const FONT_URL_BASE = "/assets/fonts/ux4g";
const CSS_OUT = path.join(
  ROOT,
  "src",
  "design-system",
  "tokens",
  "ux4g.generated.css",
);
const MANIFEST_OUT = path.join(
  path.dirname(CSS_OUT),
  "ux4g.generated.manifest.json",
);

/**
 * UX4G's universal reset. Its `:where()` wrapper means no CCure rule loses to
 * it — but author-level rules always beat the user-agent stylesheet, so its
 * `border:0` and `outline:0` land on every element CCure styles with neither.
 *
 * Measured on this tree: 107 controls (`<input type=text>`, `<select>`,
 * `<textarea>` with no className and no inline style) rely on the UA default
 * border — the search boxes and filter dropdowns on AssetRegistry, AssetDetail,
 * ComplianceWorkspace and AppLayout's global search. And CCure sets an outline
 * in only 36 of its 76 focus rules, so the rest lose their focus ring.
 *
 * In `tokens` mode the reset is not emitted at all, so the problem cannot
 * arise. In `full` mode it is rescoped to UX4G's own components. Either way the
 * shape is asserted, so a repackaged upstream fails loudly instead of quietly
 * reintroducing the defect.
 */
const RESET_RE = /:where\(\*,:before,:after\)\{/;
const RESET_SCOPED =
  ':where([class*="ux4g-"],[class*="ux4g-"]:before,[class*="ux4g-"]:after){';

const FACE_RE = /@font-face\{[^}]*\}/g;
const FAMILY_RE = /font-family:\s*([^;}]+)/i;
const DATA_URI_RE =
  /url\(\s*(["']?)data:font\/[a-z0-9+.-]+;base64,([A-Za-z0-9+/=]+)\1\s*\)/i;

/** `:root{` but not `:root[…]{` and not ` .foo :root{` — the bare token blocks. */
const ROOT_BLOCK_RE = /:root\{([\s\S]*?)\}/g;
const DARK_BLOCK_RE = /:root\[data-theme=dark\]\{([\s\S]*?)\}/g;

const slug = (family) =>
  family
    .trim()
    .replace(/^["']|["']$/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

const kb = (n) => `${(n / 1024).toFixed(1)} kB`;
const sha = (buf) =>
  createHash("sha256").update(buf).digest("hex").slice(0, 16);

async function main() {
  // ── Integrity: the output must correspond to the installed package ───────
  if (!existsSync(SOURCE_CSS)) {
    throw new Error(
      `UX4G stylesheet not found at ${SOURCE_CSS}.\nRun "npm install" first.`,
    );
  }
  const installed = JSON.parse(
    await readFile(path.join(PKG_DIR, "package.json"), "utf8"),
  );
  if (installed.version !== PINNED_VERSION) {
    throw new Error(
      `ux4g-web-components is ${installed.version}, expected ${PINNED_VERSION}.\n` +
        `Every guarantee in docs/ux4g/ was measured against ${PINNED_VERSION}: the\n` +
        `class-collision set, the reset shape, the token closure and the contrast\n` +
        `figures. Bump PINNED_VERSION only together with re-running those checks.`,
    );
  }

  const source = await readFile(SOURCE_CSS, "utf8");

  // ── Reset shape assertion (both modes) ───────────────────────────────────
  if (!RESET_RE.test(source)) {
    throw new Error(
      "UX4G's universal reset `:where(*,:before,:after){` was not found.\n" +
        "Upstream changed its reset. Re-check what it now applies to before\n" +
        "shipping — see the RESET_RE comment for what unscoped border:0 and\n" +
        "outline:0 do to unmigrated CCure pages.",
    );
  }

  const faces = source.match(FACE_RE) ?? [];
  if (faces.length === 0) {
    throw new Error(
      "No @font-face blocks found. Upstream has been repackaged.",
    );
  }

  await rm(FONT_OUT_DIR, { recursive: true, force: true });
  await mkdir(FONT_OUT_DIR, { recursive: true });
  await mkdir(path.dirname(CSS_OUT), { recursive: true });

  // ── Fonts: externalise the kept ones, drop the rest ──────────────────────
  const kept = [];
  const dropped = [];
  const rewrittenFaces = new Map(); // original face text -> rewritten (or null)

  for (const face of faces) {
    const family = face
      .match(FAMILY_RE)?.[1]
      ?.trim()
      .replace(/^["']|["']$/g, "");
    if (!family)
      throw new Error(`@font-face with no font-family: ${face.slice(0, 120)}`);

    if (!KEEP_FONTS.has(family)) {
      dropped.push(family);
      rewrittenFaces.set(face, null);
      continue;
    }

    const data = face.match(DATA_URI_RE);
    if (!data) {
      throw new Error(
        `"${family}" is on the keep list but carries no data: URI to extract.`,
      );
    }

    const original = Buffer.from(data[2], "base64");
    const woff2 = Buffer.from(await wawoff2.compress(original));
    const filename = `${slug(family)}.woff2`;
    await writeFile(path.join(FONT_OUT_DIR, filename), woff2);

    rewrittenFaces.set(
      face,
      face
        .replace(DATA_URI_RE, `url("${FONT_URL_BASE}/${filename}")`)
        .replace(
          /format\(\s*["'](?:truetype|opentype)["']\s*\)/i,
          'format("woff2")',
        ),
    );
    kept.push({
      family,
      filename,
      from: original.length,
      to: woff2.length,
      sha: sha(woff2),
    });
  }

  if (kept.length === 0) {
    throw new Error(
      "KEEP_FONTS matched no @font-face. Check the family names.",
    );
  }

  // ── Assemble the stylesheet ──────────────────────────────────────────────
  let css;
  if (MODE === "tokens") {
    // Every :root block — upstream ships SIX, not one, and taking only the
    // first silently drops 55 tokens. Plus the dark block and the kept faces.
    const roots = [...source.matchAll(ROOT_BLOCK_RE)].map(
      (m) => `:root{${m[1]}}`,
    );
    const darks = [...source.matchAll(DARK_BLOCK_RE)].map(
      (m) => `:root[data-theme=dark]{${m[1]}}`,
    );
    if (roots.length === 0 || darks.length === 0) {
      throw new Error(
        `Expected :root and :root[data-theme=dark] blocks; found ` +
          `${roots.length} and ${darks.length}. Upstream restructured its tokens.`,
      );
    }
    const faceCss = kept.map((k) =>
      rewrittenFaces.get(faces.find((f) => f.includes(k.family))),
    );
    css = [
      "/* Generated by scripts/build-ux4g-assets.mjs — do not edit.",
      ` * Source: ux4g-web-components@${PINNED_VERSION}, mode=${MODE}`,
      " * Design tokens and @font-face only; no component CSS, no reset.",
      " */",
      ...faceCss,
      ...roots,
      ...darks,
    ].join("\n");
  } else {
    css = source;
    for (const [orig, rewritten] of rewrittenFaces) {
      css = css.replace(orig, rewritten ?? "");
    }
    css = css.replace(RESET_RE, RESET_SCOPED);
    if (/:where\(\*[,)]/.test(css)) {
      throw new Error(
        "A universal :where(*) reset survived scoping. Aborting.",
      );
    }
  }

  // ── Assertions on the emitted bytes ──────────────────────────────────────
  const strayData = css.match(/url\(\s*["']?data:font\//gi);
  if (strayData) {
    throw new Error(
      `${strayData.length} data: font URI(s) survived. They would be blocked by ` +
        `font-src 'self'. Aborting.`,
    );
  }
  const external = css.match(/url\(\s*["']?https?:\/\/[^)]*\)/gi);
  if (external) {
    throw new Error(
      `Generated CSS references external origin(s):\n  ${external.join("\n  ")}\n` +
        `Air-gapped deployment forbids this. Aborting.`,
    );
  }
  const emittedFaces = css.match(/@font-face\{/g) ?? [];
  if (emittedFaces.length !== kept.length) {
    throw new Error(
      `Emitted ${emittedFaces.length} @font-face rules but wrote ${kept.length} ` +
        `font files. A rule would reference a file that is not there.`,
    );
  }
  if (MODE === "tokens" && /:where\(/.test(css)) {
    throw new Error(
      "tokens mode emitted a :where() rule — component CSS leaked into the " +
        "token subset. That reintroduces the reset this mode exists to avoid.",
    );
  }

  await writeFile(CSS_OUT, css, "utf8");

  // ── Manifest: what these bytes were derived from ─────────────────────────
  // Makes the gitignored output auditable and lets `ux4g:verify` prove the
  // build is deterministic without committing the artefacts themselves.
  const manifest = {
    generator: "scripts/build-ux4g-assets.mjs",
    source: { package: "ux4g-web-components", version: installed.version },
    mode: MODE,
    css: { bytes: Buffer.byteLength(css), sha256_16: sha(css) },
    fonts: kept.map(({ family, filename, to, sha: s }) => ({
      family,
      file: filename,
      bytes: to,
      sha256_16: s,
    })),
    droppedFonts: dropped,
  };
  await writeFile(
    MANIFEST_OUT,
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );

  // ── Report ───────────────────────────────────────────────────────────────
  console.log(
    `\n[ux4g] ux4g-web-components@${installed.version}  mode=${MODE}`,
  );
  console.log("  " + "─".repeat(66));
  for (const k of kept) {
    console.log(
      `  keep  ${k.family.padEnd(28)} ${kb(k.from).padStart(10)} → ${kb(k.to).padStart(10)}  ${k.filename}`,
    );
  }
  for (const d of dropped) {
    console.log(`  drop  ${d.padEnd(28)} ${"(no consumer)".padStart(23)}`);
  }
  console.log("  " + "─".repeat(66));
  console.log(
    `  stylesheet ${kb(Buffer.byteLength(source)).padStart(12)} → ${kb(Buffer.byteLength(css)).padStart(10)}`,
  );
  console.log(
    `  fonts      ${String(faces.length).padStart(9)} faces → ${kept.length} file(s), ${kb(kept.reduce((n, k) => n + k.to, 0))}`,
  );
  console.log(`\n  css      → ${path.relative(ROOT, CSS_OUT)}`);
  console.log(
    `  fonts    → ${path.relative(ROOT, FONT_OUT_DIR)} (${(await readdir(FONT_OUT_DIR)).length} files)`,
  );
  console.log(`  manifest → ${path.relative(ROOT, MANIFEST_OUT)}`);
  console.log(
    `  checks   → version pinned, reset shape, no data: fonts, no external origins, face/file parity\n`,
  );
}

main().catch((err) => {
  console.error(`\n[ux4g] BUILD FAILED\n${err.message}\n`);
  process.exit(1);
});
