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
 * B.2 delivers tokens and the existing font only. The baseline owns that
 * policy; an environment override cannot enable full component/reset CSS.
 * See docs/ux4g/B2_ASSET_PIPELINE.md for delivery and validation.
 *
 * ── Why the generated files are gitignored ──────────────────────────────────
 * They are a pure function of the pinned package: same version in, byte-
 * identical bytes out (asserted by `npm run ux4g:verify`). Committing
 * derived bytes would put them under review on every bump and let the checked-in
 * copy drift from what the lockfile actually installs. Docker's `npm ci`
 * supplies the input and `prebuild` regenerates them in-image, so the build
 * needs no network beyond the registry fetch it already performs.
 */

import {
  readFile,
  writeFile,
  mkdir,
  rm,
  readdir,
  rename,
  mkdtemp,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import wawoff2 from "wawoff2";
import { loadBaseline, sha256, verifyVendorInput } from "./ux4g-baseline.mjs";
import {
  ASSET_LAYOUT,
  assetPaths,
  approvedAssetMode,
  pipelineIdentity,
  tokenCssProblems,
} from "./ux4g-pipeline.mjs";
import { checkFoundation } from "./check-ux4g-foundation.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

const BASELINE = loadBaseline(ROOT);
const PKG_DIR = path.join(ROOT, "node_modules", BASELINE.npm.package);
const SOURCE_CSS = path.join(PKG_DIR, "styles", "ux4g.css");

/**
 * The reviewed identity has one authority. Package, lock, installed tree and
 * generated provenance are checked against Frontend/ux4g-baseline.json.
 */
const PINNED_VERSION = BASELINE.npm.version;

const MODE = approvedAssetMode(BASELINE);

/**
 * Fonts to keep, by the `font-family` its @font-face declares.
 *
 * Evidence for the exclusions, from docs/ux4g/02-dependency-strategy.md §5:
 *
 *   Noto Sans          — consumed by --ux4g-font-family-base, which
 *                        --ccure-font aliases, which every cc-* component
 *                        uses. The one face the browser actually fetched.
 *   Noto Sans Display  — the display token now has Common heading consumers,
 *                        but its face was already omitted. Preserve that
 *                        fallback in B.2; typography migration is deferred.
 *   Material Icons ×5  — consumed ONLY by .ux4g-icon / -outlined / -round /
 *                        -sharp / -twotone, which are component classes this
 *                        build does not ship and the class policy forbids.
 *                        CCure draws 63 inline <svg> icons and uses zero icon
 *                        fonts.
 *
 * A face not on this list has its @font-face dropped *and* its WOFF2 not
 * written, so nothing can reference a file that is absent.
 */
const KEEP_FONTS = new Set(BASELINE.assets.retainedFonts);

const {
  fonts: FONT_OUT_DIR,
  css: CSS_OUT,
  manifest: MANIFEST_OUT,
} = assetPaths(ROOT);
const FONT_URL_BASE = ASSET_LAYOUT.fontUrl;

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
 * The token-only pipeline emits no reset. Its upstream shape is still
 * asserted, so a repackaged input fails loudly instead of quietly
 * reintroducing the defect.
 */
const RESET_RE = /:where\(\*,:before,:after\)\{/;

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

/** Prepare a complete output set before replacement; restore it on write failure. */
export async function publishAssets({ root = ROOT, css, kept, manifest }) {
  const outputs = assetPaths(root);
  const lock = path.join(root, ".ux4g-assets.lock");
  try {
    await mkdir(lock);
  } catch (error) {
    if (error.code === "EEXIST")
      throw new Error(
        "Another UX4G asset publication is in progress (.ux4g-assets.lock)",
      );
    throw error;
  }
  let stage;
  let recoveryFailed = false;
  const replaced = [];
  try {
    stage = await mkdtemp(path.join(root, ".ux4g-assets-"));
    const next = path.join(stage, "next");
    await mkdir(path.join(next, "fonts"), { recursive: true });
    for (const font of kept)
      await writeFile(path.join(next, "fonts", font.filename), font.woff2);
    const metadata = `${JSON.stringify(manifest, null, 2)}\n`;
    await writeFile(path.join(next, "css"), css, "utf8");
    await writeFile(path.join(next, "publicManifest"), metadata, "utf8");
    await writeFile(path.join(next, "manifest"), metadata, "utf8");
    for (const key of ["fonts", "css", "publicManifest", "manifest"]) {
      const destination = outputs[key];
      await mkdir(path.dirname(destination), { recursive: true });
      const backup = path.join(stage, `old-${key}`);
      const existed = existsSync(destination);
      if (existed) await rename(destination, backup);
      replaced.push({ destination, backup, existed });
      await rename(path.join(next, key), destination);
    }
  } catch (error) {
    try {
      for (const { destination, backup, existed } of replaced.reverse()) {
        await rm(destination, { recursive: true, force: true });
        if (existed) await rename(backup, destination);
      }
    } catch (recoveryError) {
      recoveryFailed = true;
      throw new Error(
        `Asset publication recovery failed; preserve backups at ${stage}: ${recoveryError.message}`,
        { cause: error },
      );
    }
    throw error;
  } finally {
    if (stage && !recoveryFailed)
      await rm(stage, { recursive: true, force: true });
    await rm(lock, { recursive: true, force: true });
  }
}

async function main() {
  checkFoundation({ dependenciesOnly: true });
  // ── Integrity: the output must correspond to the installed package ───────
  if (!existsSync(SOURCE_CSS)) {
    throw new Error(
      `UX4G stylesheet not found at ${SOURCE_CSS}.\nRun "npm ci" first.`,
    );
  }
  const { installed, css: vendorCss } = verifyVendorInput(BASELINE, ROOT);
  const pipeline = pipelineIdentity(ROOT);
  const source = vendorCss.toString("utf8");

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
    if (kept.some((font) => font.filename === filename)) {
      throw new Error(`Duplicate font output filename: ${filename}`);
    }

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
      sha256: sha256(woff2),
      sourceSha256: sha256(original),
      woff2,
    });
  }

  if (
    JSON.stringify(kept.map((font) => font.family)) !==
    JSON.stringify([...KEEP_FONTS])
  ) {
    throw new Error(
      "Retained font faces do not exactly match the approved font policy.",
    );
  }

  // ── Assemble the stylesheet ──────────────────────────────────────────────
  let css;
  {
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
      ` * Source: ${BASELINE.npm.package}@${PINNED_VERSION}, mode=${MODE}`,
      " * Design tokens and @font-face only; no component CSS, no reset.",
      " */",
      ...faceCss,
      ...roots,
      ...darks,
    ].join("\n");
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

  const cssProblems = tokenCssProblems(
    css,
    kept.map((font) => font.filename),
  );
  if (cssProblems.length) throw new Error(cssProblems.join("\n"));

  // ── Manifest: what these bytes were derived from ─────────────────────────
  // Makes the gitignored output auditable and lets `ux4g:verify` prove the
  // build is deterministic without committing the artefacts themselves.
  const manifest = {
    schemaVersion: 2,
    generator: "scripts/build-ux4g-assets.mjs",
    pipeline,
    baseline: {
      file: "ux4g-baseline.json",
      sha256: sha256(await readFile(path.join(ROOT, "ux4g-baseline.json"))),
    },
    source: {
      package: BASELINE.npm.package,
      version: installed.version,
      integrity: BASELINE.npm.integrity,
      tarball: BASELINE.npm.tarball,
      publisher: BASELINE.npm.publisher,
      cssSha256: sha256(vendorCss),
    },
    mode: MODE,
    css: {
      bytes: Buffer.byteLength(css),
      sha256: sha256(css),
      sha256_16: sha(css),
    },
    fonts: kept.map(
      ({ family, filename, to, sha: s, sha256: full, sourceSha256 }) => ({
        family,
        file: filename,
        bytes: to,
        sha256_16: s,
        sha256: full,
        sourceSha256,
      }),
    ),
    droppedFonts: dropped,
  };
  await publishAssets({ css, kept, manifest });

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
    console.log(
      `  drop  ${d.padEnd(28)} ${"(deferred delivery)".padStart(23)}`,
    );
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

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((err) => {
    console.error(`\n[ux4g] BUILD FAILED\n${err.message}\n`);
    process.exit(1);
  });
}
