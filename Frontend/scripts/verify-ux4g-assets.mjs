/**
 * scripts/verify-ux4g-assets.mjs
 * ─────────────────────────────────────────────────────────────────────────────
 * Proves the generated UX4G assets are reproducible.
 *
 * This is the argument for gitignoring them. "Derived output does not need to
 * be committed" is only true if the derivation is deterministic — otherwise the
 * artefact in a Docker image and the artefact a developer has locally can
 * differ with nothing to show it. So rather than asserting reproducibility in
 * prose, this rebuilds the assets and compares hashes.
 *
 *   npm run ux4g:verify
 *
 * Run it in CI after `npm ci`. A failure means the pipeline has acquired a
 * non-deterministic input — a timestamp, a hash-map iteration order, a locale
 * dependence — and the gitignore decision would have to be revisited.
 */

import { readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

const CSS = path.join(
  ROOT,
  "src",
  "design-system",
  "tokens",
  "ux4g.generated.css",
);
const MANIFEST = path.join(
  ROOT,
  "src",
  "design-system",
  "tokens",
  "ux4g.generated.manifest.json",
);
const FONTS = path.join(ROOT, "public", "assets", "fonts", "ux4g");

const sha = (buf) => createHash("sha256").update(buf).digest("hex");

async function snapshot() {
  const css = await readFile(CSS);
  const manifest = JSON.parse(await readFile(MANIFEST, "utf8"));
  const fonts = {};
  for (const f of manifest.fonts) {
    fonts[f.file] = sha(await readFile(path.join(FONTS, f.file)));
  }
  return { css: sha(css), fonts, manifest };
}

function build(label) {
  const r = spawnSync(
    process.execPath,
    [path.join(HERE, "build-ux4g-assets.mjs")],
    { cwd: ROOT, encoding: "utf8", env: process.env },
  );
  if (r.status !== 0) {
    console.error(r.stdout ?? "");
    console.error(r.stderr ?? "");
    throw new Error(`${label}: build-ux4g-assets.mjs exited ${r.status}`);
  }
}

async function main() {
  if (!existsSync(CSS) || !existsSync(MANIFEST)) {
    console.log("[ux4g:verify] no generated assets yet — building once first");
    build("initial");
  }

  const first = await snapshot();

  // Remove the output entirely, so the second run cannot pass by leaving the
  // previous files in place.
  await rm(CSS, { force: true });
  await rm(MANIFEST, { force: true });
  await rm(FONTS, { recursive: true, force: true });

  build("second");
  const second = await snapshot();

  const problems = [];
  if (first.css !== second.css) {
    problems.push(
      `CSS differs:\n    run 1 ${first.css}\n    run 2 ${second.css}`,
    );
  }
  const files = new Set([
    ...Object.keys(first.fonts),
    ...Object.keys(second.fonts),
  ]);
  for (const f of files) {
    if (first.fonts[f] !== second.fonts[f]) {
      problems.push(
        `${f} differs:\n    run 1 ${first.fonts[f]}\n    run 2 ${second.fonts[f]}`,
      );
    }
  }

  const m = second.manifest;
  console.log("\n[ux4g:verify] reproducibility");
  console.log("  " + "─".repeat(64));
  console.log(
    `  source        ${m.source.package}@${m.source.version}  mode=${m.mode}`,
  );
  console.log(`  css sha256    ${second.css}`);
  for (const f of m.fonts) {
    console.log(`  ${f.file.padEnd(14)}${second.fonts[f.file]}`);
  }
  console.log("  " + "─".repeat(64));

  if (problems.length) {
    console.error("\n  NOT REPRODUCIBLE:\n");
    for (const p of problems) console.error(`   - ${p}`);
    console.error(
      "\n  The generated assets are gitignored on the premise that they are a\n" +
        "  pure function of the pinned package. That premise no longer holds;\n" +
        "  either fix the non-determinism or commit the artefacts.\n",
    );
    process.exit(1);
  }

  console.log("  two independent runs produced byte-identical output\n");
}

main().catch((err) => {
  console.error(`\n[ux4g:verify] FAILED\n${err.message}\n`);
  process.exit(1);
});
