// @vitest-environment node
// These tests exercise Node build tooling and filesystem publication.
import { afterEach, describe, expect, it } from "vitest";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import {
  FRONTEND_ROOT,
  loadBaseline,
} from "../../../scripts/ux4g-baseline.mjs";
import {
  approvedAssetMode,
  assetPaths,
  pipelineIdentity,
  tokenCssProblems,
} from "../../../scripts/ux4g-pipeline.mjs";
import {
  assetProblems,
  distAssetProblems,
  sourceProblems,
} from "../../../scripts/check-ux4g-foundation.mjs";
import { publishAssets } from "../../../scripts/build-ux4g-assets.mjs";

const baseline = loadBaseline();
const scratch = [];
afterEach(() =>
  scratch
    .splice(0)
    .forEach((root) => rmSync(root, { recursive: true, force: true })),
);
function rootFixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "ccure-b2-assets-"));
  scratch.push(root);
  return root;
}
function write(root, file, content) {
  const target = path.join(root, file);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, content);
}
function generatedFixture() {
  const root = rootFixture();
  for (const file of [
    "ux4g-baseline.json",
    "package-lock.json",
    "scripts/build-ux4g-assets.mjs",
    "scripts/ux4g-baseline.mjs",
    "scripts/ux4g-pipeline.mjs",
    "node_modules/wawoff2",
    "src/design-system/tokens/ux4g.generated.css",
    "src/design-system/tokens/ux4g.generated.manifest.json",
    "public/assets/fonts/ux4g",
    "public/assets/ux4g",
  ]) {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    cpSync(path.join(FRONTEND_ROOT, file), path.join(root, file), {
      recursive: true,
    });
  }
  return root;
}

describe("B.2 central asset pipeline", () => {
  it("rejects full CSS and incompatible runtime activation", () => {
    expect(approvedAssetMode(baseline, "tokens")).toBe("tokens");
    expect(() => approvedAssetMode(baseline, "full")).toThrow(
      /approved token-only/,
    );
    expect(() =>
      approvedAssetMode({ ...baseline, runtime: { enabled: true } }),
    ).toThrow(/runtime disabled/);
  });

  it("a rejected CLI override leaves the existing asset set intact", () => {
    const paths = assetPaths();
    const before = readFileSync(paths.manifest);
    const result = spawnSync(
      process.execPath,
      [path.join(FRONTEND_ROOT, "scripts/build-ux4g-assets.mjs")],
      {
        cwd: FRONTEND_ROOT,
        env: { ...process.env, UX4G_CSS_MODE: "full" },
        encoding: "utf8",
      },
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("approved token-only pipeline");
    expect(readFileSync(paths.manifest)).toEqual(before);
  });

  it("rejects stale implementation and converter input identities", () => {
    const root = generatedFixture();
    expect(assetProblems(baseline, root)).toEqual([]);
    write(root, "scripts/build-ux4g-assets.mjs", "changed generator");
    expect(assetProblems(baseline, root)).toContain(
      "generated pipeline metadata is stale or mismatched; regenerate UX4G assets",
    );
    const before = pipelineIdentity(root);
    write(
      root,
      "node_modules/wawoff2/build/compress_binding.js",
      "altered converter",
    );
    expect(pipelineIdentity(root).converter.files).not.toEqual(
      before.converter.files,
    );
  });

  it("rejects stale public provenance separately from internal metadata", () => {
    const root = generatedFixture();
    writeFileSync(assetPaths(root).publicManifest, "stale");
    expect(assetProblems(baseline, root)).toContain(
      "public UX4G provenance manifest differs from generated metadata",
    );
  });

  it("rejects missing or modified production copies", () => {
    const root = generatedFixture();
    cpSync(path.join(root, "public"), path.join(root, "dist"), {
      recursive: true,
    });
    expect(distAssetProblems(root)).toEqual([]);
    write(
      root,
      "dist/assets/fonts/ux4g/noto-sans.woff2",
      "corrupted deployed font",
    );
    write(root, "dist/assets/ux4g/manifest.json", "old deployment");
    expect(distAssetProblems(root).join("\n")).toMatch(/manifest.*stale/);
    expect(distAssetProblems(root).join("\n")).toMatch(/font.*mismatched/);
    rmSync(path.join(root, "dist/assets/fonts/ux4g"), { recursive: true });
    expect(distAssetProblems(root).join("\n")).toMatch(/inventory differs/);
  });

  it("rejects component/reset leakage and alternative font URLs", () => {
    const css =
      '@font-face{font-family:"Noto Sans";src:url("/assets/fonts/ux4g/noto-sans.woff2")}\n:root{--ux4g-example:1}';
    expect(tokenCssProblems(css, ["noto-sans.woff2"])).toEqual([]);
    expect(
      tokenCssProblems(css + "body{margin:0}", ["noto-sans.woff2"]),
    ).toContain("token pipeline contains component/reset/other CSS");
    expect(
      tokenCssProblems(
        css.replace("/assets/fonts/ux4g/", "//example.invalid/"),
        ["noto-sans.woff2"],
      ),
    ).toContain("generated CSS font URLs do not match the central font assets");
  });

  it("rejects module-level generated imports, CDN assets and copied font declarations", () => {
    const generatedCss = "ux4g." + "generated.css";
    // Fixture CSS directives must not look like actual test-module imports
    // to the repository's static import-path audit.
    const cssImport = (file) => "@im" + `port "${file}";`;
    expect(
      sourceProblems(
        baseline,
        "src/design-system/tokens/index.css",
        cssImport(`./${generatedCss}`),
      ),
    ).toEqual([]);
    expect(
      sourceProblems(
        baseline,
        "src/modules/audit/extra.css",
        cssImport(`../../design-system/tokens/${generatedCss}`),
      ),
    ).toHaveLength(1);
    const cdn = "https://cdn." + "ux4g.gov.in/UX4G@3.3.0/index.css";
    expect(
      sourceProblems(baseline, "public/index.html", `<link href="${cdn}">`),
    ).toHaveLength(1);
    expect(
      sourceProblems(
        baseline,
        "src/modules/audit/extra.css",
        '@font-face{font-family:"Noto Sans";src:url("local.woff2")}',
      ),
    ).toHaveLength(1);
  });

  it("publishes matching manifests and removes stale fonts as a complete set", async () => {
    const root = rootFixture();
    write(root, "public/assets/fonts/ux4g/stale.woff2", "old font");
    await publishAssets({
      root,
      css: "tokens",
      kept: [{ filename: "noto-sans.woff2", woff2: Buffer.from("font") }],
      manifest: { test: true },
    });
    const paths = assetPaths(root);
    expect(readdirSync(paths.fonts)).toEqual(["noto-sans.woff2"]);
    expect(readFileSync(paths.manifest)).toEqual(
      readFileSync(paths.publicManifest),
    );
    expect(
      readdirSync(root).filter((name) => name.startsWith(".ux4g-assets")),
    ).toEqual([]);
  });

  it("restores the previous output set if publication fails midway", async () => {
    const root = rootFixture();
    const paths = assetPaths(root);
    write(root, "public/assets/fonts/ux4g/previous.woff2", "old font");
    write(root, "src/design-system/tokens/ux4g.generated.css", "old CSS");
    write(
      root,
      "src/design-system/tokens/ux4g.generated.manifest.json",
      "old manifest",
    );
    write(root, "public/assets/ux4g", "blocking file");
    await expect(
      publishAssets({
        root,
        css: "new CSS",
        kept: [{ filename: "new.woff2", woff2: Buffer.from("new") }],
        manifest: { test: true },
      }),
    ).rejects.toThrow();
    expect(readFileSync(paths.css, "utf8")).toBe("old CSS");
    expect(readFileSync(paths.manifest, "utf8")).toBe("old manifest");
    expect(readFileSync(path.join(paths.fonts, "previous.woff2"), "utf8")).toBe(
      "old font",
    );
    expect(existsSync(path.join(paths.fonts, "new.woff2"))).toBe(false);
    expect(
      readdirSync(root).filter((name) => name.startsWith(".ux4g-assets")),
    ).toEqual([]);
  });
});
