import { afterEach, describe, expect, it } from "vitest";
import {
  cpSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  assetProblems,
  checkFoundation,
  cspProblems,
  dependencyProblems,
  installedPackages,
  sourceProblems,
} from "../../../scripts/check-ux4g-foundation.mjs";
import {
  FRONTEND_ROOT,
  loadBaseline,
  verifyVendorInput,
} from "../../../scripts/ux4g-baseline.mjs";

const baseline = loadBaseline();
const { package: name, version, integrity, tarball } = baseline.npm;
const scratch = [];
afterEach(() =>
  scratch
    .splice(0)
    .forEach((dir) => rmSync(dir, { recursive: true, force: true })),
);

function dependencyFixture() {
  return {
    pkg: { dependencies: { [name]: version } },
    lock: {
      packages: {
        "": { dependencies: { [name]: version } },
        [`node_modules/${name}`]: { version, integrity, resolved: tarball },
      },
    },
    installed: [{ location: `node_modules/${name}`, name, version }],
  };
}

function problems(fixture) {
  return dependencyProblems(
    baseline,
    fixture.pkg,
    fixture.lock,
    fixture.installed,
  );
}

function temporaryRoot() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "ccure-ux4g-foundation-"));
  scratch.push(dir);
  return dir;
}

function jsonFile(root, filename, value) {
  const target = path.join(root, filename);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, JSON.stringify(value));
}

describe("approved UX4G dependency foundation", () => {
  it("validates the actual locked, installed and generated foundation", () => {
    expect(checkFoundation()).toMatchObject({
      version,
      delivery: baseline.assets.mode,
      runtimeEnabled: false,
    });
  });

  it("accepts the approved exact package and provenance", () => {
    expect(problems(dependencyFixture())).toEqual([]);
  });

  it.each([`^${version}`, `~${version}`, "latest", "*"])(
    "rejects a floating dependency: %s",
    (spec) => {
      const fixture = dependencyFixture();
      fixture.pkg.dependencies[name] = spec;
      expect(problems(fixture)).toContain(
        "package.json must exactly pin the approved UX4G version",
      );
    },
  );

  it("rejects lockfile/root version drift and registry provenance substitution", () => {
    const fixture = dependencyFixture();
    fixture.lock.packages[""].dependencies[name] = "0.0.0";
    fixture.lock.packages[`node_modules/${name}`].resolved =
      "https://example.invalid/vendor.tgz";
    expect(problems(fixture).join("\n")).toMatch(
      /lockfile root.*\n.*provenance mismatch/,
    );
  });

  it("rejects same-version nested copies as well as different-version duplicates", () => {
    const fixture = dependencyFixture();
    fixture.lock.packages[`node_modules/other/node_modules/${name}`] = {
      version,
      integrity,
      resolved: tarball,
    };
    fixture.installed.push({
      location: `node_modules/other/node_modules/${name}`,
      name,
      version,
    });
    expect(problems(fixture).join("\n")).toMatch(
      /lockfile must contain exactly one.*\n.*installed tree must contain exactly one/,
    );
    fixture.installed[1].version = "0.0.0";
    expect(problems(fixture).join("\n")).toContain(
      "unapproved installed UX4G package",
    );
  });

  it("rejects unexpected UX4G packages, aliases and package dependencies", () => {
    const fixture = dependencyFixture();
    fixture.pkg.devDependencies = { "ux4g-unapproved": "0.0.0" };
    fixture.installed.push({ location: "node_modules/alias", name, version });
    fixture.installed[0].dependencies = { surprise: "1.0.0" };
    expect(problems(fixture).join("\n")).toMatch(
      /unexpected UX4G dependencies/,
    );
    expect(problems(fixture).join("\n")).toMatch(/unexpected UX4G declaration/);
    expect(problems(fixture).join("\n")).toMatch(/aliases are forbidden/);
  });

  it.each([
    "bootstrap",
    "@mui/material",
    "antd",
    "tailwindcss",
    "@chakra-ui/react",
    "primereact",
    "semantic-ui-react",
    "bulma",
    "@radix-ui/react-dialog",
  ])(
    "rejects an unapproved direct, transitive or installed framework: %s",
    (framework) => {
      const fixture = dependencyFixture();
      fixture.pkg.devDependencies = { [framework]: "1.0.0" };
      fixture.lock.packages[`node_modules/${framework}`] = { version: "1.0.0" };
      fixture.installed.push({
        location: `node_modules/${framework}`,
        name: framework,
        version: "1.0.0",
      });
      expect(
        problems(fixture).filter((message) => /UI framework/.test(message)),
      ).toHaveLength(3);
    },
  );

  it("finds nested installations independently of package.json/lockfile", () => {
    const root = temporaryRoot();
    jsonFile(root, "node_modules/outer/package.json", {
      name: "outer",
      version: "1.0.0",
    });
    jsonFile(root, `node_modules/outer/node_modules/${name}/package.json`, {
      name,
      version,
    });
    expect(installedPackages(root)).toHaveLength(2);
    expect(installedPackages(root)[1].location).toContain(
      `outer/node_modules/${name}`,
    );
  });

  it("fails on altered upstream CSS even when package version metadata agrees", () => {
    const root = temporaryRoot();
    jsonFile(root, `node_modules/${name}/package.json`, { name, version });
    const dir = path.join(root, "node_modules", name, "styles");
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, "ux4g.css"), "tampered vendor input");
    expect(() => verifyVendorInput(baseline, root)).toThrow(
      /provenance\/hash mismatch/,
    );
  });

  it("rejects corrupt generated bytes, stale metadata and extra font copies", () => {
    const root = temporaryRoot();
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
      const target = path.join(root, file);
      mkdirSync(path.dirname(target), { recursive: true });
      cpSync(path.join(FRONTEND_ROOT, file), target, { recursive: true });
    }
    const manifest = JSON.parse(
      readFileSync(
        path.join(
          root,
          "src/design-system/tokens/ux4g.generated.manifest.json",
        ),
        "utf8",
      ),
    );
    expect(assetProblems(baseline, root)).toEqual([]);
    writeFileSync(
      path.join(root, "src/design-system/tokens/ux4g.generated.css"),
      "corrupt",
    );
    writeFileSync(
      path.join(root, "public/assets/fonts/ux4g/stale.woff2"),
      "stale fixture font",
    );
    manifest.source.version = "0.0.0";
    jsonFile(
      root,
      "src/design-system/tokens/ux4g.generated.manifest.json",
      manifest,
    );
    expect(assetProblems(baseline, root)).toEqual(
      expect.arrayContaining([
        "generated source version differs from approved provenance",
        "generated CSS size/hash mismatch",
        "unexpected/missing generated font assets",
      ]),
    );
  });
});

describe("B.1 delivery boundaries", () => {
  it("rejects CSP weakening while preserving the existing policy", () => {
    const config = readFileSync(path.join(FRONTEND_ROOT, "nginx.conf"), "utf8");
    expect(cspProblems(baseline, config)).toEqual([]);
    expect(
      cspProblems(
        baseline,
        config.replaceAll(
          "script-src 'self'",
          "script-src 'self' 'unsafe-inline'",
        ),
      ),
    ).toHaveLength(1);
    expect(
      cspProblems(
        baseline,
        config.replaceAll(
          "script-src 'self'",
          "script-src 'self' 'unsafe-eval'",
        ),
      ),
    ).toHaveLength(1);
  });
  it("keeps UX4G imports inside the DS and rejects premature runtime/full CSS", () => {
    const runtimeImport = `import '${name}/runtime';`;
    expect(
      sourceProblems(baseline, "src/shell/example.jsx", runtimeImport),
    ).toHaveLength(2);
    expect(
      sourceProblems(baseline, "src/design-system/example.js", runtimeImport),
    ).toHaveLength(1);
    expect(
      sourceProblems(
        baseline,
        "src/design-system/example.css",
        `@import '${name}/styles.css';`,
      ),
    ).toHaveLength(1);
  });

  it("detects framework deep imports/CDNs while allowing domain React code", () => {
    expect(
      sourceProblems(
        baseline,
        "src/example.jsx",
        "import 'bootstrap/dist/css/bootstrap.css';",
      ),
    ).toHaveLength(1);
    expect(
      sourceProblems(
        baseline,
        "public/index.html",
        '<link href="https://cdn.jsdelivr.net/npm/bootstrap/dist/css/bootstrap.min.css">',
      ),
    ).toHaveLength(1);
    expect(
      sourceProblems(baseline, "src/example.jsx", "import React from 'react';"),
    ).toEqual([]);
  });
});
