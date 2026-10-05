/** Offline migration-aware checks. No registry access or asset writes. */
import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  FRONTEND_ROOT,
  loadBaseline,
  readJson,
  sha256,
  verifyVendorInput,
} from "./ux4g-baseline.mjs";
import {
  ASSET_LAYOUT,
  assetPaths,
  pipelineIdentity,
  tokenCssProblems,
  approvedAssetMode,
} from "./ux4g-pipeline.mjs";

const FRAMEWORK =
  /^(?:bootstrap(?:$|[-/@])|react-bootstrap(?:$|[/@])|reactstrap(?:$|[/@])|@(?:mui|material-ui|ant-design|chakra-ui|radix-ui|headlessui|fluentui|blueprintjs|tailwindcss)\/|(?:antd|tailwindcss|primereact|bulma|materialize-css|daisyui|vuetify)(?:$|[/@])|semantic-ui(?:$|[-/@])|shadcn(?:$|[-/@])|@shadcn\/)/i;
const UX4G = /ux4g/i;
const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];
const IMPORT =
  /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\(\s*|@import\s+)(["'])([^"'\n]+)\1/g;

export function installedPackages(root) {
  const records = [];
  const visited = new Set();
  function visit(dir) {
    if (!existsSync(dir)) return;
    const real = realpathSync(dir);
    if (visited.has(real)) return;
    visited.add(real);
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith(".")) continue;
      const candidate = path.join(dir, entry.name);
      const packages = entry.name.startsWith("@")
        ? readdirSync(candidate).map((name) => path.join(candidate, name))
        : [candidate];
      for (const pkgDir of packages) {
        const filename = path.join(pkgDir, "package.json");
        if (!existsSync(filename)) continue;
        records.push({
          location: path.relative(root, pkgDir).split(path.sep).join("/"),
          ...readJson(filename),
        });
        visit(path.join(pkgDir, "node_modules"));
      }
    }
  }
  visit(path.join(root, "node_modules"));
  return records;
}

const lockName = (location, entry) =>
  entry.name || location.split("node_modules/").at(-1);

export function dependencyProblems(baseline, pkg, lock, installed) {
  const problems = [];
  const { package: name, version, integrity, tarball } = baseline.npm;
  if (pkg.dependencies?.[name] !== version)
    problems.push("package.json must exactly pin the approved UX4G version");
  if (lock.packages?.[""]?.dependencies?.[name] !== version)
    problems.push("lockfile root UX4G version differs from the baseline");
  const locked = Object.entries(lock.packages ?? {}).filter(
    ([key, value]) => key && UX4G.test(lockName(key, value)),
  );
  if (locked.length !== 1 || locked[0]?.[0] !== `node_modules/${name}`)
    problems.push(
      "lockfile must contain exactly one approved UX4G package; duplicates/aliases are forbidden",
    );
  for (const [location, entry] of locked) {
    if (lockName(location, entry) !== name || entry.version !== version)
      problems.push(`unapproved UX4G lock entry: ${location}`);
    if (
      entry.integrity !== integrity ||
      entry.resolved !== tarball ||
      entry.link
    )
      problems.push(`UX4G registry provenance mismatch: ${location}`);
  }
  const copies = installed.filter((entry) => UX4G.test(entry.name));
  if (copies.length !== 1 || copies[0]?.location !== `node_modules/${name}`)
    problems.push(
      "installed tree must contain exactly one approved UX4G package; nested copies/aliases are forbidden",
    );
  for (const entry of copies) {
    if (entry.name !== name || entry.version !== version)
      problems.push(`unapproved installed UX4G package: ${entry.location}`);
    for (const field of [
      "dependencies",
      "peerDependencies",
      "optionalDependencies",
    ]) {
      const actual = Object.entries(entry[field] ?? {}).sort();
      const expected = Object.entries(baseline.npm[field] ?? {}).sort();
      if (JSON.stringify(actual) !== JSON.stringify(expected))
        problems.push(`unexpected UX4G ${field}: ${entry.location}`);
    }
  }
  for (const field of DEPENDENCY_FIELDS) {
    for (const [dep, spec] of Object.entries(pkg[field] ?? {})) {
      if (
        FRAMEWORK.test(dep) ||
        (typeof spec === "string" && FRAMEWORK.test(spec.replace(/^npm:/, "")))
      )
        problems.push(`unapproved UI framework in ${field}: ${dep}`);
      if (
        UX4G.test(`${dep} ${spec}`) &&
        (field !== "dependencies" || dep !== name || spec !== version)
      )
        problems.push(`unexpected UX4G declaration: ${field}.${dep}`);
    }
  }
  for (const [location, entry] of Object.entries(lock.packages ?? {})) {
    if (location && FRAMEWORK.test(lockName(location, entry)))
      problems.push(`unapproved UI framework in lockfile: ${location}`);
  }
  for (const entry of installed) {
    if (FRAMEWORK.test(entry.name))
      problems.push(`unapproved installed UI framework: ${entry.location}`);
  }
  return problems;
}

export function sourceProblems(baseline, filename, text) {
  const problems = [];
  if (
    filename !== ASSET_LAYOUT.css &&
    !filename.startsWith("dist/") &&
    /\.css$/.test(filename)
  ) {
    if (text.includes(`Source: ${baseline.npm.package}@`)) {
      problems.push(
        `copied UX4G stylesheet outside the central pipeline: ${filename}`,
      );
    }
    for (const family of baseline.assets.retainedFonts) {
      if (
        [...text.matchAll(/@font-face\s*\{([^}]*)\}/g)].some((match) =>
          match[1].includes(family),
        )
      ) {
        problems.push(
          `UX4G font declaration outside the central pipeline: ${filename}`,
        );
      }
    }
  }
  if (/https?:\/\/[^\s"'<>]*(?:ux4g|ux4g-web-components)/i.test(text)) {
    problems.push(`unapproved external UX4G asset source: ${filename}`);
  }
  for (const match of text.matchAll(IMPORT)) {
    const spec = match[2];
    if (
      /ux4g\.generated(?:\.css|\.manifest\.json)/.test(spec) &&
      filename !== "src/design-system/tokens/index.css"
    ) {
      problems.push(
        `generated UX4G import bypasses the central token entry point: ${filename}`,
      );
    }
    if (/ux4g/i.test(spec) && /node_modules\//.test(spec)) {
      problems.push(
        `UX4G vendor path bypasses the approved pipeline: ${filename}`,
      );
    }
    if (
      FRAMEWORK.test(spec) ||
      /(?:cdn|unpkg|jsdelivr).*\/(?:bootstrap|tailwindcss|antd|@mui)(?:[@/.-]|$)/i.test(
        spec,
      )
    )
      problems.push(`unapproved UI framework import: ${filename} -> ${spec}`);
    if (
      spec === baseline.npm.package ||
      spec.startsWith(`${baseline.npm.package}/`)
    ) {
      if (!filename.startsWith("src/design-system/"))
        problems.push(`UX4G import outside design system: ${filename}`);
      if (
        !baseline.runtime.enabled &&
        /\/(?:runtime|design-system)(?:\/|$)/.test(spec)
      )
        problems.push(
          `UX4G runtime is not approved for this phase: ${filename}`,
        );
      if (baseline.assets.mode === "tokens" && spec.endsWith("/styles.css"))
        problems.push(
          `full UX4G CSS is not approved for this phase: ${filename}`,
        );
    }
  }
  if (
    /https?:\/\/[^\s"'<>]*(?:bootstrap|tailwindcss|antd|@mui)[^\s"'<>]*\.(?:css|js)/i.test(
      text,
    )
  )
    problems.push(`unapproved UI framework asset: ${filename}`);
  if (
    !baseline.runtime.enabled &&
    filename.startsWith("dist/") &&
    /data-ux4g-runtime|__UX4G_RUNTIME_INITIALIZED__/.test(text)
  )
    problems.push(`unapproved UX4G runtime in production bundle: ${filename}`);
  return problems;
}

function sourceFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === "__tests__" || entry.name === "node_modules") return [];
    const file = path.join(dir, entry.name);
    return entry.isDirectory()
      ? sourceFiles(file)
      : /\.(jsx?|mjs|css|html|woff2?|ttf|otf)$/.test(file)
        ? [file]
        : [];
  });
}

export function assetProblems(baseline, root) {
  const problems = [];
  const outputs = assetPaths(root);
  const manifestBytes = readFileSync(outputs.manifest);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const css = readFileSync(outputs.css);
  if (
    manifest.schemaVersion !== 2 ||
    manifest.generator !== "scripts/build-ux4g-assets.mjs" ||
    JSON.stringify(manifest.pipeline) !== JSON.stringify(pipelineIdentity(root))
  ) {
    problems.push(
      "generated pipeline metadata is stale or mismatched; regenerate UX4G assets",
    );
  }
  if (
    !existsSync(outputs.publicManifest) ||
    !readFileSync(outputs.publicManifest).equals(manifestBytes)
  ) {
    problems.push(
      "public UX4G provenance manifest differs from generated metadata",
    );
  }
  const baselineBytes = readFileSync(path.join(root, "ux4g-baseline.json"));
  if (manifest.baseline?.sha256 !== sha256(baselineBytes))
    problems.push("generated baseline metadata is stale");
  for (const key of ["package", "version", "integrity", "tarball"]) {
    if (manifest.source?.[key] !== baseline.npm[key])
      problems.push(`generated source ${key} differs from approved provenance`);
  }
  if (
    JSON.stringify(manifest.source?.publisher) !==
    JSON.stringify(baseline.npm.publisher)
  )
    problems.push("generated publisher differs from approved provenance");
  if (manifest.source?.cssSha256 !== baseline.assets.sourceCssSha256)
    problems.push("generated upstream stylesheet provenance differs");
  if (manifest.mode !== baseline.assets.mode)
    problems.push("generated CSS delivery mode is not approved");
  if (
    manifest.css?.bytes !== css.length ||
    manifest.css?.sha256 !== sha256(css) ||
    manifest.css?.sha256_16 !== sha256(css).slice(0, 16)
  )
    problems.push("generated CSS size/hash mismatch");
  if (
    !css
      .toString()
      .includes(
        `Source: ${baseline.npm.package}@${baseline.npm.version}, mode=${baseline.assets.mode}`,
      )
  )
    problems.push("generated CSS version metadata mismatch");
  if (
    JSON.stringify(manifest.fonts?.map((font) => font.family)) !==
    JSON.stringify(baseline.assets.retainedFonts)
  )
    problems.push("generated fonts differ from approved retained families");
  const fontDir = outputs.fonts;
  const named = (manifest.fonts ?? []).map((font) => font.file).sort();
  const actual = readdirSync(fontDir).sort();
  if (JSON.stringify(named) !== JSON.stringify(actual))
    problems.push("unexpected/missing generated font assets");
  for (const font of manifest.fonts ?? []) {
    if (
      path.basename(font.file) !== font.file ||
      !font.file.endsWith(".woff2")
    ) {
      problems.push("invalid generated font filename");
      continue;
    }
    const file = path.join(fontDir, font.file);
    if (!existsSync(file)) {
      problems.push(`missing generated font: ${font.file}`);
      continue;
    }
    const bytes = readFileSync(file);
    if (
      font.bytes !== bytes.length ||
      font.sha256 !== sha256(bytes) ||
      font.sha256_16 !== sha256(bytes).slice(0, 16)
    )
      problems.push(`generated font size/hash mismatch: ${font.file}`);
  }
  if (/url\(\s*["']?(?:data:font|https?:|\/\/)/i.test(css.toString()))
    problems.push("generated CSS includes non-self-hosted assets");
  problems.push(...tokenCssProblems(css.toString(), named));
  return problems;
}

export function distAssetProblems(root) {
  const problems = [];
  const outputs = assetPaths(root);
  const published = path.join(root, "dist/assets/ux4g/manifest.json");
  if (
    !existsSync(published) ||
    !readFileSync(published).equals(readFileSync(outputs.manifest))
  ) {
    problems.push(
      "production UX4G manifest is missing or stale; run npm run build",
    );
  }
  const manifest = readJson(outputs.manifest);
  const fontDir = path.join(root, "dist/assets/fonts/ux4g");
  const named = manifest.fonts.map((font) => font.file).sort();
  if (
    !existsSync(fontDir) ||
    JSON.stringify(readdirSync(fontDir).sort()) !== JSON.stringify(named)
  ) {
    problems.push(
      "production UX4G font inventory differs from generated assets",
    );
  }
  for (const font of manifest.fonts) {
    const file = path.join(fontDir, font.file);
    if (!existsSync(file) || sha256(readFileSync(file)) !== font.sha256) {
      problems.push(
        `production UX4G font is missing or mismatched: ${font.file}`,
      );
    }
  }
  return problems;
}

export function cspProblems(baseline, config) {
  const policies = [
    ...config.matchAll(/add_header\s+Content-Security-Policy\s+"([^"]+)"/g),
  ].map((match) => match[1]);
  if (
    !policies.length ||
    policies.some((policy) => sha256(policy) !== baseline.csp.policySha256)
  ) {
    return ["CSP differs from the approved unchanged deployment policy"];
  }
  return [];
}

export function checkFoundation({
  root = FRONTEND_ROOT,
  dependenciesOnly = false,
  dist = false,
} = {}) {
  const baseline = loadBaseline(root);
  approvedAssetMode(baseline);
  const installed = installedPackages(root);
  const problems = dependencyProblems(
    baseline,
    readJson(path.join(root, "package.json")),
    readJson(path.join(root, "package-lock.json")),
    installed,
  );
  verifyVendorInput(baseline, root);
  problems.push(
    ...cspProblems(
      baseline,
      readFileSync(path.join(root, "nginx.conf"), "utf8"),
    ),
  );
  for (const file of ["src", "public", "dist"].flatMap((dir) =>
    sourceFiles(path.join(root, dir)),
  )) {
    const name = path.relative(root, file).split(path.sep).join("/");
    if (/\.(woff2?|ttf|otf)$/.test(name)) {
      if (
        /ux4g/i.test(name) &&
        !name.startsWith(`${ASSET_LAYOUT.fonts}/`) &&
        !name.startsWith("dist/assets/fonts/ux4g/")
      ) {
        problems.push(`UX4G font outside the central pipeline: ${name}`);
      }
      continue;
    }
    if (
      /ux4g/i.test(path.basename(name)) &&
      /\.(css|mjs|js)$/.test(name) &&
      name !== ASSET_LAYOUT.css &&
      !name.startsWith("src/__tests__/")
    ) {
      problems.push(`UX4G asset outside the central pipeline: ${name}`);
    }
    problems.push(
      ...sourceProblems(baseline, name, readFileSync(file, "utf8")),
    );
  }
  if (!dependenciesOnly) problems.push(...assetProblems(baseline, root));
  if (dist) problems.push(...distAssetProblems(root));
  if (problems.length) throw new Error(problems.join("\n"));
  return {
    package: baseline.npm.package,
    version: baseline.npm.version,
    installedPackages: installed.length,
    delivery: baseline.assets.mode,
    runtimeEnabled: baseline.runtime.enabled,
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    const result = checkFoundation({
      dependenciesOnly: process.argv.includes("--dependencies-only"),
      dist: process.argv.includes("--dist"),
    });
    console.log(`[ux4g:check] PASS ${JSON.stringify(result)}`);
  } catch (error) {
    console.error(`[ux4g:check] FAILED\n${error.message}`);
    process.exitCode = 1;
  }
}
