import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const FRONTEND_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

/**
 * Upstream's dark-theme selector for the approved release. 3.0.1 renamed it
 * from `:root[data-theme=dark]` without a changelog entry
 * (docs/ux4g/B11_UX4G_3_0_2_UPGRADE.md). Matched exactly, so a further rename
 * fails the build rather than silently shipping light tokens in dark mode.
 */
export const UPSTREAM_DARK_SELECTOR =
  ".dark,:root[data-mode=dark],[data-mode=dark]";

/**
 * The application's dark-mode contract: PreferencesContext sets
 * `data-theme="dark"` on <html>, and every authored stylesheet keys on it.
 * Upstream's `.dark` class and `[data-mode]` are never emitted; a bare `.dark`
 * would restyle any element that happened to carry that class.
 */
export const APP_DARK_SELECTOR = ":root[data-theme=dark]";

export function readJson(filename) {
  return JSON.parse(readFileSync(filename, "utf8"));
}

/** Reviewed release identity; package.json/lockfiles are checked against it. */
export function loadBaseline(root = FRONTEND_ROOT) {
  const baseline = readJson(path.join(root, "ux4g-baseline.json"));
  if (
    baseline.schemaVersion !== 1 ||
    !/^\d+\.\d+\.\d+$/.test(baseline.npm?.version ?? "") ||
    !baseline.npm?.package ||
    !baseline.npm?.integrity ||
    !/^[a-f0-9]{64}$/.test(baseline.assets?.sourceCssSha256 ?? "")
  ) {
    throw new Error(
      "Invalid UX4G baseline: exact version and provenance required",
    );
  }
  return baseline;
}

/** Fail before writing assets when the installed vendor input is wrong. */
export function verifyVendorInput(baseline, root = FRONTEND_ROOT) {
  const dir = path.join(root, "node_modules", baseline.npm.package);
  const installed = readJson(path.join(dir, "package.json"));
  if (
    installed.name !== baseline.npm.package ||
    installed.version !== baseline.npm.version
  ) {
    throw new Error(
      `UX4G installed ${installed.name}@${installed.version}; expected ` +
        `${baseline.npm.package}@${baseline.npm.version} from ux4g-baseline.json. Run npm ci.`,
    );
  }
  const css = readFileSync(path.join(dir, "styles", "ux4g.css"));
  if (sha256(css) !== baseline.assets.sourceCssSha256) {
    throw new Error("UX4G upstream stylesheet provenance/hash mismatch");
  }
  return { installed, css };
}
