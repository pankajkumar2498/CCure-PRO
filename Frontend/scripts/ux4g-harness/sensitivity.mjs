#!/usr/bin/env node
/**
 * The sensitivity gate: inject each deliberate regression into an unchanged
 * build and require the comparison against a clean capture to name it.
 *
 *   node sensitivity.mjs --base http://127.0.0.1:3216 --baseline PRE-A/report.json
 *        [--out DIR]
 *
 * Exit code 1 when any injection goes undetected in any of its expected
 * categories.
 */
import { readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { parseArgs, runCapture } from "./run.mjs";
import { diffState } from "./compare.mjs";
import { INJECTIONS } from "./lib/injections.mjs";
import { STATES, SENSITIVITY_STATES } from "./lib/states.mjs";

// `process.argv[1]` is absent when the module is imported from `node -e`.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const args = parseArgs(process.argv.slice(2));
  if (!args.base || !args.baseline) {
    console.error(
      "usage: sensitivity.mjs --base URL --baseline report.json [--out DIR]",
    );
    process.exit(2);
  }
  const baseline = JSON.parse(readFileSync(args.baseline, "utf8"));
  const outRoot = path.resolve(
    args.out || path.join(os.tmpdir(), "ccure-ux4g-harness", "sensitivity"),
  );
  // Exact ids: `selectStates` matches prefixes, and "ar-assets" would also
  // pull in every ar-assets-* variant.
  const states = STATES.filter((s) => SENSITIVITY_STATES.includes(s.id));
  const rows = [];
  let failed = false;

  for (const [name, injection] of Object.entries(INJECTIONS)) {
    const { report } = await runCapture({
      base: args.base.replace(/\/$/, ""),
      label: `sens-${name}`,
      out: path.join(outRoot, name),
      states,
      themes: ["light"],
      injection: name,
      // Saved, so the screenshot comparison is pixel-wise like every other.
      screenshots: true,
      quiet: true,
    });
    for (const [key, result] of Object.entries(report.states)) {
      const clean = baseline.states[key];
      if (!clean) {
        rows.push({
          injection: name,
          state: key,
          expected: injection.expect,
          detected: [],
          pass: false,
          note: "no baseline",
        });
        failed = true;
        continue;
      }
      const detected = diffState(clean, result).map((d) => d.category);
      const pass = injection.expect.every((c) => detected.includes(c));
      if (!pass) failed = true;
      rows.push({
        injection: name,
        state: key,
        expected: injection.expect,
        detected,
        pass,
      });
      console.log(
        `${pass ? "DETECTED " : "MISSED   "} ${name.padEnd(24)} ${key.padEnd(16)} expected [${injection.expect.join(", ")}] got [${detected.join(", ")}]`,
      );
    }
  }

  writeFileSync(
    path.join(outRoot, "sensitivity.json"),
    JSON.stringify(rows, null, 1),
  );
  console.log(
    `\n${rows.filter((r) => r.pass).length}/${rows.length} injections detected in every expected category${failed ? " — GATE FAILED" : ""}`,
  );
  process.exit(failed ? 1 : 0);
}
