#!/usr/bin/env node
/**
 * Build and serve a production image of the frontend for capture.
 *
 *   node serve.mjs build TAG [CONTEXT=Frontend]
 *   node serve.mjs up TAG PORT NAME
 *   node serve.mjs down NAME
 *
 * The container is bound to 127.0.0.1 and `api` resolves to its own loopback,
 * so nginx starts but no request can reach a live API — the harness answers
 * `/api` itself before anything leaves the browser.
 */
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const docker = (args, opts = {}) => {
  const r = spawnSync("docker", args, { encoding: "utf8", ...opts });
  if (r.status !== 0) {
    throw new Error(
      `docker ${args[0]} failed: ${(r.stderr || r.stdout || "").trim().split("\n").slice(-3).join(" | ")}`,
    );
  }
  // With stdio inherited there is no captured stdout; a successful build
  // returned null here and was reported as a failure.
  return (r.stdout || "").trim();
};

// `process.argv[1]` is absent when the module is imported from `node -e`.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const [cmd, a, b, c] = process.argv.slice(2);
  if (cmd === "build" && a) {
    docker(["build", "-t", a, b || "Frontend"], { stdio: "inherit" });
  } else if (cmd === "up" && a && b && c) {
    docker([
      "run",
      "-d",
      "--rm",
      "--name",
      c,
      "--add-host",
      "api:127.0.0.1",
      "-p",
      `127.0.0.1:${b}:80`,
      a,
    ]);
    const url = `http://127.0.0.1:${b}/`;
    let ok = false;
    for (let i = 0; i < 60 && !ok; i += 1) {
      try {
        ok = (await fetch(url)).ok;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    if (!ok) throw new Error(`${url} did not answer`);
    console.log(`${c} serving ${a} at ${url}`);
  } else if (cmd === "down" && a) {
    spawnSync("docker", ["stop", a], { stdio: "ignore" });
    console.log(`${a} stopped`);
  } else {
    console.error(
      "usage: serve.mjs build TAG [CONTEXT] | up TAG PORT NAME | down NAME",
    );
    process.exit(2);
  }
}
