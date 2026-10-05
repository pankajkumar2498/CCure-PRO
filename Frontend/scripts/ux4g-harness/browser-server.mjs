/** Isolated production-build server. Never proxies or connects to an API. */
import { createServer } from "node:http";
import { readFile, stat, mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { FRONTEND_ROOT } from "../ux4g-baseline.mjs";

const fixture = await mkdtemp(path.join(os.tmpdir(), "ccure-ux4g-fixture-"));
const build = spawnSync(
  process.execPath,
  ["scripts/ux4g-harness/build-primitives.mjs", fixture],
  { cwd: FRONTEND_ROOT, stdio: "inherit" },
);
if (build.status !== 0) {
  await rm(fixture, { recursive: true, force: true });
  process.exit(1);
}
const csp = readFileSync(path.join(FRONTEND_ROOT, "nginx.conf"), "utf8").match(
  /add_header Content-Security-Policy "([^"]+)"/,
)?.[1];
if (!csp)
  throw new Error("Production CSP must be available for browser checks");
const types = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};
const server = createServer(async (request, response) => {
  response.setHeader("Content-Security-Policy", csp);
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Cache-Control", "no-store");
  const pathname = decodeURIComponent(
    new URL(request.url, "http://127.0.0.1:3277").pathname,
  );
  if (pathname === "/__health") {
    response.end("isolated");
    return;
  }
  if (pathname.startsWith("/api/")) {
    response.writeHead(403);
    response.end("Synthetic browser fixtures are required");
    return;
  }
  const isFixture = pathname.startsWith("/__ux4g-fixture/");
  const root = isFixture
    ? path.join(fixture, "dist")
    : path.join(FRONTEND_ROOT, "dist");
  const relative = isFixture
    ? pathname.slice("/__ux4g-fixture/".length)
    : pathname.slice(1);
  let filename = path.resolve(root, relative || "index.html");
  if (!filename.startsWith(root + path.sep)) {
    response.writeHead(403);
    response.end();
    return;
  }
  try {
    if (!(await stat(filename)).isFile()) throw new Error("not a file");
  } catch {
    // Fixture bundles use root-relative /assets URLs. Dist hashes are unique.
    if (pathname.startsWith("/assets/") && path.extname(pathname)) {
      filename = path.join(fixture, "dist", pathname.slice(1));
      try {
        await stat(filename);
      } catch {
        response.writeHead(404);
        response.end();
        return;
      }
    } else filename = path.join(root, "index.html");
  }
  try {
    response.setHeader(
      "Content-Type",
      types[path.extname(filename)] || "application/octet-stream",
    );
    response.end(await readFile(filename));
  } catch {
    response.writeHead(404);
    response.end();
  }
});
server.listen(3277, "127.0.0.1");
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () =>
    server.close(async () => {
      await rm(fixture, { recursive: true, force: true });
      process.exit(0);
    }),
  );
