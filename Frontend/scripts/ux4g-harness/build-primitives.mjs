import { build } from "vite";
import react from "@vitejs/plugin-react";
import { mkdir, writeFile, cp } from "node:fs/promises";
import path from "node:path";
import { FRONTEND_ROOT } from "../ux4g-baseline.mjs";

const output = process.argv[2];
if (!output || !path.isAbsolute(output))
  throw new Error("Provide an absolute temporary output directory");
const entry = path.join(output, "entry");
await mkdir(entry, { recursive: true });
await writeFile(
  path.join(entry, "index.html"),
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>UX4G adapter validation</title></head><body><div id="root"></div><script type="module" src="${FRONTEND_ROOT}/scripts/ux4g-harness/primitives.jsx"></script></body></html>`,
);
await build({
  configFile: false,
  root: entry,
  plugins: [react()],
  publicDir: false,
  build: { outDir: path.join(output, "dist"), emptyOutDir: true },
});
await cp(
  path.join(FRONTEND_ROOT, "public/assets/fonts"),
  path.join(output, "dist/assets/fonts"),
  { recursive: true },
);
