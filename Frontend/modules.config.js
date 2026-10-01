/**
 * Frontend/modules.config.js — where each part of the frontend lives, and what
 * it may import. Phase 12.3 (docs/architecture/PHASE12_FRONTEND_SHELL.md §3.6).
 *
 * The one place the folder layout is written down. `vite.config.js` builds its
 * path aliases from it, and `src/__tests__/architecture/moduleBoundaries.test.js`
 * enforces the import rules over every file, by resolved path. The ESLint
 * `no-restricted-imports` rules in `.eslintrc.json` repeat the alias half for
 * fast feedback in an editor; the test checks they agree with this file.
 *
 *   shell          the platform: CCure Home, product entry pages, the shared
 *                  HTTP client, auth state, route guard, permissions, sign-in
 *                  screens, shared navigation. Imports itself and the design
 *                  system — never a product.
 *   design-system  the UI primitives. Imports nothing of the application.
 *   <module>       one product. Imports itself, the shell and the design
 *                  system — never another product.
 *
 * Audit predates the module folders: until Phase 12.4 moves it, every file
 * outside shell/, design-system/ and the module folders, plus
 * modules/web-scanning/ (which folds into modules/audit/), is Audit's.
 */

/** Product modules: key → folder under src/. Each gets an `@<key>` alias. */
export const MODULES = {
  audit: "src/modules/audit",
  policy: "src/modules/policy",
  rank: "src/modules/rank",
  ir: "src/modules/ir",
};

/** Folders under src/modules/ that belong to a product module by name only. */
export const LEGACY_MODULE_FOLDERS = {
  "src/modules/web-scanning": "audit",
};

/** Shared layers. */
export const SHELL = "src/shell";
export const DESIGN_SYSTEM = "src/design-system";

/** The composition root: mounts the shell and every module. */
export const ROOT_FILES = ["src/main.jsx", "src/App.jsx"];

/** Owner of legacy (pre-12.4) Audit locations: everything else under src/. */
export const LEGACY_OWNER = "audit";

/** Path aliases: `@shell/…` and one `@<module>/…` per product module. */
export const ALIASES = {
  "@shell": SHELL,
  ...Object.fromEntries(
    Object.entries(MODULES).map(([key, dir]) => [`@${key}`, dir]),
  ),
};
