/**
 * Frontend/modules.config.js — where each part of the frontend lives, and what
 * it may import. Phase 12.3–12.4 (docs/architecture/PHASE12_FRONTEND_SHELL.md
 * §3.6, §9, §10).
 *
 * The one place the folder layout is written down. `vite.config.js` builds its
 * path aliases from it, and `src/__tests__/architecture/moduleBoundaries.test.js`
 * enforces it over every file, by resolved path: every source file must sit in
 * one of the places named here, and every import must respect the rules. The
 * ESLint `no-restricted-imports` overrides in `.eslintrc.json` repeat the alias
 * half for fast feedback in an editor; the test checks they agree.
 *
 *   shell          the platform: CCure Home, product entry pages, the shared
 *                  HTTP client, auth state, route guard, permissions, and the
 *                  shared capabilities every product uses — user, organisation,
 *                  role, email-domain and audit-log administration, the account
 *                  menu, notifications, organisation switching, platform
 *                  preferences. Imports itself and the design system — never a
 *                  product.
 *   design-system  the UI primitives. Imports nothing of the application.
 *   <module>       one product. Imports itself, the shell and the design
 *                  system — never another product.
 *   root           the composition root: mounts the shell and every module.
 */

/** Product modules: key → folder under src/. Each gets an `@<key>` alias. */
export const MODULES = {
  audit: "src/modules/audit",
  policy: "src/modules/policy",
  rank: "src/modules/rank",
  ir: "src/modules/ir",
};

/** Shared layers. */
export const SHELL = "src/shell";
export const DESIGN_SYSTEM = "src/design-system";

/** The composition root: mounts the shell and every module. */
export const ROOT_FILES = ["src/main.jsx", "src/App.jsx"];

/**
 * The application-wide stylesheet `main.jsx` loads, and the files it
 * `@import`s. Owned by the root because every page — the platform's and every
 * product's — renders under it. Moving it into a product would make every other
 * product depend on that product's CSS. Any part may import one of these
 * (Audit's ComplianceWorkspace imports scan.css directly; removing that import
 * would change the order rules land in the bundle).
 */
export const GLOBAL_STYLES = [
  "src/styles/global.css",
  "src/styles/theme.css",
  "src/styles/layout.css",
  "src/styles/forms.css",
  "src/styles/scan.css",
  "src/styles/responsive.css",
  "src/styles/animations.css",
  "src/styles/dark-mode.css",
];

/**
 * Files whose owner is undecided, each with the reason. Nothing may be added
 * here to make a build pass: a file belongs to the shell, a module or the root.
 *
 * Empty since the sign-in screens moved to `src/shell/auth/` (6 Oct 2026): they
 * are platform screens by function and no longer carry a product's name. The
 * group is kept so a future undecided file has somewhere honest to wait, and a
 * test pins that nothing sits here without a reason.
 */
export const PENDING = {};

/** Path aliases: `@shell/…` and one `@<module>/…` per product module. */
export const ALIASES = {
  "@shell": SHELL,
  ...Object.fromEntries(
    Object.entries(MODULES).map(([key, dir]) => [`@${key}`, dir]),
  ),
};
