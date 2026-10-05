# Frontend development standard

Read `../docs/FRONTEND_ARCHITECTURE.md` and
`../docs/ux4g/B1_VERSION_FOUNDATION.md` and
`../docs/ux4g/B2_ASSET_PIPELINE.md` and
`../docs/ux4g/B3_B4_SHARED_PRIMITIVES_SHELL.md` and
`../docs/ux4g/B5_B6_AUTH_AUDIT_MIGRATION.md` before changing frontend infrastructure.

- `ux4g-baseline.json` is the one approved UX4G release/provenance definition.
  Use the latest officially published/recommended stable release applicable to
  the project after compatibility/security/CSP validation. Pin it exactly and
  keep package, lockfile, installed input and generated metadata consistent.
- Common, authentication and all product modules share the CCure Design System.
  Prefer official UX4G components/patterns where equivalents exist as their
  approved pipeline/adapters become available. Do not introduce a separate
  module design system or competing framework without explicit approval.
- Custom equivalents require a documented technical reason. Keep domain-specific
  functionality in its module and generic presentation in the design system.
- B.3/B.4 use official scoped component CSS through shared React adapters.
  Modules import `design-system/index.js`, never official classes, vendor CSS
  or vendor behavior directly. Preserve native props/events and form values.
  Document compatibility/accessibility exceptions in the relevant phase report.
  Specialized and domain components stay in their existing module.
- B.5/B.6 migrate Auth and Audit presentation through those same adapters.
  Continue using shared form semantics, React-owned menus/dialogs, loading and
  empty states. Keep domain evidence, risk charts and topology in Audit. The
  scoped browser catalogue is `scripts/ux4g-harness/b5-b6.mjs`; its API writes
  must remain explicitly synthetic. Policy/Rank/IR and later phases are outside
  this migration.
- Generate UX4G assets only through `scripts/build-ux4g-assets.mjs`. Do not
  add module-local copies, font declarations or CDN imports. Asset paths and
  converter/generator identities are centralized in `scripts/ux4g-pipeline.mjs`.
  The scoped component subset is generated alongside tokens and fonts; never
  activate the vendor global reset. `UX4G_CSS_MODE` cannot select full CSS.
  Preserve the current font policy until
  an explicit typography/component migration is authorized.
- Preserve CSP, accessibility tests, API/auth/RBAC behavior, routes and module
  boundaries. Never relax script policy to enable a vendor runtime.
- For foundation changes run `npm ci`, `npm ls ux4g-web-components`, `npm ls --all`,
  `npm run ux4g:check -- --dependencies-only`, build, `npm run ux4g:verify`,
  `npm run ux4g:check -- --dist`, tests and lint; use browser/Docker checks for runtime impact.
- Do not claim complete UX4G adoption or GIGW/WCAG conformance from a dependency
  update. Record remaining migration work and a coherent rollback.
