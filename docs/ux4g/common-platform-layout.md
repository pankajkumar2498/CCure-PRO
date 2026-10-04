# Common Platform layout alignment

Validated on 4 October 2026.

The Common Platform used the same `CcureAppShell` as Audit but capped its main
area at `72rem`. Shell padding also wrapped the administration pages' own
gutters. Removing the cap and assigning gutters to each page gives Home,
product entry pages, access-denied pages, and all six administration modules
the full width available beside the sidebar.

## Design-system integration

The implementation uses the existing shared UX4G foundation and React adapters
in `Frontend/src/design-system`. It keeps the pinned
`ux4g-web-components@2.1.0` dependency, self-hosted fonts, generated tokens,
theme handling, and CSP-compatible React interactions. The npm version is
distinct from the design-system version: upstream's README maps npm 2.1.0 to
CDN UX4G 3.2.0, in the UX4G 3.x design family. See
[the existing dependency strategy](02-dependency-strategy.md).

Remaining administration presentation now uses shared tables, pagination,
checkboxes, buttons, badges, and loading indicators. Role controls use the
same typography, spacing, color, and focus tokens as other controls. Forms,
toolbars, role details, and pagination wrap on small screens; wide tables
scroll within their own accessible containers.

## Verification

- All 3,027 frontend tests passed across 104 files, including authorization,
  organization scope, role delegation, reauthentication, and API contracts.
- Added audit-log checks for first/last paging, page-size reset, unchanged
  `skip`/`limit` parameters, and one detail request per keyboard activation.
- Production build and ESLint passed. The build retains its existing bundle
  size and mixed-import warnings.
- Headless Chrome captured eight Common Platform pages at 1920, 1024, 390,
  and 320 pixels, plus desktop dark mode and four mobile administration
  dialogs. All 45 post-change states loaded without runtime errors, viewport
  horizontal overflow, measured text contrast failures, or unmocked API reads.
- At 1920 pixels, the main area grew from 1080 to 1700 pixels and the user and
  organization tables grew from 971 to 1640 pixels. At 320 pixels, the role
  and audit-log pages fit the viewport; they previously widened it to 329.
- A sampled Audit Asset Registry screenshot was pixel-identical before and
  after. Global Audit layout rules were not edited.

Browser checks used isolated production builds, fixture authorization payloads,
and mocked API responses. No real backend was contacted. Captures and reports
are in `/tmp/ccure-common-ui-before-checks` and
`/tmp/ccure-common-ui-after-checks` for this session.

No backend, API client, request payload, permission decision, or authentication
logic was changed. The authorization inventory was regenerated solely to update
source line references after import additions.
