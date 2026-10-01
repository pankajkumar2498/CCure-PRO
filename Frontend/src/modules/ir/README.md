# `src/modules/ir/` — CCure IR integration (frontend)

**Nothing is built here yet.** CCure IR is a separate service (Stage 4), not a
core module: the platform registry lists it as a `ServiceProduct`, and the shell
renders its card on CCure Home and its entry page at `/ir-dashboard` from
`GET /platform/modules`, which reports it `not_yet_available`.

This folder is where the **frontend integration** with the IR service will
live — the screens this application shows for IR, and the client that talks to
the IR service's API. The IR service's own code is not here.

When the first IR screen ships:

1. Put its pages, components, API client and styles under this folder. Import
   it elsewhere as `@ir/…`.
2. Mount it at its registry `entry_path`, `/ir-dashboard`, as a static route in
   `src/App.jsx`; a static route outranks the shell's entry page.
3. In the **same** change, the platform sets IR's `tile_state` to `available` in
   `Backend/ccure_platform/modules/` — never in the frontend.
4. Put its tests under `src/__tests__/modules/ir/`.

May import: this folder (`@ir/…`), the shell (`@shell/…`) and the design
system. Must never import another product (`@audit/…`, `@policy/…`,
`@rank/…`). `Frontend/modules.config.js` is the rule and
`src/__tests__/architecture/moduleBoundaries.test.js` enforces it.

Ownership: `@TODO-project-owner` until an IR team is named (`.github/CODEOWNERS`).
