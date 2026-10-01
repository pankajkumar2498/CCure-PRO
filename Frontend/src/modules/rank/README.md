# `src/modules/rank/` — CCure Rank (frontend)

**Nothing is built here yet.** CCure Rank has no frontend feature, data or
settings in this installation. Its card on CCure Home and its entry page at
`/rank-dashboard` are rendered by the shell from the platform registry
(`GET /platform/modules`), which reports it `not_yet_available`.

This folder is the Rank team's. When the team ships its first screen:

1. Put every Rank page, component, API client, hook and stylesheet under
   this folder. Import it elsewhere as `@rank/…`.
2. Mount the dashboard at its registry `entry_path`, `/rank-dashboard`, as a
   static route in `src/App.jsx`. A static route outranks the shell's
   registry-driven entry page, so the placeholder disappears by itself.
3. In the **same** change, the platform sets the product's `tile_state` to
   `available` in `Backend/ccure_platform/modules/` — never in the frontend.
   `Backend/tests/repo/test_platform_entry_routes.py` refuses an available
   product with no route, and a route for a product that is not available.
4. Put its tests under `src/__tests__/modules/rank/`.

May import: this folder (`@rank/…`), the shell (`@shell/…`) and the design
system. Must never import another product (`@audit/…`, `@policy/…`, `@ir/…`):
share through the shell instead. `Frontend/modules.config.js` is the rule and
`src/__tests__/architecture/moduleBoundaries.test.js` enforces it.

See `docs/FRONTEND_ARCHITECTURE.md` §2 and
`docs/architecture/PHASE12_FRONTEND_SHELL.md`.
