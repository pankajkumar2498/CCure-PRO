/**
 * src/modules/audit/config/permissions.js — permissions that more than one part
 * of Audit's UI must agree on.
 *
 * AMT Integration's one action is importing an inventory, which the backend
 * authorises as `settings:update` (`POST /assets/import-amt`). The sidebar item
 * and the `/admin/amt` route both name that permission here, so the page cannot
 * be reachable by URL by someone the sidebar — and the API — would refuse.
 * (The route used to be gated on `assets:update`, which an analyst holds.)
 */
export const AMT_PERMISSION = Object.freeze({
  resource: "settings",
  action: "update",
});
