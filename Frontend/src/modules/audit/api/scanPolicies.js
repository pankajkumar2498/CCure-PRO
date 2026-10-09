/**
 * Scan policies — what a scan assesses, as a reusable named configuration.
 *
 * Eleven operations across four RBAC atoms, and the split is deliberate on the
 * backend's side: "may this person run a scan" and "may this person decide
 * what every scan assesses" are different authorisations, so `scan_policies:*`
 * is not `scans:*`.
 *
 *   read    list, settings, validate, get, usage
 *   create  create, new version
 *   update  patch, enable, status
 *   delete  delete
 *
 * Three properties of the contract the UI has to respect:
 *
 * * **The vocabulary comes from `/settings`, never from here.** Scan kinds,
 *   statuses, config keys, check families and severities are all served by the
 *   API. Hardcoding them means a build that silently omits a family the
 *   backend added, and a form that offers one it removed.
 *
 * * **`is_usable` is derived and must not be recomputed.** It is true only
 *   when the policy is `active` *and* enabled; the backend owns that rule and
 *   a second copy here would agree until the day it did not.
 *
 * * **A version supersedes.** `POST /{id}/version` creates the next version of
 *   the family and archives the current one, pointing
 *   `superseded_by_policy_id` at the new row. It is not an edit: an edit
 *   changes what existing schedules will assess, a version leaves the old one
 *   intact for the scans that already cite it.
 */

import api from "@shell/api/axiosInstance";

const BASE = "/scan-policies";

/** Status is lifecycle; `is_enabled` is a separate switch. Both gate usability. */
export const POLICY_STATUS_TONE = {
  draft: "neutral",
  active: "success",
  archived: "warning",
};

/** 1. List. Server-side filters; there is no pagination on this endpoint. */
export const listPolicies = (params = {}) => api.get(BASE, { params });

/** 2. The vocabulary every form control is built from. */
export const getPolicySettings = () => api.get(`${BASE}/settings`);

/**
 * 3. Validate a configuration without saving it.
 *
 * Answers `{valid, errors[], warnings[]}` with prose an operator can act on —
 * "a policy that excludes the built-in checks must name at least one
 * framework, or the configuration audit assesses nothing and the host reports
 * as clean". Worth surfacing verbatim rather than paraphrasing.
 */
export const validatePolicy = (config, scanKind = "any") =>
  api.post(`${BASE}/validate`, { config, scan_kind: scanKind });

/** 4. Create. 201, or 409 on a duplicate name, or 422 with field errors. */
export const createPolicy = (body) => api.post(BASE, body);

/** 5. Read one. */
export const getPolicy = (id) => api.get(`${BASE}/${encodeURIComponent(id)}`);

/** 6. Edit in place. Changes what future scans using it will assess. */
export const updatePolicy = (id, body) =>
  api.patch(`${BASE}/${encodeURIComponent(id)}`, body);

/** 7. The enable switch, independent of lifecycle status. */
export const setPolicyEnabled = (id, isEnabled) =>
  api.post(`${BASE}/${encodeURIComponent(id)}/enable`, {
    is_enabled: isEnabled,
  });

/** 8. The lifecycle: draft → active → archived. */
export const setPolicyStatus = (id, status) =>
  api.post(`${BASE}/${encodeURIComponent(id)}/status`, { status });

/** 9. Supersede with a new version of the same family. */
export const createPolicyVersion = (id, body) =>
  api.post(`${BASE}/${encodeURIComponent(id)}/version`, body);

/**
 * 10. What depends on this policy.
 *
 * `scan_count` is read from the scans' own snapshots rather than a join,
 * because a scan keeps its configuration record after the policy is deleted.
 * That is why deleting a policy never falsifies a completed scan.
 */
export const getPolicyUsage = (id) =>
  api.get(`${BASE}/${encodeURIComponent(id)}/usage`);

/**
 * 11. Delete.
 *
 * Refused with 409 while a schedule references it, because the foreign key is
 * ON DELETE SET NULL and deleting anyway leaves that schedule running under
 * the request defaults — a silent broadening of what it assesses. `force`
 * is the deliberate way through and the response names what it orphaned.
 */
export const deletePolicy = (id, { force = false } = {}) =>
  api.delete(`${BASE}/${encodeURIComponent(id)}`, {
    params: force ? { force: true } : {},
  });

/** The scan's own immutable record — a different endpoint, and the point of it. */
export const getScanPolicySnapshot = (scanId) =>
  api.get(`/scans/${encodeURIComponent(scanId)}/policy`);

/**
 * Field-level messages from a 422, keyed by the field they belong to.
 *
 * FastAPI answers `{message, errors:[{loc:["body","scan_kind"], msg}]}`. Shown
 * whole at the top of a form, an operator has to work out which control is
 * wrong; keyed by field, the form can say it where they are looking.
 */
export function fieldErrors(error) {
  const rows = error?.response?.data?.errors;
  if (!Array.isArray(rows)) return {};
  const out = {};
  for (const row of rows) {
    const loc = Array.isArray(row?.loc) ? row.loc : [];
    // ["body", "scan_kind"] -> "scan_kind"
    const field = loc.length > 1 ? String(loc[loc.length - 1]) : "_";
    // Pydantic prefixes its own messages with "Value error, ".
    out[field] = String(row?.msg || "").replace(/^Value error,\s*/, "");
  }
  return out;
}

/** The backend's own wording for anything that is not field-level. */
export function policyErrorMessage(error, fallback) {
  const body = error?.response?.data;
  return body?.message || body?.detail || fallback;
}
