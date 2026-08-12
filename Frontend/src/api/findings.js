/**
 * src/api/findings.js
 * Wrappers for the Findings / Vulnerability Browser REST API.
 */
import api from "./axiosInstance";

export const getFindings = ({
  severity,
  status,
  priority,
  in_kev,
  search,
  asset_id,
  scan_id,
  sort_by = "priority",
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/findings", {
    params: {
      ...(severity ? { severity } : {}),
      ...(status ? { status } : {}),
      ...(priority ? { priority } : {}),
      ...(in_kev !== undefined ? { in_kev } : {}),
      ...(search ? { search } : {}),
      ...(asset_id ? { asset_id } : {}),
      ...(scan_id ? { scan_id } : {}),
      sort_by,
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

/**
 * Findings rolled up to the component that would actually be remediated.
 *
 * One outdated application produces one finding per CVE published against it —
 * a single Chrome install twelve major versions behind returns 1,736 rows. An
 * operator upgrades Chrome once, so this returns that as one row carrying the
 * CVE count, the worst CVSS and whether any are known-exploited.
 */
export const getFindingsGrouped = ({
  severity,
  status,
  asset_id,
  scan_id,
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/findings/grouped/by-component", {
    params: {
      ...(severity ? { severity } : {}),
      ...(status ? { status } : {}),
      ...(asset_id ? { asset_id } : {}),
      ...(scan_id ? { scan_id } : {}),
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const getFinding = (id, orgId) =>
  api.get(`/findings/${id}`, { params: orgId ? { org_id: orgId } : {} });

export const updateFindingStatus = (id, status, reason, notes) =>
  api.patch(`/findings/${id}/status`, {
    status,
    accepted_risk_reason: reason,
    remediation_notes: notes,
  });

export const updateFindingNotes = (id, remediation_notes) =>
  api.patch(`/findings/${id}/notes`, { remediation_notes });
