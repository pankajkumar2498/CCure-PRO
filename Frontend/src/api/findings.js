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
