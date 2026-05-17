/**
 * src/api/assets.js
 * Wrappers for the Asset Registry REST API.
 */
import api from "./axiosInstance";

export const getAssets = ({
  search, risk_level, os_family, is_managed, is_active,
  subnet, sort_by = "risk_score", sort_dir = "desc",
  skip = 0, limit = 50, org_id,
} = {}) =>
  api.get("/assets", {
    params: {
      ...(search      ? { search }      : {}),
      ...(risk_level  ? { risk_level }  : {}),
      ...(os_family   ? { os_family }   : {}),
      ...(is_managed  !== undefined ? { is_managed } : {}),
      ...(is_active   !== undefined ? { is_active }  : {}),
      ...(subnet      ? { subnet }      : {}),
      sort_by, sort_dir, skip, limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const getAsset = (id, orgId) =>
  api.get(`/assets/${id}`, { params: orgId ? { org_id: orgId } : {} });

export const getAssetServices  = (id, orgId) =>
  api.get(`/assets/${id}/services`,  { params: orgId ? { org_id: orgId } : {} });

export const getAssetFindings  = (id, status, orgId) =>
  api.get(`/assets/${id}/findings`,  { params: { ...(status ? { status } : {}), ...(orgId ? { org_id: orgId } : {}) } });

export const getAssetChangelog = (id, orgId) =>
  api.get(`/assets/${id}/changelog`, { params: orgId ? { org_id: orgId } : {} });

export const updateAsset = (id, body) =>
  api.patch(`/assets/${id}`, body);

export const addAssetTag    = (id, tag)      => api.post(`/assets/${id}/tags`, { tag });
export const removeAssetTag = (id, tag)      => api.delete(`/assets/${id}/tags/${encodeURIComponent(tag)}`);
export const addAssetNote   = (id, content)  => api.post(`/assets/${id}/notes`, { content });
