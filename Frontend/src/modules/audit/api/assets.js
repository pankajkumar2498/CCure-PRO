/**
 * src/modules/audit/api/assets.js
 * Wrappers for the Asset Registry REST API.
 */
import api from "@shell/api/axiosInstance";

export const getAssets = ({
  search,
  risk_level,
  os_family,
  verification_status,
  is_managed,
  is_active,
  subnet,
  sort_by = "risk_score",
  sort_dir = "desc",
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/assets", {
    params: {
      ...(search ? { search } : {}),
      ...(risk_level ? { risk_level } : {}),
      ...(os_family ? { os_family } : {}),
      ...(verification_status ? { verification_status } : {}),
      ...(is_managed !== undefined ? { is_managed } : {}),
      ...(is_active !== undefined ? { is_active } : {}),
      ...(subnet ? { subnet } : {}),
      sort_by,
      sort_dir,
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const getGlobalServices = ({
  search,
  port,
  protocol,
  asset_type,
  subnet,
  sort_by = "asset_count",
  sort_dir = "desc",
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/assets/services", {
    params: {
      ...(search ? { search } : {}),
      ...(port ? { port } : {}),
      ...(protocol ? { protocol } : {}),
      ...(asset_type ? { asset_type } : {}),
      ...(subnet ? { subnet } : {}),
      sort_by,
      sort_dir,
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const getServiceAssets = ({
  service_name,
  port,
  protocol,
  search,
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/assets/services/assets", {
    params: {
      service_name,
      port,
      protocol,
      ...(search ? { search } : {}),
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const getGlobalCertificates = ({
  search,
  sort_by = "expiration",
  sort_dir = "asc",
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/assets/certificates", {
    params: {
      ...(search ? { search } : {}),
      sort_by,
      sort_dir,
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const getAsset = (id, orgId) =>
  api.get(`/assets/${id}`, { params: orgId ? { org_id: orgId } : {} });

export const getAssetServices = (id, orgId) =>
  api.get(`/assets/${id}/services`, { params: orgId ? { org_id: orgId } : {} });

export const getAssetFindings = (id, status, orgId) =>
  api.get(`/assets/${id}/findings`, {
    params: {
      ...(status ? { status } : {}),
      ...(orgId ? { org_id: orgId } : {}),
    },
  });

export const getAssetChangelog = (id, orgId) =>
  api.get(`/assets/${id}/changelog`, {
    params: orgId ? { org_id: orgId } : {},
  });

export const updateAsset = (id, body) => api.patch(`/assets/${id}`, body);

export const addAssetTag = (id, tag) => api.post(`/assets/${id}/tags`, { tag });
export const removeAssetTag = (id, tag) =>
  api.delete(`/assets/${id}/tags/${encodeURIComponent(tag)}`);
export const addAssetNote = (id, content) =>
  api.post(`/assets/${id}/notes`, { content });

export const importAmtInventory = (formData, orgId) =>
  api.post("/assets/import-amt", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    params: orgId ? { org_id: orgId } : {},
  });

export const getCoverageStats = (orgId) =>
  api.get("/assets/coverage-stats", { params: orgId ? { org_id: orgId } : {} });

export const getReconciliationDrilldown = ({
  category,
  search,
  owner,
  department,
  location,
  skip = 0,
  limit = 50,
  org_id,
} = {}) =>
  api.get("/assets/reconciliation/drilldown", {
    params: {
      category,
      ...(search ? { search } : {}),
      ...(owner ? { owner } : {}),
      ...(department ? { department } : {}),
      ...(location ? { location } : {}),
      skip,
      limit,
      ...(org_id ? { org_id } : {}),
    },
  });

export const exportReconciliationCsv = ({
  category,
  search,
  owner,
  department,
  location,
  org_id,
} = {}) =>
  api.get("/assets/reconciliation/drilldown", {
    params: {
      category,
      ...(search ? { search } : {}),
      ...(owner ? { owner } : {}),
      ...(department ? { department } : {}),
      ...(location ? { location } : {}),
      export: true,
      ...(org_id ? { org_id } : {}),
    },
    responseType: "blob",
  });
