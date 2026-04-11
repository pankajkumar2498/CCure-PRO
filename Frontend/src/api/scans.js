/**
 * src/api/scans.js
 * Wrappers for scan history and recycle-bin APIs.
 */
import api from "./axiosInstance";

export const getScans   = (skip = 0, limit = 50, scope = "active") =>
  api.get("/scans", { params: { skip, limit, scope } });

export const getScan    = (id) =>
  api.get(`/scans/${id}`);

export const deleteScan = (id) =>
  api.delete(`/scans/${id}`);

export const archiveScan = (id) =>
  api.post(`/scans/${id}/archive`);

export const restoreScan = (id) =>
  api.post(`/scans/${id}/restore`);

export const purgeScan  = (id) =>
  api.delete(`/scans/${id}/purge`);
