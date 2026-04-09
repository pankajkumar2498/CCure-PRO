/**
 * src/api/scans.js
 * Wrappers for GET /scans, GET /scans/{id}, DELETE /scans/{id}
 */
import api from "./axiosInstance";

export const getScans      = (skip = 0, limit = 50) =>
  api.get("/scans", { params: { skip, limit } });

export const getScan       = (id) =>
  api.get(`/scans/${id}`);

export const deleteScan    = (id) =>
  api.delete(`/scans/${id}`);
