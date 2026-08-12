/**
 * src/api/scans.js
 * Wrappers for scan history and recycle-bin APIs.
 */
import api, { authSession } from "./axiosInstance";

/**
 * GET /scans
 *
 * `search` and `status` are applied server-side. Filtering in the browser only
 * ever saw the rows already fetched, so a search past the first page silently
 * missed matches.
 */
export const getScans = (
  skip = 0,
  limit = 50,
  scope = "active",
  created_by,
  { search, status, pipeline_mode, sort_by, sort_dir } = {},
) => {
  const params = { skip, limit, scope };
  if (created_by) params.created_by = created_by;
  if (search) params.search = search;
  if (status && status !== "all") params.status = status;
  if (pipeline_mode && pipeline_mode !== "all")
    params.pipeline_mode = pipeline_mode;
  if (sort_by) {
    params.sort_by = sort_by;
    params.sort_dir = sort_dir || "desc";
  }
  return api.get("/scans", { params });
};

export const getScan = (id) => api.get(`/scans/${id}`);

export const deleteScan = (id) => api.delete(`/scans/${id}`);

export const archiveScan = (id) => api.post(`/scans/${id}/archive`);

export const stopScan = (id) => api.post(`/scans/${id}/stop`);

export const restoreScan = (id) => api.post(`/scans/${id}/restore`);

export const purgeScan = (id) => api.delete(`/scans/${id}/purge`);

export const deleteReport = (id) => api.delete(`/reports/${id}`);

/** GET /scan/quota — returns the org's current quota status */
export const getScanQuota = () => api.get("/scan/quota");

const streamUrl = ({
  scope = "active",
  skip = 0,
  limit = 200,
  interval = 2,
  created_by,
  search,
  status,
} = {}) => {
  const baseURL = api.defaults.baseURL || "";
  const prefix = baseURL.endsWith("/") ? baseURL.slice(0, -1) : baseURL;
  const params = new URLSearchParams({
    scope,
    skip: String(skip),
    limit: String(limit),
    interval: String(interval),
  });
  if (created_by) params.set("created_by", created_by);
  // The live stream must apply the same filters as the list request, or each
  // snapshot replaces the filtered view with an unfiltered one.
  if (search) params.set("search", search);
  if (status && status !== "all") params.set("status", status);

  const activeOrgId = localStorage.getItem("activeOrgId");
  if (activeOrgId) params.set("org_id", activeOrgId);

  return `${prefix}/scans/events?${params.toString()}`;
};

const parseSseMessage = (message) => {
  let event = "message";
  const data = [];

  message.split(/\r?\n/).forEach((line) => {
    if (line.startsWith("event:")) {
      event = line.slice(6).trim() || "message";
      return;
    }
    if (line.startsWith("data:")) {
      data.push(line.slice(5).trimStart());
    }
  });

  return {
    event,
    data: data.length ? JSON.parse(data.join("\n")) : null,
  };
};

export const streamScanEvents = async ({
  scope = "active",
  skip = 0,
  limit = 200,
  interval = 2,
  created_by,
  search,
  status,
  signal,
  onEvent,
} = {}) => {
  const headers = { Accept: "text/event-stream" };
  const token = authSession.getAccessToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(
    streamUrl({ scope, skip, limit, interval, created_by, search, status }),
    {
      headers,
      credentials: "include",
      signal,
    },
  );

  if (!response.ok || !response.body) {
    throw new Error(`Scan history stream failed (${response.status})`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (!signal?.aborted) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const messages = buffer.split(/\r?\n\r?\n/);
    buffer = messages.pop() || "";

    messages
      .filter(Boolean)
      .map(parseSseMessage)
      .forEach((payload) => onEvent?.(payload));
  }
};
