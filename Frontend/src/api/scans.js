/**
 * src/api/scans.js
 * Wrappers for scan history and recycle-bin APIs.
 */
import api, { authSession } from "./axiosInstance";

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

export const deleteReport = (id) =>
  api.delete(`/reports/${id}`);

/** GET /scan/quota — returns the org's current quota status */
export const getScanQuota = () =>
  api.get("/scan/quota");



const streamUrl = ({ scope = "active", skip = 0, limit = 200, interval = 2 } = {}) => {
  const baseURL = api.defaults.baseURL || "";
  const prefix = baseURL.endsWith("/") ? baseURL.slice(0, -1) : baseURL;
  const params = new URLSearchParams({
    scope,
    skip: String(skip),
    limit: String(limit),
    interval: String(interval),
  });
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
  signal,
  onEvent,
} = {}) => {
  const headers = { Accept: "text/event-stream" };
  const token = authSession.getAccessToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(streamUrl({ scope, skip, limit, interval }), {
    headers,
    credentials: "include",
    signal,
  });

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
