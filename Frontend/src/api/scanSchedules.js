import axiosInstance from "./axiosInstance";

// Scheduled and recurring scans.
//
// Scheduling does not run scans: a due schedule dispatches the same Celery task
// the manual scan routes dispatch, so a scheduled run appears in Scan History,
// reports and the dashboard exactly like a manual one.
//
// A schedule never carries a secret. Credentialed schedules reference a stored
// credential by `credentialId`; the worker resolves and decrypts it. There is
// deliberately no password field anywhere in this module.

// The credentials this org can attach, gated on scan_schedules:read rather
// than compliance:read — picking a credential for a scan is a scanning task,
// and requiring a compliance permission for it would lock out an analyst who
// has no compliance role. Identifying fields only; no material is returned.
export const listScheduleCredentials = async () => {
  const response = await axiosInstance.get("/scan-schedules/credentials");
  return response.data.credentials || [];
};

export const listScanSchedules = async ({ scanKind, enabled } = {}) => {
  const params = {};
  if (scanKind) params.scan_kind = scanKind;
  if (enabled !== undefined && enabled !== null) params.enabled = enabled;
  const response = await axiosInstance.get("/scan-schedules", { params });
  return response.data;
};

export const getScanSchedule = async (id) => {
  const response = await axiosInstance.get(`/scan-schedules/${id}`);
  return response.data;
};

// The zones the *server* can resolve, rather than a list hardcoded here. A
// hardcoded list can name a zone the scheduler would then quietly fall back to
// UTC on, which is an hour or more of silent drift nobody can see.
export const listTimezones = async () => {
  const response = await axiosInstance.get("/scan-schedules/timezones");
  return response.data.timezones || [];
};

const toPayload = (form) => ({
  name: form.name,
  description: form.description || null,
  scan_kind: form.scanKind,
  targets: (form.targets || "")
    .split(/[\n,]/)
    .map((t) => t.trim())
    .filter(Boolean),
  scan_options: form.scanOptions || {},
  credential_id: form.credentialId || null,
  recurrence: form.recurrence,
  timezone: form.timezone,
  run_at: form.runAt,
  // Sent only where the recurrence uses them. The server refuses a cron
  // expression outside the custom recurrence, and refuses weekly/monthly
  // without their day — matching CHECK constraints in the database, so the
  // three layers cannot disagree about which fields are meaningful.
  day_of_week: form.recurrence === "weekly" ? Number(form.dayOfWeek) : null,
  day_of_month: form.recurrence === "monthly" ? Number(form.dayOfMonth) : null,
  cron_expression: form.recurrence === "custom" ? form.cronExpression : null,
  starts_at: form.startsAt ? new Date(form.startsAt).toISOString() : null,
  is_enabled: form.isEnabled !== false,
});

export const createScanSchedule = async (form) => {
  const response = await axiosInstance.post("/scan-schedules", toPayload(form));
  return response.data;
};

export const updateScanSchedule = async (id, form) => {
  const payload = toPayload(form);
  // scan_kind is create-only: changing it would change which task the schedule
  // dispatches and which options mean anything.
  delete payload.scan_kind;
  delete payload.is_enabled;
  const response = await axiosInstance.patch(`/scan-schedules/${id}`, payload);
  return response.data;
};

export const setScanScheduleEnabled = async (id, isEnabled) => {
  const response = await axiosInstance.post(`/scan-schedules/${id}/enable`, {
    is_enabled: isEnabled,
  });
  return response.data;
};

// Dispatches immediately and deliberately does not move the next scheduled
// run — testing a schedule at 11:00 must not cancel that night's real run.
export const runScanScheduleNow = async (id) => {
  const response = await axiosInstance.post(`/scan-schedules/${id}/run-now`);
  return response.data;
};

export const listScanScheduleRuns = async (id, limit = 50) => {
  const response = await axiosInstance.get(`/scan-schedules/${id}/runs`, {
    params: { limit },
  });
  return response.data;
};

export const deleteScanSchedule = async (id) => {
  const response = await axiosInstance.delete(`/scan-schedules/${id}`);
  return response.data;
};
