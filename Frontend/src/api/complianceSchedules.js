/**
 * Recurring compliance scans.
 *
 * Four operations that have existed since the first compliance migration, with
 * Celery beat polling `compliance_scan_schedules` every sixty seconds — and no
 * frontend reference to any of them. Phase 7 recorded it as the largest single
 * UI coverage gap in the product: live machinery with no way to drive it.
 *
 * This is **not** a second scheduler. The backend owns frequency, the next run
 * and the lifecycle; the UI states them and asks for changes through the same
 * contract. Nothing here computes a next run.
 *
 * RBAC, measured on the live grants:
 *
 *   compliance:read              viewer, analyst, org_admin, superadmin
 *   compliance:manage_schedules  analyst, org_admin, superadmin
 */

import api from "@shell/api/axiosInstance";

const BASE = "/compliance/schedules";

/** The frequencies the API's own pattern admits. Not a copy of a guess. */
export const SCHEDULE_FREQUENCIES = [
  "daily",
  "weekly",
  "monthly",
  "quarterly",
  "continuous",
];

/** When the schedule should notify. Same source. */
export const NOTIFY_ON = ["always", "on_failure_only", "on_score_drop"];

/** 1. List. Parked frameworks are excluded by the backend, not here. */
export const listComplianceSchedules = () => api.get(BASE);

/** 2. Create. `framework_id` and `policy_id` are both required by the API. */
export const createComplianceSchedule = (body) => api.post(BASE, body);

/** 3. Patch. Only `is_active`, `frequency`, `notify_on` and the channels. */
export const updateComplianceSchedule = (id, body) =>
  api.patch(`${BASE}/${encodeURIComponent(id)}`, body);

/** 4. Delete. */
export const deleteComplianceSchedule = (id) =>
  api.delete(`${BASE}/${encodeURIComponent(id)}`);

/**
 * What a schedule's lifecycle actually says.
 *
 * `is_active`, `last_run_at` and `next_run_at` are three separate facts and a
 * single "status" word loses two of them. An inactive schedule that has run
 * before is not the same as an active one that never has, and neither is
 * "scheduled".
 */
export function scheduleState(schedule) {
  if (!schedule) return { label: "unknown", tone: "neutral" };
  if (!schedule.is_active) {
    return {
      label: "Paused",
      tone: "neutral",
      detail: "This schedule will not run until it is resumed.",
    };
  }
  if (!schedule.next_run_at) {
    return {
      label: "Active — no next run recorded",
      tone: "warning",
      // Deliberately not "due now". The compliance scheduler treats a null
      // next run as due on the very next tick, which is a behaviour worth
      // showing rather than hiding behind the word "active".
      detail:
        "The backend records no next run for this schedule. Its scheduler treats that as due on the next tick.",
    };
  }
  return { label: "Active", tone: "success" };
}

/** The backend's own wording for a refusal. */
export function scheduleErrorMessage(error, fallback) {
  const body = error?.response?.data;
  const rows = body?.errors;
  if (Array.isArray(rows) && rows.length) {
    return rows
      .map((r) => String(r?.msg || "").replace(/^Value error,\s*/, ""))
      .filter(Boolean)
      .join(" ");
  }
  return body?.message || body?.detail || fallback;
}
