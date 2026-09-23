/**
 * Remediation and SLA — who owns a finding, when it is due, and whether it
 * was really fixed. Twelve operations across three RBAC atoms.
 *
 *   findings:read        summary, overdue, pending-verification, one finding,
 *                        its history, and the SLA policy
 *   findings:update      assign, state change, note
 *   findings:accept_risk accept a risk, withdraw an acceptance
 *   settings:update      set the SLA policy
 *
 * Four properties of the contract the UI must not restate in its own words:
 *
 * * **No human action can reach `verified_fixed`, and none can reach
 *   `reopened`.** The backend's human transition table has no edge into
 *   either; only `core/remediation/verification.py` — driven by a scan
 *   comparison — may write them. So those two are absent from what this
 *   module offers, with the reason attached rather than implied. Asking for
 *   `verified_fixed` answers 400 saying a scan has to establish it, and the
 *   claim a person is actually in a position to make is
 *   `pending_verification`.
 *
 * * **`risk_accepted` is refused on the state path too**, for a different
 *   reason: it needs a reason and an approver, so it has its own endpoint and
 *   its own permission.
 *
 * * **The exception fields outlive the exception.** Withdrawing an acceptance
 *   clears `expires_at` and moves the state, but leaves `reason`,
 *   `accepted_by` and `accepted_at` in place — measured against the live API.
 *   So the only sound test for "this risk is accepted" is
 *   `remediation.state === "risk_accepted"`, which is what `isRiskAccepted`
 *   is for. Reading a non-null `reason` as an acceptance labels an open
 *   finding as one the organisation decided to carry.
 *
 * * **`no_sla` is not `within_sla`.** "Comfortably inside its deadline" and
 *   "has no deadline" are different facts and the backend counts them
 *   separately; folding them inflates every figure built on this.
 */

import api from "./axiosInstance";

const BASE = "/remediation";

/* ── Vocabulary ─────────────────────────────────────────────────────────── */

/** Every value `remediation_state` admits, in the backend's own order. */
export const REMEDIATION_STATES = [
  "open",
  "assigned",
  "in_remediation",
  "pending_verification",
  "verified_fixed",
  "reopened",
  "risk_accepted",
];

/**
 * The states a person may ask for through `PATCH .../state`, and why the
 * other three are missing. Offering a target the backend structurally refuses
 * is a control that can only ever produce an error.
 */
export const HUMAN_UNREACHABLE_STATES = {
  verified_fixed:
    "A scan establishes this, not a person. Claim pending verification instead.",
  reopened:
    "A scan reopens a finding by detecting it again; there is no manual edge into this state.",
  risk_accepted:
    "Accepting a risk needs a reason and an approver, so it has its own action and its own permission.",
};

export const REQUESTABLE_STATES = REMEDIATION_STATES.filter(
  (state) => !(state in HUMAN_UNREACHABLE_STATES),
);

export const STATE_LABELS = {
  open: "Open",
  assigned: "Assigned",
  in_remediation: "In remediation",
  pending_verification: "Pending verification",
  verified_fixed: "Verified fixed",
  reopened: "Reopened",
  risk_accepted: "Risk accepted",
};

export const STATE_TONE = {
  open: "neutral",
  assigned: "info",
  in_remediation: "info",
  pending_verification: "warning",
  verified_fixed: "success",
  reopened: "danger",
  risk_accepted: "warning",
};

/** The six SLA positions. `not_applicable` is a state, never a blank. */
export const SLA_LABELS = {
  within_sla: "Within SLA",
  due_soon: "Due soon",
  overdue: "Overdue",
  resolved: "Resolved",
  pending_verification: "Awaiting verification",
  not_applicable: "No deadline",
};

export const SLA_TONE = {
  within_sla: "success",
  due_soon: "warning",
  overdue: "danger",
  resolved: "neutral",
  pending_verification: "info",
  not_applicable: "neutral",
};

/** What the event trail can record. Shown verbatim where the API gives one. */
export const EVENT_LABELS = {
  assigned: "Assigned",
  unassigned: "Unassigned",
  state_changed: "State changed",
  note_added: "Note added",
  risk_accepted: "Risk accepted",
  exception_expired: "Exception expired",
  verified: "Verified by a scan",
  reopened: "Reopened by a scan",
  sla_set: "SLA set",
  sla_changed: "SLA changed",
};

/* ── Reading ────────────────────────────────────────────────────────────── */

/** 1. Counts by state and SLA position, plus the executive line. */
export const getRemediationSummary = (params = {}) =>
  api.get(`${BASE}/summary`, { params });

/** 2. Past their due date, soonest first. `total` is never truncated. */
export const listOverdue = (params = {}) =>
  api.get(`${BASE}/overdue`, { params });

/** 3. Fix claimed, waiting for a scan to agree. */
export const listPendingVerification = (params = {}) =>
  api.get(`${BASE}/pending-verification`, { params });

/** 4. One finding's remediation view. */
export const getFindingRemediation = (findingId, params = {}) =>
  api.get(`${BASE}/findings/${encodeURIComponent(findingId)}`, { params });

/** 5. The append-only event trail, oldest first. */
export const getFindingHistory = (findingId, params = {}) =>
  api.get(`${BASE}/findings/${encodeURIComponent(findingId)}/history`, {
    params,
  });

/** 6. This organisation's deadlines, with the build's defaults beside them. */
export const getSlaPolicy = (params = {}) =>
  api.get(`${BASE}/sla-policy`, { params });

/* ── Writing ────────────────────────────────────────────────────────────── */

/**
 * 7. Set the deadlines. `settings:update`, which is a narrower grant than the
 * `findings:update` the rest of the writes take — an analyst works the queue,
 * an org admin decides what "late" means.
 *
 * A partial update merges: sending only `critical` leaves the other five
 * alone. Existing findings keep their recorded due dates and the response
 * says so in its own `note`.
 */
export const setSlaPolicy = (body, params = {}) =>
  api.put(`${BASE}/sla-policy`, body, { params });

/**
 * 8. Assign, reassign or unassign, in bulk. `owner_id: null` unassigns.
 * The owner must be a user in the same organisation or the API answers 400.
 */
export const assignFindings = (body, params = {}) =>
  api.post(`${BASE}/assign`, body, { params });

/** 9. Move through the workflow. See `HUMAN_UNREACHABLE_STATES`. */
export const setRemediationState = (findingId, body, params = {}) =>
  api.patch(`${BASE}/findings/${encodeURIComponent(findingId)}/state`, body, {
    params,
  });

/** 10. Append a note. The finding keeps the latest; the trail keeps them all. */
export const addRemediationNote = (findingId, body, params = {}) =>
  api.post(`${BASE}/findings/${encodeURIComponent(findingId)}/notes`, body, {
    params,
  });

/** 11. Record a decision to carry the risk. Reason required, expiry optional. */
export const acceptFindingRisk = (findingId, body, params = {}) =>
  api.post(
    `${BASE}/findings/${encodeURIComponent(findingId)}/accept-risk`,
    body,
    { params },
  );

/** 12. Return an accepted finding to the queue. */
export const withdrawFindingAcceptance = (findingId, body = {}, params = {}) =>
  api.post(
    `${BASE}/findings/${encodeURIComponent(findingId)}/withdraw-acceptance`,
    body,
    { params },
  );

/* ── Reading the payload without over-claiming ──────────────────────────── */

/**
 * The only sound test for an accepted risk.
 *
 * `exception.reason`, `accepted_by` and `accepted_at` survive a withdrawal —
 * confirmed against the live API, where a withdrawn finding came back `open`
 * still carrying all three. They are the record of a decision that was taken,
 * not evidence that it still stands.
 */
export const isRiskAccepted = (finding) =>
  finding?.remediation?.state === "risk_accepted";

/**
 * True when the finding carries the residue of an acceptance that is no
 * longer in force — worth showing, and worth labelling as history.
 */
export const hadRiskAccepted = (finding) =>
  Boolean(finding?.exception?.accepted_at) && !isRiskAccepted(finding);

/**
 * How the due date reads in words. `days_remaining` is negative once the date
 * has passed, and the backend states the unit rather than leaving a reader to
 * assume business days.
 */
export function dueDescription(sla) {
  if (!sla) return "—";
  const days = sla.days_remaining;
  const unit = sla.unit || "calendar days";
  if (sla.state === "not_applicable" || sla.due_at == null) {
    return "No deadline applies";
  }
  if (!Number.isFinite(days)) return "—";
  if (days < 0) {
    const n = Math.abs(days);
    return `${n} ${unit} overdue`;
  }
  if (days === 0) return "Due today";
  return `${days} ${unit} remaining`;
}

/** The backend's own wording for anything that is not field-level. */
export function remediationErrorMessage(error, fallback) {
  const body = error?.response?.data;
  const rows = body?.errors;
  if (Array.isArray(rows) && rows.length) {
    return rows
      .map((row) => String(row?.msg || "").replace(/^Value error,\s*/, ""))
      .filter(Boolean)
      .join(" ");
  }
  return body?.message || body?.detail || fallback;
}
