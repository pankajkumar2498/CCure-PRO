/**
 * This organisation's remediation deadlines.
 *
 * Reading them takes `findings:read`; setting them takes `Manage remediation SLA policy`,
 * which on the live grants is org_admin and superadmin only. That split is the
 * backend's and it is deliberate — an analyst works the queue, an
 * administrator decides what "late" means — so the form is read-only rather
 * than absent for everyone who can see the queue.
 *
 * Three things the form has to say out loud, because each is a number that
 * does not mean what it looks like:
 *
 * * **Zero days is no deadline, not "due immediately".** `due_at_for` returns
 *   None when the configured number of days is zero, and `sla_state` then
 *   answers `not_applicable`. That is why `none` and `unscored` ship at zero:
 *   an unrated finding carries no obligation. A reader who assumes zero means
 *   "today" has it exactly backwards.
 *
 * * **A partial update merges.** Sending only `critical` leaves the other five
 *   alone; the backend merges over the stored map. So the form submits only
 *   what changed and says so.
 *
 * * **Existing findings keep their recorded due dates.** The change applies
 *   from the next scan that syncs them, and the API returns that sentence in
 *   its own `note` — which is rendered verbatim rather than paraphrased,
 *   because rewriting thousands of historical deadlines from a settings edit
 *   would alter what a past report said was overdue.
 */

import { useCallback, useEffect, useState } from "react";
import {
  CcureLoader,
  CcureAlert,
  CcureButton,
  CcureInput,
  CcureCheckbox,
} from "../../../../design-system";
import {
  getSlaPolicy,
  remediationErrorMessage,
  setSlaPolicy,
} from "@audit/api/remediation";

const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "unscored",
];

/** The severities come from the API's own `defaults`, never from a copy here. */
const severityKeys = (policy) => {
  const keys = Object.keys(policy?.defaults || policy?.days_by_severity || {});
  const known = SEVERITY_ORDER.filter((k) => keys.includes(k));
  const extra = keys.filter((k) => !SEVERITY_ORDER.includes(k)).sort();
  return [...known, ...extra];
};

export default function SlaPolicyPanel({ canEdit = false }) {
  const [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState({});
  const [dueSoon, setWindowDays] = useState("");
  const [kev, setKev] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await getSlaPolicy();
      setPolicy(data);
      setDraft({ ...(data.days_by_severity || {}) });
      setWindowDays(String(data.due_soon_window_days ?? ""));
      setKev(Boolean(data.honour_kev_due_date));
    } catch (err) {
      setError(remediationErrorMessage(err, "Could not read the SLA policy."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <CcureLoader label="Reading the SLA policy…" />;
  if (error) return <CcureAlert variant="danger">{error}</CcureAlert>;
  if (!policy) return null;

  const keys = severityKeys(policy);
  const current = policy.days_by_severity || {};
  const defaults = policy.defaults || {};

  const changedDays = {};
  for (const k of keys) {
    const raw = draft[k];
    const n = Number(raw);
    if (raw !== "" && Number.isInteger(n) && n !== current[k])
      changedDays[k] = n;
  }
  const windowChanged =
    dueSoon !== "" && Number(dueSoon) !== policy.due_soon_window_days;
  const kevChanged = kev !== Boolean(policy.honour_kev_due_date);
  const dirty =
    Object.keys(changedDays).length > 0 || windowChanged || kevChanged;

  const save = async () => {
    setBusy(true);
    setNotice(null);
    try {
      // Only what changed. The backend merges, so sending the whole map would
      // work — but it would also overwrite a value somebody else had just set.
      const body = {};
      if (Object.keys(changedDays).length) body.days_by_severity = changedDays;
      if (windowChanged) body.due_soon_window_days = Number(dueSoon);
      if (kevChanged) body.honour_kev_due_date = kev;

      const { data } = await setSlaPolicy(body);
      setPolicy(data);
      setDraft({ ...(data.days_by_severity || {}) });
      setWindowDays(String(data.due_soon_window_days ?? ""));
      setKev(Boolean(data.honour_kev_due_date));
      setNotice({
        variant: "success",
        text: data.note || "SLA policy updated.",
      });
    } catch (err) {
      setNotice({
        variant: "danger",
        text: remediationErrorMessage(err, "The API refused this policy."),
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rm-sla">
      {notice ? (
        <CcureAlert variant={notice.variant} onClose={() => setNotice(null)}>
          {notice.text}
        </CcureAlert>
      ) : null}

      {!canEdit ? (
        <CcureAlert variant="info">
          These deadlines are shown read-only. Changing them needs the
          <strong> Manage remediation SLA policy</strong> permission.
        </CcureAlert>
      ) : null}

      <p className="rm-note">
        Deadlines are in <strong>{policy.unit || "calendar days"}</strong>,
        counted from when a finding was first found. Rediscovery does not
        restart the clock. <strong>Zero means no deadline applies</strong> — not
        that the finding is due immediately.
      </p>

      <div className="rm-sla__grid">
        {keys.map((k) => (
          <CcureInput
            key={k}
            label={k.charAt(0).toUpperCase() + k.slice(1)}
            type="number"
            min={0}
            value={draft[k] ?? ""}
            onChange={(e) => setDraft((d) => ({ ...d, [k]: e.target.value }))}
            disabled={!canEdit || busy}
            hint={`Default ${defaults[k]}`}
          />
        ))}
      </div>

      <div className="rm-sla__grid">
        <CcureInput
          label="Due soon window"
          type="number"
          min={0}
          max={365}
          value={dueSoon}
          onChange={(e) => setWindowDays(e.target.value)}
          disabled={!canEdit || busy}
          hint="How long before the due date a finding starts reporting due soon."
        />
        <CcureCheckbox
          className="rm-check"
          checked={kev}
          disabled={!canEdit || busy}
          onChange={(e) => setKev(e.target.checked)}
        >
          <span>
            Honour CISA KEV due dates
            <small className="rm-muted">
              {" "}
              — a KEV date is used where it is <em>earlier</em> than the
              internal one, never where it is later. An organisation cannot
              extend a federal deadline by writing a setting.
            </small>
          </span>
        </CcureCheckbox>
      </div>

      {canEdit ? (
        <div className="rm-actionrow">
          <CcureButton
            variant="primary"
            disabled={!dirty || busy}
            onClick={save}
          >
            Save deadlines
          </CcureButton>
          <CcureButton
            variant="ghost"
            disabled={!dirty || busy}
            onClick={() => {
              setDraft({ ...current });
              setWindowDays(String(policy.due_soon_window_days ?? ""));
              setKev(Boolean(policy.honour_kev_due_date));
            }}
          >
            Discard changes
          </CcureButton>
        </div>
      ) : null}
    </div>
  );
}
