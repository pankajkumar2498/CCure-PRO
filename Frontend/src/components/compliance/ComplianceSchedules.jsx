/**
 * Recurring compliance scans — list, create, pause, resume, retime, delete.
 *
 * The backend has run these on beat every sixty seconds since the first
 * compliance migration and no screen could create one. This is the screen.
 *
 * Three things it deliberately does not do:
 *
 * * **It computes no schedule.** Frequency, the last run and the next run are
 *   the backend's; this states them and asks for changes. A second scheduler
 *   in the browser would drift from the one that actually fires.
 *
 * * **It does not collapse the lifecycle into one word.** `is_active`,
 *   `last_run_at` and `next_run_at` are three facts. A paused schedule that
 *   has run, and an active one that never has, are different situations and a
 *   single "status" column loses both.
 *
 * * **It does not invent a frequency or a notification mode.** Both
 *   vocabularies come from the API's own patterns.
 *
 * RBAC: listing needs `compliance:read`; every write needs
 * `compliance:manage_schedules`, which on the live grants is analyst and
 * above. Without it the controls are absent rather than disabled — a row of
 * dead buttons tells nobody what they are missing.
 */

import { useCallback, useEffect, useState } from "react";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureSelect,
  CcureTable,
} from "../../design-system";
import {
  NOTIFY_ON,
  SCHEDULE_FREQUENCIES,
  createComplianceSchedule,
  deleteComplianceSchedule,
  listComplianceSchedules,
  scheduleErrorMessage,
  scheduleState,
  updateComplianceSchedule,
} from "../../api/complianceSchedules";

const when = (iso) => {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
};

const Never = <span className="cwh-sch__muted">never</span>;

export default function ComplianceSchedules({
  canManage = false,
  frameworks = [],
  policies = [],
}) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(null);
  const [busy, setBusy] = useState(false);

  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    framework_id: "",
    policy_id: "",
    frequency: "weekly",
    notify_on: "always",
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await listComplianceSchedules();
      setRows(data?.data || []);
    } catch (err) {
      setError(
        scheduleErrorMessage(err, "Could not read the compliance schedules."),
      );
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (fn, ok) => {
    setBusy(true);
    setNotice(null);
    try {
      await fn();
      setNotice({ variant: "success", text: ok });
      await load();
      return true;
    } catch (err) {
      setNotice({
        variant: "danger",
        text: scheduleErrorMessage(err, "The API refused this change."),
      });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const columns = [
    {
      key: "framework",
      header: "Framework",
      isRowHeader: true,
      cell: (s) => (
        <>
          <span>{s.framework_id}</span>
          <span className="cwh-sch__muted"> · policy {s.policy_id}</span>
        </>
      ),
    },
    { key: "frequency", header: "Frequency", cell: (s) => s.frequency },
    {
      key: "state",
      header: "State",
      cell: (s) => {
        const st = scheduleState(s);
        return (
          <CcureBadge variant={st.tone} title={st.detail}>
            {st.label}
          </CcureBadge>
        );
      },
    },
    {
      key: "last_run_at",
      header: "Last run",
      // A schedule that has never run says so. An empty cell would read as a
      // missing value rather than as an event that has not happened.
      cell: (s) => when(s.last_run_at) ?? Never,
    },
    {
      key: "next_run_at",
      header: "Next run",
      cell: (s) => when(s.next_run_at) ?? Never,
    },
    { key: "notify_on", header: "Notify", cell: (s) => s.notify_on },
    ...(canManage
      ? [
          {
            key: "actions",
            header: "Actions",
            cell: (s) => (
              <span className="cwh-sch__actions">
                <CcureButton
                  size="sm"
                  variant="secondary"
                  disabled={busy}
                  onClick={() =>
                    run(
                      () =>
                        updateComplianceSchedule(s.id, {
                          is_active: !s.is_active,
                        }),
                      s.is_active ? "Schedule paused." : "Schedule resumed.",
                    )
                  }
                >
                  {s.is_active ? "Pause" : "Resume"}
                </CcureButton>
                <CcureSelect
                  label="Frequency"
                  aria-label={`Frequency for ${s.framework_id}`}
                  value={s.frequency}
                  disabled={busy}
                  onChange={(e) =>
                    run(
                      () =>
                        updateComplianceSchedule(s.id, {
                          frequency: e.target.value,
                        }),
                      "Frequency updated.",
                    )
                  }
                >
                  {SCHEDULE_FREQUENCIES.map((f) => (
                    <option key={f} value={f}>
                      {f}
                    </option>
                  ))}
                </CcureSelect>
                <CcureButton
                  size="sm"
                  variant="ghost"
                  disabled={busy}
                  onClick={() =>
                    run(
                      () => deleteComplianceSchedule(s.id),
                      "Schedule deleted.",
                    )
                  }
                >
                  Delete
                </CcureButton>
              </span>
            ),
          },
        ]
      : []),
  ];

  return (
    <div className="cwh-sch">
      <p className="cwh-sch__lede">
        Recurring compliance scans. The scheduler runs on the server every sixty
        seconds; the times below are its own, not this page&apos;s.
      </p>

      {notice ? (
        <CcureAlert variant={notice.variant} onClose={() => setNotice(null)}>
          {notice.text}
        </CcureAlert>
      ) : null}
      {error ? <CcureAlert variant="danger">{error}</CcureAlert> : null}

      {canManage ? (
        <div className="cwh-sch__new">
          {!creating ? (
            <CcureButton variant="primary" onClick={() => setCreating(true)}>
              New schedule
            </CcureButton>
          ) : (
            <form
              className="cwh-sch__form"
              onSubmit={async (e) => {
                e.preventDefault();
                const ok = await run(
                  () => createComplianceSchedule(form),
                  "Schedule created.",
                );
                if (ok) setCreating(false);
              }}
            >
              <CcureSelect
                label="Framework"
                required
                value={form.framework_id}
                onChange={(e) =>
                  setForm((f) => ({ ...f, framework_id: e.target.value }))
                }
              >
                <option value="">Choose…</option>
                {frameworks.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name || f.id}
                  </option>
                ))}
              </CcureSelect>
              <CcureSelect
                label="Policy"
                required
                value={form.policy_id}
                onChange={(e) =>
                  setForm((f) => ({ ...f, policy_id: e.target.value }))
                }
              >
                <option value="">Choose…</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name || p.id}
                  </option>
                ))}
              </CcureSelect>
              <CcureSelect
                label="Frequency"
                value={form.frequency}
                onChange={(e) =>
                  setForm((f) => ({ ...f, frequency: e.target.value }))
                }
              >
                {SCHEDULE_FREQUENCIES.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </CcureSelect>
              <CcureSelect
                label="Notify"
                value={form.notify_on}
                onChange={(e) =>
                  setForm((f) => ({ ...f, notify_on: e.target.value }))
                }
              >
                {NOTIFY_ON.map((n) => (
                  <option key={n} value={n}>
                    {n.replace(/_/g, " ")}
                  </option>
                ))}
              </CcureSelect>
              <CcureInput
                label="First run (optional)"
                type="datetime-local"
                value={form.first_run_at || ""}
                onChange={(e) =>
                  setForm((f) => ({ ...f, first_run_at: e.target.value }))
                }
                hint="Leave empty to let the scheduler place the first run."
              />
              <div className="cwh-sch__formactions">
                <CcureButton type="submit" variant="primary" disabled={busy}>
                  Create
                </CcureButton>
                <CcureButton
                  type="button"
                  variant="ghost"
                  onClick={() => setCreating(false)}
                >
                  Cancel
                </CcureButton>
              </div>
            </form>
          )}
        </div>
      ) : (
        <CcureAlert variant="info">
          Creating and changing schedules needs the
          <strong> compliance:manage_schedules</strong> permission.
        </CcureAlert>
      )}

      <CcureTable
        caption="Compliance scan schedules"
        columns={columns}
        rows={rows}
        rowKey={(s) => s.id}
        loading={loading}
        emptyMessage="No recurring compliance scan is configured."
        density="compact"
      />
    </div>
  );
}
