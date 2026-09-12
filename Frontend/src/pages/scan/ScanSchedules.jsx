/**
 * pages/scan/ScanSchedules.jsx
 * ───────────────────────────────────────────────────────────────────────────
 * Scheduled and recurring scans — create, edit, enable, run, delete, and see
 * what happened.
 *
 * Scheduling does not add a scan engine. A due schedule dispatches the same
 * task a manual scan does, so a scheduled run appears in Scan History, in
 * reports and on the dashboard exactly like one somebody started by hand.
 *
 * Two things this page is careful about:
 *
 * **It never asks for a password.** A credentialed schedule picks a stored
 * credential by name; the material stays encrypted in the database and is
 * resolved by the worker. There is no password field in this form, and adding
 * one would put a plaintext secret in the database and in the broker payload
 * on every run.
 *
 * **A time is never shown without its zone.** "02:00" is meaningless on its
 * own to anyone administering hosts in more than one country, and the whole
 * point of storing an IANA zone rather than an offset is that the schedule
 * keeps its wall-clock time across daylight saving.
 *
 * ── Checkpoint 3C batch 13 ──────────────────────────────────────────────────
 * Rendered on CCure primitives; every read, every write and every argument
 * to `api/scanSchedules` is unchanged. Two things worth recording:
 *
 *   * `Run now` is a scan dispatch. It stays a single explicit button in the
 *     row, is never the default action of anything, and no dialog or keyboard
 *     path reaches it. Delete stays behind a confirmation.
 *   * The page destructured `{ addToast, removeToast }` from `useToasts()`,
 *     which exports `{ push, dismiss }`. Every success and failure path threw
 *     after the API call had already been made — save reported "Could not
 *     save the schedule." on success and left the form open; enable, run and
 *     delete performed the write and never refreshed the list. The calls now
 *     use the toaster's real API, so the post-write refresh the code always
 *     intended actually happens. Recorded as an intentional behaviour change
 *     in the checkpoint report.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { ToastContainer, useToasts } from "../../components/common/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureField,
  CcureInput,
  CcureLoader,
  CcureSelect,
  CcureTable,
} from "../../design-system";
import {
  createScanSchedule,
  deleteScanSchedule,
  listScanScheduleRuns,
  listScanSchedules,
  listTimezones,
  runScanScheduleNow,
  setScanScheduleEnabled,
  listScheduleCredentials,
  updateScanSchedule,
} from "../../api/scanSchedules";
import "../../styles/scan-schedules.css";

const WEEKDAYS = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];

const RECURRENCES = [
  { value: "once", label: "One time" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
  { value: "custom", label: "Custom (cron)" },
];

const STATUS_VARIANT = {
  dispatched: "success",
  failed: "danger",
  skipped: "warning",
};

const EMPTY_FORM = {
  name: "",
  description: "",
  scanKind: "network",
  targets: "",
  credentialId: "",
  recurrence: "daily",
  timezone: "UTC",
  runAt: "02:00",
  dayOfWeek: 0,
  dayOfMonth: 1,
  cronExpression: "",
  startsAt: "",
  isEnabled: true,
  scanOptions: {},
};

function StatusPill({ status }) {
  if (!status) return <span className="ss-muted">—</span>;
  return (
    <CcureBadge variant={STATUS_VARIANT[status] || "neutral"}>
      {String(status).toUpperCase()}
    </CcureBadge>
  );
}

/** Absolute local time plus a relative hint — "in 6 hours" alone is unauditable. */
function When({ iso, emptyLabel = "—" }) {
  if (!iso) return <span className="ss-muted">{emptyLabel}</span>;
  const when = new Date(iso);
  const deltaMin = Math.round((when.getTime() - Date.now()) / 60000);
  const rel =
    Math.abs(deltaMin) < 60
      ? `${Math.abs(deltaMin)} min ${deltaMin >= 0 ? "from now" : "ago"}`
      : Math.abs(deltaMin) < 60 * 48
        ? `${Math.round(Math.abs(deltaMin) / 60)} h ${deltaMin >= 0 ? "from now" : "ago"}`
        : when.toLocaleDateString();
  return (
    <span className="ss-when">
      <time dateTime={when.toISOString()} title={when.toISOString()}>
        {when.toLocaleString()}
      </time>
      <span className="ss-when__rel"> ({rel})</span>
    </span>
  );
}

const SCHEDULE_COLUMNS = [
  { key: "name", header: "Name" },
  { key: "kind", header: "Kind" },
  { key: "recurrence", header: "Recurrence" },
  { key: "next", header: "Next run" },
  { key: "last", header: "Last run" },
  { key: "result", header: "Last result" },
  { key: "actions", header: "Actions", align: "end" },
];

const RUN_COLUMNS = [
  { key: "when", header: "When" },
  { key: "trigger", header: "Trigger" },
  { key: "status", header: "Status" },
  { key: "scan", header: "Scan" },
  { key: "detail", header: "Detail" },
];

export default function ScanSchedules() {
  const { toasts, push: addToast, dismiss: removeToast } = useToasts();

  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [timezones, setTimezones] = useState([]);
  const [credentials, setCredentials] = useState([]);

  const [filterKind, setFilterKind] = useState("");
  const [filterEnabled, setFilterEnabled] = useState("");

  const [editing, setEditing] = useState(null); // null | "new" | schedule id
  const [form, setForm] = useState(EMPTY_FORM);
  const [formError, setFormError] = useState("");

  const [historyFor, setHistoryFor] = useState(null);
  const [runs, setRuns] = useState([]);
  const [runsLoading, setRunsLoading] = useState(false);

  const [confirmDelete, setConfirmDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listScanSchedules({
        scanKind: filterKind || undefined,
        enabled: filterEnabled === "" ? undefined : filterEnabled === "true",
      });
      setSchedules(data.schedules || []);
    } catch (err) {
      addToast(
        err?.response?.data?.detail || "Could not load scan schedules.",
        "error",
      );
    } finally {
      setLoading(false);
    }
  }, [filterKind, filterEnabled, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    listTimezones()
      .then(setTimezones)
      .catch(() => setTimezones(["UTC"]));
    listScheduleCredentials()
      .then(setCredentials)
      .catch(() => setCredentials([]));
  }, []);

  const openNew = () => {
    setForm({
      ...EMPTY_FORM,
      // Default to the operator's own zone rather than UTC: a schedule is
      // almost always meant in local time, and defaulting to UTC is how
      // "02:00" silently becomes the middle of the working day.
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    });
    setFormError("");
    setEditing("new");
  };

  const openEdit = (schedule) => {
    setForm({
      name: schedule.name,
      description: schedule.description || "",
      scanKind: schedule.scan_kind,
      targets: (schedule.targets || []).join("\n"),
      credentialId: schedule.credential_id || "",
      recurrence: schedule.recurrence,
      timezone: schedule.timezone,
      runAt: schedule.run_at,
      dayOfWeek: schedule.day_of_week ?? 0,
      dayOfMonth: schedule.day_of_month ?? 1,
      cronExpression: schedule.cron_expression || "",
      startsAt: schedule.starts_at ? schedule.starts_at.slice(0, 16) : "",
      isEnabled: schedule.is_enabled,
      scanOptions: schedule.scan_options || {},
    });
    setFormError("");
    setEditing(schedule.id);
  };

  const save = async (event) => {
    event?.preventDefault?.();
    setSaving(true);
    setFormError("");
    try {
      if (editing === "new") {
        await createScanSchedule(form);
        addToast(`Schedule "${form.name}" created.`, "success");
      } else {
        await updateScanSchedule(editing, form);
        addToast(`Schedule "${form.name}" updated.`, "success");
      }
      setEditing(null);
      await load();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      // A 422 body is a list of field errors; surfacing "[object Object]"
      // would tell the user nothing about which field to fix.
      setFormError(
        Array.isArray(detail)
          ? detail.map((d) => d.msg || JSON.stringify(d)).join("; ")
          : detail || "Could not save the schedule.",
      );
    } finally {
      setSaving(false);
    }
  };

  const toggleEnabled = async (schedule) => {
    try {
      await setScanScheduleEnabled(schedule.id, !schedule.is_enabled);
      addToast(
        `"${schedule.name}" ${schedule.is_enabled ? "disabled" : "enabled"}.`,
        "success",
      );
      await load();
    } catch (err) {
      addToast(
        err?.response?.data?.detail || "Could not change state.",
        "error",
      );
    }
  };

  const runNow = async (schedule) => {
    try {
      const result = await runScanScheduleNow(schedule.id);
      const run = result.run || {};
      if (run.status === "dispatched") {
        addToast(
          `"${schedule.name}" started — scan ${run.scan_id}.`,
          "success",
        );
      } else {
        // A refusal is reported here rather than swallowed: a schedule that
        // silently does nothing is the failure this whole feature exists to
        // make visible.
        addToast(
          `"${schedule.name}" did not run: ${run.detail || run.status}`,
          "error",
        );
      }
      await load();
    } catch (err) {
      addToast(
        err?.response?.data?.detail || "Could not run the schedule.",
        "error",
      );
    }
  };

  const openHistory = async (schedule) => {
    setHistoryFor(schedule);
    setRunsLoading(true);
    try {
      const data = await listScanScheduleRuns(schedule.id);
      setRuns(data.runs || []);
    } catch (err) {
      addToast(
        err?.response?.data?.detail || "Could not load history.",
        "error",
      );
      setRuns([]);
    } finally {
      setRunsLoading(false);
    }
  };

  const doDelete = async () => {
    if (!confirmDelete) return;
    setDeleting(true);
    try {
      await deleteScanSchedule(confirmDelete.id);
      addToast(`Schedule "${confirmDelete.name}" deleted.`, "success");
      setConfirmDelete(null);
      await load();
    } catch (err) {
      addToast(err?.response?.data?.detail || "Could not delete.", "error");
    } finally {
      setDeleting(false);
    }
  };

  const needsCredential = form.scanKind === "credentialed";

  const autoDisabled = useMemo(
    () => schedules.filter((s) => !s.is_enabled && s.consecutive_failures > 0),
    [schedules],
  );

  const setField = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  return (
    <AppLayout pageTitle="Scan Schedules">
      <div className="page-inner ss-page">
        <div className="page-title-row">
          <div>
            <h1 className="page-title">Scan Schedules</h1>
            <p className="page-subtitle">
              Scheduled scans run through the same pipeline as manual ones, so
              their results appear in Scan History, reports and the dashboard
              exactly as if you had started them yourself.
            </p>
          </div>
          <div className="ss-toolbar">
            <CcureButton variant="primary" size="sm" onClick={openNew}>
              New schedule
            </CcureButton>
          </div>
        </div>

        {autoDisabled.length > 0 && (
          <CcureAlert variant="warning" className="ss-auto-off">
            <strong>
              {autoDisabled.length} schedule
              {autoDisabled.length === 1 ? "" : "s"} switched off after repeated
              failures.
            </strong>{" "}
            Assurance scanning has stopped for{" "}
            {autoDisabled.length === 1 ? "it" : "them"}. Fix the cause and
            re-enable — re-enabling clears the failure count.
          </CcureAlert>
        )}

        <div className="ss-filters">
          <CcureSelect
            id="ss-filter-kind"
            label="Kind"
            fieldClassName="ss-filter"
            value={filterKind}
            onChange={(e) => setFilterKind(e.target.value)}
          >
            <option value="">All kinds</option>
            <option value="network">Network</option>
            <option value="credentialed">Credentialed</option>
          </CcureSelect>
          <CcureSelect
            id="ss-filter-enabled"
            label="State"
            fieldClassName="ss-filter"
            value={filterEnabled}
            onChange={(e) => setFilterEnabled(e.target.value)}
          >
            <option value="">Enabled and disabled</option>
            <option value="true">Enabled only</option>
            <option value="false">Disabled only</option>
          </CcureSelect>
        </div>

        {loading ? (
          <CcureLoader label="Loading scan schedules…" />
        ) : schedules.length === 0 ? (
          <CcureEmptyState
            icon="🗓"
            title="No scan schedules yet"
            description="Create one to run a network or credentialed scan on a recurring basis."
          />
        ) : (
          <CcureTable caption="Scan schedules" columns={SCHEDULE_COLUMNS}>
            {schedules.map((s) => (
              <tr key={s.id}>
                <th scope="row">
                  <div className="ss-name">{s.name}</div>
                  <div className="ss-sub">
                    {(s.targets || []).length} target
                    {(s.targets || []).length === 1 ? "" : "s"}
                    {s.credential_name ? ` · ${s.credential_name}` : ""}
                  </div>
                </th>
                <td>{s.scan_kind}</td>
                <td>{s.summary}</td>
                <td>
                  {s.is_enabled ? (
                    <When iso={s.next_run_at} emptyLabel="not scheduled" />
                  ) : (
                    <span className="ss-muted">disabled</span>
                  )}
                </td>
                <td>
                  <When iso={s.last_run_at} emptyLabel="never" />
                </td>
                <td>
                  <StatusPill status={s.last_status} />
                  {s.last_error && (
                    <div className="ss-error" title={s.last_error}>
                      {s.last_error}
                    </div>
                  )}
                </td>
                <td className="cc-table__cell--end cc-table__cell--nowrap">
                  <div className="ss-actions">
                    {/* Dispatches a scan. One explicit button, no default
                        action anywhere else reaches it. */}
                    <CcureButton
                      variant="secondary"
                      size="sm"
                      aria-label={`Run ${s.name} now`}
                      onClick={() => runNow(s)}
                    >
                      Run now
                    </CcureButton>
                    <CcureButton
                      variant="secondary"
                      size="sm"
                      aria-label={`${s.is_enabled ? "Disable" : "Enable"} ${s.name}`}
                      onClick={() => toggleEnabled(s)}
                    >
                      {s.is_enabled ? "Disable" : "Enable"}
                    </CcureButton>
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      aria-label={`Edit ${s.name}`}
                      onClick={() => openEdit(s)}
                    >
                      Edit
                    </CcureButton>
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      aria-label={`History for ${s.name}`}
                      onClick={() => openHistory(s)}
                    >
                      History
                    </CcureButton>
                    <CcureButton
                      variant="danger"
                      size="sm"
                      aria-label={`Delete ${s.name}`}
                      onClick={() => setConfirmDelete(s)}
                    >
                      Delete
                    </CcureButton>
                  </div>
                </td>
              </tr>
            ))}
          </CcureTable>
        )}

        {editing && (
          <CcureCard
            className="ss-form"
            title={editing === "new" ? "New schedule" : "Edit schedule"}
            headingLevel={2}
          >
            <form className="ss-form-grid" onSubmit={save}>
              {formError && (
                <CcureAlert variant="danger">{formError}</CcureAlert>
              )}

              <CcureInput
                id="ss-name"
                label="Name"
                value={form.name}
                onChange={setField("name")}
              />

              <CcureInput
                id="ss-description"
                label="Description"
                value={form.description}
                onChange={setField("description")}
              />

              <CcureSelect
                id="ss-kind"
                label="Scan kind"
                value={form.scanKind}
                disabled={editing !== "new"}
                onChange={setField("scanKind")}
                hint={
                  editing !== "new"
                    ? "The kind cannot be changed — it decides which pipeline runs and which options apply. Create a new schedule instead."
                    : undefined
                }
              >
                <option value="network">Network scan</option>
                <option value="credentialed">Credentialed scan</option>
              </CcureSelect>

              <CcureField
                id="ss-targets"
                label="Targets (one per line, or comma separated)"
                hint="Re-checked against your organisation's authorised scan ranges on every run, not just now."
              >
                <textarea
                  id="ss-targets"
                  className="cc-field__control ss-mono"
                  rows={3}
                  value={form.targets}
                  onChange={setField("targets")}
                  aria-describedby="ss-targets-hint"
                />
              </CcureField>

              {needsCredential && (
                <CcureSelect
                  id="ss-credential"
                  label="Credential"
                  value={form.credentialId}
                  onChange={setField("credentialId")}
                  hint="Referenced, never copied. The password stays encrypted and is read only by the scanner at run time."
                >
                  <option value="">Select a stored credential…</option>
                  {credentials.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.username})
                    </option>
                  ))}
                </CcureSelect>
              )}

              <CcureSelect
                id="ss-recurrence"
                label="Recurrence"
                value={form.recurrence}
                onChange={setField("recurrence")}
              >
                {RECURRENCES.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </CcureSelect>

              {form.recurrence === "once" ? (
                <CcureInput
                  id="ss-starts-at"
                  label="Run at"
                  type="datetime-local"
                  value={form.startsAt}
                  onChange={setField("startsAt")}
                />
              ) : (
                <>
                  <CcureInput
                    id="ss-run-at"
                    label="Time of day"
                    type="time"
                    value={form.runAt}
                    onChange={setField("runAt")}
                    fieldClassName="ss-narrow"
                  />

                  <CcureSelect
                    id="ss-timezone"
                    label="Time zone"
                    value={form.timezone}
                    onChange={setField("timezone")}
                    hint="The schedule keeps this wall-clock time across daylight saving."
                  >
                    {timezones.map((tz) => (
                      <option key={tz} value={tz}>
                        {tz}
                      </option>
                    ))}
                  </CcureSelect>
                </>
              )}

              {form.recurrence === "weekly" && (
                <CcureSelect
                  id="ss-day-of-week"
                  label="Day of week"
                  value={form.dayOfWeek}
                  onChange={setField("dayOfWeek")}
                >
                  {WEEKDAYS.map((d, i) => (
                    <option key={d} value={i}>
                      {d}
                    </option>
                  ))}
                </CcureSelect>
              )}

              {form.recurrence === "monthly" && (
                <CcureInput
                  id="ss-day-of-month"
                  label="Day of month"
                  type="number"
                  min={1}
                  max={31}
                  value={form.dayOfMonth}
                  onChange={setField("dayOfMonth")}
                  fieldClassName="ss-narrow"
                  hint="A month shorter than this runs on its last day — the 31st becomes the 28th or 29th in February."
                />
              )}

              {form.recurrence === "custom" && (
                <CcureInput
                  id="ss-cron"
                  label="Cron expression"
                  value={form.cronExpression}
                  onChange={setField("cronExpression")}
                  placeholder="0 2 * * *"
                  className="ss-mono"
                />
              )}

              <div className="ss-form-actions">
                <CcureButton
                  type="submit"
                  variant="primary"
                  loading={saving}
                  disabled={saving}
                >
                  {saving ? "Saving…" : "Save"}
                </CcureButton>
                <CcureButton
                  variant="secondary"
                  onClick={() => setEditing(null)}
                >
                  Cancel
                </CcureButton>
              </div>
            </form>
          </CcureCard>
        )}

        {historyFor && (
          <CcureCard
            className="ss-history"
            title={`Execution history — ${historyFor.name}`}
            headingLevel={2}
            actions={
              <CcureButton
                variant="secondary"
                size="sm"
                onClick={() => setHistoryFor(null)}
              >
                Close
              </CcureButton>
            }
          >
            {runsLoading ? (
              <CcureLoader label="Loading run history…" />
            ) : runs.length === 0 ? (
              <CcureEmptyState
                title="No runs yet"
                description="This schedule has not been dispatched."
              />
            ) : (
              <CcureTable
                caption={`Execution history for ${historyFor.name}`}
                columns={RUN_COLUMNS}
                density="compact"
              >
                {runs.map((r) => (
                  <tr key={r.id}>
                    <th scope="row">
                      <When iso={r.triggered_at} />
                    </th>
                    <td>{r.trigger}</td>
                    <td>
                      <StatusPill status={r.status} />
                    </td>
                    <td>
                      {/* A failure before a scan existed has no scan to link
                          to, which is exactly the case this table exists to
                          make visible. */}
                      {r.scan_id ? (
                        <a
                          className="ss-link"
                          href={`/history?scan=${r.scan_id}`}
                        >
                          {r.scan_id}
                        </a>
                      ) : (
                        <span className="ss-muted">no scan was created</span>
                      )}
                    </td>
                    <td className="ss-error">{r.detail || ""}</td>
                  </tr>
                ))}
              </CcureTable>
            )}
          </CcureCard>
        )}
      </div>

      <CcureConfirmDialog
        open={Boolean(confirmDelete)}
        title={confirmDelete ? `Delete "${confirmDelete.name}"?` : ""}
        subtitle="The schedule and its run history are removed. Scans it already produced are kept — they are evidence of what was on the network at the time."
        confirmLabel="Delete"
        tone="danger"
        busy={deleting}
        onConfirm={doDelete}
        onCancel={() => setConfirmDelete(null)}
      />

      <ToastContainer toasts={toasts} dismiss={removeToast} />
    </AppLayout>
  );
}
