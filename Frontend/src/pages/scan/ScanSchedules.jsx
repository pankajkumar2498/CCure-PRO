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
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import AppLayout from "../../components/layout/AppLayout";
import Button from "../../components/common/Button";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import EmptyState from "../../components/common/EmptyState";
import Loader from "../../components/common/Loader";
import { ToastContainer, useToasts } from "../../components/common/Toast";
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

const STATUS_STYLE = {
  dispatched: { bg: "#dcfce7", fg: "#166534", label: "DISPATCHED" },
  failed: { bg: "#fee2e2", fg: "#991b1b", label: "FAILED" },
  skipped: { bg: "#fef3c7", fg: "#92400e", label: "SKIPPED" },
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
  if (!status) return <span style={{ color: "#94a3b8" }}>—</span>;
  const s = STATUS_STYLE[status] || {
    bg: "#e2e8f0",
    fg: "#334155",
    label: String(status).toUpperCase(),
  };
  return (
    <span
      style={{
        display: "inline-block",
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: "0.06em",
        padding: "2px 8px",
        borderRadius: 4,
        background: s.bg,
        color: s.fg,
      }}
    >
      {s.label}
    </span>
  );
}

/** Absolute local time plus a relative hint — "in 6 hours" alone is unauditable. */
function When({ iso, emptyLabel = "—" }) {
  if (!iso) return <span style={{ color: "#94a3b8" }}>{emptyLabel}</span>;
  const when = new Date(iso);
  const deltaMin = Math.round((when.getTime() - Date.now()) / 60000);
  const rel =
    Math.abs(deltaMin) < 60
      ? `${Math.abs(deltaMin)} min ${deltaMin >= 0 ? "from now" : "ago"}`
      : Math.abs(deltaMin) < 60 * 48
        ? `${Math.round(Math.abs(deltaMin) / 60)} h ${deltaMin >= 0 ? "from now" : "ago"}`
        : when.toLocaleDateString();
  return (
    <span title={when.toISOString()}>
      {when.toLocaleString()}
      <span style={{ color: "#64748b", fontSize: 12 }}> ({rel})</span>
    </span>
  );
}

export default function ScanSchedules() {
  const { toasts, addToast, removeToast } = useToasts();

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

  const save = async () => {
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
    try {
      await deleteScanSchedule(confirmDelete.id);
      addToast(`Schedule "${confirmDelete.name}" deleted.`, "success");
      setConfirmDelete(null);
      await load();
    } catch (err) {
      addToast(err?.response?.data?.detail || "Could not delete.", "error");
    }
  };

  const needsCredential = form.scanKind === "credentialed";

  const autoDisabled = useMemo(
    () => schedules.filter((s) => !s.is_enabled && s.consecutive_failures > 0),
    [schedules],
  );

  return (
    <AppLayout>
      <ToastContainer toasts={toasts} removeToast={removeToast} />

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <h1 style={{ margin: 0, flex: 1 }}>Scan Schedules</h1>
        <Button onClick={openNew}>New schedule</Button>
      </div>

      <p style={{ color: "#475569", maxWidth: 760 }}>
        Scheduled scans run through the same pipeline as manual ones, so their
        results appear in Scan History, reports and the dashboard exactly as if
        you had started them yourself.
      </p>

      {autoDisabled.length > 0 && (
        <div
          style={{
            background: "#fef3c7",
            border: "1px solid #fcd34d",
            borderRadius: 6,
            padding: "10px 14px",
            margin: "12px 0",
            color: "#92400e",
          }}
        >
          <strong>
            {autoDisabled.length} schedule
            {autoDisabled.length === 1 ? "" : "s"} switched off after repeated
            failures.
          </strong>{" "}
          Assurance scanning has stopped for{" "}
          {autoDisabled.length === 1 ? "it" : "them"}. Fix the cause and
          re-enable — re-enabling clears the failure count.
        </div>
      )}

      <div style={{ display: "flex", gap: 10, margin: "14px 0" }}>
        <select
          value={filterKind}
          onChange={(e) => setFilterKind(e.target.value)}
        >
          <option value="">All kinds</option>
          <option value="network">Network</option>
          <option value="credentialed">Credentialed</option>
        </select>
        <select
          value={filterEnabled}
          onChange={(e) => setFilterEnabled(e.target.value)}
        >
          <option value="">Enabled and disabled</option>
          <option value="true">Enabled only</option>
          <option value="false">Disabled only</option>
        </select>
      </div>

      {loading ? (
        <Loader />
      ) : schedules.length === 0 ? (
        <EmptyState
          title="No scan schedules yet"
          message="Create one to run a network or credentialed scan on a recurring basis."
        />
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr
              style={{ textAlign: "left", borderBottom: "2px solid #e2e8f0" }}
            >
              <th style={{ padding: 8 }}>Name</th>
              <th style={{ padding: 8 }}>Kind</th>
              <th style={{ padding: 8 }}>Recurrence</th>
              <th style={{ padding: 8 }}>Next run</th>
              <th style={{ padding: 8 }}>Last run</th>
              <th style={{ padding: 8 }}>Last result</th>
              <th style={{ padding: 8 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id} style={{ borderBottom: "1px solid #f1f5f9" }}>
                <td style={{ padding: 8 }}>
                  <div style={{ fontWeight: 600 }}>{s.name}</div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>
                    {(s.targets || []).length} target
                    {(s.targets || []).length === 1 ? "" : "s"}
                    {s.credential_name ? ` · ${s.credential_name}` : ""}
                  </div>
                </td>
                <td style={{ padding: 8 }}>{s.scan_kind}</td>
                <td style={{ padding: 8 }}>{s.summary}</td>
                <td style={{ padding: 8 }}>
                  {s.is_enabled ? (
                    <When iso={s.next_run_at} emptyLabel="not scheduled" />
                  ) : (
                    <span style={{ color: "#94a3b8" }}>disabled</span>
                  )}
                </td>
                <td style={{ padding: 8 }}>
                  <When iso={s.last_run_at} emptyLabel="never" />
                </td>
                <td style={{ padding: 8 }}>
                  <StatusPill status={s.last_status} />
                  {s.last_error && (
                    <div
                      style={{ fontSize: 12, color: "#b91c1c", maxWidth: 280 }}
                      title={s.last_error}
                    >
                      {s.last_error}
                    </div>
                  )}
                </td>
                <td style={{ padding: 8, whiteSpace: "nowrap" }}>
                  <Button variant="secondary" onClick={() => runNow(s)}>
                    Run now
                  </Button>{" "}
                  <Button variant="secondary" onClick={() => toggleEnabled(s)}>
                    {s.is_enabled ? "Disable" : "Enable"}
                  </Button>{" "}
                  <Button variant="secondary" onClick={() => openEdit(s)}>
                    Edit
                  </Button>{" "}
                  <Button variant="secondary" onClick={() => openHistory(s)}>
                    History
                  </Button>{" "}
                  <Button variant="danger" onClick={() => setConfirmDelete(s)}>
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {editing && (
        <div
          style={{
            marginTop: 24,
            padding: 16,
            border: "1px solid #e2e8f0",
            borderRadius: 8,
          }}
        >
          <h2 style={{ marginTop: 0 }}>
            {editing === "new" ? "New schedule" : "Edit schedule"}
          </h2>

          {formError && (
            <div
              style={{
                background: "#fee2e2",
                color: "#991b1b",
                padding: "8px 12px",
                borderRadius: 6,
                marginBottom: 12,
              }}
            >
              {formError}
            </div>
          )}

          <div style={{ display: "grid", gap: 12, maxWidth: 720 }}>
            <label>
              Name
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={{ width: "100%" }}
              />
            </label>

            <label>
              Description
              <input
                value={form.description}
                onChange={(e) =>
                  setForm({ ...form, description: e.target.value })
                }
                style={{ width: "100%" }}
              />
            </label>

            <label>
              Scan kind
              <select
                value={form.scanKind}
                disabled={editing !== "new"}
                onChange={(e) => setForm({ ...form, scanKind: e.target.value })}
                style={{ width: "100%" }}
              >
                <option value="network">Network scan</option>
                <option value="credentialed">Credentialed scan</option>
              </select>
              {editing !== "new" && (
                <span style={{ fontSize: 12, color: "#64748b" }}>
                  The kind cannot be changed — it decides which pipeline runs
                  and which options apply. Create a new schedule instead.
                </span>
              )}
            </label>

            <label>
              Targets (one per line, or comma separated)
              <textarea
                rows={3}
                value={form.targets}
                onChange={(e) => setForm({ ...form, targets: e.target.value })}
                style={{ width: "100%", fontFamily: "monospace" }}
              />
              <span style={{ fontSize: 12, color: "#64748b" }}>
                Re-checked against your organisation&apos;s authorised scan
                ranges on every run, not just now.
              </span>
            </label>

            {needsCredential && (
              <label>
                Credential
                <select
                  value={form.credentialId}
                  onChange={(e) =>
                    setForm({ ...form, credentialId: e.target.value })
                  }
                  style={{ width: "100%" }}
                >
                  <option value="">Select a stored credential…</option>
                  {credentials.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.username})
                    </option>
                  ))}
                </select>
                <span style={{ fontSize: 12, color: "#64748b" }}>
                  Referenced, never copied. The password stays encrypted and is
                  read only by the scanner at run time.
                </span>
              </label>
            )}

            <label>
              Recurrence
              <select
                value={form.recurrence}
                onChange={(e) =>
                  setForm({ ...form, recurrence: e.target.value })
                }
                style={{ width: "100%" }}
              >
                {RECURRENCES.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
            </label>

            {form.recurrence === "once" ? (
              <label>
                Run at
                <input
                  type="datetime-local"
                  value={form.startsAt}
                  onChange={(e) =>
                    setForm({ ...form, startsAt: e.target.value })
                  }
                  style={{ width: "100%" }}
                />
              </label>
            ) : (
              <>
                <label>
                  Time of day
                  <input
                    type="time"
                    value={form.runAt}
                    onChange={(e) =>
                      setForm({ ...form, runAt: e.target.value })
                    }
                  />
                </label>

                <label>
                  Time zone
                  <select
                    value={form.timezone}
                    onChange={(e) =>
                      setForm({ ...form, timezone: e.target.value })
                    }
                    style={{ width: "100%" }}
                  >
                    {timezones.map((tz) => (
                      <option key={tz} value={tz}>
                        {tz}
                      </option>
                    ))}
                  </select>
                  <span style={{ fontSize: 12, color: "#64748b" }}>
                    The schedule keeps this wall-clock time across daylight
                    saving.
                  </span>
                </label>
              </>
            )}

            {form.recurrence === "weekly" && (
              <label>
                Day of week
                <select
                  value={form.dayOfWeek}
                  onChange={(e) =>
                    setForm({ ...form, dayOfWeek: e.target.value })
                  }
                  style={{ width: "100%" }}
                >
                  {WEEKDAYS.map((d, i) => (
                    <option key={d} value={i}>
                      {d}
                    </option>
                  ))}
                </select>
              </label>
            )}

            {form.recurrence === "monthly" && (
              <label>
                Day of month
                <input
                  type="number"
                  min={1}
                  max={31}
                  value={form.dayOfMonth}
                  onChange={(e) =>
                    setForm({ ...form, dayOfMonth: e.target.value })
                  }
                />
                <span style={{ fontSize: 12, color: "#64748b" }}>
                  A month shorter than this runs on its last day — the 31st
                  becomes the 28th or 29th in February.
                </span>
              </label>
            )}

            {form.recurrence === "custom" && (
              <label>
                Cron expression
                <input
                  value={form.cronExpression}
                  onChange={(e) =>
                    setForm({ ...form, cronExpression: e.target.value })
                  }
                  placeholder="0 2 * * *"
                  style={{ width: "100%", fontFamily: "monospace" }}
                />
              </label>
            )}

            <div style={{ display: "flex", gap: 8 }}>
              <Button onClick={save} disabled={saving}>
                {saving ? "Saving…" : "Save"}
              </Button>
              <Button variant="secondary" onClick={() => setEditing(null)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}

      {historyFor && (
        <div
          style={{
            marginTop: 24,
            padding: 16,
            border: "1px solid #e2e8f0",
            borderRadius: 8,
          }}
        >
          <div style={{ display: "flex", alignItems: "center" }}>
            <h2 style={{ marginTop: 0, flex: 1 }}>
              Execution history — {historyFor.name}
            </h2>
            <Button variant="secondary" onClick={() => setHistoryFor(null)}>
              Close
            </Button>
          </div>

          {runsLoading ? (
            <Loader />
          ) : runs.length === 0 ? (
            <EmptyState
              title="No runs yet"
              message="This schedule has not been dispatched."
            />
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr
                  style={{
                    textAlign: "left",
                    borderBottom: "2px solid #e2e8f0",
                  }}
                >
                  <th style={{ padding: 8 }}>When</th>
                  <th style={{ padding: 8 }}>Trigger</th>
                  <th style={{ padding: 8 }}>Status</th>
                  <th style={{ padding: 8 }}>Scan</th>
                  <th style={{ padding: 8 }}>Detail</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id} style={{ borderBottom: "1px solid #f1f5f9" }}>
                    <td style={{ padding: 8 }}>
                      <When iso={r.triggered_at} />
                    </td>
                    <td style={{ padding: 8 }}>{r.trigger}</td>
                    <td style={{ padding: 8 }}>
                      <StatusPill status={r.status} />
                    </td>
                    <td style={{ padding: 8 }}>
                      {/* A failure before a scan existed has no scan to link
                          to, which is exactly the case this table exists to
                          make visible. */}
                      {r.scan_id ? (
                        <a href={`/history?scan=${r.scan_id}`}>{r.scan_id}</a>
                      ) : (
                        <span style={{ color: "#94a3b8" }}>
                          no scan was created
                        </span>
                      )}
                    </td>
                    <td style={{ padding: 8, color: "#b91c1c" }}>
                      {r.detail || ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {confirmDelete && (
        <ConfirmDialog
          open
          title={`Delete "${confirmDelete.name}"?`}
          subtitle="The schedule and its run history are removed. Scans it already produced are kept — they are evidence of what was on the network at the time."
          confirmLabel="Delete"
          onConfirm={doDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
    </AppLayout>
  );
}
