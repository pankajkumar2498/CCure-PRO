/**
 * Scan policy management — one workspace over eleven operations.
 *
 * Deliberately not a page per endpoint. List, detail, create, edit, version,
 * status, enable, usage and delete are all things an operator does *to a
 * policy*, so they live where the policy is; only the per-scan snapshot lives
 * elsewhere, because it is a question about a scan rather than about a policy.
 *
 * Four things this screen has to get right, all of them about not overstating
 * what the backend said:
 *
 * * **The vocabulary is fetched, never hardcoded.** Scan kinds, statuses,
 *   config keys, check families and severities all come from `/settings`. A
 *   build with its own copy silently omits a family the backend added.
 *
 * * **`is_usable` is the backend's, not ours.** A policy is usable only when
 *   it is `active` *and* enabled. Recomputing that here would produce a second
 *   rule that agrees until it does not.
 *
 * * **Versioning is not editing.** An edit changes what schedules already
 *   pointing at the policy will assess next time; a version supersedes,
 *   archives the old row, and leaves it intact for the scans that cite it.
 *   They are separate controls with separate wording for that reason.
 *
 * * **Deleting is refused while something depends on it.** The API answers 409
 *   naming the schedules, because the foreign key is ON DELETE SET NULL and
 *   deleting anyway leaves them running under request defaults — a silent
 *   broadening of scope. `force` exists and is presented as the deliberate
 *   act it is.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  CcureLoader,
  CcureEmptyState,
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureModal,
  CcureSelect,
  CcureTable,
  CcureToastProvider,
  useCcureToast,
  CcureCheckbox,
} from "../../../../design-system";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import {
  POLICY_STATUS_TONE,
  createPolicy,
  createPolicyVersion,
  deletePolicy,
  fieldErrors,
  getPolicySettings,
  getPolicyUsage,
  listPolicies,
  policyErrorMessage,
  setPolicyEnabled,
  setPolicyStatus,
  updatePolicy,
  validatePolicy,
} from "@audit/api/scanPolicies";
import "../../styles/scan-policies.css";

/** Config keys that hold a list of free-text values, entered comma-separated. */
const LIST_KEYS = new Set([
  "framework_ids",
  "platforms",
  "sections",
  "custom_ports",
  "exclude_ports",
  "excluded_check_ids",
  "excluded_tags",
  "excluded_targets",
]);

const BOOL_KEYS = new Set([
  "allow_intrusive",
  "include_builtin_checks",
  "os_detection",
  "require_credential",
]);

function parseList(text) {
  return String(text || "")
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** The editor for one policy's `config`, built from the API's own key list. */
function ConfigEditor({ settings, config, onChange, disabled }) {
  const keys = settings?.config_keys || [];
  const set = (key, value) => onChange({ ...config, [key]: value });
  const unset = (key) => {
    const next = { ...config };
    delete next[key];
    onChange(next);
  };

  return (
    <div className="sp-config">
      <p className="sp-note">
        An empty field means <strong>no restriction</strong>, not
        &quot;nothing&quot;. Leaving frameworks blank selects every framework
        the workspace has installed, which is what a scan does without a policy.
      </p>

      {keys.map((key) => {
        const value = config[key];
        const present = value !== undefined;

        if (BOOL_KEYS.has(key)) {
          return (
            <CcureCheckbox
              key={key}
              className="sp-field sp-field--check"
              disabled={disabled}
              checked={value === true}
              onChange={(e) => (e.target.checked ? set(key, true) : unset(key))}
            >
              {key.replace(/_/g, " ")}
            </CcureCheckbox>
          );
        }

        if (key === "min_severity") {
          return (
            <CcureSelect
              key={key}
              label="minimum severity"
              value={present ? value : ""}
              disabled={disabled}
              fieldClassName="sp-field"
              onChange={(e) =>
                e.target.value ? set(key, e.target.value) : unset(key)
              }
            >
              <option value="">No floor</option>
              {(settings?.severities || []).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </CcureSelect>
          );
        }

        if (key === "check_families") {
          const selected = Array.isArray(value) ? value : [];
          return (
            <fieldset
              key={key}
              className="sp-field sp-fieldset"
              disabled={disabled}
            >
              <legend>check families</legend>
              <div className="sp-checks">
                {(settings?.check_families || []).map((fam) => (
                  <CcureCheckbox
                    key={fam}
                    className="sp-check"
                    checked={selected.includes(fam)}
                    onChange={(e) => {
                      const next = e.target.checked
                        ? [...selected, fam]
                        : selected.filter((f) => f !== fam);
                      if (next.length === 0) unset(key);
                      else set(key, next);
                    }}
                  >
                    {fam.replace(/_/g, " ")}
                  </CcureCheckbox>
                ))}
              </div>
            </fieldset>
          );
        }

        if (LIST_KEYS.has(key)) {
          return (
            <CcureInput
              key={key}
              label={key.replace(/_/g, " ")}
              value={Array.isArray(value) ? value.join(", ") : value ?? ""}
              disabled={disabled}
              placeholder="comma separated"
              fieldClassName="sp-field"
              onChange={(e) => {
                const list = parseList(e.target.value);
                if (list.length === 0) unset(key);
                else set(key, list);
              }}
            />
          );
        }

        // Everything else is a scalar the API names but does not enumerate.
        return (
          <CcureInput
            key={key}
            label={key.replace(/_/g, " ")}
            value={present ? String(value) : ""}
            disabled={disabled}
            fieldClassName="sp-field"
            onChange={(e) =>
              e.target.value ? set(key, e.target.value) : unset(key)
            }
          />
        );
      })}
    </div>
  );
}

function PolicyWorkspace() {
  const { user } = useAuth();
  const toast = useCcureToast();

  const canRead = can(user, "audit.scan_policy.read");
  const canCreate = can(user, "audit.scan_policy.manage");
  const canUpdate = can(user, "audit.scan_policy.manage");
  const canDelete = can(user, "audit.scan_policy.delete");

  const [settings, setSettings] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [filterKind, setFilterKind] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [usableOnly, setUsableOnly] = useState(false);

  const [selected, setSelected] = useState(null);
  const [usage, setUsage] = useState(null);

  const [editor, setEditor] = useState(null); // {mode, policy}
  const [form, setForm] = useState(null);
  const [formErrors, setFormErrors] = useState({});
  const [validation, setValidation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(null);

  const load = useCallback(async () => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const params = {};
      if (filterKind) params.scan_kind = filterKind;
      if (filterStatus) params.status = filterStatus;
      if (usableOnly) params.usable_only = true;
      const { data } = await listPolicies(params);
      setPolicies(data?.policies || []);
    } catch (err) {
      setError(policyErrorMessage(err, "The policies could not be loaded."));
    } finally {
      setLoading(false);
    }
  }, [canRead, filterKind, filterStatus, usableOnly]);

  useEffect(() => {
    if (!canRead) return;
    getPolicySettings()
      .then(({ data }) => setSettings(data))
      .catch(() => setSettings(null));
  }, [canRead]);

  useEffect(() => {
    load();
  }, [load]);

  const openDetail = async (policy) => {
    setSelected(policy);
    setUsage(null);
    try {
      const { data } = await getPolicyUsage(policy.id);
      setUsage(data);
    } catch {
      setUsage(null);
    }
  };

  const openEditor = (mode, policy = null) => {
    setFormErrors({});
    setValidation(null);
    setEditor({ mode, policy });
    if (mode === "create") {
      setForm({
        name: "",
        description: "",
        scan_kind: "any",
        status: "draft",
        is_enabled: true,
        config: {},
      });
    } else if (mode === "version") {
      setForm({
        name: policy.name,
        description: policy.description || "",
        config: { ...(policy.config || {}) },
        activate: true,
      });
    } else {
      setForm({
        name: policy.name,
        description: policy.description || "",
        scan_kind: policy.scan_kind,
        config: { ...(policy.config || {}) },
      });
    }
  };

  const runValidate = async () => {
    try {
      const { data } = await validatePolicy(
        form.config,
        form.scan_kind || editor?.policy?.scan_kind || "any",
      );
      setValidation(data);
    } catch (err) {
      setValidation({
        valid: false,
        errors: [policyErrorMessage(err, "Validation could not be run.")],
        warnings: [],
      });
    }
  };

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    setFormErrors({});
    try {
      if (editor.mode === "create") {
        await createPolicy(form);
        toast.success("Policy created.");
      } else if (editor.mode === "version") {
        await createPolicyVersion(editor.policy.id, {
          config: form.config,
          name: form.name,
          description: form.description,
          activate: form.activate,
        });
        toast.success("New version created; the previous one is archived.");
      } else {
        await updatePolicy(editor.policy.id, {
          name: form.name,
          description: form.description,
          scan_kind: form.scan_kind,
          config: form.config,
        });
        toast.success("Policy updated.");
      }
      setEditor(null);
      setSelected(null);
      await load();
    } catch (err) {
      const fields = fieldErrors(err);
      setFormErrors(fields);
      const message = policyErrorMessage(err, "The policy could not be saved.");
      if (Object.keys(fields).length === 0) toast.danger(message);
      setValidation({ valid: false, errors: [message], warnings: [] });
    } finally {
      setBusy(false);
    }
  };

  const act = async (fn, okMessage) => {
    if (busy) return;
    setBusy(true);
    try {
      await fn();
      toast.success(okMessage);
      setSelected(null);
      setConfirm(null);
      await load();
    } catch (err) {
      toast.danger(
        policyErrorMessage(err, "That action could not be completed."),
      );
      // A 409 on delete carries the schedules by name; keep the dialog open so
      // the operator can read it and choose force deliberately.
      if (err?.response?.status === 409 && confirm) {
        setConfirm({ ...confirm, conflict: policyErrorMessage(err, "") });
      } else {
        setConfirm(null);
      }
    } finally {
      setBusy(false);
    }
  };

  const rows = useMemo(() => policies, [policies]);

  if (!canRead) {
    return (
      <div className="sp-page">
        <CcureAlert variant="info" title="Scan policies unavailable">
          {denyMessage} Viewing scan policies needs{" "}
          <code>scan_policies:read</code>, which is separate from permission to
          run a scan.
        </CcureAlert>
      </div>
    );
  }

  return (
    <div className="sp-page">
      <header className="sp-header">
        <div>
          <h1 className="sp-title">Scan Policies</h1>
          <p className="sp-subtitle">
            What a scan assesses, as a reusable named configuration. A scan
            keeps its own copy, so editing a policy never changes a completed
            scan&apos;s record.
          </p>
        </div>
        {canCreate && (
          <CcureButton variant="primary" onClick={() => openEditor("create")}>
            New policy
          </CcureButton>
        )}
      </header>

      {error ? (
        <CcureAlert variant="danger" title="Could not load policies">
          {error}
        </CcureAlert>
      ) : null}

      <div className="sp-filters">
        <CcureSelect
          label="Scan kind"
          value={filterKind}
          onChange={(e) => setFilterKind(e.target.value)}
          fieldClassName="sp-filter"
        >
          <option value="">All kinds</option>
          {(settings?.scan_kinds || []).map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </CcureSelect>
        <CcureSelect
          label="Status"
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          fieldClassName="sp-filter"
        >
          <option value="">All statuses</option>
          {(settings?.statuses || []).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </CcureSelect>
        <CcureCheckbox
          className="sp-check sp-check--standalone"
          checked={usableOnly}
          onChange={(e) => setUsableOnly(e.target.checked)}
        >
          Only policies a scan may use now
        </CcureCheckbox>
      </div>

      {loading ? (
        <CcureLoader label="Loading policies…" />
      ) : rows.length === 0 ? (
        <CcureEmptyState
          title="No scan policies match"
          description="No scan policies match. A scan with no policy still records what it assessed — a policy makes that choice reusable and named."
        />
      ) : (
        <CcureTable
          caption="Scan policies"
          density="compact"
          rows={rows}
          rowKey={(p) => p.id}
          columns={[
            { key: "name", header: "Name", isRowHeader: true },
            {
              key: "policy_family_code",
              header: "Family",
              cell: (p) => (
                <span className="sp-muted">
                  {p.policy_family_code} v{p.version_number}
                </span>
              ),
            },
            { key: "scan_kind", header: "Kind" },
            {
              key: "status",
              header: "Status",
              cell: (p) => (
                <CcureBadge variant={POLICY_STATUS_TONE[p.status] || "neutral"}>
                  {p.status}
                </CcureBadge>
              ),
            },
            {
              key: "is_usable",
              header: "Usable now",
              // The backend's derived value, never recomputed here.
              cell: (p) =>
                p.is_usable ? (
                  <CcureBadge variant="success">yes</CcureBadge>
                ) : (
                  <span className="sp-muted">
                    {p.is_enabled ? "not active" : "disabled"}
                  </span>
                ),
            },
            {
              key: "use_count",
              header: "Scans",
              cell: (p) => p.use_count ?? 0,
            },
            {
              key: "open",
              header: "Details",
              cell: (p) => (
                <CcureButton
                  variant="ghost"
                  size="sm"
                  type="button"
                  className="sp-link"
                  onClick={() => openDetail(p)}
                >
                  Open
                </CcureButton>
              ),
            },
          ]}
        />
      )}

      {/* ── Detail ── */}
      {selected ? (
        <CcureModal
          open
          onClose={() => setSelected(null)}
          title={selected.name}
          size="lg"
        >
          <dl className="sp-detail">
            <div>
              <dt>Family / version</dt>
              <dd>
                {selected.policy_family_code} v{selected.version_number}
              </dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <CcureBadge
                  variant={POLICY_STATUS_TONE[selected.status] || "neutral"}
                >
                  {selected.status}
                </CcureBadge>{" "}
                {selected.is_enabled ? "enabled" : "disabled"}
              </dd>
            </div>
            <div>
              <dt>Scan kind</dt>
              <dd>{selected.scan_kind}</dd>
            </div>
            <div>
              <dt>Fingerprint</dt>
              <dd className="sp-mono">
                {String(selected.fingerprint || "").slice(0, 16)}
              </dd>
            </div>
            <div>
              <dt>Used by scans</dt>
              <dd>{usage?.scan_count ?? selected.use_count ?? 0}</dd>
            </div>
            <div>
              <dt>Schedules</dt>
              <dd>
                {usage
                  ? usage.schedules?.length
                    ? usage.schedules.map((s) => s.name || s.id).join(", ")
                    : "none"
                  : "…"}
              </dd>
            </div>
            {selected.superseded_by_policy_id ? (
              <div>
                <dt>Superseded by</dt>
                <dd className="sp-mono">{selected.superseded_by_policy_id}</dd>
              </div>
            ) : null}
          </dl>

          {selected.description ? (
            <p className="sp-note">{selected.description}</p>
          ) : null}

          <h3 className="sp-subtitle">Configuration</h3>
          <dl className="sp-summary">
            {Object.entries(selected.summary || {}).map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
              </div>
            ))}
          </dl>

          <div className="sp-actions">
            {canUpdate && (
              <>
                <CcureButton
                  variant="secondary"
                  disabled={busy}
                  onClick={() => {
                    setSelected(null);
                    openEditor("edit", selected);
                  }}
                >
                  Edit
                </CcureButton>
                <CcureButton
                  variant="secondary"
                  disabled={busy}
                  onClick={() =>
                    act(
                      () => setPolicyEnabled(selected.id, !selected.is_enabled),
                      selected.is_enabled
                        ? "Policy disabled."
                        : "Policy enabled.",
                    )
                  }
                >
                  {selected.is_enabled ? "Disable" : "Enable"}
                </CcureButton>
                {(settings?.statuses || [])
                  .filter((s) => s !== selected.status)
                  .map((s) => (
                    <CcureButton
                      key={s}
                      variant="secondary"
                      disabled={busy}
                      onClick={() =>
                        act(
                          () => setPolicyStatus(selected.id, s),
                          `Policy moved to ${s}.`,
                        )
                      }
                    >
                      Mark {s}
                    </CcureButton>
                  ))}
              </>
            )}
            {canCreate && (
              <CcureButton
                variant="secondary"
                disabled={busy}
                onClick={() => {
                  const policy = selected;
                  setSelected(null);
                  openEditor("version", policy);
                }}
                title="Supersede this policy with a new version, leaving this one intact"
              >
                New version
              </CcureButton>
            )}
            {canDelete && (
              <CcureButton
                variant="danger"
                disabled={busy}
                onClick={() => setConfirm({ policy: selected, force: false })}
              >
                Delete
              </CcureButton>
            )}
          </div>
        </CcureModal>
      ) : null}

      {/* ── Create / edit / version ── */}
      {editor && form ? (
        <CcureModal
          open
          onClose={() => setEditor(null)}
          title={
            editor.mode === "create"
              ? "New scan policy"
              : editor.mode === "version"
                ? `New version of ${editor.policy.name}`
                : `Edit ${editor.policy.name}`
          }
          size="lg"
        >
          {editor.mode === "version" ? (
            <CcureAlert
              variant="info"
              live={false}
              title="This supersedes, it does not edit"
            >
              The current version is archived and kept, so the scans that cite
              it stay accurate. Schedules pointing at the family pick this one
              up next time they run.
            </CcureAlert>
          ) : null}

          <CcureInput
            label="Name"
            required
            value={form.name}
            error={formErrors.name}
            disabled={busy}
            fieldClassName="sp-field"
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <CcureInput
            label="Description"
            value={form.description}
            error={formErrors.description}
            disabled={busy}
            fieldClassName="sp-field"
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />

          {editor.mode !== "version" && (
            <CcureSelect
              label="Scan kind"
              value={form.scan_kind}
              error={formErrors.scan_kind}
              disabled={busy}
              fieldClassName="sp-field"
              onChange={(e) => setForm({ ...form, scan_kind: e.target.value })}
            >
              {(settings?.scan_kinds || []).map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </CcureSelect>
          )}

          {editor.mode === "create" && (
            <CcureSelect
              label="Initial status"
              value={form.status}
              error={formErrors.status}
              disabled={busy}
              fieldClassName="sp-field"
              hint="A policy is only usable once it is active and enabled."
              onChange={(e) => setForm({ ...form, status: e.target.value })}
            >
              {/* `archived` is refused at creation by the API — a policy
                  created already retired is a mistake every time. */}
              {(settings?.statuses || [])
                .filter((s) => s !== "archived")
                .map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
            </CcureSelect>
          )}

          {editor.mode === "version" && (
            <CcureCheckbox
              className="sp-check sp-check--standalone"
              checked={form.activate}
              disabled={busy}
              onChange={(e) => setForm({ ...form, activate: e.target.checked })}
            >
              Activate the new version immediately
            </CcureCheckbox>
          )}

          <h3 className="sp-subtitle">Configuration</h3>
          <ConfigEditor
            settings={settings}
            config={form.config}
            disabled={busy}
            onChange={(config) => setForm({ ...form, config })}
          />

          {validation ? (
            <CcureAlert
              variant={validation.valid ? "success" : "danger"}
              title={
                validation.valid
                  ? "Configuration is valid"
                  : "Configuration refused"
              }
            >
              {/* The backend's own wording — it explains the consequence, not
                  just the rule: "...or the configuration audit assesses
                  nothing and the host reports as clean". */}
              {validation.valid ? (
                "This configuration resolves to something a scan can run."
              ) : (
                <ul className="sp-errors">
                  {(validation.errors || []).map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              )}
              {(validation.warnings || []).length > 0 && (
                <ul className="sp-errors">
                  {validation.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              )}
            </CcureAlert>
          ) : null}

          <div className="sp-actions">
            <CcureButton
              variant="secondary"
              disabled={busy}
              onClick={runValidate}
            >
              Check configuration
            </CcureButton>
            <CcureButton variant="primary" disabled={busy} onClick={submit}>
              {busy
                ? "Saving…"
                : editor.mode === "create"
                  ? "Create policy"
                  : editor.mode === "version"
                    ? "Create version"
                    : "Save changes"}
            </CcureButton>
            <CcureButton
              variant="secondary"
              disabled={busy}
              onClick={() => setEditor(null)}
            >
              Cancel
            </CcureButton>
          </div>
        </CcureModal>
      ) : null}

      {/* ── Delete ── */}
      {confirm ? (
        <CcureModal
          open
          onClose={() => setConfirm(null)}
          title={`Delete ${confirm.policy.name}?`}
        >
          <p className="sp-note">
            Completed scans are unaffected: each keeps its own configuration
            record, which is why deleting a policy cannot falsify a scan that
            used it.
          </p>
          {confirm.conflict ? (
            <CcureAlert
              variant="warning"
              title="Something still depends on this"
            >
              {confirm.conflict}
            </CcureAlert>
          ) : null}
          <CcureCheckbox
            className="sp-check sp-check--standalone"
            checked={confirm.force}
            disabled={busy}
            onChange={(e) =>
              setConfirm({ ...confirm, force: e.target.checked })
            }
          >
            Delete anyway, leaving any schedules to run under the scan request
            defaults
          </CcureCheckbox>
          <div className="sp-actions">
            <CcureButton
              variant="danger"
              disabled={busy}
              onClick={() =>
                act(
                  () =>
                    deletePolicy(confirm.policy.id, { force: confirm.force }),
                  "Policy deleted.",
                )
              }
            >
              {busy ? "Deleting…" : "Delete"}
            </CcureButton>
            <CcureButton
              variant="secondary"
              disabled={busy}
              onClick={() => setConfirm(null)}
            >
              Cancel
            </CcureButton>
          </div>
        </CcureModal>
      ) : null}
    </div>
  );
}

export default function ScanPolicies() {
  return (
    <AppLayout>
      {/* This app mounts no global toast provider; each page brings its own. */}
      <CcureToastProvider>
        <PolicyWorkspace />
      </CcureToastProvider>
    </AppLayout>
  );
}
