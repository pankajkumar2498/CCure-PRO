/**
 * pages/scan/ScanCredentials.jsx
 * ───────────────────────────────────────────────────────────────────────────
 * Manage the credentials scans authenticate with — SSH and native Windows.
 *
 * Three things this page is careful about:
 *
 * **A secret is write-only.** The server never returns credential material, so
 * there is nothing to display and no "reveal" control to build. Editing shows
 * an empty password field meaning "leave unchanged"; typing in it replaces the
 * secret. A masked field that round-trips the real value is how a password
 * ends up in a browser's DOM and its autofill store.
 *
 * **Validation is a real authentication attempt**, so it needs a target — a
 * credential is not valid or invalid on its own. The result distinguishes
 * "wrong password" from "nothing listening" from "not permitted", because
 * those need three different actions and collapsing them into "failed" is what
 * turns a firewall rule into a support ticket.
 *
 * **Windows needs no agent.** The help text says so explicitly, because the
 * previous implementation required OpenSSH Server on every Windows target and
 * people will reasonably assume that is still true.
 */

import { useCallback, useEffect, useState } from "react";
import AppLayout from "@audit/components/layout/AppLayout";
import { ToastContainer, useToasts } from "@shell/feedback/Toast";
import {
  CcureAlert,
  CcureButton,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureModal,
  CcureSelect,
  CcureTable,
  CcureTextarea,
} from "../../../../design-system";
import "../../styles/scan-credentials.css";
import {
  createCredential,
  deleteCredential,
  listCredentialTypes,
  listCredentials,
  updateCredential,
  validateCredential,
} from "@audit/api/credentials";

const EMPTY_FORM = {
  name: "",
  username: "",
  domain: "",
  credentialType: "windows",
  authMethod: "ntlm",
  password: "",
  privateKey: "",
  port: "",
  options: {},
};

/** Each reason needs a different action, so each keeps its own wording — and
 *  its own alert variant, so the six do not collapse into "failed". The
 *  hardcoded hex pairs these carried were a light-theme palette on a page that
 *  renders in whichever theme the account chose. */
const REASON_TEXT = {
  authenticated: { variant: "success", label: "Authenticated" },
  authentication_failed: {
    variant: "danger",
    label: "Authentication failed",
    hint: "Check the username form, the password, and whether the account is locked.",
  },
  insufficient_privileges: {
    variant: "warning",
    label: "Insufficient privileges",
    hint: "The credential is valid but the account cannot read what the scan needs. Add it to Administrators or Remote Management Users.",
  },
  unreachable: {
    variant: "danger",
    label: "Unreachable",
    hint: "Nothing answered on that port. Check the service is running and the firewall permits it.",
  },
  configuration_error: {
    variant: "warning",
    label: "Configuration problem",
    hint: "The host answered but is configured in a way that prevents the scan.",
  },
  failed: { variant: "danger", label: "Failed" },
};

function ResultBanner({ result }) {
  if (!result) return null;
  const style = REASON_TEXT[result.reason] || REASON_TEXT.failed;
  return (
    <CcureAlert
      variant={style.variant}
      title={`${style.label}${result.target ? ` — ${result.target}` : ""}`}
      className="sc-result"
    >
      {result.authenticated_as && <div>as {result.authenticated_as}</div>}
      {style.hint && <div>{style.hint}</div>}
      {result.detail && <div className="sc-detail">{result.detail}</div>}
    </CcureAlert>
  );
}

export default function ScanCredentials() {
  /* `useToasts()` returns { toasts, push, dismiss }. This page destructured
     `addToast`/`removeToast`, so both were undefined and EVERY toast call threw
     — including the success toasts, which sit inside their handlers' `try`. A
     credential that saved successfully therefore rendered "Could not save the
     credential" and left the modal open, inviting a retry that created a
     duplicate. Renamed on the way in rather than renamed throughout, so the
     five call sites and the handlers around them stay byte-identical. */
  const { toasts, push: addToast, dismiss: removeToast } = useToasts();

  const [credentials, setCredentials] = useState([]);
  const [types, setTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [editing, setEditing] = useState(null); // null | "new" | id
  const [form, setForm] = useState(EMPTY_FORM);
  const [formError, setFormError] = useState("");

  const [validatingFor, setValidatingFor] = useState(null);
  const [validateTarget, setValidateTarget] = useState("");
  const [validateResult, setValidateResult] = useState(null);
  const [validating, setValidating] = useState(false);

  const [confirmDelete, setConfirmDelete] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listCredentials();
      setCredentials(data.credentials || []);
    } catch (err) {
      addToast(
        err?.response?.data?.detail || "Could not load credentials.",
        "error",
      );
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    listCredentialTypes()
      .then(setTypes)
      .catch(() => setTypes([]));
  }, []);

  const selectedType = types.find((t) => t.value === form.credentialType);
  const methods = selectedType?.auth_methods || ["password"];
  const needsKey = form.authMethod === "key";

  const openNew = () => {
    setForm(EMPTY_FORM);
    setFormError("");
    setEditing("new");
  };

  const openEdit = (cred) => {
    setForm({
      name: cred.name,
      username: cred.username,
      domain: cred.domain || "",
      credentialType: cred.credential_type,
      authMethod: cred.auth_method,
      // Deliberately blank. The server never returns the secret, and an empty
      // field here means "leave it unchanged".
      password: "",
      privateKey: "",
      port: cred.port || "",
      options: cred.options || {},
    });
    setFormError("");
    setEditing(cred.id);
  };

  const save = async () => {
    setSaving(true);
    setFormError("");
    try {
      if (editing === "new") {
        await createCredential(form);
        addToast(`Credential "${form.name}" created.`, "success");
      } else {
        await updateCredential(editing, form);
        addToast(`Credential "${form.name}" updated.`, "success");
      }
      setEditing(null);
      await load();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setFormError(
        Array.isArray(detail)
          ? detail.map((d) => d.msg || JSON.stringify(d)).join("; ")
          : detail || "Could not save the credential.",
      );
    } finally {
      setSaving(false);
    }
  };

  const runValidate = async () => {
    if (!validateTarget.trim()) return;
    setValidating(true);
    setValidateResult(null);
    try {
      const result = await validateCredential(
        validatingFor.id,
        validateTarget.trim(),
      );
      setValidateResult(result);
    } catch (err) {
      setValidateResult({
        reason: "failed",
        detail: err?.response?.data?.detail || "Validation request failed.",
        target: validateTarget,
      });
    } finally {
      setValidating(false);
    }
  };

  const doDelete = async () => {
    if (!confirmDelete) return;
    try {
      const result = await deleteCredential(confirmDelete.id);
      addToast(
        result.note || `Credential "${confirmDelete.name}" deleted.`,
        result.schedules_affected ? "warning" : "success",
      );
      setConfirmDelete(null);
      await load();
    } catch (err) {
      addToast(err?.response?.data?.detail || "Could not delete.", "error");
    }
  };

  /* Declared columns, so CcureTable owns the caption, `scope="col"` on every
     header and `scope="row"` on the credential's name. */
  const columns = [
    {
      key: "name",
      header: "Name",
      isRowHeader: true,
      cell: (c) => <span className="sc-name">{c.name}</span>,
    },
    { key: "credential_type", header: "Type", cell: (c) => c.credential_type },
    {
      key: "principal",
      header: "Account",
      cell: (c) => (
        <span className="sc-account">
          <code className="sc-principal">{c.principal}</code>
          <span className="sc-account-meta">
            {c.auth_method}
            {c.has_secret ? "" : " · no secret stored"}
          </span>
        </span>
      ),
    },
    { key: "transport", header: "Transport", cell: (c) => c.transport },
    { key: "port", header: "Port", mono: true, cell: (c) => c.port },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      nowrap: true,
      cell: (c) => (
        <div className="sc-actions">
          <CcureButton
            variant="secondary"
            size="sm"
            onClick={() => {
              setValidatingFor(c);
              setValidateTarget("");
              setValidateResult(null);
            }}
            /* One "Validate" per row is N identical entries in a reader's
               control list, and picking the wrong one authenticates the wrong
               credential against a host. */
            aria-label={`Validate ${c.name}`}
          >
            Validate
          </CcureButton>
          <CcureButton
            variant="secondary"
            size="sm"
            onClick={() => openEdit(c)}
            aria-label={`Edit ${c.name}`}
          >
            Edit
          </CcureButton>
          <CcureButton
            variant="danger"
            size="sm"
            onClick={() => setConfirmDelete(c)}
            aria-label={`Delete ${c.name}`}
          >
            Delete
          </CcureButton>
        </div>
      ),
    },
  ];

  return (
    <AppLayout>
      {/* The prop is `dismiss` — `removeToast` was silently ignored, so a
          toast could not be dismissed by clicking it. */}
      <ToastContainer toasts={toasts} dismiss={removeToast} />

      <div className="page-inner sc-page">
        <div className="sc-header">
          <h1 className="page-title">Scan Credentials</h1>
          <CcureButton onClick={openNew}>New credential</CcureButton>
        </div>

        <p className="page-subtitle sc-lede">
          Credentials used by authenticated scans. Secrets are encrypted at rest
          and never returned — scans and schedules reference a credential by id,
          so no password is stored on a scan or passed to a worker.{" "}
          <strong>Windows targets need no agent and no OpenSSH</strong>:
          collection uses WinRM, the remote-management service Windows already
          ships.
        </p>

        {loading ? (
          <div className="sc-loading">
            <CcureLoader label="Loading credentials…" />
          </div>
        ) : credentials.length === 0 ? (
          <CcureEmptyState
            title="No credentials yet"
            description="Add one to run authenticated Linux or Windows scans."
          />
        ) : (
          <CcureTable
            caption={`Scan credentials — ${credentials.length} stored`}
            columns={columns}
            rows={credentials}
            rowKey={(c) => c.id}
            density="comfortable"
          />
        )}

        {validatingFor && (
          <section className="sc-panel" aria-labelledby="sc-validate-heading">
            <div className="sc-panel-head">
              <h2 id="sc-validate-heading" className="sc-panel-title">
                Validate &quot;{validatingFor.name}&quot;
              </h2>
              <CcureButton
                variant="secondary"
                size="sm"
                onClick={() => setValidatingFor(null)}
              >
                Close
              </CcureButton>
            </div>
            <p className="sc-panel-note">
              This makes a real authentication attempt against the host you
              name. A credential is not valid or invalid on its own.
            </p>
            <div className="sc-validate-row">
              <CcureInput
                label="Host or IP to test against"
                placeholder="Host or IP to test against"
                value={validateTarget}
                onChange={(e) => setValidateTarget(e.target.value)}
                fieldClassName="sc-validate-field"
              />
              <CcureButton
                onClick={runValidate}
                loading={validating}
                disabled={validating || !validateTarget.trim()}
              >
                {validating ? "Testing…" : "Test now"}
              </CcureButton>
            </div>
            <ResultBanner result={validateResult} />
          </section>
        )}

        {/* The credential form is a real dialog now — focus trapped and
            restored — because it collects a secret, and focus escaping behind
            it is how a password gets typed into the page underneath. */}
        <CcureModal
          open={Boolean(editing)}
          onClose={() => setEditing(null)}
          title={editing === "new" ? "New credential" : "Edit credential"}
          subtitle="Secrets are write-only: the server never returns them."
          size="md"
          footer={
            <>
              <CcureButton variant="secondary" onClick={() => setEditing(null)}>
                Cancel
              </CcureButton>
              <CcureButton onClick={save} loading={saving}>
                {saving ? "Saving…" : "Save"}
              </CcureButton>
            </>
          }
        >
          {formError && (
            <CcureAlert variant="danger" className="sc-form-error">
              {formError}
            </CcureAlert>
          )}

          <div className="sc-form">
            <CcureInput
              label="Name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />

            <CcureSelect
              label="Type"
              value={form.credentialType}
              disabled={editing !== "new"}
              hint={
                selectedType && !selectedType.available
                  ? selectedType.unavailable_reason
                  : undefined
              }
              onChange={(e) => {
                const next = types.find((t) => t.value === e.target.value);
                setForm({
                  ...form,
                  credentialType: e.target.value,
                  authMethod: next?.auth_methods?.[0] || "password",
                });
              }}
            >
              {types.map((t) => (
                <option key={t.value} value={t.value} disabled={!t.available}>
                  {t.label}
                </option>
              ))}
            </CcureSelect>

            <CcureInput
              label="Username"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
            />

            {form.credentialType === "windows" && (
              <CcureInput
                label="Domain (leave blank for a local account)"
                placeholder="CORP"
                hint="Stored separately from the username: NTLM needs a domain-qualified user and Kerberos needs user@REALM, and the right form is built for you."
                value={form.domain}
                onChange={(e) => setForm({ ...form, domain: e.target.value })}
              />
            )}

            <CcureSelect
              label="Authentication method"
              value={form.authMethod}
              onChange={(e) => setForm({ ...form, authMethod: e.target.value })}
            >
              {methods.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </CcureSelect>

            {/* Deliberately NOT CcurePasswordField. It owns a reveal toggle,
                and there is nothing here to reveal: the server never returns
                the secret, and a field that could display one is how a
                password reaches the DOM and the browser autofill store. */}
            {needsKey ? (
              <CcureTextarea
                label="Private key"
                id="sc-private-key"
                className="cc-field__control sc-key"
                rows={4}
                value={form.privateKey}
                onChange={(e) =>
                  setForm({ ...form, privateKey: e.target.value })
                }
                placeholder={
                  editing === "new"
                    ? "-----BEGIN OPENSSH PRIVATE KEY-----"
                    : "Leave blank to keep the stored key"
                }
              />
            ) : (
              <CcureInput
                label="Password"
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                placeholder={
                  editing === "new"
                    ? ""
                    : "Leave blank to keep the stored password"
                }
              />
            )}

            <CcureInput
              label="Port"
              type="number"
              value={form.port}
              onChange={(e) => setForm({ ...form, port: e.target.value })}
              placeholder={String(selectedType?.default_port || "")}
              hint={
                form.credentialType === "windows"
                  ? "5985 is WinRM over HTTP — still encrypted, because NTLM encrypts the payload. 5986 is WinRM over HTTPS."
                  : undefined
              }
            />
          </div>
        </CcureModal>

        <CcureConfirmDialog
          open={Boolean(confirmDelete)}
          title={confirmDelete ? `Delete "${confirmDelete.name}"?` : "Delete?"}
          subtitle="Any schedule using this credential will start failing with a missing-credential error rather than running an unauthenticated scan that would report the host as clean."
          confirmLabel="Delete"
          tone="danger"
          onConfirm={doDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      </div>
    </AppLayout>
  );
}
