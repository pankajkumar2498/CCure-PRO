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
import AppLayout from "../../components/layout/AppLayout";
import Button from "../../components/common/Button";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import EmptyState from "../../components/common/EmptyState";
import Loader from "../../components/common/Loader";
import { ToastContainer, useToasts } from "../../components/common/Toast";
import {
  createCredential,
  deleteCredential,
  listCredentialTypes,
  listCredentials,
  updateCredential,
  validateCredential,
} from "../../api/credentials";

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

/** Each reason needs a different action, so each gets its own wording. */
const REASON_TEXT = {
  authenticated: { tone: "#166534", bg: "#dcfce7", label: "Authenticated" },
  authentication_failed: {
    tone: "#991b1b",
    bg: "#fee2e2",
    label: "Authentication failed",
    hint: "Check the username form, the password, and whether the account is locked.",
  },
  insufficient_privileges: {
    tone: "#92400e",
    bg: "#fef3c7",
    label: "Insufficient privileges",
    hint: "The credential is valid but the account cannot read what the scan needs. Add it to Administrators or Remote Management Users.",
  },
  unreachable: {
    tone: "#991b1b",
    bg: "#fee2e2",
    label: "Unreachable",
    hint: "Nothing answered on that port. Check the service is running and the firewall permits it.",
  },
  configuration_error: {
    tone: "#92400e",
    bg: "#fef3c7",
    label: "Configuration problem",
    hint: "The host answered but is configured in a way that prevents the scan.",
  },
  failed: { tone: "#991b1b", bg: "#fee2e2", label: "Failed" },
};

function ResultBanner({ result }) {
  if (!result) return null;
  const style = REASON_TEXT[result.reason] || REASON_TEXT.failed;
  return (
    <div
      style={{
        background: style.bg,
        color: style.tone,
        border: `1px solid ${style.tone}33`,
        borderRadius: 6,
        padding: "10px 14px",
        margin: "10px 0",
      }}
    >
      <strong>
        {style.label}
        {result.target ? ` — ${result.target}` : ""}
      </strong>
      {result.authenticated_as && (
        <div style={{ fontSize: 13 }}>as {result.authenticated_as}</div>
      )}
      {style.hint && <div style={{ fontSize: 13 }}>{style.hint}</div>}
      {result.detail && (
        <div style={{ fontSize: 12, marginTop: 4, opacity: 0.85 }}>
          {result.detail}
        </div>
      )}
    </div>
  );
}

export default function ScanCredentials() {
  const { toasts, addToast, removeToast } = useToasts();

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

  return (
    <AppLayout>
      <ToastContainer toasts={toasts} removeToast={removeToast} />

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <h1 style={{ margin: 0, flex: 1 }}>Scan Credentials</h1>
        <Button onClick={openNew}>New credential</Button>
      </div>

      <p style={{ color: "#475569", maxWidth: 780 }}>
        Credentials used by authenticated scans. Secrets are encrypted at rest
        and never returned — scans and schedules reference a credential by id,
        so no password is stored on a scan or passed to a worker.{" "}
        <strong>Windows targets need no agent and no OpenSSH</strong>:
        collection uses WinRM, the remote-management service Windows already
        ships.
      </p>

      {loading ? (
        <Loader />
      ) : credentials.length === 0 ? (
        <EmptyState
          title="No credentials yet"
          message="Add one to run authenticated Linux or Windows scans."
        />
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr
              style={{ textAlign: "left", borderBottom: "2px solid #e2e8f0" }}
            >
              <th style={{ padding: 8 }}>Name</th>
              <th style={{ padding: 8 }}>Type</th>
              <th style={{ padding: 8 }}>Account</th>
              <th style={{ padding: 8 }}>Transport</th>
              <th style={{ padding: 8 }}>Port</th>
              <th style={{ padding: 8 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {credentials.map((c) => (
              <tr key={c.id} style={{ borderBottom: "1px solid #f1f5f9" }}>
                <td style={{ padding: 8, fontWeight: 600 }}>{c.name}</td>
                <td style={{ padding: 8 }}>{c.credential_type}</td>
                <td style={{ padding: 8 }}>
                  <code>{c.principal}</code>
                  <div style={{ fontSize: 12, color: "#64748b" }}>
                    {c.auth_method}
                    {c.has_secret ? "" : " · no secret stored"}
                  </div>
                </td>
                <td style={{ padding: 8 }}>{c.transport}</td>
                <td style={{ padding: 8 }}>{c.port}</td>
                <td style={{ padding: 8, whiteSpace: "nowrap" }}>
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setValidatingFor(c);
                      setValidateTarget("");
                      setValidateResult(null);
                    }}
                  >
                    Validate
                  </Button>{" "}
                  <Button variant="secondary" onClick={() => openEdit(c)}>
                    Edit
                  </Button>{" "}
                  <Button variant="danger" onClick={() => setConfirmDelete(c)}>
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {validatingFor && (
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
              Validate &quot;{validatingFor.name}&quot;
            </h2>
            <Button variant="secondary" onClick={() => setValidatingFor(null)}>
              Close
            </Button>
          </div>
          <p style={{ color: "#475569", fontSize: 14 }}>
            This makes a real authentication attempt against the host you name.
            A credential is not valid or invalid on its own.
          </p>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              placeholder="Host or IP to test against"
              value={validateTarget}
              onChange={(e) => setValidateTarget(e.target.value)}
              style={{ flex: 1, maxWidth: 320 }}
            />
            <Button
              onClick={runValidate}
              disabled={validating || !validateTarget.trim()}
            >
              {validating ? "Testing…" : "Test now"}
            </Button>
          </div>
          <ResultBanner result={validateResult} />
        </div>
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
            {editing === "new" ? "New credential" : "Edit credential"}
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

          <div style={{ display: "grid", gap: 12, maxWidth: 640 }}>
            <label>
              Name
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={{ width: "100%" }}
              />
            </label>

            <label>
              Type
              <select
                value={form.credentialType}
                disabled={editing !== "new"}
                onChange={(e) => {
                  const next = types.find((t) => t.value === e.target.value);
                  setForm({
                    ...form,
                    credentialType: e.target.value,
                    authMethod: next?.auth_methods?.[0] || "password",
                    port: next?.default_port || "",
                  });
                }}
                style={{ width: "100%" }}
              >
                {types.map((t) => (
                  <option key={t.value} value={t.value} disabled={!t.available}>
                    {t.label}
                    {t.available ? "" : " — unavailable in this build"}
                  </option>
                ))}
              </select>
              {selectedType && !selectedType.available && (
                <span style={{ fontSize: 12, color: "#b91c1c" }}>
                  {selectedType.unavailable_reason}
                </span>
              )}
            </label>

            <label>
              Username
              <input
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                style={{ width: "100%" }}
              />
            </label>

            {form.credentialType === "windows" && (
              <label>
                Domain (leave blank for a local account)
                <input
                  value={form.domain}
                  onChange={(e) => setForm({ ...form, domain: e.target.value })}
                  placeholder="CORP"
                  style={{ width: "100%" }}
                />
                <span style={{ fontSize: 12, color: "#64748b" }}>
                  Stored separately from the username: NTLM needs
                  <code> DOMAIN\\user</code> and Kerberos needs
                  <code> user@REALM</code>, and the right form is built for you.
                </span>
              </label>
            )}

            <label>
              Authentication method
              <select
                value={form.authMethod}
                onChange={(e) =>
                  setForm({ ...form, authMethod: e.target.value })
                }
                style={{ width: "100%" }}
              >
                {methods.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>

            {needsKey ? (
              <label>
                Private key
                <textarea
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
                  style={{ width: "100%", fontFamily: "monospace" }}
                />
              </label>
            ) : (
              <label>
                Password
                <input
                  type="password"
                  autoComplete="new-password"
                  value={form.password}
                  onChange={(e) =>
                    setForm({ ...form, password: e.target.value })
                  }
                  placeholder={
                    editing === "new"
                      ? ""
                      : "Leave blank to keep the stored password"
                  }
                  style={{ width: "100%" }}
                />
              </label>
            )}

            <label>
              Port
              <input
                type="number"
                value={form.port}
                onChange={(e) => setForm({ ...form, port: e.target.value })}
                placeholder={String(selectedType?.default_port || "")}
              />
              {form.credentialType === "windows" && (
                <span style={{ fontSize: 12, color: "#64748b" }}>
                  5985 is WinRM over HTTP — still encrypted, because NTLM
                  encrypts the payload. 5986 is WinRM over HTTPS.
                </span>
              )}
            </label>

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

      {confirmDelete && (
        <ConfirmDialog
          open
          title={`Delete "${confirmDelete.name}"?`}
          subtitle="Any schedule using this credential will start failing with 'no credential is attached' rather than running an unauthenticated scan that would report the host as clean."
          confirmLabel="Delete"
          onConfirm={doDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
    </AppLayout>
  );
}
