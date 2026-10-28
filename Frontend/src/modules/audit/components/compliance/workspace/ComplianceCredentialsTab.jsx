/**
 * The compliance workspace's Credentials Manager tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import { createCredential, deleteCredential } from "@audit/api/credentials";
import {
  CcureCard,
  CcureTableStatus,
  CcureTable,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureSelect,
  CcurePasswordField,
  CcureTextarea,
  CcureConfirmDialog,
} from "../../../../../design-system";
import { PagingControls } from "./shared";

export default function ComplianceCredentialsTab({
  credentialToDelete,
  credentialsList,
  credentialsPagination,
  deletingCredential,
  fetchTabData,
  isComplianceAdmin,
  loading,
  newCredAuthMethod,
  newCredKeyContent,
  newCredName,
  newCredPassword,
  newCredPort,
  newCredUsername,
  pushToast,
  savingCredential,
  setCredentialToDelete,
  setDeletingCredential,
  setNewCredAuthMethod,
  setNewCredKeyContent,
  setNewCredName,
  setNewCredPassword,
  setNewCredPort,
  setNewCredUsername,
  setSavingCredential,
}) {
  return (
    <div className="cwc-layout">
      <div ref={credentialsPagination.cardRef} className="cwc-list">
        <CcureCard title="Saved Credentials" bodyFlush>
          <div className="cwc-paging">
            <PagingControls
              pagination={credentialsPagination}
              total={credentialsList.length}
              loading={loading}
              label="Credentials pagination"
              itemNoun="credentials"
              sizes={[10, 25, 50, 100]}
            />
          </div>
          <CcureTableStatus
            loading={loading}
            count={credentialsList.length}
            noun="credentials"
          />
          <CcureTable
            caption="Saved credentials"
            columns={[
              {
                key: "name",
                header: "Nickname",
                isRowHeader: true,
                className: "cwc-name",
                cell: (c) => c.name,
              },
              {
                key: "username",
                header: "Username",
                cell: (c) => c.username,
              },
              {
                key: "port",
                header: "Port",
                mono: true,
                cell: (c) => c.port,
              },
              {
                key: "auth_method",
                header: "Auth Method",
                nowrap: true,
                cell: (c) => (
                  <CcureBadge
                    variant={c.auth_method === "key" ? "primary" : "neutral"}
                  >
                    {c.auth_method === "key" ? "SSH Key" : "Password"}
                  </CcureBadge>
                ),
              },
              ...(isComplianceAdmin
                ? [
                    {
                      key: "actions",
                      header: "Actions",
                      cell: (c) => (
                        <CcureButton
                          variant="ghost"
                          size="sm"
                          className="cwc-delete"
                          aria-label={`Delete ${c.name}`}
                          aria-haspopup="dialog"
                          onClick={() => setCredentialToDelete(c)}
                        >
                          Delete
                        </CcureButton>
                      ),
                    },
                  ]
                : []),
            ]}
            rows={credentialsPagination.paginatedItems}
            rowKey={(c) => c.id}
            loading={loading}
            emptyMessage="No saved credentials registered."
          />
        </CcureCard>
      </div>

      {isComplianceAdmin && (
        <CcureCard title="Register Credential" className="cwc-register">
          <form
            className="cwc-form"
            onSubmit={async (e) => {
              e.preventDefault();
              if (savingCredential) return;
              setSavingCredential(true);
              try {
                // The form registers SSH credentials, as it always has; the
                // store's own form (Scan Credentials) offers every type.
                await createCredential({
                  name: newCredName,
                  username: newCredUsername,
                  credentialType: "ssh",
                  authMethod: newCredAuthMethod,
                  password:
                    newCredAuthMethod === "password" ? newCredPassword : null,
                  privateKey:
                    newCredAuthMethod === "key" ? newCredKeyContent : null,
                  port: parseInt(newCredPort) || 22,
                });
                pushToast("Credential saved successfully.", "success");
                setNewCredName("");
                setNewCredUsername("");
                setNewCredPassword("");
                setNewCredKeyContent("");
                setNewCredPort(22);
                fetchTabData();
              } catch (err) {
                pushToast(
                  "Failed to save credential: " +
                    (err.response?.data?.detail ||
                      err.response?.data?.message ||
                      err.message),
                  "error",
                );
              } finally {
                setSavingCredential(false);
              }
            }}
          >
            <CcureInput
              label="Name / Nickname"
              value={newCredName}
              onChange={(e) => setNewCredName(e.target.value)}
              placeholder="e.g. Production Webservers"
              required
            />

            <CcureInput
              label="Username"
              value={newCredUsername}
              onChange={(e) => setNewCredUsername(e.target.value)}
              placeholder="e.g. root"
              required
            />

            <CcureInput
              type="number"
              label="Port"
              value={newCredPort}
              onChange={(e) => setNewCredPort(e.target.value)}
              required
            />

            <CcureSelect
              label="Authentication Method"
              value={newCredAuthMethod}
              /* Switching method drops whatever the other method held:
                         it is sent as null once the method changes, and
                         keeping it meant it returned if the operator switched
                         back. */
              onChange={(e) => {
                setNewCredAuthMethod(e.target.value);
                setNewCredPassword("");
                setNewCredKeyContent("");
              }}
            >
              <option value="password">Password</option>
              <option value="key">Private SSH Key</option>
            </CcureSelect>

            {/* The secret is typed here and sent once, in the request
                        body. `new-password` stops the browser offering the
                        signed-in user's own password into a field that stores
                        someone else's, and keeps a revealed field out of form
                        history. */}
            {newCredAuthMethod === "password" ? (
              <CcurePasswordField
                label="Password"
                value={newCredPassword}
                onChange={(e) => setNewCredPassword(e.target.value)}
                placeholder="••••••••"
                hint="Stored encrypted. The saved list never shows it."
                autoComplete="new-password"
                required
              />
            ) : (
              <CcureTextarea
                id="cwc-key"
                label="Private Key Content"
                hint="Stored encrypted. The saved list never shows it."
                required
                className="cc-field__control cwc-key"
                value={newCredKeyContent}
                onChange={(e) => setNewCredKeyContent(e.target.value)}
                placeholder="-----BEGIN OpenSSH PRIVATE KEY-----..."
                aria-describedby="cwc-key-hint"
              />
            )}

            <CcureButton
              type="submit"
              variant="primary"
              block
              loading={savingCredential}
              className="cwc-submit"
            >
              Save Target Credential
            </CcureButton>
          </form>
        </CcureCard>
      )}

      {/* Deleting asks in a design-system dialog rather than the
                  browser's confirm, which focuses OK: here Cancel takes focus,
                  Escape cancels, and the dialog is busy and cannot be dismissed
                  or confirmed again while the DELETE is out. */}
      <CcureConfirmDialog
        open={credentialToDelete !== null}
        title="Delete credential"
        subtitle="The stored password or key is removed with it. This cannot be undone."
        warning={
          credentialToDelete
            ? `Are you sure you want to delete ${credentialToDelete.name}?`
            : null
        }
        confirmLabel="Delete credential"
        busy={deletingCredential}
        onCancel={() => setCredentialToDelete(null)}
        onConfirm={async () => {
          if (deletingCredential || !credentialToDelete) return;
          const c = credentialToDelete;
          setDeletingCredential(true);
          try {
            await deleteCredential(c.id);
            pushToast("Credential deleted successfully.", "success");
            fetchTabData();
          } catch (e) {
            pushToast(
              "Delete failed: " +
                (e.response?.data?.detail ||
                  e.response?.data?.message ||
                  e.message),
              "error",
            );
          } finally {
            setDeletingCredential(false);
            setCredentialToDelete(null);
          }
        }}
      />
    </div>
  );
}
