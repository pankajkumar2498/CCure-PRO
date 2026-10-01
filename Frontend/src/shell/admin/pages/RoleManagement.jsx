import { useEffect, useState, useCallback } from "react";
import ProductFrame from "../../layout/ProductFrame";
import { listRoles, listRolePermissions } from "../../api/admin";
import { useToasts, ToastContainer } from "../../feedback/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureEmptyState,
  CcureLoader,
  CcureTable,
} from "../../../design-system";
import "../styles/role-management.css";

/**
 * Roles & Permissions — read-only view of the RBAC catalogue.
 *
 * Checkpoint 3C: the first production page migrated onto the CCure design
 * system. Presentation only — every handler, hook, piece of state and API call
 * below is unchanged from the pre-migration file, and the two endpoints
 * (`GET /admin/roles/`, `GET /admin/roles/{id}/permissions/`) are called in the
 * same order, the same number of times, with the same arguments.
 */

/**
 * Permission actions were previously coloured by hand: `manage` in red
 * (#dc2626 on #fef2f2) and everything else in blue (#0369a1 on #f0f9ff).
 *
 * The distinction is real and worth keeping — `manage` is the broadest grant in
 * the catalogue — so it survives as a semantic variant rather than a literal.
 * The colours now come from tokens and therefore respond to the theme, which
 * the hex never did.
 */
const actionVariant = (action) => (action === "manage" ? "danger" : "info");

export default function RoleManagement() {
  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingPerms, setLoadingPerms] = useState(false);
  const [error, setError] = useState("");
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  // Declared before `loadRoles`, which calls it. A dependency array is
  // evaluated during render, so naming `handleSelectRole` in `loadRoles`'s
  // array while it was still declared below would have thrown a temporal dead
  // zone ReferenceError. `pushToast` is a `useCallback([])`, so this identity
  // is stable and neither the callback below nor its effect re-runs.
  const handleSelectRole = useCallback(
    async (role) => {
      setSelectedRole(role);
      setLoadingPerms(true);
      try {
        const data = await listRolePermissions(role.id);
        setPermissions(data.permissions);
      } catch (err) {
        pushToast("Failed to load permissions for this role.", "error");
      } finally {
        setLoadingPerms(false);
      }
    },
    [pushToast],
  );

  const loadRoles = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listRoles();
      setRoles(data.roles);
      if (data.roles.length > 0) {
        handleSelectRole(data.roles[0]);
      }
    } catch (err) {
      setError("Failed to load roles.");
    } finally {
      setLoading(false);
    }
  }, [handleSelectRole]);

  useEffect(() => {
    loadRoles();
  }, [loadRoles]);

  if (loading) {
    return (
      <ProductFrame pageTitle="Roles & Permissions">
        {/* Was a bare `<div className="spinner" />` — visible, but announced
            nothing at all. CcureLoader carries a polite live region. */}
        <CcureLoader label="Loading roles…" />
      </ProductFrame>
    );
  }

  const permissionColumns = [
    {
      key: "resource",
      header: "Resource",
      // scope="row": the resource identifies its row, so a reader announces
      // "scans, Action, execute" rather than a naked value.
      isRowHeader: true,
      mono: true,
      nowrap: true,
    },
    {
      key: "action",
      header: "Action",
      nowrap: true,
      cell: (p) => (
        <CcureBadge variant={actionVariant(p.action)}>{p.action}</CcureBadge>
      ),
    },
    {
      key: "description",
      header: "Description",
      cell: (p) => p.description || `Allows access to ${p.resource}`,
    },
  ];

  return (
    <ProductFrame pageTitle="Roles & Permissions">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Roles &amp; Permissions</h2>
            <p className="page-subtitle">
              View system roles and their granular access control
            </p>
          </div>
        </div>

        {error && (
          // role="alert" — a load failure appearing after the request settles
          // is an event, and the page renders nothing else useful when it
          // happens.
          <CcureAlert variant="danger" className="rm-alert">
            {error}
          </CcureAlert>
        )}

        <div className="admin-grid">
          <CcureCard title="Roles" headingLevel={3} bodyFlush>
            <div className="rm-role-list">
              {roles.map((r) => (
                <CcureButton
                  key={r.id}
                  type="button"
                  variant="ghost"
                  size="md"
                  block
                  // aria-pressed is the whole point of using a button here:
                  // the pre-migration page styled the selected role but
                  // announced nothing, so a screen-reader user could not tell
                  // which role the permissions panel belonged to.
                  aria-pressed={selectedRole?.id === r.id}
                  className="rm-role"
                  onClick={() => handleSelectRole(r)}
                >
                  <span className="rm-role__name">{r.name}</span>
                  <span className="rm-role__description">
                    {r.description || "No description"}
                  </span>
                </CcureButton>
              ))}
            </div>
          </CcureCard>

          <CcureCard
            title={`Permissions for ${selectedRole?.name ?? "—"}`}
            subtitle="Granted capabilities for this role"
            headingLevel={3}
            bodyFlush
          >
            <CcureTable
              // The table had no caption before, so it was announced as
              // "table" with no indication of what it held.
              caption={`Permissions granted to the ${selectedRole?.name ?? "selected"} role`}
              columns={permissionColumns}
              rows={permissions}
              rowKey={(p) => p.id}
              loading={loadingPerms}
              loadingRows={3}
              density="compact"
              empty={
                <CcureEmptyState
                  title="No permissions assigned to this role."
                  description="This role grants no capabilities."
                />
              }
            />
            {loadingPerms && (
              // The skeleton rows are aria-hidden, so without this the load is
              // silent to a screen reader.
              <p className="cc-sr-only" role="status" aria-live="polite">
                Loading permissions…
              </p>
            )}
          </CcureCard>
        </div>
      </div>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </ProductFrame>
  );
}
