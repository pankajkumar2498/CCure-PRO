/**
 * src/shell/admin/components/UserRolesPanel.jsx — a user's role assignments (RBAC-7).
 *
 * Shows what the platform RBAC API reports — each role's display name, kind and state,
 * its scope and the assignment's status — and offers to assign or end one. The roles on
 * offer are exactly those the backend marks `assignable` for the signed-in account
 * (`GET /platform/rbac/assignable-roles`: organisation boundary, delegation ceiling,
 * system-role restrictions, self-assignment); the rest are listed with the backend's
 * reasons and cannot be chosen. No role label decides any of it, and the backend checks
 * the assignment again. Role names here are display text.
 */
import { useCallback, useEffect, useState } from "react";
import {
  assignRbacRole,
  getUserAssignments,
  listAssignableRoles,
  reauthRequired,
  refusalMessages,
  revokeRbacAssignment,
} from "../../api/rbac";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureLoader,
  CcureSelect,
  CcureTable,
} from "../../../design-system";
import { can } from "../../auth/permissions";
import ReauthDialog from "./ReauthDialog";

const statusVariant = {
  active: "success",
  revoked: "neutral",
  expired: "warning",
};

export default function UserRolesPanel({ user, currentUser }) {
  const [assignments, setAssignments] = useState(null);
  const [offer, setOffer] = useState(null);
  const [choice, setChoice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState(null);
  const canAssignOrg = can(currentUser, "platform.user.assign_role", {
    orgId: user.organization_id || user.org_id,
  });
  const canAssignPlatform = can(currentUser, "platform.role.assign_platform", {
    scope: "platform",
  });
  const canAssign = canAssignOrg || canAssignPlatform;

  const load = useCallback(async () => {
    setError("");
    try {
      const [a, o] = await Promise.all([
        getUserAssignments(user.id),
        listAssignableRoles({
          userId: user.id,
          orgId: user.organization_id || user.org_id,
        }),
      ]);
      setAssignments(a.assignments);
      setOffer(o);
    } catch (err) {
      setError(refusalMessages(err).join(" "));
      setAssignments([]);
    }
  }, [user]);

  useEffect(() => {
    load();
  }, [load]);

  const act = async (fn, opts = {}) => {
    setBusy(true);
    setError("");
    try {
      await fn(opts);
      setChoice("");
      await load();
    } catch (err) {
      if (reauthRequired(err) && !opts.reauthCode) setPending(() => fn);
      else setError(refusalMessages(err).join(" "));
    } finally {
      setBusy(false);
    }
  };

  if (assignments === null) return <CcureLoader label="Loading roles…" />;

  const live = new Set(
    assignments.filter((a) => a.status === "active").map((a) => a.role.id),
  );
  const options = (offer?.roles || []).filter(
    (r) => r.assignable && !live.has(r.id),
  );
  const refused = (offer?.roles || []).filter((r) => !r.assignable);

  return (
    <div className="um-roles">
      {error && <CcureAlert variant="danger">{error}</CcureAlert>}
      <CcureTable
        caption={`Role assignments for ${user.username}`}
        columns={[
          { key: "role", header: "Role" },
          { key: "kind", header: "Kind" },
          { key: "scope", header: "Scope" },
          { key: "status", header: "Status" },
          { key: "actions", header: "Actions", align: "end" },
        ]}
      >
        {assignments.length === 0 && (
          <tr>
            <td colSpan={5}>
              No active RBAC role assignments. This account has no role-based
              access.
            </td>
          </tr>
        )}
        {assignments.map((a) => (
          <tr key={a.id}>
            <th scope="row">
              {a.role.display_name}
              {a.role.state !== "active" && (
                <CcureBadge variant="warning">{a.role.state}</CcureBadge>
              )}
            </th>
            <td>{a.role.kind}</td>
            <td>
              {a.scope_type === "platform"
                ? "platform"
                : `organisation ${a.scope_org_id}`}
            </td>
            <td>
              <CcureBadge variant={statusVariant[a.status] || "neutral"}>
                {a.status}
              </CcureBadge>
            </td>
            <td>
              {(a.scope_type === "platform"
                ? canAssignPlatform
                : canAssignOrg) &&
                a.status === "active" && (
                  <CcureButton
                    type="button"
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    aria-label={`Remove ${a.role.display_name} from ${user.username}`}
                    onClick={() => act((o) => revokeRbacAssignment(a.id, o))}
                  >
                    Remove
                  </CcureButton>
                )}
            </td>
          </tr>
        ))}
      </CcureTable>

      {canAssign && (
        <div className="um-roles__assign">
          <CcureSelect
            id="um-assign-role"
            label="Assign a role"
            value={choice}
            onChange={(e) => setChoice(e.target.value)}
          >
            <option value="">Choose a role</option>
            {options.map((r) => (
              <option key={r.id} value={r.id}>
                {r.display_name}
              </option>
            ))}
          </CcureSelect>
          <CcureButton
            type="button"
            disabled={!choice || busy}
            onClick={() => act((o) => assignRbacRole(user.id, choice, o))}
          >
            Assign
          </CcureButton>
          {refused.length > 0 && (
            <p className="um-roles__note">
              Not available to you:{" "}
              {refused
                .map(
                  (r) =>
                    `${r.display_name} (${r.reasons.join(", ") || "refused"})`,
                )
                .join("; ")}
            </p>
          )}
        </div>
      )}
      <ReauthDialog
        open={!!pending}
        busy={busy}
        onCancel={() => setPending(null)}
        onSubmit={(code) => {
          const fn = pending;
          setPending(null);
          act(fn, { reauthCode: code });
        }}
      />
    </div>
  );
}
