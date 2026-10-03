/**
 * src/shell/admin/components/RolePermissionEditor.jsx — pick a role's permissions
 * from the backend's catalogue (RBAC-7).
 *
 * Nothing is hardcoded here: the list is what `GET /platform/rbac/permissions`
 * returns, grouped by module and resource, each row showing scope, sensitivity and
 * whether an organisation role may hold it. An administrator cannot type a key — only
 * tick one the catalogue offers — and a retired permission, one an organisation role
 * cannot hold, and one beyond the administrator's own delegation are shown but not
 * selectable. That is a convenience: the backend refuses all of it again.
 */
import { useMemo } from "react";
import { CcureBadge } from "../../../design-system";
import { can } from "../../auth/permissions";

const groupByModule = (catalogue) => {
  const modules = new Map();
  for (const p of catalogue) {
    if (!modules.has(p.module)) modules.set(p.module, new Map());
    const resources = modules.get(p.module);
    if (!resources.has(p.resource)) resources.set(p.resource, []);
    resources.get(p.resource).push(p);
  }
  return modules;
};

export function whyUnavailable(permission, { orgRole, user }) {
  if (permission.status === "retired")
    return "Retired permissions cannot be assigned.";
  if (orgRole && permission.scope === "platform")
    return "A platform-wide permission cannot be held by an organisation role.";
  if (orgRole && !permission.delegable)
    return "This permission cannot be delegated to an organisation role.";
  if (!can(user, permission.key))
    return "Beyond your own delegation: you cannot grant what you do not hold.";
  return "";
}

export default function RolePermissionEditor({
  catalogue,
  selected,
  onToggle,
  user,
  orgRole,
  readOnly,
}) {
  const modules = useMemo(() => groupByModule(catalogue), [catalogue]);
  if (catalogue.length === 0) {
    return (
      <p className="rm-muted">The permission catalogue is not available.</p>
    );
  }
  return (
    <div className="rm-perms" role="group" aria-label="Permissions">
      {[...modules.entries()].map(([module, resources]) => (
        <section key={module} className="rm-perm-module">
          <h4 className="rm-perm-module__title">{module}</h4>
          {[...resources.entries()].map(([resource, perms]) => (
            <fieldset key={resource} className="rm-perm-resource">
              <legend>{resource}</legend>
              {perms.map((p) => {
                const checked = selected.has(p.key);
                const reason = whyUnavailable(p, { orgRole, user });
                // a held key stays removable even when it could not be newly granted
                const disabled = readOnly || (!checked && !!reason);
                return (
                  <label
                    key={p.key}
                    className={`rm-perm${disabled ? " rm-perm--off" : ""}`}
                    title={disabled && reason ? reason : p.description}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={disabled}
                      onChange={() => onToggle(p.key)}
                      aria-label={p.key}
                    />
                    <span className="rm-perm__action">{p.action}</span>
                    <span className="rm-perm__desc">{p.description}</span>
                    <CcureBadge variant="info">{p.scope}</CcureBadge>
                    {p.sensitivity === "privileged" && (
                      <CcureBadge variant="danger">privileged</CcureBadge>
                    )}
                    {!p.delegable && (
                      <CcureBadge variant="neutral">not delegable</CcureBadge>
                    )}
                    {p.status !== "active" && (
                      <CcureBadge variant="warning">{p.status}</CcureBadge>
                    )}
                    {disabled && !readOnly && reason && (
                      <span className="cc-sr-only">{reason}</span>
                    )}
                  </label>
                );
              })}
            </fieldset>
          ))}
        </section>
      ))}
    </div>
  );
}
