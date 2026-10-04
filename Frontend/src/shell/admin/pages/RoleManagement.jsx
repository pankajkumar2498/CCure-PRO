import { useCallback, useEffect, useMemo, useState } from "react";
import ProductFrame from "../../layout/ProductFrame";
import {
  createRbacRole,
  getRbacRole,
  listPermissionCatalogue,
  listRbacRoles,
  reauthRequired,
  refusalMessages,
  replaceRbacRole,
  setRbacRolePermissions,
  transitionRbacRole,
  updateRbacRole,
} from "../../api/rbac";
import { useAuth } from "../../auth/AuthContext";
import { can } from "../../auth/permissions";
import { useToasts, ToastContainer } from "../../feedback/Toast";
import {
  CcureAlert,
  CcureButton,
  CcureCard,
  CcureCheckbox,
  CcureInput,
  CcureLoader,
  CcureModal,
  CcureSelect,
} from "../../../design-system";
import ReauthDialog from "../components/ReauthDialog";
import RolePermissionEditor from "../components/RolePermissionEditor";
import "../styles/role-management.css";

/**
 * Roles & Permissions — Platform RBAC administration (RBAC-7).
 *
 * Every control is driven by what the backend says the signed-in account may do
 * (`can(user, key)` over the authorization payload) and by what the backend returns
 * for each role (`kind`, `state`, `retirement_blockers`, `sensitive`). A role's
 * display name is a label: nothing here branches on it. The page is advisory — each
 * change is checked again by the backend, and a refusal is shown as the backend's
 * own reasons.
 */

export default function RoleManagement() {
  const { user } = useAuth();
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const [roles, setRoles] = useState([]);
  const [catalogue, setCatalogue] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [draft, setDraft] = useState(new Set());
  const [name, setName] = useState("");
  const [showRetired, setShowRetired] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newKeys, setNewKeys] = useState(new Set());
  const [replaceTo, setReplaceTo] = useState("");
  const [pending, setPending] = useState(null);

  const canCreate = can(user, "platform.role.create");

  const loadRoles = useCallback(async () => {
    const data = await listRbacRoles({ includeRetired: showRetired });
    setRoles(data.roles);
    return data.roles;
  }, [showRetired]);

  const loadDetail = useCallback(async (id) => {
    const d = await getRbacRole(id);
    setDetail(d);
    setDraft(new Set(d.permissions));
    setName(d.display_name);
    setReplaceTo("");
    return d;
  }, []);

  useEffect(() => {
    let live = true;
    (async () => {
      setLoading(true);
      try {
        const [list, cat] = await Promise.all([
          loadRoles(),
          listPermissionCatalogue(),
        ]);
        if (!live) return;
        setCatalogue(cat.permissions);
        if (list.length > 0) {
          setSelectedId(list[0].id);
          await loadDetail(list[0].id);
        }
      } catch (err) {
        if (live) setError("Failed to load roles.");
      } finally {
        if (live) setLoading(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [loadRoles, loadDetail]);

  const select = async (role) => {
    setSelectedId(role.id);
    try {
      await loadDetail(role.id);
    } catch {
      pushToast("Failed to load this role.", "error");
    }
  };

  // Run one governed change. A step-up request pauses it for an authenticator code;
  // a refusal shows the backend's reasons and changes nothing.
  const run = async (fn, done) => {
    setBusy(true);
    try {
      await fn({});
      await loadRoles();
      if (selectedId) await loadDetail(selectedId);
      if (done) pushToast(done, "success");
    } catch (err) {
      if (reauthRequired(err)) {
        setPending({ fn, done });
      } else {
        pushToast(refusalMessages(err).join(" "), "error");
      }
    } finally {
      setBusy(false);
    }
  };

  const confirmReauth = async (code) => {
    const { fn, done } = pending;
    setPending(null);
    setBusy(true);
    try {
      await fn({ reauthCode: code });
      await loadRoles();
      if (selectedId) await loadDetail(selectedId);
      if (done) pushToast(done, "success");
    } catch (err) {
      pushToast(refusalMessages(err).join(" "), "error");
    } finally {
      setBusy(false);
    }
  };

  const isSystem = detail?.kind === "system";
  const orgRole = detail ? detail.assignable_scope === "organization" : true;
  const canRename = detail
    ? isSystem
      ? can(user, "platform.role.rename_system")
      : can(user, "platform.role.update")
    : false;
  const canEditPermissions =
    !!detail &&
    !isSystem &&
    detail.state === "active" &&
    can(user, "platform.role.update");
  const canRetire = detail
    ? isSystem
      ? can(user, "platform.role.retire_system")
      : can(user, "platform.role.retire")
    : false;

  const dirty = useMemo(() => {
    if (!detail) return false;
    const a = [...draft].sort().join();
    return a !== [...detail.permissions].sort().join();
  }, [draft, detail]);

  const toggle = (setter) => (key) =>
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const replacements = roles.filter(
    (r) =>
      detail &&
      r.id !== detail.id &&
      r.state === "active" &&
      r.assignable_scope === detail.assignable_scope,
  );

  if (loading) {
    return (
      <ProductFrame pageTitle="Roles & Permissions">
        <div className="page-inner">
          <CcureLoader label="Loading roles…" />
        </div>
      </ProductFrame>
    );
  }

  return (
    <ProductFrame pageTitle="Roles & Permissions">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h1 className="page-title">Roles &amp; Permissions</h1>
            <p className="page-subtitle">
              Manage roles, their permissions and their lifecycle. Names are
              labels; what a role can do is its permissions.
            </p>
          </div>
          <div className="rm-toolbar">
            <CcureCheckbox
              checked={showRetired}
              onChange={(e) => setShowRetired(e.target.checked)}
            >
              Show retired roles
            </CcureCheckbox>
            {canCreate && (
              <CcureButton type="button" onClick={() => setCreating(true)}>
                New custom role
              </CcureButton>
            )}
          </div>
        </div>

        {error && (
          <CcureAlert variant="danger" className="rm-alert">
            {error}
          </CcureAlert>
        )}

        <div className="rm-grid">
          <CcureCard title="Roles" headingLevel={2} bodyFlush>
            <div className="rm-role-list">
              {roles.map((r) => (
                <CcureButton
                  key={r.id}
                  type="button"
                  variant="ghost"
                  size="md"
                  block
                  aria-pressed={selectedId === r.id}
                  className="rm-role"
                  onClick={() => select(r)}
                >
                  <span className="rm-role__name">{r.display_name}</span>
                  <span className="rm-role__description">
                    {r.kind} · {r.state} · {r.permission_count} permissions ·{" "}
                    {r.assignment_count} holders
                  </span>
                </CcureButton>
              ))}
            </div>
          </CcureCard>

          {detail && (
            <CcureCard
              title={detail.display_name}
              subtitle={`${detail.kind} role · ${detail.assignable_scope} scope · ${detail.state}`}
              headingLevel={2}
            >
              <div className="rm-section">
                <CcureInput
                  id="rm-name"
                  label="Display name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={!canRename || detail.state === "retired" || busy}
                  hint="A label only. Renaming a role changes nothing it can do."
                />
                <CcureButton
                  type="button"
                  disabled={
                    !canRename ||
                    busy ||
                    name.trim() === detail.display_name ||
                    !name.trim()
                  }
                  onClick={() =>
                    run(
                      (opts) =>
                        updateRbacRole(
                          detail.id,
                          { display_name: name.trim() },
                          opts,
                        ),
                      "Role renamed.",
                    )
                  }
                >
                  Save name
                </CcureButton>
              </div>

              <div className="rm-section">
                <h3>Permissions</h3>
                {isSystem && (
                  <p className="rm-muted">
                    A system role&apos;s permissions change with a catalogue
                    release, not here.
                  </p>
                )}
                <RolePermissionEditor
                  catalogue={catalogue}
                  selected={draft}
                  onToggle={toggle(setDraft)}
                  user={user}
                  orgRole={orgRole}
                  readOnly={!canEditPermissions || busy}
                />
                {canEditPermissions && (
                  <CcureButton
                    type="button"
                    disabled={!dirty || busy}
                    onClick={() =>
                      run(
                        (opts) =>
                          setRbacRolePermissions(detail.id, [...draft], opts),
                        "Permissions updated.",
                      )
                    }
                  >
                    Save permissions
                  </CcureButton>
                )}
              </div>

              <div className="rm-section">
                <h3>Lifecycle</h3>
                <p className="rm-muted">
                  {detail.assignment_count} active assignment
                  {detail.assignment_count === 1 ? "" : "s"}.
                  {detail.retirement_blockers.length > 0 &&
                    ` To retire this role: ${detail.retirement_blockers.join(", ")}.`}
                </p>
                {canRetire && detail.state === "active" && (
                  <CcureButton
                    type="button"
                    variant="secondary"
                    disabled={busy}
                    onClick={() =>
                      run(
                        (opts) =>
                          transitionRbacRole(
                            detail.id,
                            { target: "retiring" },
                            opts,
                          ),
                        "Role is retiring.",
                      )
                    }
                  >
                    Start retiring
                  </CcureButton>
                )}
                {canRetire && detail.state === "retiring" && (
                  <CcureButton
                    type="button"
                    variant="danger"
                    disabled={busy}
                    onClick={() =>
                      run(
                        (opts) =>
                          transitionRbacRole(
                            detail.id,
                            { target: "retired" },
                            opts,
                          ),
                        "Role retired.",
                      )
                    }
                  >
                    Retire
                  </CcureButton>
                )}
                {canRetire && detail.state === "retired" && (
                  <CcureButton
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      run(
                        (opts) =>
                          transitionRbacRole(
                            detail.id,
                            { target: "active" },
                            opts,
                          ),
                        "Role reactivated.",
                      )
                    }
                  >
                    Reactivate
                  </CcureButton>
                )}
                {canRetire &&
                  detail.state !== "retired" &&
                  detail.assignment_count > 0 && (
                    <div className="rm-replace">
                      <CcureSelect
                        id="rm-replace"
                        label="Move holders to"
                        value={replaceTo}
                        onChange={(e) => setReplaceTo(e.target.value)}
                      >
                        <option value="">Choose a replacement role</option>
                        {replacements.map((r) => (
                          <option key={r.id} value={r.id}>
                            {r.display_name}
                          </option>
                        ))}
                      </CcureSelect>
                      <CcureButton
                        type="button"
                        disabled={!replaceTo || busy}
                        onClick={() =>
                          run(
                            (opts) =>
                              replaceRbacRole(detail.id, replaceTo, opts),
                            "Assignments moved.",
                          )
                        }
                      >
                        Move assignments
                      </CcureButton>
                    </div>
                  )}
              </div>

              <div className="rm-section">
                <h3>History</h3>
                <ul className="rm-history">
                  {detail.history.map((h) => (
                    <li key={`${h.revision}-${h.change_kind}`}>
                      #{h.revision} {h.change_kind} — {h.display_name} (
                      {h.state})
                    </li>
                  ))}
                </ul>
              </div>
            </CcureCard>
          )}
        </div>
      </div>

      <CcureModal
        open={creating}
        onClose={() => setCreating(false)}
        title="New custom role"
        subtitle="Belongs to your organisation and can hold only permissions you may delegate."
        size="lg"
        footer={
          <>
            <CcureButton
              type="button"
              variant="ghost"
              onClick={() => setCreating(false)}
            >
              Cancel
            </CcureButton>
            <CcureButton
              type="button"
              disabled={!newName.trim() || busy}
              onClick={async () => {
                setCreating(false);
                await run(
                  (opts) =>
                    createRbacRole(
                      {
                        display_name: newName.trim(),
                        permission_keys: [...newKeys],
                      },
                      opts,
                    ),
                  "Role created.",
                );
                setNewName("");
                setNewKeys(new Set());
              }}
            >
              Create role
            </CcureButton>
          </>
        }
      >
        <CcureInput
          id="rm-new-name"
          label="Display name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
        />
        <RolePermissionEditor
          catalogue={catalogue}
          selected={newKeys}
          onToggle={toggle(setNewKeys)}
          user={user}
          orgRole
          readOnly={false}
        />
      </CcureModal>

      <ReauthDialog
        open={!!pending}
        busy={busy}
        onCancel={() => setPending(null)}
        onSubmit={confirmReauth}
      />
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </ProductFrame>
  );
}
