import { useEffect, useMemo, useState } from "react";
import Button from "../common/Button";
import FormField from "../common/FormField";
import RoleSelector from "../common/RoleSelector";

const createInitial = {
  username: "",
  full_name: "",
  email: "",
  password: "",
  role_id: "",
  organization_id: "",
};

export default function UserForm({
  mode = "create",
  user,
  roles = [],
  organizations = [],
  currentUser = null,
  onSubmit,
  onCancel,
  busy,
}) {
  const [form, setForm] = useState(createInitial);
  const title = mode === "create" ? "Create new user" : "Edit user details";
  const submitLabel = mode === "create" ? "Create user" : "Save changes";
  const roleName = currentUser?.role?.name?.toLowerCase() || "";
  const isSuperadmin = roleName === "superadmin";

  useEffect(() => {
    if (mode === "edit" && user) {
      setForm({
        username: user.username || "",
        full_name: user.full_name || "",
        email: user.email || "",
        password: "",
        role_id: user.role_id ?? "",
        organization_id: user.organization_id || user.org_id || "",
      });
    } else {
      setForm({
        ...createInitial,
        organization_id: isSuperadmin ? "" : currentUser?.org_id || "",
      });
    }
  }, [currentUser?.org_id, isSuperadmin, mode, user]);

  const isRoleSelected = useMemo(() => !!form.role_id, [form.role_id]);
  const isOrganizationSelected = useMemo(
    () => !isSuperadmin || !!form.organization_id,
    [form.organization_id, isSuperadmin]
  );
  const canSubmit = mode === "create"
    ? form.username.trim() && form.email.trim() && form.password.trim() && isRoleSelected && isOrganizationSelected
    : form.email.trim() && isRoleSelected && isOrganizationSelected;

  const handleChange = (field) => (event) => {
    const value = event.target.value;
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!canSubmit) return;
    onSubmit({ ...form });
  };

  return (
    <div className="card card--admin-form">
      <div className="form-card-header">
        <div>
          <h3 className="card-title">{title}</h3>
          <p className="card-subtitle">Manage access, role assignments, and account details.</p>
        </div>
      </div>

      <form className="user-form-grid" onSubmit={handleSubmit}>
        {mode === "create" && (
          <FormField label="Username" htmlFor="username">
            <input
              id="username"
              className="field-input"
              type="text"
              placeholder="jane.doe"
              value={form.username}
              onChange={handleChange("username")}
              disabled={busy}
              required
            />
          </FormField>
        )}

        <FormField label="Full name" htmlFor="fullName">
          <input
            id="fullName"
            className="field-input"
            type="text"
            placeholder="Jane Doe"
            value={form.full_name}
            onChange={handleChange("full_name")}
            disabled={busy}
          />
        </FormField>

        <FormField label="Email address" htmlFor="email">
          <input
            id="email"
            className="field-input"
            type="email"
            placeholder="jane.doe@example.com"
            value={form.email}
            onChange={handleChange("email")}
            disabled={busy}
            required
          />
        </FormField>

        {mode === "create" && (
          <FormField label="Password" htmlFor="password">
            <input
              id="password"
              className="field-input"
              type="password"
              placeholder="Create secure password"
              value={form.password}
              onChange={handleChange("password")}
              disabled={busy}
              required
            />
          </FormField>
        )}

        <FormField label="Role" className="field--full">
          <RoleSelector
            roles={roles}
            value={form.role_id}
            onChange={(role_id) => setForm((prev) => ({ ...prev, role_id }))}
            disabled={busy}
          />
        </FormField>

        {isSuperadmin && (
          <FormField label="Organization" className="field--full">
            <select
              className="field-input"
              value={form.organization_id}
              onChange={(event) => setForm((prev) => ({ ...prev, organization_id: event.target.value }))}
              disabled={busy}
              required
            >
              <option value="">Select organization</option>
              {organizations.map((organization) => (
                <option key={organization.id} value={organization.id}>
                  {organization.name} ({organization.slug})
                </option>
              ))}
            </select>
          </FormField>
        )}

        <div className="form-action-row">
          <Button type="button" variant="ghost" size="md" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" size="md" loading={busy} disabled={!canSubmit || busy}>
            {submitLabel}
          </Button>
        </div>
      </form>
    </div>
  );
}
