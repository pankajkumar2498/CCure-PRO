import { useEffect, useMemo, useState } from "react";
import Button from "../common/Button";
import FormField from "../common/FormField";
import RoleSelector from "../common/RoleSelector";
import { checkUsername, checkEmail } from "../../api/auth";
import { useDebounce } from "../../hooks/useDebounce";
import { isSuperAdmin } from "../../auth/permissions";

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
  const [usernameTaken, setUsernameTaken] = useState(false);
  const [emailTaken, setEmailTaken] = useState(false);

  const debouncedUsername = useDebounce(form.username, 500);
  const debouncedEmail = useDebounce(form.email, 500);

  useEffect(() => {
    if (mode === "create" && debouncedUsername.length >= 3) {
      checkUsername(debouncedUsername).then(res => setUsernameTaken(!res.available)).catch(() => { });
    } else {
      setUsernameTaken(false);
    }
  }, [debouncedUsername, mode]);

  useEffect(() => {
    if (mode === "edit" && user?.email === debouncedEmail) {
      setEmailTaken(false);
      return;
    }

    if (/\S+@\S+\.\S+/.test(debouncedEmail)) {
      checkEmail(debouncedEmail).then(res => setEmailTaken(!res.available)).catch(() => { });
    } else {
      setEmailTaken(false);
    }
  }, [debouncedEmail, mode, user]);
  const title = mode === "create" ? "Create new user" : "Edit user details";
  const submitLabel = mode === "create" ? "Create user" : "Save changes";
  const isSuperadmin = isSuperAdmin(currentUser);

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
  const canSubmit = (mode === "create"
    ? form.username.trim() && form.email.trim() && form.password.trim() && isRoleSelected && isOrganizationSelected
    : form.email.trim() && isRoleSelected && isOrganizationSelected) && !usernameTaken && !emailTaken;

  const handleChange = (field) => (event) => {
    const value = event.target.value;
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!canSubmit) return;
    onSubmit({ ...form, email: form.email.trim().toLowerCase() });
  };

  return (
    <div className="card card--admin-form">
      <div className="form-card-header">
        <div>
          <h3 className="card-title">{title}</h3>
          <p className="card-subtitle">Manage access, role assignments, and account details.</p>
        </div>
      </div>

      <form className="form-horizontal" onSubmit={handleSubmit}>
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
            {usernameTaken && (
              <span className="field-hint field-hint--error" style={{ color: "var(--danger)" }}>This username is already taken.</span>
            )}
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
            placeholder="jane.doe@ccure.com"
            value={form.email}
            onChange={handleChange("email")}
            disabled={busy}
            required
          />
          {emailTaken && (
            <span className="field-hint field-hint--error" style={{ color: "var(--danger)" }}>This email is already taken.</span>
          )}
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
            {usernameTaken && (
              <span className="field-hint field-hint--error" style={{ color: "var(--danger)" }}>This username is already taken.</span>
            )}
          </FormField>
        )}

        <RoleSelector
          label="Role"
          roles={roles}
          value={form.role_id}
          onChange={(role_id) => setForm((prev) => ({ ...prev, role_id }))}
          disabled={busy}
        />

        {isSuperadmin && (
          <FormField label="Organization">
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
