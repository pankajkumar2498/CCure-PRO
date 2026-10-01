/**
 * components/admin/UserForm.jsx — Checkpoint 3C batch 13.
 *
 * The create/edit form UserManagement mounts inside its dialog. Same props,
 * same validation, same submit payload (`{ ...form, email: lowercased }`) as
 * before the migration; the availability checks are the same debounced calls.
 *
 * What changed is only how the fields are built:
 *   * every control is a CcureInput / CcureSelect, so the Role and
 *     Organization selects — previously a <label> with no `for` — are
 *     associated with their labels;
 *   * the password is a CcurePasswordField: type=password, visibility toggle,
 *     `autocomplete="new-password"` so a browser never offers the admin's own
 *     credential into a field that creates someone else's. The value reaches
 *     `onSubmit` and nothing else: no attribute, name or text carries it;
 *   * "already taken" is a field error (role=alert, aria-invalid) rather than
 *     a coloured span, so it is announced and blocks submit as it always did.
 *
 * `RoleSelector` was a <select> with an unassociated label and one consumer;
 * it is a CcureSelect here and the file is retired in this batch.
 */
import { useEffect, useMemo, useState } from "react";
import { checkUsername, checkEmail } from "@shell/api/auth";
import { useDebounce } from "@shell/hooks/useDebounce";
import { isSuperAdmin } from "@shell/auth/permissions";
import {
  CcureButton,
  CcureInput,
  CcurePasswordField,
  CcureSelect,
} from "../../../../design-system";

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
      checkUsername(debouncedUsername)
        .then((res) => setUsernameTaken(!res.available))
        .catch(() => {});
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
      checkEmail(debouncedEmail)
        .then((res) => setEmailTaken(!res.available))
        .catch(() => {});
    } else {
      setEmailTaken(false);
    }
  }, [debouncedEmail, mode, user]);

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
    [form.organization_id, isSuperadmin],
  );
  const canSubmit =
    (mode === "create"
      ? form.username.trim() &&
        form.email.trim() &&
        form.password.trim() &&
        isRoleSelected &&
        isOrganizationSelected
      : form.email.trim() && isRoleSelected && isOrganizationSelected) &&
    !usernameTaken &&
    !emailTaken;

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
    <form className="um-form" onSubmit={handleSubmit}>
      <p className="um-form__lead">
        Manage access, role assignments, and account details.
      </p>

      {mode === "create" && (
        <CcureInput
          id="um-username"
          label="Username"
          type="text"
          placeholder="jane.doe"
          value={form.username}
          onChange={handleChange("username")}
          disabled={busy}
          required
          autoComplete="off"
          error={usernameTaken ? "This username is already taken." : undefined}
        />
      )}

      <CcureInput
        id="um-full-name"
        label="Full name"
        type="text"
        placeholder="Jane Doe"
        value={form.full_name}
        onChange={handleChange("full_name")}
        disabled={busy}
        autoComplete="off"
      />

      <CcureInput
        id="um-email"
        label="Email address"
        type="email"
        placeholder="jane.doe@ccure.com"
        value={form.email}
        onChange={handleChange("email")}
        disabled={busy}
        required
        autoComplete="off"
        error={emailTaken ? "This email is already taken." : undefined}
      />

      {mode === "create" && (
        <CcurePasswordField
          id="um-password"
          label="Password"
          placeholder="Create secure password"
          value={form.password}
          onChange={handleChange("password")}
          disabled={busy}
          required
          autoComplete="new-password"
          capsLockWarning={false}
        />
      )}

      <CcureSelect
        id="um-role"
        label="Role"
        value={form.role_id ?? ""}
        onChange={(event) =>
          setForm((prev) => ({
            ...prev,
            role_id: event.target.value ? Number(event.target.value) : "",
          }))
        }
        disabled={busy}
        required
      >
        <option value="">Select role</option>
        {roles.map((role) => (
          <option key={role.id} value={role.id}>
            {role.name}
          </option>
        ))}
      </CcureSelect>

      {isSuperadmin && (
        <CcureSelect
          id="um-organization"
          label="Organization"
          value={form.organization_id}
          onChange={(event) =>
            setForm((prev) => ({
              ...prev,
              organization_id: event.target.value,
            }))
          }
          disabled={busy}
          required
        >
          <option value="">Select organization</option>
          {organizations.map((organization) => (
            <option key={organization.id} value={organization.id}>
              {organization.name} ({organization.slug})
            </option>
          ))}
        </CcureSelect>
      )}

      <div className="um-form__actions">
        <CcureButton variant="secondary" onClick={onCancel} disabled={busy}>
          Cancel
        </CcureButton>
        <CcureButton
          type="submit"
          variant="primary"
          loading={busy}
          disabled={!canSubmit || busy}
        >
          {submitLabel}
        </CcureButton>
      </div>
    </form>
  );
}
