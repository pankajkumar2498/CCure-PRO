/**
 * components/admin/OrganizationForm.jsx — Checkpoint 3C batch 13.
 *
 * The create/edit form OrganizationManagement mounts inside its dialog. Same
 * props and validation: name, slug, `is_active` only with
 * `showStatus`, and — on create, only when any of its fields is filled — the
 * optional initial-administrator block (`admin_username`, `admin_email`,
 * `admin_full_name`, `admin_password`).
 *
 * Batch 5 left this component out of the page migration because of that
 * password: it is credential-handling surface. On CCure primitives it is a
 * CcurePasswordField with `autocomplete="new-password"`, type=password, a
 * visibility toggle, and a value that reaches `onSubmit` and nothing else.
 * The availability errors are field errors (role=alert, aria-invalid) rather
 * than coloured spans placed outside their field.
 */
import { useEffect, useMemo, useState } from "react";
import { checkUsername, checkEmail } from "../../api/auth";
import { useDebounce } from "../../hooks/useDebounce";
import {
  CcureButton,
  CcureInput,
  CcurePasswordField,
  CcureSelect,
} from "../../../design-system";
import "../styles/organization-form.css";

export default function OrganizationForm({
  mode,
  organization = {},
  onSubmit,
  onCancel,
  busy,
  showStatus = false,
}) {
  const [name, setName] = useState(organization.name || "");
  const [slug, setSlug] = useState(organization.slug || "");
  const [status, setStatus] = useState(
    organization.is_active ?? true ? "active" : "inactive",
  );

  // Admin User Provisioning (Creation only)
  const [adminUsername, setAdminUsername] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [adminFullName, setAdminFullName] = useState("");
  const [adminPassword, setAdminPassword] = useState("");

  const [usernameTaken, setUsernameTaken] = useState(false);
  const [emailTaken, setEmailTaken] = useState(false);

  const debouncedUsername = useDebounce(adminUsername, 500);
  const debouncedEmail = useDebounce(adminEmail, 500);

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
    if (mode === "create" && /\S+@\S+\.\S+/.test(debouncedEmail)) {
      checkEmail(debouncedEmail)
        .then((res) => setEmailTaken(!res.available))
        .catch(() => {});
    } else {
      setEmailTaken(false);
    }
  }, [debouncedEmail, mode]);

  useEffect(() => {
    setName(organization.name || "");
    setSlug(organization.slug || "");
    setStatus(organization.is_active ?? true ? "active" : "inactive");
  }, [organization]);

  const isAdminProvisioning =
    adminUsername.trim() || adminEmail.trim() || adminPassword.trim();
  const isAdminValid = isAdminProvisioning
    ? adminUsername.trim().length >= 3 &&
      adminEmail.includes("@") &&
      adminPassword.length >= 6 &&
      !usernameTaken &&
      !emailTaken
    : true;

  const isValid = useMemo(
    () =>
      name.trim().length >= 3 &&
      slug.trim().length >= 2 &&
      (mode === "create" ? isAdminValid : true),
    [name, slug, mode, isAdminValid],
  );

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!isValid) return;

    const payload = {
      name: name.trim(),
      slug: slug.trim(),
    };

    if (mode === "create" && isAdminProvisioning) {
      payload.admin_username = adminUsername.trim();
      payload.admin_email = adminEmail.trim();
      payload.admin_full_name = adminFullName.trim();
      payload.admin_password = adminPassword;
    }

    if (showStatus) {
      payload.is_active = status === "active";
    }

    onSubmit(payload);
  };

  return (
    <form className="of-form" onSubmit={handleSubmit}>
      <div>
        {/* h3: the dialog that mounts this form already carries the h2. */}
        <h3 className="of-title">
          {mode === "edit" ? "Edit organization" : "Add organization"}
        </h3>
        <p className="of-lead">
          Keep organizational metadata accurate for audit and access policies.
        </p>
      </div>

      <div className="of-section">
        <CcureInput
          id="organization-name"
          label="Organization name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Acme Security"
          autoComplete="organization"
          autoFocus
        />

        <CcureInput
          id="organization-slug"
          label="URL"
          value={slug}
          onChange={(event) => setSlug(event.target.value)}
          placeholder="cdac-kp"
          autoComplete="off"
          hint={
            mode === "edit"
              ? "Changing the URL will affect organization URLs and API identifiers."
              : "Used in organization links and API identifiers."
          }
        />

        {showStatus && (
          <CcureSelect
            id="organization-status"
            label="Status"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </CcureSelect>
        )}
      </div>

      {mode === "create" && (
        <fieldset className="of-section of-section--admin">
          <legend className="of-legend">Initial Organization Admin</legend>
          <p className="of-lead">
            Optionally provision an initial administrator for this organization.
          </p>

          <CcureInput
            id="admin-username"
            label="Admin username"
            value={adminUsername}
            onChange={(event) => setAdminUsername(event.target.value)}
            placeholder="admin"
            autoComplete="off"
            error={
              usernameTaken ? "This username is already taken." : undefined
            }
          />

          <CcureInput
            id="admin-email"
            label="Admin email"
            type="email"
            value={adminEmail}
            onChange={(event) => setAdminEmail(event.target.value)}
            placeholder="admin@acme.com"
            autoComplete="off"
            error={emailTaken ? "This email is already taken." : undefined}
          />

          <CcureInput
            id="admin-fullname"
            label="Full name"
            value={adminFullName}
            onChange={(event) => setAdminFullName(event.target.value)}
            placeholder="Jane Doe"
            autoComplete="off"
          />

          <CcurePasswordField
            id="admin-password"
            label="Password"
            value={adminPassword}
            onChange={(event) => setAdminPassword(event.target.value)}
            autoComplete="new-password"
            capsLockWarning={false}
            hint="At least 6 characters. Sent once, to create the administrator; never stored by this form."
          />
        </fieldset>
      )}

      <div className="of-actions">
        <CcureButton variant="secondary" onClick={onCancel} disabled={busy}>
          Cancel
        </CcureButton>
        <CcureButton
          type="submit"
          variant="primary"
          loading={busy}
          disabled={!isValid || busy}
        >
          {busy
            ? mode === "edit"
              ? "Saving…"
              : "Creating…"
            : mode === "edit"
              ? "Save changes"
              : "Create organization"}
        </CcureButton>
      </div>
    </form>
  );
}
