import { useEffect, useMemo, useState } from "react";
import Button from "../common/Button";
import FormField from "../common/FormField";
import { checkUsername, checkEmail } from "../../api/auth";
import { useDebounce } from "../../hooks/useDebounce";

const organizationPlans = [
  { value: "community", label: "Community" },
  { value: "business", label: "Business" },
  { value: "enterprise", label: "Enterprise" },
];

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
  const [plan, setPlan] = useState(organization.plan || "community");
  const [status, setStatus] = useState((organization.is_active ?? true) ? "active" : "inactive");
  const [maxAssets, setMaxAssets] = useState(organization.max_assets ?? 500);
  const [maxUsers, setMaxUsers] = useState(organization.max_users ?? 10);

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
      checkUsername(debouncedUsername).then(res => setUsernameTaken(!res.available)).catch(() => { });
    } else {
      setUsernameTaken(false);
    }
  }, [debouncedUsername, mode]);

  useEffect(() => {
    if (mode === "create" && /\S+@\S+\.\S+/.test(debouncedEmail)) {
      checkEmail(debouncedEmail).then(res => setEmailTaken(!res.available)).catch(() => { });
    } else {
      setEmailTaken(false);
    }
  }, [debouncedEmail, mode]);

  useEffect(() => {
    setName(organization.name || "");
    setSlug(organization.slug || "");
    setPlan(organization.plan || "community");
    setStatus((organization.is_active ?? true) ? "active" : "inactive");
    setMaxAssets(organization.max_assets ?? 500);
    setMaxUsers(organization.max_users ?? 10);
  }, [organization]);

  const isAdminProvisioning = adminUsername.trim() || adminEmail.trim() || adminPassword.trim();
  const isAdminValid = isAdminProvisioning
    ? adminUsername.trim().length >= 3 && adminEmail.includes("@") && adminPassword.length >= 6 && !usernameTaken && !emailTaken
    : true;

  const isValid = useMemo(
    () =>
      name.trim().length >= 3 &&
      slug.trim().length >= 2 &&
      Number(maxAssets) > 0 &&
      Number(maxUsers) > 0 &&
      (mode === "create" ? isAdminValid : true),
    [name, slug, maxAssets, maxUsers, mode, isAdminValid]
  );

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!isValid) return;

    const payload = {
      ...organization,
      name: name.trim(),
      slug: slug.trim(),
      plan,
      max_assets: Number(maxAssets),
      max_users: Number(maxUsers),
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
    <form className="card card--form" onSubmit={handleSubmit}>
      <div className="card__header">
        <div>
          <h2>{mode === "edit" ? "Edit organization" : "Add organization"}</h2>
          <p className="muted-text">Keep organizational metadata accurate for audit, subscription tracking, and access policies.</p>
        </div>
      </div>

      <div className="form-horizontal">
        <FormField label="Organization name" htmlFor="organization-name">
          <input
            id="organization-name"
            className="field-input"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Acme Security"
            autoFocus
          />
        </FormField>

        <FormField label="URL" htmlFor="organization-slug">
          <input
            id="organization-slug"
            className="field-input"
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
            placeholder="cdac-kp"
          />
          <div className="field-hint">
            {mode === "edit"
              ? "Changing the URL will affect organization URLs and API identifiers."
              : "Used in organization links and API identifiers."}
          </div>
        </FormField>

        <FormField label="Subscription plan" htmlFor="organization-plan">
          <select
            id="organization-plan"
            className="field-input"
            value={plan}
            onChange={(event) => setPlan(event.target.value)}
          >
            {organizationPlans.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </FormField>

        {showStatus && (
          <FormField label="Status" htmlFor="organization-status">
            <select
              id="organization-status"
              className="field-input"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </FormField>
        )}

        <FormField label="Max assets" htmlFor="organization-max-assets">
          <input
            id="organization-max-assets"
            className="field-input"
            type="number"
            min="1"
            value={maxAssets}
            onChange={(event) => setMaxAssets(event.target.value)}
          />
        </FormField>

        <FormField label="Max users" htmlFor="organization-max-users">
          <input
            id="organization-max-users"
            className="field-input"
            type="number"
            min="1"
            value={maxUsers}
            onChange={(event) => setMaxUsers(event.target.value)}
          />
        </FormField>
      </div>

      {mode === "create" && (
        <>
          <div className="card__header" style={{ marginTop: "32px", paddingTop: "24px", borderTop: "1px solid var(--border)" }}>
            <div>
              <h2>Initial Organization Admin</h2>
              <p className="muted-text">Optionally provision an initial administrator for this organization.</p>
            </div>
          </div>

          <div className="form-horizontal">
            <FormField label="Admin username" htmlFor="admin-username">
              <input
                id="admin-username"
                className="field-input"
                value={adminUsername}
                onChange={(event) => setAdminUsername(event.target.value)}
                placeholder="admin"
              />
            </FormField>
            {usernameTaken && (
              <span className="field-hint field-hint--error" style={{ color: "var(--danger)", marginTop: "-10px", display: "block" }}>This username is already taken.</span>
            )}

            <FormField label="Admin email" htmlFor="admin-email">
              <input
                id="admin-email"
                className="field-input"
                type="email"
                value={adminEmail}
                onChange={(event) => setAdminEmail(event.target.value)}
                placeholder="admin@acme.com"
              />
            </FormField>
            {emailTaken && (
              <span className="field-hint field-hint--error" style={{ color: "var(--danger)", marginTop: "-10px", display: "block" }}>This email is already taken.</span>
            )}

            <FormField label="Full name" htmlFor="admin-fullname">
              <input
                id="admin-fullname"
                className="field-input"
                value={adminFullName}
                onChange={(event) => setAdminFullName(event.target.value)}
                placeholder="Jane Doe"
              />
            </FormField>

            <FormField label="Password" htmlFor="admin-password">
              <input
                id="admin-password"
                className="field-input"
                type="password"
                value={adminPassword}
                onChange={(event) => setAdminPassword(event.target.value)}
                placeholder="��������"
              />
            </FormField>
          </div>
        </>
      )}

      <div className="form-actions" style={{ marginTop: "32px" }}>
        <Button type="button" variant="ghost" size="md" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" size="md" loading={busy} disabled={!isValid || busy}>
          {busy ? (mode === "edit" ? "Saving…" : "Creating…") : mode === "edit" ? "Save changes" : "Create organization"}
        </Button>
      </div>
    </form>
  );
}




