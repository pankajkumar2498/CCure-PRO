import { useEffect, useMemo, useState } from "react";
import Button from "../common/Button";
import FormField from "../common/FormField";

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

  useEffect(() => {
    setName(organization.name || "");
    setSlug(organization.slug || "");
    setPlan(organization.plan || "community");
    setStatus((organization.is_active ?? true) ? "active" : "inactive");
    setMaxAssets(organization.max_assets ?? 500);
    setMaxUsers(organization.max_users ?? 10);
  }, [organization]);

  const isValid = useMemo(
    () =>
      name.trim().length >= 3 &&
      slug.trim().length >= 2 &&
      Number(maxAssets) > 0 &&
      Number(maxUsers) > 0,
    [name, slug, maxAssets, maxUsers]
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

      <div className="form-grid">
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

        <FormField label="URL slug" htmlFor="organization-slug">
          <input
            id="organization-slug"
            className="field-input"
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
            placeholder="acme-security"
          />
          <div className="field-hint">
            {mode === "edit"
              ? "Changing the slug will affect organization URLs and API identifiers."
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

      <div className="form-actions">
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
