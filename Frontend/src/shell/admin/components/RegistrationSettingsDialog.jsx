import { useEffect, useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import { can } from "../../auth/permissions";
import {
  getRegistrationSettings,
  updateRegistrationSettings,
} from "../../api/registrationSettings";
import { reauthRequired, refusalMessages } from "../../api/rbac";
import ReauthDialog from "./ReauthDialog";
import {
  CcureAlert,
  CcureButton,
  CcureCheckbox,
  CcureLoader,
  CcureModal,
} from "../../../design-system";
import "../styles/registration-settings.css";

const validPolicy = (value) =>
  typeof value?.self_registration_enabled === "boolean" &&
  typeof value?.deployment_default === "boolean" &&
  typeof value?.administrator_approval_required === "boolean" &&
  ["deployment", "administrator"].includes(value?.source) &&
  Number.isInteger(value?.revision) &&
  value.revision >= 0;

export default function RegistrationSettingsDialog({ onClose }) {
  const { user } = useAuth();
  const writable = can(user, "platform.registration.manage", {
    scope: "platform",
  });
  const [policy, setPolicy] = useState(null);
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [pending, setPending] = useState(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    let live = true;
    setLoading(true);
    setPolicy(null);
    setError("");
    getRegistrationSettings()
      .then((value) => {
        if (!validPolicy(value)) throw new Error("Invalid registration policy");
        if (live) {
          setPolicy(value);
          setEnabled(value.self_registration_enabled);
        }
      })
      .catch(() => {
        if (live)
          setError(
            "Registration settings are unavailable. Try loading them again.",
          );
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [attempt]);

  const save = async (body, reauthCode) => {
    setBusy(true);
    setError("");
    setSuccess("");
    setPending(null);
    try {
      const value = await updateRegistrationSettings(body, { reauthCode });
      if (!validPolicy(value)) throw new Error("Invalid registration policy");
      setPolicy(value);
      setEnabled(value.self_registration_enabled);
      setSuccess(
        value.source === "deployment"
          ? "Now using the deployment default."
          : `Self-registration ${value.self_registration_enabled ? "enabled" : "disabled"}.`,
      );
    } catch (err) {
      if (reauthRequired(err)) {
        setPending(body);
      } else {
        setError(
          err?.response
            ? refusalMessages(err).join(" ")
            : "Could not save registration settings. Reload them to confirm the current policy.",
        );
      }
    } finally {
      setBusy(false);
    }
  };

  const locked = busy || Boolean(pending) || !writable;
  return (
    <>
      <CcureModal
        open
        title="Registration settings"
        subtitle="Control self-service account registration across all organizations in CCurePRO."
        onClose={busy || pending ? undefined : onClose}
        closeLabel="Close registration settings"
        closeOnOverlayClick={false}
        footer={
          <CcureButton
            variant="ghost"
            onClick={onClose}
            disabled={busy || Boolean(pending)}
          >
            Close
          </CcureButton>
        }
      >
        <div className="registration-settings-content">
          {error && <CcureAlert tone="danger">{error}</CcureAlert>}
          {success && <div role="status">{success}</div>}
          {loading ? (
            <CcureLoader label="Loading registration settings…" />
          ) : policy ? (
            <form
              className="registration-settings-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (!locked)
                  save({
                    self_registration_enabled: enabled,
                    revision: policy.revision,
                  });
              }}
            >
              <p>
                Last confirmed policy:{" "}
                <strong>
                  {policy.self_registration_enabled ? "Enabled" : "Disabled"}
                </strong>
                .{" "}
                {policy.source === "deployment"
                  ? "Using the deployment default."
                  : "Using the saved administrator setting."}
              </p>
              <CcureCheckbox
                checked={enabled}
                disabled={locked}
                onChange={(event) => {
                  setEnabled(event.target.checked);
                  setSuccess("");
                }}
                hint="Shows Register here on the sign-in page and allows new account registrations."
              >
                Allow self-registration
              </CcureCheckbox>
              <p>
                New accounts still require email verification
                {policy.administrator_approval_required
                  ? " and administrator approval"
                  : ""}
                . Existing accounts can continue to sign in when registration is
                disabled.
              </p>
              {!writable && <p>You have read-only access to this policy.</p>}
              {writable && (
                <div className="registration-settings-actions">
                  <CcureButton
                    type="submit"
                    loading={busy}
                    disabled={
                      locked || enabled === policy.self_registration_enabled
                    }
                  >
                    Save changes
                  </CcureButton>
                  {policy.source === "administrator" && (
                    <CcureButton
                      type="button"
                      variant="secondary"
                      disabled={locked}
                      onClick={() =>
                        save({
                          self_registration_enabled: null,
                          revision: policy.revision,
                        })
                      }
                    >
                      Use deployment default
                    </CcureButton>
                  )}
                </div>
              )}
              <p>
                Deployment default:{" "}
                {policy.deployment_default ? "Enabled" : "Disabled"}.
              </p>
            </form>
          ) : null}
          {!loading && (
            <CcureButton
              type="button"
              variant="ghost"
              disabled={busy || Boolean(pending)}
              onClick={() => {
                setSuccess("");
                setAttempt((value) => value + 1);
              }}
            >
              Reload settings
            </CcureButton>
          )}
        </div>
      </CcureModal>
      <ReauthDialog
        open={Boolean(pending)}
        busy={busy}
        onCancel={() => setPending(null)}
        onSubmit={(code) => {
          if (pending) save(pending, code);
        }}
      />
    </>
  );
}
