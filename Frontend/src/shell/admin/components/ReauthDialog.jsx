/**
 * src/shell/admin/components/ReauthDialog.jsx — step-up for a sensitive change.
 * The backend asked for a current authenticator code (`reauth_required`); this asks
 * for it and hands it back. The code lives in component state only: it is not stored,
 * not logged and cleared when the dialog closes.
 */
import { useState } from "react";
import { CcureButton, CcureInput, CcureModal } from "../../../design-system";

export default function ReauthDialog({ open, onSubmit, onCancel, busy }) {
  const [code, setCode] = useState("");
  const close = () => {
    setCode("");
    onCancel();
  };
  const submit = (event) => {
    event.preventDefault();
    const value = code.trim();
    setCode("");
    if (value) onSubmit(value);
  };
  return (
    <CcureModal
      open={open}
      onClose={close}
      title="Confirm with your authenticator"
      subtitle="This change affects who can do what. Enter a current code to continue."
      size="sm"
      footer={
        <>
          <CcureButton type="button" variant="ghost" onClick={close}>
            Cancel
          </CcureButton>
          <CcureButton
            type="submit"
            form="rbac-reauth-form"
            disabled={busy || !code.trim()}
          >
            Confirm
          </CcureButton>
        </>
      }
    >
      <form id="rbac-reauth-form" onSubmit={submit}>
        <CcureInput
          id="rbac-reauth-code"
          label="Authenticator code"
          value={code}
          onChange={(event) => setCode(event.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={12}
          autoFocus
        />
      </form>
    </CcureModal>
  );
}
