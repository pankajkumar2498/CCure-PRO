import { CcureButton, CcureLoader } from "../../../design-system";

export default function RegistrationStatus({ loading, onRetry }) {
  if (loading) {
    return (
      <CcureLoader
        inline
        size="sm"
        label="Checking registration availability…"
      />
    );
  }

  return (
    <>
      <span role="status">Registration options are unavailable.</span>{" "}
      <CcureButton type="button" variant="ghost" size="sm" onClick={onRetry}>
        Retry
      </CcureButton>
    </>
  );
}
