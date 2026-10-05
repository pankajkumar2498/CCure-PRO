/**
 * src/shell/auth/IncompatibleBackend.jsx
 * Shown when the backend does not answer with the authorization contract this
 * build requires. There is no older-backend fallback: the UI says so instead of
 * guessing what the account may do.
 */
import { CcureAlert, CcureCard } from "../../design-system";

export default function IncompatibleBackend({ message }) {
  return (
    <main
      style={{
        minHeight: "100dvh",
        display: "grid",
        placeItems: "center",
        padding: "var(--ccure-space-xl)",
      }}
    >
      <CcureCard style={{ maxWidth: "32rem", width: "100%" }}>
        <h1
          style={{
            fontSize: "var(--ccure-text-xl)",
            marginBottom: "var(--ccure-space-md)",
          }}
        >
          Backend not compatible
        </h1>
        <CcureAlert variant="danger">{message}</CcureAlert>
      </CcureCard>
    </main>
  );
}
