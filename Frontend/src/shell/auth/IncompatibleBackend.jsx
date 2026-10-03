/**
 * src/shell/auth/IncompatibleBackend.jsx
 * Shown when the backend does not answer with the authorization contract this
 * build requires. There is no older-backend fallback: the UI says so instead of
 * guessing what the account may do.
 */
export default function IncompatibleBackend({ message }) {
  return (
    <div
      role="alert"
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "16px",
        background: "#1a2332",
        color: "#fff",
        textAlign: "center",
      }}
    >
      <div style={{ maxWidth: 520 }}>
        <h1 style={{ fontSize: "1.25rem", marginBottom: 12 }}>
          Backend not compatible
        </h1>
        <p>{message}</p>
      </div>
    </div>
  );
}
