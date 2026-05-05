export default function Loader({ label = "Loading..." }) {
  return (
    <div className="loader-shell">
      <div className="spinner" aria-hidden="true" />
      <div className="loader-label">{label}</div>
    </div>
  );
}
