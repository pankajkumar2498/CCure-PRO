export default function FormField({
  htmlFor,
  label,
  hint,
  children,
  className = "",
}) {
  return (
    <div className={`field ${className}`.trim()}>
      {label ? (
        <label className="field-label" htmlFor={htmlFor}>
          {label}
        </label>
      ) : null}
      {children}
      {hint ? <div className="field-hint">{hint}</div> : null}
    </div>
  );
}
