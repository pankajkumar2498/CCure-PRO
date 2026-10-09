import { forwardRef, useId } from "react";

/** Native checkbox semantics with the official UX4G label/control anatomy. */
const CcureCheckbox = forwardRef(function CcureCheckbox(
  {
    children,
    className = "",
    title,
    error,
    hint,
    id: providedId,
    "aria-describedby": extra,
    "aria-labelledby": labelledBy,
    ...props
  },
  ref,
) {
  const generatedId = useId();
  const id = providedId || generatedId;
  const description =
    [error ? `${id}-error` : hint ? `${id}-hint` : null, extra]
      .filter(Boolean)
      .join(" ") || undefined;
  return (
    <label
      className={`cc-checkbox cc-ux4g ux4g-checkbox ux4g-checkbox-m ${error ? "ux4g-checkbox-error" : ""} ${className}`.trim()}
      title={title}
    >
      <input
        ref={ref}
        id={id}
        aria-labelledby={
          labelledBy ||
          (!props["aria-label"] && children ? `${id}-label` : undefined)
        }
        aria-describedby={description}
        type="checkbox"
        className="ux4g-checkbox-input"
        aria-invalid={error ? "true" : undefined}
        {...props}
      />
      <span className="ux4g-checkbox-control" aria-hidden="true">
        <span className="ux4g-checkmark" />
      </span>
      <span className="ux4g-checkbox-content">
        <span className="ux4g-checkbox-label" id={`${id}-label`}>
          {children}
        </span>
        {hint && !error ? (
          <span className="ux4g-checkbox-description" id={`${id}-hint`}>
            {hint}
          </span>
        ) : null}
        {error ? (
          <span className="cc-field__error" id={`${id}-error`} role="alert">
            {error}
          </span>
        ) : null}
      </span>
    </label>
  );
});
export default CcureCheckbox;
