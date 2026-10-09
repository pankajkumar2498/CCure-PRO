import { forwardRef, useId } from "react";
import { CcureField, describedBy } from "./CcureInput";

const CcureTextarea = forwardRef(function CcureTextarea(
  {
    id: providedId,
    label,
    hint,
    error,
    required = false,
    className = "",
    fieldClassName = "",
    "aria-describedby": extra,
    ...props
  },
  ref,
) {
  const generatedId = useId();
  const id = providedId || generatedId;
  return (
    <CcureField
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      className={`ux4g-textarea-container ux4g-textarea-m ${error ? "ux4g-textarea-error" : "ux4g-textarea-default"} ${fieldClassName}`}
    >
      <div className="ux4g-textarea">
        <textarea
          {...props}
          ref={ref}
          id={id}
          required={required || undefined}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={describedBy(id, hint, error, extra)}
          className={`cc-field__control ux4g-textarea-input ${className}`}
        />
      </div>
    </CcureField>
  );
});
export default CcureTextarea;
