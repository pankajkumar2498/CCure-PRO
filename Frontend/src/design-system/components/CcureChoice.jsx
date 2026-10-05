import { forwardRef, useId } from "react";

function Choice(
  {
    kind,
    children,
    hint,
    error,
    className = "",
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
  const radio = kind === "radio";
  return (
    <label
      className={`cc-choice cc-ux4g ux4g-${kind} ux4g-${kind}-m ${error ? `ux4g-${kind}-error` : ""} ${className}`}
    >
      <input
        {...props}
        id={id}
        aria-labelledby={
          labelledBy ||
          (!props["aria-label"] && children ? `${id}-label` : undefined)
        }
        aria-describedby={description}
        ref={ref}
        type={radio ? "radio" : "checkbox"}
        role={radio ? undefined : "switch"}
        className={`ux4g-${kind}-input`}
        aria-invalid={error ? "true" : undefined}
      />
      <span className={`ux4g-${kind}-control`} aria-hidden="true">
        {radio ? (
          <span className="ux4g-radiomark" />
        ) : (
          <span className="ux4g-switch-track">
            <span className="ux4g-switch-thumb" />
          </span>
        )}
      </span>
      {children || hint || error ? (
        <span className={`ux4g-${kind}-content`}>
          <span className={`ux4g-${kind}-label`} id={`${id}-label`}>
            {children}
          </span>
          {hint && !error ? (
            <span className={`ux4g-${kind}-description`} id={`${id}-hint`}>
              {hint}
            </span>
          ) : null}
          {error ? (
            <span className="cc-field__error" id={`${id}-error`} role="alert">
              {error}
            </span>
          ) : null}
        </span>
      ) : null}
    </label>
  );
}
export const CcureRadio = forwardRef((props, ref) =>
  Choice({ ...props, kind: "radio" }, ref),
);
CcureRadio.displayName = "CcureRadio";
export const CcureSwitch = forwardRef((props, ref) =>
  Choice({ ...props, kind: "switch" }, ref),
);
CcureSwitch.displayName = "CcureSwitch";
