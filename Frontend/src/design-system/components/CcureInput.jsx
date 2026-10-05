import { forwardRef, useId } from "react";

/**
 * CcureField / CcureInput / CcureSelect
 *
 * The whole point of this file is the wiring between a control and the text
 * around it. Phase 0 measured **zero** uses of `aria-describedby` across 51k
 * lines and 153 inputs: hints and validation errors were visually adjacent to
 * their field and invisible to assistive technology, so a screen reader
 * announced the field name and nothing about why it had just been rejected.
 *
 * Three associations are made here, and none of them is optional:
 *
 *   1. `<label for>` ↔ `id`         — gives the control its accessible name
 *   2. `aria-describedby`           — attaches hint and error text
 *   3. `aria-invalid`               — states the error condition itself, which
 *                                     is what a screen reader announces on
 *                                     entry and what the CSS keys its red
 *                                     border off, so the two cannot disagree
 *
 * Ids come from React's `useId`, so a field may be rendered many times on a
 * page — a filter row repeated per column, say — without colliding. Hand-rolled
 * ids are how two controls end up sharing a label, at which point clicking one
 * label focuses the wrong field.
 */
export function CcureField({
  id,
  label,
  hint,
  error,
  required = false,
  className = "",
  children,
}) {
  return (
    <div
      className={`cc-field cc-ux4g ux4g-input-container ux4g-input-m ${error ? "ux4g-input-error" : "ux4g-input-default"} ${className}`.trim()}
    >
      {label ? (
        <label className="cc-field__label" htmlFor={id}>
          {label}
          {required && (
            <>
              <span className="cc-field__required" aria-hidden="true">
                *
              </span>
              {/* "*" alone is not a label. Announced text is what tells a
                  non-sighted user the field is mandatory. */}
              <span className="cc-sr-only"> (required)</span>
            </>
          )}
        </label>
      ) : null}

      {children}

      {/* Hint is rendered only when there is no error, so the description does
          not read as "enter 8+ characters. Password is too short." — the error
          supersedes the hint rather than queueing behind it. */}
      {hint && !error ? (
        <div className="cc-field__hint" id={`${id}-hint`}>
          {hint}
        </div>
      ) : null}

      {/* role="alert" so a validation failure appearing after submit is
          announced without the user having to go looking for it. */}
      {error ? (
        <div className="cc-field__error" id={`${id}-error`} role="alert">
          {error}
        </div>
      ) : null}
    </div>
  );
}

/** Shared describedby assembly — an input and a select must not drift apart. */
export function describedBy(id, hint, error, extra) {
  return (
    [error ? `${id}-error` : null, hint && !error ? `${id}-hint` : null, extra]
      .filter(Boolean)
      .join(" ") || undefined
  );
}

const CcureInput = forwardRef(function CcureInput(
  {
    id: providedId,
    label,
    hint,
    error,
    required = false,
    type = "text",
    className = "",
    fieldClassName = "",
    /* An interactive control rendered inside the field's box — a password
       visibility toggle, a unit suffix, a clear button. It is deliberately a
       sibling of the input rather than a wrapper around it, so the input keeps
       its own `id`, label association and describedby wiring: an adorned field
       and a plain one are the same field to assistive technology. */
    adornment,
    "aria-describedby": extraDescribedBy,
    ...rest
  },
  ref,
) {
  const generatedId = useId();
  const id = providedId || generatedId;

  const control = (
    <input
      ref={ref}
      id={id}
      type={type}
      className={`cc-field__control ux4g-input-input ${className}`.trim()}
      aria-invalid={error ? "true" : undefined}
      aria-describedby={describedBy(id, hint, error, extraDescribedBy)}
      /* `required` is set on the element as well as announced in the label.
         The attribute is what the browser and assistive tech both read; the
         label text is what a user hears when the field is announced. */
      required={required || undefined}
      {...rest}
    />
  );

  return (
    <CcureField
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      className={fieldClassName}
    >
      <div className="ux4g-input cc-field__adorned">
        {control}
        {adornment ? (
          <span className="cc-field__adornment ux4g-input-actions">
            {adornment}
          </span>
        ) : null}
      </div>
    </CcureField>
  );
});

export const CcureSelect = forwardRef(function CcureSelect(
  {
    id: providedId,
    label,
    hint,
    error,
    required = false,
    className = "",
    fieldClassName = "",
    "aria-describedby": extraDescribedBy,
    children,
    ...rest
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
      className={`ux4g-select ux4g-select-m ${fieldClassName}`}
    >
      <select
        ref={ref}
        id={id}
        className={`cc-field__control ux4g-select-control ${className}`.trim()}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={describedBy(id, hint, error, extraDescribedBy)}
        required={required || undefined}
        {...rest}
      >
        {children}
      </select>
    </CcureField>
  );
});

export default CcureInput;
