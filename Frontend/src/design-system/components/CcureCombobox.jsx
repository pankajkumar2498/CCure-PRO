import { forwardRef, useEffect, useId, useRef, useState } from "react";
import { CcureField, describedBy } from "./CcureInput";

/** Single-value searchable UX4G Select; native select remains the legacy adapter. */
const CcureCombobox = forwardRef(function CcureCombobox(
  {
    id: providedId,
    label,
    hint,
    error,
    required = false,
    disabled = false,
    options = [],
    value = "",
    onChange,
    name,
    placeholder = "Select an option",
    className = "",
    "aria-describedby": extra,
  },
  ref,
) {
  const generatedId = useId();
  const id = providedId || generatedId;
  const input = useRef(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const selected = options.find((option) => option.value === value);
  const filtered = options.filter((option) =>
    option.label.toLowerCase().includes(query.toLowerCase()),
  );
  const enabled = filtered.filter((option) => !option.disabled);
  const current = enabled[Math.min(active, Math.max(0, enabled.length - 1))];
  const optionId = (option) => `${id}-option-${options.indexOf(option)}`;
  useEffect(() => {
    input.current?.setCustomValidity(
      required && !selected ? "Select an option" : "",
    );
    if (open && current)
      document
        .getElementById(`${id}-option-${options.indexOf(current)}`)
        ?.scrollIntoView?.({ block: "nearest" });
  }, [required, selected, open, current, id, options]);
  function choose(option) {
    if (!option || option.disabled) return;
    onChange?.(option.value, option);
    setOpen(false);
    setQuery("");
    input.current?.focus();
  }
  return (
    <CcureField
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      className={`cc-combobox ux4g-select ux4g-select-m ${open ? "is-open" : ""} ${className}`}
    >
      {name ? (
        <input type="hidden" name={name} value={value} disabled={disabled} />
      ) : null}
      <input
        ref={(node) => {
          input.current = node;
          if (typeof ref === "function") ref(node);
          else if (ref) ref.current = node;
        }}
        id={id}
        role="combobox"
        type="text"
        className="ux4g-select-control"
        disabled={disabled}
        aria-expanded={open}
        aria-controls={open ? `${id}-listbox` : undefined}
        aria-autocomplete="list"
        aria-activedescendant={open && current ? optionId(current) : undefined}
        required={required}
        aria-required={required || undefined}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={describedBy(id, hint, error, extra)}
        autoComplete="off"
        placeholder={placeholder}
        value={open ? query : selected?.label || ""}
        onClick={() => {
          if (!open) {
            setOpen(true);
            setQuery("");
            setActive(0);
          }
        }}
        onFocus={() => {
          setOpen(true);
          setQuery("");
          setActive(0);
        }}
        onChange={(event) => {
          setQuery(event.target.value);
          setOpen(true);
          setActive(0);
        }}
        onBlur={() => {
          setOpen(false);
          setQuery("");
        }}
        onKeyDown={(event) => {
          if (event.key === "Escape" && open) {
            event.preventDefault();
            event.stopPropagation();
            setOpen(false);
            setQuery("");
          }
          if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
            event.preventDefault();
            if (!open) {
              setOpen(true);
              setQuery("");
              setActive(event.key === "ArrowUp" ? enabled.length - 1 : 0);
            } else
              setActive((old) =>
                event.key === "Home"
                  ? 0
                  : event.key === "End"
                    ? enabled.length - 1
                    : (old +
                        (event.key === "ArrowDown" ? 1 : -1) +
                        enabled.length) %
                      Math.max(1, enabled.length),
              );
          }
          if (event.key === "Enter" && open) {
            event.preventDefault();
            choose(current);
          }
        }}
      />
      {open ? (
        <div
          id={`${id}-listbox`}
          role="listbox"
          aria-label={label}
          className="cc-combobox__list ux4g-select-menu"
        >
          {filtered.map((option) => (
            <div
              key={option.value}
              id={optionId(option)}
              role="option"
              aria-selected={option.value === value}
              aria-disabled={option.disabled || undefined}
              className={`ux4g-select-option ${option === current ? "is-active" : ""}`}
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => choose(option)}
            >
              {option.label}
            </div>
          ))}
          {!filtered.length ? <div role="status">No options found</div> : null}
        </div>
      ) : null}
    </CcureField>
  );
});
export default CcureCombobox;
