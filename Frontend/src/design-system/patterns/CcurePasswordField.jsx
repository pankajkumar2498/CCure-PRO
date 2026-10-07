import { useId, useState } from "react";
import CcureInput from "../components/CcureInput";

/**
 * CcurePasswordField — a password entry control with the three affordances
 * every credential form in this product needs, wired for assistive technology.
 *
 * It exists because Login, Register and ResetPassword carried six copies of
 * the same markup between them and each copy had the same defects:
 *
 *   * the visibility toggle was a bare `<button>` inside a hand-rolled
 *     wrapper, so its state ("password shown" / "password hidden") was never
 *     announced — only its purpose was;
 *   * the caps-lock warning was a plain `<div>`. It appears *after* the user
 *     starts typing, which is precisely the moment a screen reader has nothing
 *     to say about it, so the one user who cannot see the field also could not
 *     be told why their password keeps being refused;
 *   * the strength meter was four unlabelled `<span>`s and a word. The word
 *     was the only part conveyed non-visually, and it appeared without ever
 *     being announced as it changed.
 *
 * Three deliberate non-changes:
 *
 *   * the existing default tab order is preserved. Authentication opts into
 *     a keyboard-reachable reveal control with visibilityToggleTabIndex={0}.
 *   * `type` flips between "password" and "text" exactly as before. Nothing
 *     here changes what is submitted.
 *   * the strength grading is passed in rather than computed, because the two
 *     pages that use it own their own rules and this component must not become
 *     a second, competing password policy.
 */

/** The four rules the product's password policy checks, in report order. */
export const PASSWORD_RULES = [
  { id: "length", label: "12+ chars", test: (pw) => pw.length >= 12 },
  { id: "upper", label: "Uppercase", test: (pw) => /[A-Z]/.test(pw) },
  { id: "digit", label: "Number", test: (pw) => /[0-9]/.test(pw) },
  {
    id: "special",
    label: "Special char",
    test: (pw) => /[^a-zA-Z0-9]/.test(pw),
  },
];

/** Grade a password against PASSWORD_RULES. Shared so two pages cannot drift. */
export function gradePassword(pw) {
  if (!pw) return { label: "", level: 0 };
  const level = PASSWORD_RULES.filter((r) => r.test(pw)).length;
  return { label: ["", "Weak", "Fair", "Good", "Strong"][level], level };
}

function EyeIcon({ off }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
      {off && <line x1="3" y1="3" x2="21" y2="21" />}
    </svg>
  );
}

export default function CcurePasswordField({
  id: providedId,
  value,
  onChange,
  label = "Password",
  /** Show the four-segment strength meter and the rule checklist. */
  showStrength = false,
  /** Show the "Caps Lock is ON" warning. On by default: it is why a correct
      password gets refused, and there is no cost to a user who is not
      affected. */
  capsLockWarning = true,
  /** Auth forms opt into keyboard reveal without changing other consumers. */
  visibilityToggleTabIndex = -1,
  hint,
  error,
  className = "",
  ...rest
}) {
  const generatedId = useId();
  const id = providedId || generatedId;
  const [revealed, setRevealed] = useState(false);
  const [capsLock, setCapsLock] = useState(false);

  const handleKey = (e) => {
    if (capsLockWarning && e.getModifierState) {
      setCapsLock(e.getModifierState("CapsLock"));
    }
  };

  const strength = showStrength ? gradePassword(value) : null;
  const capsId = `${id}-caps`;
  const strengthId = `${id}-strength`;

  /* The warning and the meter describe the field, so they are attached with
     aria-describedby rather than left as adjacent text. Without this the
     screen reader announces the label and the error and nothing about why the
     password is being rejected. */
  const describedBy =
    [capsLock ? capsId : null, strength?.label ? strengthId : null]
      .filter(Boolean)
      .join(" ") || undefined;

  return (
    <div className={`cc-password ${className}`.trim()}>
      <CcureInput
        id={id}
        label={label}
        type={revealed ? "text" : "password"}
        value={value}
        onChange={onChange}
        onKeyDown={handleKey}
        onKeyUp={handleKey}
        hint={hint}
        error={error}
        aria-describedby={describedBy}
        adornment={
          <button
            type="button"
            tabIndex={visibilityToggleTabIndex}
            className="cc-password__toggle"
            /* The name states the action; aria-pressed states the current
               condition. Together they answer "what does this do" and "what is
               it doing now", which a name alone cannot.

               The field's own label is folded into the name because a reset
               form has two of these. Two buttons sharing one accessible name
               is what a screen reader reads as "Toggle password visibility
               button" twice, with nothing to say which field either belongs
               to — the exact defect the original pages avoided by hand and
               that a shared component would otherwise reintroduce. */
            aria-label={`Toggle ${label} visibility`}
            aria-pressed={revealed}
            aria-controls={id}
            onClick={() => setRevealed((v) => !v)}
          >
            <EyeIcon off={revealed} />
          </button>
        }
        {...rest}
      />

      {capsLock && (
        /* role="status" rather than "alert": caps lock is a condition worth
           knowing, not an error to interrupt with. */
        <div className="cc-password__caps" id={capsId} role="status">
          Caps Lock is ON
        </div>
      )}

      {showStrength && value && (
        <div className="cc-password__strength" id={strengthId}>
          <div
            className="cc-password__meter"
            role="meter"
            aria-valuemin={0}
            aria-valuemax={PASSWORD_RULES.length}
            aria-valuenow={strength.level}
            aria-valuetext={`${strength.label} password`}
            aria-label="Password strength"
          >
            {PASSWORD_RULES.map((rule, i) => (
              <span
                key={rule.id}
                className={`cc-password__seg${
                  i < strength.level
                    ? ` cc-password__seg--${strength.level}`
                    : ""
                }`}
              />
            ))}
          </div>
          <span className="cc-password__grade">{strength.label}</span>

          {/* The checklist is what tells someone *what to change*. The glyph is
              decorative; the rule's met/unmet state is carried in text so it
              does not depend on colour — WCAG 1.4.1. */}
          <ul className="cc-password__rules">
            {PASSWORD_RULES.map((rule) => {
              const met = rule.test(value);
              return (
                <li
                  key={rule.id}
                  className={`cc-password__rule${
                    met ? " cc-password__rule--met" : ""
                  }`}
                >
                  <span aria-hidden="true">{met ? "✓" : "•"}</span>
                  <span className="cc-sr-only">
                    {met ? "Met:" : "Not met:"}
                  </span>{" "}
                  {rule.label}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
