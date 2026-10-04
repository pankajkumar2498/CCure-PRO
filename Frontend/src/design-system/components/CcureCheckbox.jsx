import { forwardRef } from "react";

/** Native checkbox behavior with the shared UX4G typography, color and focus tokens. */
const CcureCheckbox = forwardRef(function CcureCheckbox(
  { children, className = "", title, ...props },
  ref,
) {
  return (
    <label className={`cc-checkbox ${className}`.trim()} title={title}>
      <input ref={ref} type="checkbox" {...props} />
      {children}
    </label>
  );
});

export default CcureCheckbox;
