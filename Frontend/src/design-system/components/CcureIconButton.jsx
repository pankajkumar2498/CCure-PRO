import { forwardRef } from "react";
import CcureButton from "./CcureButton";

/** Same button API, with an explicit accessible name and official icon sizing. */
const CcureIconButton = forwardRef(function CcureIconButton(
  {
    label,
    "aria-label": ariaLabel,
    variant = "ghost",
    size = "md",
    className = "",
    ...props
  },
  ref,
) {
  const appearance =
    {
      primary: "primary",
      secondary: "outline-primary",
      ghost: "text-primary",
      danger: "outline-primary",
    }[variant] || "text-primary";
  return (
    <CcureButton
      {...props}
      ref={ref}
      aria-label={ariaLabel || label}
      variant={variant}
      size={size}
      className={`cc-icon-button ux4g-icon-btn ux4g-icon-btn-${appearance} ux4g-icon-btn-${{ sm: "s", md: "m", lg: "l" }[size] || "m"} ${className}`}
    />
  );
});
export default CcureIconButton;
