import { forwardRef } from "react";

const Button = forwardRef(
  (
    {
      variant = "primary",
      size = "md",
      loading = false,
      children,
      className = "",
      ...props
    },
    ref
  ) => {
    const variantClass = {
      primary: "btn btn--primary",
      ghost: "btn btn--ghost",
      danger: "btn btn--danger",
      info: "btn btn--info",
      secondary: "btn btn--secondary",
    }[variant] || "btn btn--primary";

    return (
      <button
        ref={ref}
        className={`${variantClass} btn--${size} ${className}`.trim()}
        disabled={props.disabled || loading}
        aria-busy={loading ? "true" : undefined}
        {...props}
      >
        {loading && <span className="btn-spinner" aria-hidden="true" />}
        <span className="btn-label">{children}</span>
      </button>
    );
  }
);

export default Button;
