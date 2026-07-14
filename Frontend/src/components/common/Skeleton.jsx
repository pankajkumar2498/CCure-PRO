import React from "react";

/**
 * A simple Skeleton loader component.
 * @param {string} width - e.g. "100%", "200px"
 * @param {string} height - e.g. "20px", "100%"
 * @param {string} borderRadius - e.g. "4px", "50%"
 * @param {string} margin - optional margin
 */
export default function Skeleton({
  width = "100%",
  height = "20px",
  borderRadius = "4px",
  margin = "0",
}) {
  return (
    <div
      className="skeleton-loader"
      style={{
        width,
        height,
        borderRadius,
        margin,
        backgroundColor: "var(--border)",
        backgroundImage:
          "linear-gradient(90deg, rgba(255,255,255, 0), rgba(255,255,255, 0.05), rgba(255,255,255, 0))",
        backgroundSize: "200px 100%",
        backgroundRepeat: "no-repeat",
        animation: "skeleton-shimmer 1.5s infinite linear",
      }}
    >
      <style>{`
        @keyframes skeleton-shimmer {
          0% { background-position: -200px 0; }
          100% { background-position: calc(200px + 100%) 0; }
        }
      `}</style>
    </div>
  );
}
