/**
 * src/components/scan/RiskBadge.jsx
 * Colored badge for Critical / High / Medium / Low / Info
 */
export default function RiskBadge({ level, score }) {
  const map = {
    Critical: { color: "#ff4d4d", bg: "rgba(255,77,77,.12)", border: "rgba(255,77,77,.3)" },
    High:     { color: "#f97316", bg: "rgba(249,115,22,.12)", border: "rgba(249,115,22,.3)" },
    Medium:   { color: "#f59e0b", bg: "rgba(245,158,11,.12)", border: "rgba(245,158,11,.3)" },
    Low:      { color: "#22c55e", bg: "rgba(34,197,94,.12)",  border: "rgba(34,197,94,.3)"  },
    Info:     { color: "#60a5fa", bg: "rgba(96,165,250,.12)", border: "rgba(96,165,250,.3)" },
  };
  const s = map[level] || map.Info;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      background: s.bg, border: `1px solid ${s.border}`,
      color: s.color, borderRadius: 4,
      padding: "2px 8px", fontSize: 11,
      fontFamily: "var(--mono)", letterSpacing: ".06em",
    }}>
      {score !== undefined && <b style={{ fontSize: 12 }}>{score}</b>}
      {level || "Info"}
    </span>
  );
}
