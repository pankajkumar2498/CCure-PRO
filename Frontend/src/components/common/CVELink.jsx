export default function CVELink({ cveId, className = "cve-id", style = {} }) {
  if (!cveId || cveId === "N/A" || cveId === "Unknown") {
    return (
      <span className={className} style={style}>
        {cveId}
      </span>
    );
  }

  const cleanId = String(cveId).trim();

  // Guard check to make sure it matches standard CVE structure
  const isCveFormat = /^CVE-\d{4}-\d{4,}$/i.test(cleanId);
  if (!isCveFormat) {
    return (
      <span className={className} style={style}>
        {cleanId}
      </span>
    );
  }

  const url = `https://nvd.nist.gov/vuln/detail/${cleanId.toUpperCase()}`;

  const handleClick = (e) => {
    // Prevent navigation / modal / side-drawer toggle actions on parents
    e.stopPropagation();
  };

  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className={className}
      onClick={handleClick}
      style={{
        color: "var(--accent, #3b82f6)",
        textDecoration: "none",
        fontWeight: "inherit",
        cursor: "pointer",
        ...style,
      }}
    >
      {cleanId}
    </a>
  );
}
