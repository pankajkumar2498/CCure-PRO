import { useId } from "react";
import "../../styles/cve-link.css";

/**
 * CVELink
 *
 * A CVE identifier as a link to its NVD record, or as plain text when it is
 * not one. Nine call sites across six pages — table cells, clickable rows,
 * and the heading that names AssetDetail's finding drawer.
 *
 * ── Only a well-formed CVE becomes a URL ────────────────────────────────────
 * The identifier comes from scan data, and the product also mints identifiers
 * NVD has never heard of (`CCURE-CFG-…`, `CCURE-CHK-NUCLEI-…`). The anchored
 * pattern is the whole boundary: anything that is not `CVE-YYYY-NNNN…` from
 * first character to last renders as inert text, so no scan-supplied string
 * reaches an href.
 *
 * ── Colour comes from the page (Checkpoint 3C batch 15) ─────────────────────
 * The legacy anchor carried `color: var(--accent, #3b82f6)` inline, which
 * outranked every class a page gave it — `ad-cve-link`, `ad-inherit` and
 * `vb-inherit` were written and never took effect. The base rule in
 * cve-link.css is zero-specificity for the same reason. A consumer's inline
 * `style` still wins, as before; CredentialedResults colours by severity so.
 *
 * ── Leaving the application ────────────────────────────────────────────────
 * The link opens NVD in a new tab, an external request on a product that
 * otherwise makes none. That is said in the accessible *description*, never
 * the name: the drawer heading holds only this link, and a hint in the name
 * would be read out as part of the dialog's title.
 */
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/";

export default function CVELink({ cveId, className = "cve-id", style }) {
  const hintId = useId();

  if (!cveId || cveId === "N/A" || cveId === "Unknown") {
    return (
      <span className={className} style={style}>
        {cveId}
      </span>
    );
  }

  const cleanId = String(cveId).trim();

  if (!CVE_PATTERN.test(cleanId)) {
    return (
      <span className={className} style={style}>
        {cleanId}
      </span>
    );
  }

  return (
    <>
      <a
        href={`${NVD_DETAIL}${cleanId.toUpperCase()}`}
        target="_blank"
        rel="noopener noreferrer"
        className={["cve-link", className].filter(Boolean).join(" ")}
        style={style}
        aria-describedby={hintId}
        // Rows and cards around it are clickable; following the link must not
        // also open a drawer or navigate the row.
        onClick={(e) => e.stopPropagation()}
      >
        {cleanId}
      </a>
      {/* `hidden`, not visually hidden: it must stay out of any name computed
          from the surrounding content, and a description may reference a
          hidden element. */}
      <span id={hintId} hidden>
        Opens the NVD record in a new tab
      </span>
    </>
  );
}
