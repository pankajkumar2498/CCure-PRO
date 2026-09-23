/**
 * What is known about a CVE finding beyond its score.
 *
 * The credentialed report has always carried exploit intelligence, priority,
 * the matched versions and the vendor's own remediation, and the findings list
 * rendered none of it — measured at **zero references** to fourteen fields
 * across every renderer on that page. On one live scan that hid 10 KEV-listed
 * findings, 11 with a public exploit, 2 linked to ransomware and 42 carrying
 * the only remediation text anyone has written for them.
 *
 * Three rules this component exists to hold:
 *
 * * **Absent is absent.** Every signal is rendered only when the API sent it.
 *   `has_exploit: false` is a measured "no public exploit is known"; a missing
 *   `has_exploit` is "nobody looked", and they must not print the same. Hence
 *   `isPresent` rather than truthiness, and never `value || 0`.
 *
 * * **`has_exploit` is exploit *availability*, never exploitability.**
 *   CLAUDE.md: it means a public exploit exists for the CVE, and says nothing
 *   about whether this host can be exploited — that depends on configuration
 *   and reachability the feed knows nothing about. The label and its title say
 *   so.
 *
 * * **A vendor advisory carries its own identity.** `vendor_remediation` is
 *   prefixed with the advisory id by the backend precisely so ICS guidance can
 *   never read as the desktop vendor's own advice. It is rendered verbatim,
 *   and where the backend did not prefix it the advisory id is shown beside
 *   it rather than merged into the text.
 */

import { CcureBadge } from "../../design-system";

/** Sent, as opposed to falsy. `0`, `false` and `""` are answers. */
export const isPresent = (value) =>
  value !== null && value !== undefined && value !== "";

/** A percentage from an EPSS probability, which the API sends as 0..1. */
const asPct = (value) =>
  typeof value === "number" ? `${(value * 100).toFixed(1)}%` : null;

/**
 * The signals worth putting on the row itself: each is either a mandated
 * deadline, evidence of exploitation, or the product's own triage order.
 */
export function FindingSignals({ cve = {} }) {
  const chips = [];

  if (cve.in_kev === true) {
    chips.push(
      <CcureBadge
        key="kev"
        variant="danger"
        title="Listed in CISA's Known Exploited Vulnerabilities catalogue. BOD 22-01 sets a mandated remediation date."
      >
        KEV
        {isPresent(cve.kev_due_date) ? ` · due ${cve.kev_due_date}` : ""}
      </CcureBadge>,
    );
  }

  if (cve.has_exploit === true) {
    chips.push(
      <CcureBadge
        key="exploit"
        variant="warning"
        title="A public exploit exists for this CVE. It does not mean this host is exploitable — that depends on configuration and reachability this feed knows nothing about."
      >
        Exploit available
      </CcureBadge>,
    );
  }

  if (cve.verified_exploit === true) {
    chips.push(
      <CcureBadge
        key="verified"
        variant="danger"
        title="ExploitDB confirmed the exploit reproducible."
      >
        Verified exploit
      </CcureBadge>,
    );
  }

  if (cve.canary_confirmed === true) {
    chips.push(
      <CcureBadge
        key="canary"
        variant="danger"
        title="Observed being exploited against VulnCheck's own honeypots — direct observation rather than a report of one."
      >
        Seen exploited
      </CcureBadge>,
    );
  }

  if (cve.ransomware_linked === true) {
    chips.push(
      <CcureBadge
        key="ransomware"
        variant="danger"
        title="Known use in ransomware campaigns."
      >
        Ransomware
      </CcureBadge>,
    );
  }

  if (isPresent(cve.priority_level)) {
    chips.push(
      <CcureBadge
        key="priority"
        variant={cve.priority_level === "P0" ? "danger" : "neutral"}
        title={
          isPresent(cve.priority_score)
            ? `Computed priority ${cve.priority_score}`
            : "Computed priority"
        }
      >
        {cve.priority_level}
      </CcureBadge>,
    );
  }

  const epss = asPct(cve.epss_score);
  if (epss) {
    chips.push(
      <CcureBadge
        key="epss"
        variant="neutral"
        title="EPSS — the modelled probability of exploitation in the next 30 days."
      >
        EPSS {epss}
      </CcureBadge>,
    );
  }

  if (!chips.length) return null;
  return <span className="cr-signals">{chips}</span>;
}

const Row = ({ label, children }) => (
  <div className="cr-enrich__row">
    <dt>{label}</dt>
    <dd>{children}</dd>
  </div>
);

/**
 * The rest of what the API said about this finding.
 *
 * Rendered inside the row's disclosure rather than on it: a credentialed scan
 * produces thousands of findings, and every one of these fields on every row
 * is a wall nobody reads.
 */
export function FindingDetail({ cve = {} }) {
  const rows = [];

  if (isPresent(cve.matched_by)) {
    rows.push(
      <Row key="matched" label="Matched by">
        {/* How the finding was established, which is its provenance. */}
        <code>{cve.matched_by}</code>
      </Row>,
    );
  }
  if (isPresent(cve.detection_method)) {
    rows.push(
      <Row key="detection" label="Detection">
        <code>{cve.detection_method}</code>
      </Row>,
    );
  }
  if (isPresent(cve.qod)) {
    rows.push(
      <Row key="qod" label="Quality of detection">
        {cve.qod}
        {isPresent(cve.confidence) ? ` · ${cve.confidence}` : ""}
      </Row>,
    );
  } else if (isPresent(cve.confidence)) {
    rows.push(
      <Row key="confidence" label="Confidence">
        {cve.confidence}
      </Row>,
    );
  }
  if (isPresent(cve.attack_surface)) {
    rows.push(
      <Row key="surface" label="Attack surface">
        {cve.attack_surface}
      </Row>,
    );
  }
  if (isPresent(cve.installed_version ?? cve.installed_ver)) {
    rows.push(
      <Row key="installed" label="Installed version">
        <code>{cve.installed_version ?? cve.installed_ver}</code>
      </Row>,
    );
  }
  if (isPresent(cve.detected_version)) {
    rows.push(
      <Row key="detected" label="Detected version">
        <code>{cve.detected_version}</code>
      </Row>,
    );
  }
  if (isPresent(cve.fixed_version ?? cve.fixed_ver)) {
    rows.push(
      <Row key="fixed" label="Fixed in">
        <code>{cve.fixed_version ?? cve.fixed_ver}</code>
      </Row>,
    );
  }
  if (isPresent(cve.cvss_vector)) {
    rows.push(
      <Row key="vector" label="CVSS vector">
        <code>{cve.cvss_vector}</code>
        {isPresent(cve.cvss_version) ? ` (v${cve.cvss_version})` : ""}
      </Row>,
    );
  }
  const pct = asPct(cve.epss_percentile);
  if (pct) {
    rows.push(
      <Row key="percentile" label="EPSS percentile">
        {pct}
      </Row>,
    );
  }
  if (Array.isArray(cve.exploit_sources) && cve.exploit_sources.length) {
    rows.push(
      <Row key="sources" label="Exploit intelligence from">
        {cve.exploit_sources.join(", ")}
      </Row>,
    );
  }
  if (isPresent(cve.vendor_remediation)) {
    rows.push(
      <Row key="remediation" label="Vendor remediation">
        {/* Verbatim. The backend prefixes it with the advisory id so that ICS
            guidance can never read as the desktop vendor's own advice, and
            re-wording it here would undo that. */}
        {cve.vendor_remediation}
      </Row>,
    );
  }
  if (Array.isArray(cve.vendor_advisories) && cve.vendor_advisories.length) {
    rows.push(
      <Row key="advisories" label="Vendor advisories">
        <ul className="cr-enrich__list">
          {cve.vendor_advisories.map((a, i) => {
            const id = a?.advisory_id || a?.id || a?.url || `advisory-${i}`;
            return (
              <li key={id}>
                {a?.url ? (
                  <a href={a.url} target="_blank" rel="noreferrer">
                    {a.advisory_id || a.url}
                  </a>
                ) : (
                  a?.advisory_id || String(id)
                )}
              </li>
            );
          })}
        </ul>
      </Row>,
    );
  }

  if (!rows.length) return null;
  return <dl className="cr-enrich">{rows}</dl>;
}
