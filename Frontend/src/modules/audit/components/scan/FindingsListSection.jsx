/**
 * The CVE findings list, with its severity filter and — new — pagination.
 *
 * Extracted from `CredentialedResults` for two reasons, one visible and one
 * structural.
 *
 * The visible one: `filteredCves.map(...)` rendered every row it was given,
 * which on a real credentialed scan is 1,871 findings mounted into one DOM
 * tree. It is slow to mount, slow to scroll, and the operator cannot find
 * anything in it.
 *
 * The structural one: the page returns early for its loading and error states,
 * so a hook added at the point the list is built would be called conditionally
 * — which React forbids and which would have broken the page's other state the
 * first time a scan errored. A component that owns its own filter and paging
 * has no such ordering problem.
 *
 * The markup, the severity vocabulary and the counts are unchanged, so an
 * existing report reads exactly as it did. Only the number of rows in the DOM
 * at once is different.
 */

import { useState } from "react";
import CVELink from "../common/CVELink";
import {
  CcureButton,
  CcurePagination,
  CcureSeverityBadge,
} from "../../../../design-system";
import usePagedRows from "@audit/hooks/usePagedRows";
import { FindingSignals, FindingDetail } from "./FindingEnrichment";

/**
 * The row's own disclosure for everything below the headline.
 *
 * A component rather than inline state, because a credentialed scan renders
 * up to a page of these and a hook cannot be called inside `map`.
 */
function FindingMore({ cve }) {
  const [open, setOpen] = useState(false);
  const detail = <FindingDetail cve={cve} />;
  if (!detail) return null;
  return (
    <div className="cr-finding__more">
      <CcureButton
        variant="ghost"
        size="sm"
        type="button"
        className="cr-finding__moretoggle"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? "Hide detail" : "Detail"}
      </CcureButton>
      {open ? detail : null}
    </div>
  );
}

export default function FindingsListSection({
  cves = [],
  severitySummary = {},
  severityOrder = [],
  glyph: Glyph = "span",
}) {
  const [filter, setFilter] = useState("All");

  const paged = usePagedRows(cves, {
    filter: (c) => filter === "All" || c.severity === filter,
    resetKey: filter,
  });

  return (
    <>
      {/* Severity summary */}
      <ul className="cr-sev-summary" aria-label="Findings by severity">
        {Object.entries(severitySummary)
          .filter(([, n]) => n > 0)
          .map(([sev, n]) => (
            <li key={sev} className="cr-sev-summary__item">
              <span
                className={`cr-sev-dot cr-sev-dot--${String(sev).toLowerCase()}`}
                aria-hidden="true"
              />
              {n} {sev}
            </li>
          ))}
      </ul>

      {/* Severity filter */}
      <div
        className="cr-filter"
        role="group"
        aria-label="Filter findings by severity"
      >
        {severityOrder.map((sev) => (
          <CcureButton
            key={sev}
            variant="secondary"
            size="sm"
            className="cr-toggle"
            aria-pressed={filter === sev}
            onClick={() => setFilter(sev)}
          >
            {sev}
            {sev !== "All" && severitySummary[sev] > 0 && (
              <span className="cr-toggle__count">({severitySummary[sev]})</span>
            )}
          </CcureButton>
        ))}
      </div>

      {paged.total === 0 ? (
        <p className="cr-note">No findings at this severity.</p>
      ) : (
        <>
          <ul className="cr-findings">
            {paged.rows.map((cve, i) => (
              <li key={`${cve.cve_id || "cve"}-${i}`} className="cr-finding">
                <div className="cr-finding__head">
                  <CVELink cveId={cve.cve_id} className="cr-finding__id" />
                  <CcureSeverityBadge severity={cve.severity} />
                  {cve.cvss_score && (
                    <span className="cr-mono cr-muted">
                      CVSS {cve.cvss_score}
                    </span>
                  )}
                  {cve.package && (
                    <span className="cr-mono cr-muted">
                      {cve.package} {cve.installed_ver}
                    </span>
                  )}
                  {cve.fixed_ver && (
                    <span className="cr-tone-success">
                      <Glyph>→</Glyph> fixed in {cve.fixed_ver}
                    </span>
                  )}
                </div>
                {/* KEV, exploit availability, ransomware use and the computed
                    priority — the fields that decide which of a thousand
                    findings is worked first, and which reached no screen
                    before this. */}
                <FindingSignals cve={cve} />
                <p className="cr-finding__desc">{cve.description}</p>
                <FindingMore cve={cve} />
              </li>
            ))}
          </ul>
          <CcurePagination
            page={paged.page}
            pageSize={paged.pageSize}
            total={paged.total}
            onPageChange={paged.setPage}
            onPageSizeChange={paged.setPageSize}
            itemNoun="findings"
          />
        </>
      )}
    </>
  );
}
