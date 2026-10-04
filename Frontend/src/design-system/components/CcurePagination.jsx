import { useId } from "react";
import CcureButton from "./CcureButton";

/**
 * CcurePagination
 *
 * Modelled on what seven pages already do by hand (AuditLogs, UserManagement,
 * DeletedUsers, EmailDomainRules, AMTIntegration, ScanHistory,
 * ComplianceWorkspace): `page` / `pageSize` / `total`, a "Showing X–Y of N"
 * summary, a page-size selector and prev/next. Same shape, so migrating a page
 * is a substitution rather than a redesign.
 *
 * `page` is **1-based**, matching every existing call site and every backend
 * query parameter this application sends. Introducing a 0-based component
 * here would put an off-by-one at each of the seven boundaries.
 *
 * Three accessibility points:
 *
 *   * The `<nav>` is labelled, because a page can hold more than one.
 *   * The status text is a **live region**. Paging replaces the rows below
 *     without moving focus, so a screen-reader user gets no indication that
 *     anything happened; announcing "Page 2 of 9" is what makes the control
 *     usable rather than merely operable.
 *   * The page-size `<select>` has a real associated `<label>`. The existing
 *     implementations use a bare `<select>` next to the word "Show".
 */
export default function CcurePagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [25, 50, 100],
  pageSizeLabel = "Rows per page",
  showBoundaryLinks = false,
  label = "Pagination",
  itemNoun = "results",
  disabled = false,
  className = "",
}) {
  const sizeId = useId();

  const pageCount = Math.max(1, Math.ceil((total || 0) / (pageSize || 1)));
  const current = Math.min(Math.max(1, page || 1), pageCount);
  const first = total === 0 ? 0 : (current - 1) * pageSize + 1;
  const last = Math.min(current * pageSize, total || 0);

  const atStart = current <= 1;
  const atEnd = current >= pageCount;

  return (
    <nav className={`cc-pagination ${className}`.trim()} aria-label={label}>
      <div className="cc-pagination__summary">
        Showing {first}–{last} of {total ?? 0} {itemNoun}
      </div>

      <div className="cc-pagination__controls">
        {onPageSizeChange ? (
          <div className="cc-pagination__size">
            <label htmlFor={sizeId}>{pageSizeLabel}</label>
            <select
              id={sizeId}
              value={pageSize}
              disabled={disabled}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
            >
              {pageSizeOptions.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        {showBoundaryLinks && (
          <CcureButton
            variant="secondary"
            size="sm"
            disabled={disabled || atStart}
            onClick={() => onPageChange(1)}
          >
            First
          </CcureButton>
        )}

        <CcureButton
          variant="secondary"
          size="sm"
          disabled={disabled || atStart}
          onClick={() => onPageChange(current - 1)}
        >
          Previous
        </CcureButton>

        {/* Live, because the rows change without focus moving. Polite rather
            than assertive: it is a confirmation, not an interruption. */}
        <span
          className="cc-pagination__status"
          role="status"
          aria-live="polite"
        >
          Page {current} of {pageCount}
        </span>

        <CcureButton
          variant="secondary"
          size="sm"
          disabled={disabled || atEnd}
          onClick={() => onPageChange(current + 1)}
        >
          Next
        </CcureButton>
        {showBoundaryLinks && (
          <CcureButton
            variant="secondary"
            size="sm"
            disabled={disabled || atEnd}
            onClick={() => onPageChange(pageCount)}
          >
            Last
          </CcureButton>
        )}
      </div>
    </nav>
  );
}
