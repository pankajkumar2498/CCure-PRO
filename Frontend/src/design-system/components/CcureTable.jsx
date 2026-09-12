import { useCallback, useEffect, useId, useRef, useState } from "react";

/**
 * CcureTable
 *
 * The accessibility-critical primitive. Measured across the application at the
 * start of this migration: **46 tables, 330 header cells, zero `scope`
 * attributes and zero `<caption>` elements.** Data tables are this product's
 * primary output — a scan result, a finding list, an asset register — so a
 * table a screen-reader user cannot navigate is not a cosmetic gap.
 *
 * What this supplies that a hand-rolled `<table>` does not:
 *
 *   * a `<caption>`, visible or visually hidden, so the table has a name
 *   * `scope="col"` on every column header, and `scope="row"` on the cell that
 *     identifies its row — which is what lets a reader announce "Port, 22" as
 *     it moves across rather than reading a naked value
 *   * `aria-sort` on the sorted column, with a real `<button>` inside the
 *     header rather than a click handler on the cell
 *   * a scroll container that becomes keyboard-reachable only when it actually
 *     overflows
 *   * loading and empty states that occupy the table rather than replacing it,
 *     so the header row does not disappear and reflow the page
 *
 * ── Two APIs, deliberately ──────────────────────────────────────────────────
 * Declarative (`columns` + `rows`) covers the common case. Passing `children`
 * instead gives the caller the `<tbody>` while keeping the caption, the
 * semantics, the scroll container and the styling. Forcing 46 differently
 * shaped tables through one row-renderer would be the kind of abstraction that
 * makes callers fight it.
 */

/** Column shape (all optional except `key` and `header`):
 *   key       string   — identifies the column; also the sort key
 *   header    node     — header content
 *   cell      (row, index) => node   — defaults to row[key]
 *   align     "start" | "center" | "end"
 *   mono      boolean  — tabular data: addresses, ports, hashes, CVE ids
 *   nowrap    boolean
 *   width     string   — a CSS width for the <col>
 *   sortable  boolean
 *   isRowHeader boolean — render as <th scope="row"> instead of <td>
 */

export default function CcureTable({
  caption,
  captionVisible = false,
  columns = [],
  rows = [],
  rowKey,
  children,
  sort = null,
  onSortChange,
  loading = false,
  loadingRows = 3,
  empty,
  emptyMessage = "No rows to display.",
  density = "comfortable",
  hoverable = true,
  stickyHeader = false,
  className = "",
  ...rest
}) {
  const captionId = useId();
  const wrapRef = useRef(null);
  const [scrollable, setScrollable] = useState(false);

  /**
   * A horizontally scrolling region must be reachable by keyboard, or the
   * columns past the fold cannot be read without a mouse. But a container that
   * is always focusable adds a tab stop to every table on the page whether or
   * not it scrolls, which is its own nuisance — so the tabindex is applied
   * only while the content actually overflows.
   */
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return undefined;
    const measure = () => setScrollable(el.scrollWidth > el.clientWidth + 1);
    measure();
    if (typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [rows, columns, children]);

  const handleSort = useCallback(
    (key) => {
      if (!onSortChange) return;
      const direction =
        sort?.key === key && sort?.direction === "ascending"
          ? "descending"
          : "ascending";
      onSortChange({ key, direction });
    },
    [onSortChange, sort],
  );

  const colCount = columns.length || 1;
  const showEmpty = !loading && !children && rows.length === 0;

  return (
    <div
      className="cc-table-wrap"
      ref={wrapRef}
      // The region needs a name for the same reason any landmark does.
      role={scrollable ? "region" : undefined}
      aria-labelledby={scrollable && caption ? captionId : undefined}
      tabIndex={scrollable ? 0 : undefined}
    >
      <table
        className={[
          "cc-table",
          `cc-table--${density}`,
          hoverable ? "cc-table--hoverable" : "",
          stickyHeader ? "cc-table--sticky" : "",
          className,
        ]
          .filter(Boolean)
          .join(" ")}
        {...rest}
      >
        {/* A caption is the table's accessible name. Hiding it visually is
            fine; omitting it is what leaves 46 tables anonymous. */}
        {caption ? (
          <caption
            id={captionId}
            className={captionVisible ? "cc-table__caption" : "cc-sr-only"}
          >
            {caption}
          </caption>
        ) : null}

        {columns.some((c) => c.width) ? (
          <colgroup>
            {columns.map((c) => (
              <col
                key={c.key}
                style={c.width ? { width: c.width } : undefined}
              />
            ))}
          </colgroup>
        ) : null}

        {columns.length > 0 ? (
          <thead>
            <tr>
              {columns.map((col) => {
                const isSorted = sort?.key === col.key;
                const ariaSort = col.sortable
                  ? isSorted
                    ? sort.direction
                    : "none"
                  : undefined;

                return (
                  <th
                    key={col.key}
                    scope="col"
                    aria-sort={ariaSort}
                    className={cellClass(col)}
                  >
                    {col.sortable && onSortChange ? (
                      <button
                        type="button"
                        className="cc-table__sort"
                        onClick={() => handleSort(col.key)}
                      >
                        <span>{col.header}</span>
                        {/* aria-sort on the th already conveys the state, so
                            the glyph is decorative. It exists so a sighted
                            user is not relying on colour alone. */}
                        <span
                          className="cc-table__sort-indicator"
                          aria-hidden="true"
                        >
                          {isSorted
                            ? sort.direction === "ascending"
                              ? "▲"
                              : "▼"
                            : "↕"}
                        </span>
                      </button>
                    ) : (
                      col.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
        ) : null}

        <tbody>
          {children}

          {!children && !loading
            ? rows.map((row, index) => (
                <tr key={rowKey ? rowKey(row, index) : index}>
                  {columns.map((col) => {
                    const content = col.cell
                      ? col.cell(row, index)
                      : row[col.key];
                    // scope="row" is what makes a reader announce the row's
                    // identity alongside each cell as it moves across.
                    return col.isRowHeader ? (
                      <th key={col.key} scope="row" className={cellClass(col)}>
                        {content}
                      </th>
                    ) : (
                      <td key={col.key} className={cellClass(col)}>
                        {content}
                      </td>
                    );
                  })}
                </tr>
              ))
            : null}

          {loading
            ? Array.from({ length: loadingRows }).map((_, r) => (
                <tr key={`cc-skel-${r}`}>
                  {(columns.length ? columns : [{ key: "x" }]).map((col) => (
                    <td key={col.key}>
                      <span className="cc-skeleton cc-skeleton--text" />
                    </td>
                  ))}
                </tr>
              ))
            : null}

          {showEmpty ? (
            <tr>
              {/* Inside the table, not instead of it: replacing the whole
                  table with an empty state removes the header row and reflows
                  everything around it on every filter change. */}
              <td colSpan={colCount} className="cc-table__message">
                {empty ?? emptyMessage}
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

function cellClass(col) {
  return [
    col.align === "end" ? "cc-table__cell--end" : "",
    col.align === "center" ? "cc-table__cell--center" : "",
    col.nowrap ? "cc-table__cell--nowrap" : "",
    col.mono ? "cc-table__cell--mono" : "",
    col.className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
}

/**
 * Announces a table's loading state to assistive technology.
 *
 * `CcureTable`'s skeleton rows are visual only — a screen reader sees empty
 * cells and is told nothing. Wrap a table whose data arrives asynchronously in
 * this, or render your own polite live region, so "Loading results" is
 * actually said rather than merely shown.
 */
export function CcureTableStatus({ loading, count, noun = "rows" }) {
  return (
    <p className="cc-sr-only" role="status" aria-live="polite">
      {loading ? "Loading results" : `${count} ${noun}`}
    </p>
  );
}
