/**
 * Filter → sort → page, in that order, for a table the operator drives.
 *
 * Written because three sections of the credentialed results page need the
 * same thing and the page already had the alternative: `filteredCves.map(...)`
 * renders every row it is given, which on a real scan is 1,871 rows of table
 * in one DOM tree. That is slow to mount, slow to scroll, and unreadable.
 *
 * The order matters and is not arbitrary. Paging before filtering shows "1–25
 * of 254" and then displays four rows, because the filter ran on the page
 * rather than the set. Sorting after paging sorts only what is on screen,
 * which looks like sorting until the operator turns the page.
 *
 * The page index is reset whenever the *set* changes — a filter that leaves
 * fewer rows than the current offset would otherwise strand the operator on an
 * empty page with no indication that anything matched.
 */

import { useEffect, useMemo, useState } from "react";

export default function usePagedRows(
  rows,
  { filter = null, sorter = null, initialPageSize = 25, resetKey = "" } = {},
) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);

  const filtered = useMemo(
    () => (filter ? (rows || []).filter(filter) : rows || []),
    // `filter` is a fresh closure on every render, so depending on it would
    // recompute constantly. `resetKey` is what the caller says has changed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [rows, resetKey],
  );

  const sorted = useMemo(() => {
    if (!sorter) return filtered;
    // Copy first: Array.prototype.sort mutates, and mutating the array that
    // came out of the API response makes a later render disagree with itself.
    return [...filtered].sort(sorter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, resetKey]);

  const total = sorted.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    setPage(1);
  }, [resetKey, pageSize]);

  // Clamp rather than trust: `page` can be left past the end by a filter that
  // narrowed the set between renders.
  const current = Math.min(Math.max(1, page), pageCount);
  const visible = useMemo(
    () => sorted.slice((current - 1) * pageSize, current * pageSize),
    [sorted, current, pageSize],
  );

  return {
    rows: visible,
    total,
    page: current,
    pageSize,
    setPage,
    setPageSize,
    /** True when a filter is hiding rows — for "no match" versus "nothing collected". */
    isFiltered: (rows || []).length !== total,
  };
}
