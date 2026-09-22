/**
 * Candidates the audit evaluated and then ruled out.
 *
 * These are not findings and they are not noise: they are the part of the
 * chain an operator needs to read the rest of it honestly —
 *
 *     detected → evaluated → suppressed → reported
 *
 * Without them a scan that evaluated 1,871 candidates and reported 1,871
 * findings looks identical to one that evaluated 1,871 and withheld 400. The
 * backend has carried this per host since the methodology appendix reported
 * zero suppressions for every credentialed scan, whatever it had withheld; the
 * only place it surfaced was Scan History.
 *
 * The empty case is a real answer and says so in words. An empty table would
 * read as "this was not computed", which is the confusion the project's
 * empty-state rule exists to prevent.
 */

import { useState } from "react";
import { CcureInput, CcurePagination, CcureTable } from "../../design-system";
import usePagedRows from "../../hooks/usePagedRows";

export default function SuppressedFindingsSection({
  suppressed,
  candidatesEvaluated = null,
  reportedCount = null,
}) {
  const [search, setSearch] = useState("");
  const rows = suppressed || [];
  const needle = search.trim().toLowerCase();

  const paged = usePagedRows(rows, {
    filter: (row) =>
      !needle ||
      String(row.identifier || "")
        .toLowerCase()
        .includes(needle) ||
      String(row.reason || "")
        .toLowerCase()
        .includes(needle) ||
      String(row.host || "")
        .toLowerCase()
        .includes(needle),
    resetKey: needle,
  });

  return (
    <div className="sf-root">
      {/* The chain, stated with whatever numbers the API supplied. Each part
          is omitted rather than guessed when it was not reported. */}
      <ul className="sf-chain" aria-label="Finding lifecycle">
        {candidatesEvaluated !== null && candidatesEvaluated !== undefined ? (
          <li className="sf-chain__step">
            <span className="sf-chain__value">
              {Number(candidatesEvaluated).toLocaleString()}
            </span>
            <span className="sf-chain__label">Candidates evaluated</span>
          </li>
        ) : null}
        <li className="sf-chain__step">
          <span className="sf-chain__value">
            {rows.length.toLocaleString()}
          </span>
          <span className="sf-chain__label">Suppressed</span>
        </li>
        {reportedCount !== null && reportedCount !== undefined ? (
          <li className="sf-chain__step">
            <span className="sf-chain__value">
              {Number(reportedCount).toLocaleString()}
            </span>
            <span className="sf-chain__label">Reported as findings</span>
          </li>
        ) : null}
      </ul>

      {rows.length === 0 ? (
        <p className="sf-empty">
          No findings were suppressed or withheld for this scan. Every candidate
          the audit evaluated either became a finding or was not applicable to
          this host.
        </p>
      ) : (
        <>
          <div className="sf-toolbar">
            <p className="sf-note">
              Each of these was evaluated and then ruled out, with the reason
              recorded at the time. They are excluded from the findings above.
            </p>
            <CcureInput
              type="search"
              label="Search suppressed"
              placeholder="Identifier, host or reason…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              fieldClassName="sf-search"
            />
          </div>

          {paged.total === 0 ? (
            <p className="sf-note">No suppressed findings match that search.</p>
          ) : (
            <>
              <CcureTable
                caption="Suppressed candidates"
                density="compact"
                rows={paged.rows}
                rowKey={(row, i) => `${row.identifier || "x"}-${i}`}
                columns={[
                  {
                    key: "identifier",
                    header: "Identifier",
                    isRowHeader: true,
                    mono: true,
                  },
                  { key: "host", header: "Host", mono: true },
                  {
                    key: "reason",
                    header: "Reason withheld",
                    cell: (row) => (
                      <span className="sf-reason">{row.reason || "—"}</span>
                    ),
                  },
                ]}
              />
              <CcurePagination
                page={paged.page}
                pageSize={paged.pageSize}
                total={paged.total}
                onPageChange={paged.setPage}
                onPageSizeChange={paged.setPageSize}
                itemNoun="suppressed candidates"
              />
            </>
          )}
        </>
      )}
    </div>
  );
}
