/**
 * The compliance workspace's Exceptions tab. Moved from
 * `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import { useId } from "react";
import {
  CcureBadge,
  CcureButton,
  CcurePagination,
  CcureTableStatus,
  CcureTable,
} from "../../../../../design-system";

// The Exceptions tab: the pending findings the workspace has already read,
// paged in the browser. Nothing here writes. CcurePagination has no first or
// last page control, which the tab has always offered, so those two buttons
// sit beside it.
export default function ExceptionsPanel({
  exceptions,
  pagination,
  loading,
  canApprove = false,
  onDecide,
  deciding = false,
}) {
  const headingId = useId();
  const {
    page,
    setPage,
    pageSize,
    setPageSize,
    cardRef,
    totalPages,
    displayPage,
    paginatedItems,
  } = pagination;

  const columns = [
    {
      key: "control_id",
      header: "Control ID",
      isRowHeader: true,
      mono: true,
      cell: (exc) => exc.control_id,
    },
    {
      key: "asset_id",
      header: "Asset ID",
      mono: true,
      cell: (exc) => exc.asset_id || "Global",
    },
    {
      key: "reason",
      header: "Waiver Reason",
      cell: (exc) => exc.evidence?.note || exc.reason || "—",
    },
    {
      key: "status",
      header: "Status",
      cell: (exc) => (
        <CcureBadge
          variant={
            exc.status === "approved"
              ? "success"
              : exc.status === "rejected"
                ? "danger"
                : "warning"
          }
        >
          {exc.status}
        </CcureBadge>
      ),
    },
    {
      key: "approved_by",
      header: "Decided by",
      /* Who carried the decision. A waiver is an accepted risk and the
         record of who accepted it is the point of the workflow. */
      cell: (exc) => exc.approved_by || <span className="cwh-muted">—</span>,
    },
    ...(canApprove
      ? [
          {
            key: "decide",
            header: "Decision",
            /* `PATCH /compliance/exceptions/{id}` has existed with its own
               permission and no screen: the workspace listed waiver requests
               and nothing could act on one. The backend refuses anything that
               is not already `pending`, so the controls appear only there. */
            cell: (exc) =>
              exc.status === "pending" ? (
                <span className="cwh-decide">
                  <CcureButton
                    size="sm"
                    variant="primary"
                    disabled={deciding}
                    onClick={() => onDecide?.(exc, "approved")}
                  >
                    Approve
                  </CcureButton>
                  <CcureButton
                    size="sm"
                    variant="secondary"
                    disabled={deciding}
                    onClick={() => onDecide?.(exc, "rejected")}
                  >
                    Reject
                  </CcureButton>
                </span>
              ) : (
                <span className="cwh-muted">settled</span>
              ),
          },
        ]
      : []),
  ];

  return (
    <section ref={cardRef} className="cwx-panel" aria-labelledby={headingId}>
      <h2 id={headingId} className="cwx-panel__title">
        Exceptions
      </h2>

      <div className="cwx-panel__paging">
        <CcurePagination
          page={page}
          pageSize={pageSize}
          total={exceptions.length}
          onPageChange={setPage}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setPage(1);
          }}
          pageSizeOptions={[10, 25, 50, 100]}
          label="Exceptions pagination"
          itemNoun="waivers"
          disabled={loading}
        />
        <div className="cwx-panel__jump" role="group" aria-label="Jump to page">
          <CcureButton
            variant="ghost"
            size="sm"
            disabled={loading || displayPage === 1}
            onClick={() => setPage(1)}
          >
            First page
          </CcureButton>
          <CcureButton
            variant="ghost"
            size="sm"
            disabled={loading || displayPage === totalPages}
            onClick={() => setPage(totalPages)}
          >
            Last page
          </CcureButton>
        </div>
      </div>

      <CcureTableStatus
        loading={loading}
        count={exceptions.length}
        noun="waivers"
      />
      <CcureTable
        caption="Pending exceptions and waivers"
        columns={columns}
        rows={paginatedItems}
        rowKey={(exc) => exc.id}
        loading={loading}
        emptyMessage="No pending exceptions or waivers recorded."
      />
    </section>
  );
}
