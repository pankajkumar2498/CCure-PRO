/**
 * The compliance workspace's Approvals Queue tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import {
  cancelRemediationRequest,
  decideRemediationRequest,
} from "@audit/api/compliance";
import {
  CcureTableStatus,
  CcureTable,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
} from "../../../../../design-system";
import { PagingControls } from "./shared";

export default function ComplianceApprovalsTab({
  approvalsList,
  approvalsPagination,
  fetchTabData,
  isComplianceAdmin,
  loading,
  pushToast,
  queueDecision,
  queueDecisionBusy,
  setModalOpen,
  setModalType,
  setQueueDecision,
  setQueueDecisionBusy,
  setSelectedFinding,
  user,
}) {
  return (
    <section
      ref={approvalsPagination.cardRef}
      className="cwe-queue"
      aria-labelledby="cwe-queue-title"
    >
      <h2 id="cwe-queue-title" className="cwe-queue__title">
        Remediation Approvals Queue
      </h2>
      <PagingControls
        pagination={approvalsPagination}
        total={approvalsList.length}
        loading={loading}
        label="Approvals pagination"
        itemNoun="tickets"
        sizes={[10, 25, 50, 100]}
      />
      <CcureTableStatus
        loading={loading}
        count={approvalsList.length}
        noun="tickets"
      />
      <CcureTable
        caption="Remediation approval requests"
        columns={[
          {
            key: "id",
            header: "Ticket ID",
            isRowHeader: true,
            mono: true,
            className: "cwe-ticket",
            cell: (req) => req.id,
          },
          {
            key: "control",
            header: "Control & Asset",
            cell: (req) => (
              <span className="cwe-cell">
                <span className="cwe-cell__control">
                  {req.id.startsWith("crrq_rollback_") && (
                    <CcureBadge variant="warning" className="cwe-rollback">
                      Rollback
                    </CcureBadge>
                  )}
                  {req.control_id} - {req.control_title}
                </span>
                <span className="cwe-cell__detail">
                  {"Target Host:"}{" "}
                  <span className="cwe-mono">{req.asset_ip}</span>
                </span>
              </span>
            ),
          },
          {
            key: "fix_command",
            header: "Fix Command",
            cell: (req) => (
              <code className="cwe-command">{req.fix_command}</code>
            ),
          },
          {
            key: "requested_by",
            header: "Requested By",
            cell: (req) => req.requested_by,
          },
          {
            key: "status",
            header: "Status",
            nowrap: true,
            // The status is the badge's word; the colour repeats it.
            cell: (req) => (
              <CcureBadge
                className="cwe-status"
                variant={
                  req.status === "pending_approval"
                    ? "warning"
                    : req.status === "executed"
                      ? "success"
                      : req.status === "approved"
                        ? "info"
                        : req.status === "failed"
                          ? "danger"
                          : "neutral"
                }
              >
                {req.status.replace("_", " ")}
              </CcureBadge>
            ),
          },
          {
            key: "actions",
            header: "Actions",
            cell: (req) => (
              <span className="cwe-actions">
                {req.status === "pending_approval" &&
                  (req.requested_by === user?.id ? (
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      className="cwe-danger-text"
                      aria-haspopup="dialog"
                      aria-label={`${
                        req.id.startsWith("crrq_rollback_")
                          ? "Cancel Rollback"
                          : "Cancel Request"
                      } ${req.id}`}
                      onClick={() => setQueueDecision({ req, kind: "cancel" })}
                    >
                      {req.id.startsWith("crrq_rollback_")
                        ? "Cancel Rollback"
                        : "Cancel Request"}
                    </CcureButton>
                  ) : isComplianceAdmin ? (
                    <>
                      <CcureButton
                        variant="primary"
                        size="sm"
                        aria-haspopup="dialog"
                        aria-label={`Approve ${req.id}`}
                        onClick={() =>
                          setQueueDecision({ req, kind: "approve" })
                        }
                      >
                        Approve
                      </CcureButton>
                      <CcureButton
                        variant="ghost"
                        size="sm"
                        className="cwe-danger-text"
                        aria-haspopup="dialog"
                        aria-label={`Reject ${req.id}`}
                        onClick={() =>
                          setQueueDecision({ req, kind: "reject" })
                        }
                      >
                        Reject
                      </CcureButton>
                    </>
                  ) : (
                    <span className="cwe-pending">Pending approval</span>
                  ))}
                {(req.status === "executed" || req.status === "failed") &&
                  req.execution_log && (
                    <>
                      <CcureButton
                        variant="ghost"
                        size="sm"
                        aria-haspopup="dialog"
                        aria-label={`View Logs for ${req.id}`}
                        onClick={() => {
                          setSelectedFinding({
                            control_id: req.control_id,
                            control_title: req.control_title,
                            asset_ip: req.asset_ip,
                            execution_log: req.execution_log,
                          });
                          setModalType("log_viewer");
                          setModalOpen(true);
                        }}
                      >
                        View Logs
                      </CcureButton>
                      {req.status === "executed" &&
                        !req.id.startsWith("crrq_rollback_") &&
                        (() => {
                          const hasActiveRollback = approvalsList.some(
                            (r) =>
                              r.finding_id === req.finding_id &&
                              r.id.startsWith("crrq_rollback_") &&
                              (r.status === "pending_approval" ||
                                r.status === "approved"),
                          );
                          if (!hasActiveRollback) {
                            return (
                              <CcureButton
                                variant="ghost"
                                size="sm"
                                className="cwe-danger-text"
                                aria-haspopup="dialog"
                                aria-label={`Rollback ${req.id}`}
                                onClick={() => {
                                  setSelectedFinding({
                                    id: req.id,
                                    control_id: req.control_id,
                                    control_title: req.control_title,
                                    asset_ip: req.asset_ip,
                                    fix_command: req.fix_command,
                                    recommendation_text:
                                      "Reverse the security control and reopen the port on the target machine.",
                                  });
                                  setModalType("rollback");
                                  setModalOpen(true);
                                }}
                              >
                                Rollback
                              </CcureButton>
                            );
                          }
                          return null;
                        })()}
                    </>
                  )}
              </span>
            ),
          },
        ]}
        rows={approvalsPagination.paginatedItems}
        rowKey={(req) => req.id}
        loading={loading}
        emptyMessage="No approval tickets in this status."
      />

      {/* Cancelling, approving and rejecting each ask first. Approving
                  queues a script to run on a customer host with the
                  credentials the request was made with, and rejecting or
                  cancelling clears those credentials, so none of them is a
                  single click: Go back takes focus, Escape goes back, and the
                  question is busy and cannot be answered twice while its
                  request is out. */}
      <CcureConfirmDialog
        open={queueDecision !== null}
        title={
          queueDecision
            ? `${
                queueDecision.kind === "cancel"
                  ? "Cancel"
                  : queueDecision.kind === "approve"
                    ? "Approve"
                    : "Reject"
              } ${
                queueDecision.req.id.startsWith("crrq_rollback_")
                  ? "rollback"
                  : "remediation"
              } request`
            : ""
        }
        subtitle={
          queueDecision
            ? `${queueDecision.req.id} — ${queueDecision.req.control_id} on ${queueDecision.req.asset_ip}`
            : undefined
        }
        warning={
          !queueDecision
            ? null
            : queueDecision.kind === "cancel"
              ? `Are you sure you want to cancel this ${
                  queueDecision.req.id.startsWith("crrq_rollback_")
                    ? "rollback"
                    : "remediation"
                } request?`
              : queueDecision.kind === "approve"
                ? `Approving queues this ${
                    queueDecision.req.id.startsWith("crrq_rollback_")
                      ? "rollback"
                      : "remediation"
                  } to run on ${queueDecision.req.asset_ip} with the credentials it was requested with.`
                : `Rejecting closes this ${
                    queueDecision.req.id.startsWith("crrq_rollback_")
                      ? "rollback"
                      : "remediation"
                  } request and clears the credentials held with it; it will not run.`
        }
        confirmLabel={
          !queueDecision
            ? "Confirm"
            : queueDecision.kind === "cancel"
              ? queueDecision.req.id.startsWith("crrq_rollback_")
                ? "Cancel Rollback"
                : "Cancel Request"
              : queueDecision.kind === "approve"
                ? "Approve"
                : "Reject"
        }
        cancelLabel="Go back"
        tone={queueDecision?.kind === "approve" ? "info" : "danger"}
        busy={queueDecisionBusy}
        onCancel={() => setQueueDecision(null)}
        onConfirm={async () => {
          if (queueDecisionBusy || !queueDecision) return;
          const { req, kind } = queueDecision;
          setQueueDecisionBusy(true);
          if (kind === "cancel") {
            const label = req.id.startsWith("crrq_rollback_")
              ? "rollback"
              : "remediation";
            try {
              await cancelRemediationRequest(req.id);
              pushToast(
                `${label.charAt(0).toUpperCase() + label.slice(1)} request cancelled successfully.`,
                "success",
              );
              fetchTabData();
            } catch (e) {
              pushToast(
                "Cancellation failed: " +
                  (e.response?.data?.detail ||
                    e.response?.data?.message ||
                    e.message),
                "error",
              );
            }
          } else if (kind === "approve") {
            try {
              await decideRemediationRequest(req.id, "approved");
              const label = req.id.startsWith("crrq_rollback_")
                ? "Rollback"
                : "Remediation request";
              pushToast(`${label} approved and queued.`, "success");
              fetchTabData();
            } catch (e) {
              pushToast(
                "Approval failed: " +
                  (e.response?.data?.detail ||
                    e.response?.data?.message ||
                    e.message),
                "error",
              );
            }
          } else {
            try {
              await decideRemediationRequest(req.id, "rejected");
              const label = req.id.startsWith("crrq_rollback_")
                ? "Rollback"
                : "Remediation request";
              pushToast(`${label} rejected.`, "success");
              fetchTabData();
            } catch (e) {
              pushToast(
                "Rejection failed: " +
                  (e.response?.data?.detail ||
                    e.response?.data?.message ||
                    e.message),
                "error",
              );
            }
          }
          setQueueDecisionBusy(false);
          setQueueDecision(null);
        }}
      />
    </section>
  );
}
