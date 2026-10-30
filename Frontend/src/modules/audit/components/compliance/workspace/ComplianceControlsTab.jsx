/**
 * The compliance workspace's Controls tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import {
  CcureCard,
  CcureInput,
  CcureSelect,
  CcureTableStatus,
  CcureTable,
  CcureBadge,
  CcureIcon,
  CcureButton,
} from "../../../../../design-system";
import { THEME_LABELS } from "./shared";

export default function ComplianceControlsTab({
  controlsData,
  controlsSearch,
  controlsStatusFilter,
  fetchTabData,
  loading,
  openAttestModal,
  setControlsSearch,
  setControlsStatusFilter,
}) {
  return (
    <CcureCard
      title="Control Register"
      subtitle="Every control of the selected framework, with its current verdict and attestation state."
      className="cwv-controls"
    >
      <div className="cwv-filters cwv-controls__filters">
        <CcureInput
          type="search"
          label="Search controls"
          placeholder="Search controls…"
          value={controlsSearch}
          onChange={(e) => setControlsSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") fetchTabData();
          }}
        />
        <CcureSelect
          label="Status"
          value={controlsStatusFilter}
          onChange={(e) => {
            setControlsStatusFilter(e.target.value);
            setTimeout(fetchTabData, 0);
          }}
        >
          <option value="all">All statuses</option>
          <option value="pass">Implemented</option>
          <option value="fail">Not implemented</option>
          <option value="manual_review">Awaiting review</option>
          <option value="not_assessed">Not assessed</option>
          <option value="not_applicable">Excluded</option>
          <option value="exception">Exception</option>
        </CcureSelect>
      </div>

      {/* Readiness, not a single percentage. "62% compliant" cannot
                  distinguish a framework nobody has assessed from one that was
                  assessed and failed. */}
      {controlsData?.summary && (
        <dl className="cwv-tiles">
          {[
            ["Implemented", controlsData.summary.passed, "success"],
            ["Not implemented", controlsData.summary.failed, "danger"],
            [
              "Awaiting review",
              controlsData.summary.awaiting_review,
              "warning",
            ],
            ["Not assessed", controlsData.summary.not_assessed, "neutral"],
            ["Excluded", controlsData.summary.not_applicable, "neutral"],
          ].map(([label, value, tone]) => (
            <div key={label} className="cwv-tiles__item">
              <dt className="cwv-tiles__label">{label}</dt>
              <dd className={`cwv-tiles__value cwv-tiles__value--${tone}`}>
                {value}
              </dd>
            </div>
          ))}
        </dl>
      )}

      <CcureTableStatus
        loading={loading && (controlsData?.data || []).length === 0}
        count={(controlsData?.data || []).length}
        noun="controls"
      />
      <CcureTable
        caption="Control register"
        rows={controlsData?.data || []}
        rowKey={(c) => c.control_id}
        loading={loading && (controlsData?.data || []).length === 0}
        emptyMessage="No controls match the current filter."
        columns={[
          {
            key: "ref",
            header: "Ref",
            isRowHeader: true,
            mono: true,
            nowrap: true,
            cell: (c) => c.control_number,
          },
          {
            key: "control",
            header: "Control",
            cell: (c) => (
              <>
                <span className="cwv-cell__title">{c.title}</span>
                {c.description && (
                  <span className="cwv-cell__detail cwv-cell__detail--measure">
                    {c.description}
                  </span>
                )}
              </>
            ),
          },
          {
            key: "theme",
            header: "Theme",
            cell: (c) => (
              <>
                {/* NIST CSF is Function ▸ Category ▸ Subcategory.
                            Printing the bare `theme` code showed "GV"
                            against all 31 Govern rows and named neither
                            level. The API derives both from the
                            Subcategory id and returns null for frameworks
                            that are not CSF, so this falls back cleanly. */}
                <span className="cwv-cell__title">
                  {c.function || THEME_LABELS[c.theme] || c.theme}
                </span>
                {c.category && (
                  <span className="cwv-cell__detail">
                    {c.category} · {c.category_name}
                  </span>
                )}
              </>
            ),
          },
          {
            key: "mode",
            header: "Mode",
            cell: (c) => <span className="cwv-caps">{c.scannability}</span>,
          },
          {
            key: "status",
            header: "Status",
            cell: (c) => (
              <CcureBadge
                variant={
                  c.status === "pass"
                    ? "success"
                    : c.status === "fail"
                      ? "danger"
                      : c.status === "not_applicable"
                        ? "neutral"
                        : "warning"
                }
              >
                {c.status === "not_assessed"
                  ? "NOT ASSESSED"
                  : c.status.replace(/_/g, " ").toUpperCase()}
              </CcureBadge>
            ),
          },
          {
            key: "evidence",
            header: "Evidence",
            nowrap: true,
            cell: (c) =>
              c.evidence_file_count > 0 ? (
                <>
                  <CcureIcon name="paperclip" /> {c.evidence_file_count}
                </>
              ) : (
                "—"
              ),
          },
          {
            key: "reviewed",
            header: "Reviewed",
            nowrap: true,
            cell: (c) =>
              c.reviewed_at
                ? new Date(c.reviewed_at).toLocaleDateString()
                : "—",
          },
          {
            key: "actions",
            header: "Actions",
            cell: (c) => (
              <CcureButton
                variant="primary"
                size="sm"
                onClick={() => openAttestModal(c)}
              >
                Attest
              </CcureButton>
            ),
          },
        ]}
      />
    </CcureCard>
  );
}
