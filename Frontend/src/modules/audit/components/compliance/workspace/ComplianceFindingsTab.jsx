/**
 * The compliance workspace's Findings tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import {
  CcureInput,
  CcureSelect,
  CcureButton,
  CcureTableStatus,
  CcureTable,
  CcureSeverityBadge,
  CcureBadge,
} from "../../../../../design-system";
import { PagingControls } from "./shared";

export default function ComplianceFindingsTab({
  filterAsset,
  filterIg,
  filterSearch,
  filterSeverity,
  filterStatus,
  filteredFindings,
  findings,
  findingsPagination,
  handleOpenEditRule,
  loading,
  openAttestModal,
  selectedFrameworkId,
  setFilterAsset,
  setFilterIg,
  setFilterSearch,
  setFilterSeverity,
  setFilterStatus,
  setModalOpen,
  setModalType,
  setSelectedFinding,
  uniqueAssets,
}) {
  return (
    <section
      ref={findingsPagination.cardRef}
      className="cwv-findings cwv-view"
      aria-labelledby="cwv-findings-title"
    >
      <h2 id="cwv-findings-title" className="cwv-view__title">
        Findings
      </h2>

      {/* Filter controls bar */}
      <div className="cwv-filters cwv-filters--bar">
        <CcureInput
          label="Search findings"
          placeholder="Search by Control, Rule..."
          value={filterSearch}
          onChange={(e) => setFilterSearch(e.target.value)}
        />
        <CcureSelect
          label="Asset"
          value={filterAsset}
          onChange={(e) => setFilterAsset(e.target.value)}
        >
          <option value="all">All Assets</option>
          {uniqueAssets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname && a.hostname !== "Unknown"
                ? `${a.hostname} (${a.ip})`
                : a.ip || a.id}
            </option>
          ))}
        </CcureSelect>
        <CcureSelect
          label="Status"
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
        >
          <option value="all">All Statuses</option>
          <option value="pass">Pass</option>
          <option value="fail">Fail</option>
          <option value="manual_review">Manual Review</option>
        </CcureSelect>
        <CcureSelect
          label="Severity"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </CcureSelect>

        {selectedFrameworkId === "cfw_cis_v8_1" && (
          <CcureSelect
            label="Implementation group"
            value={filterIg}
            onChange={(e) => setFilterIg(e.target.value)}
          >
            <option value="all">All Groups (IG1-3)</option>
            <option value="ig1">IG1 (Cyber Hygiene)</option>
            <option value="ig2">IG2 (Enterprise)</option>
            <option value="ig3">IG3 (Advanced)</option>
          </CcureSelect>
        )}

        {(filterSearch ||
          filterAsset !== "all" ||
          filterStatus !== "all" ||
          filterSeverity !== "all") && (
          <CcureButton
            variant="ghost"
            size="sm"
            className="cwv-filters__clear"
            onClick={() => {
              setFilterSearch("");
              setFilterAsset("all");
              setFilterStatus("all");
              setFilterSeverity("all");
              findingsPagination.setPage(1);
            }}
          >
            Clear Filters
          </CcureButton>
        )}
      </div>

      <PagingControls
        pagination={findingsPagination}
        total={filteredFindings.length}
        loading={loading}
        label="Findings pagination"
        itemNoun={
          findings.length !== filteredFindings.length
            ? `findings (filtered from ${findings.length} total)`
            : "findings"
        }
        sizes={[25, 50, 100, 250]}
      />

      <CcureTableStatus
        loading={loading}
        count={filteredFindings.length}
        noun="findings"
      />
      <CcureTable
        caption="Compliance findings"
        rows={findingsPagination.paginatedItems}
        rowKey={(f) => f.id}
        loading={loading}
        loadingRows={5}
        emptyMessage="No matching compliance findings discovered."
        columns={[
          {
            key: "control",
            header: "Control ID",
            isRowHeader: true,
            mono: true,
            nowrap: true,
            cell: (f) => f.control_id,
          },
          {
            key: "title",
            header: "Rule / Control Title",
            cell: (f) => (
              <>
                <span className="cwv-cell__title">{f.control_title}</span>
                {f.rule_name && (
                  <span className="cwv-cell__detail">
                    {"Rule Code:"}{" "}
                    <span className="cwv-mono">{f.rule_name}</span>
                  </span>
                )}
              </>
            ),
          },
          {
            key: "severity",
            header: "Severity",
            cell: (f) => (
              <CcureSeverityBadge severity={f.severity || "medium"} />
            ),
          },
          {
            key: "asset",
            header: "Asset Name / IP",
            cell: (f) =>
              f.asset_hostname && f.asset_hostname !== "Unknown" ? (
                <>
                  <span className="cwv-asset">
                    <span className="cwv-cell__title">{f.asset_hostname}</span>
                    {f.asset_reboot_pending && (
                      <CcureBadge
                        variant="warning"
                        title="System reboot is required to apply configuration changes."
                      >
                        Reboot Required
                      </CcureBadge>
                    )}
                  </span>
                  <span className="cwv-cell__detail cwv-mono">
                    {f.asset_ip}
                  </span>
                </>
              ) : f.asset_ip ? (
                <span className="cwv-asset">
                  <span className="cwv-mono">{f.asset_ip}</span>
                  {f.asset_reboot_pending && (
                    <CcureBadge
                      variant="warning"
                      title="System reboot is required to apply configuration changes."
                    >
                      Reboot Required
                    </CcureBadge>
                  )}
                </span>
              ) : (
                "Global"
              ),
          },
          {
            key: "source",
            header: "Scan Mode",
            cell: (f) => <CcureBadge>{f.source}</CcureBadge>,
          },
          {
            key: "status",
            header: "Status",
            cell: (f) => (
              <>
                <CcureBadge
                  variant={
                    f.status === "pass"
                      ? "success"
                      : f.status === "fail"
                        ? "danger"
                        : "info"
                  }
                >
                  {f.status}
                </CcureBadge>
                {/* The engine already writes a plain-English
                            reason into the evidence payload whenever
                            a control could not be assessed. It was
                            never displayed, so `manual_review`
                            reached the operator with no indication of
                            what to do about it. */}
                {f.status === "manual_review" && f.status_reason && (
                  <span className="cwv-cell__detail cwv-cell__detail--reason">
                    {f.status_reason}
                  </span>
                )}
              </>
            ),
          },
          {
            key: "actions",
            header: "Actions",
            cell: (f) => (
              <span className="cwv-actions">
                {/* Offered on every verdict, not only a failure: what
                            a pass rested on is as much a reviewer's question
                            as what a failure did, and a manual_review carries
                            the reason in the same block. */}
                <CcureButton
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSelectedFinding(f);
                    setModalType("evidence");
                    setModalOpen(true);
                  }}
                >
                  Evidence
                </CcureButton>
                {f.status === "fail" && (
                  <>
                    <CcureButton
                      variant="primary"
                      size="sm"
                      onClick={() => {
                        setSelectedFinding(f);
                        setModalType("remediate");
                        setModalOpen(true);
                      }}
                    >
                      Remediate
                    </CcureButton>
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setSelectedFinding(f);
                        setModalType("exception");
                        setModalOpen(true);
                      }}
                    >
                      Waiver
                    </CcureButton>
                  </>
                )}
                {f.status === "manual_review" && (
                  <CcureButton
                    variant="primary"
                    size="sm"
                    onClick={() => openAttestModal(f)}
                  >
                    Verify
                  </CcureButton>
                )}
                {f.rule_id && (
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={() => handleOpenEditRule(f)}
                  >
                    Edit Rule
                  </CcureButton>
                )}
              </span>
            ),
          },
        ]}
      />
    </section>
  );
}
