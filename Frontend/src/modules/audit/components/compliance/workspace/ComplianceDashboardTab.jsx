/**
 * The compliance workspace's Dashboard tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import {
  CcureCard,
  CcureSelect,
  CcureButton,
  CcureIcon,
  CcureProgress,
  CcureBadge,
  CcureInput,
} from "../../../../../design-system";
import {
  SCORE_TONE,
  getScoreClass,
  NIST_FUNCTION_BADGE,
  THEME_LABELS,
} from "./shared";

export default function ComplianceDashboardTab({
  activeFrameworks,
  besImpactLevelFilter,
  cdeScopeFilter,
  componentTypeFilter,
  handleDownloadReport,
  impactLevelFilter,
  loading,
  nis2AnnualTurnover,
  nis2EntityTypeFilter,
  nis2SectorFilter,
  perFrameworkScores,
  privacyRoleFilter,
  purdueLevelFilter,
  regionalEntityFilter,
  reportFmt,
  reportFw,
  saqProfileFilter,
  sdfScopeFilter,
  selectedFrameworkId,
  setNis2AnnualTurnover,
  setReportFmt,
  setReportFw,
  slLevelFilter,
  standardNumberFilter,
  summary,
  zeroTrustOnly,
}) {
  return (
    <div className="cwv-dashboard">
      <div className="cwv-dashboard__scores">
        <CcureCard title="Overall Score">
          <p
            className={`cwv-score cwv-score--${SCORE_TONE[getScoreClass(summary.score_pct)]}`}
          >
            {summary.score_pct}%
          </p>
        </CcureCard>
        <CcureCard title="Risk-Weighted Score">
          <p
            className={`cwv-score cwv-score--${SCORE_TONE[getScoreClass(summary.weighted_score_pct)]}`}
          >
            {summary.weighted_score_pct}%
          </p>
        </CcureCard>
        <CcureCard
          title={
            !selectedFrameworkId || selectedFrameworkId === "all"
              ? "All Frameworks"
              : selectedFrameworkId === "cfw_nist_csf_v2"
                ? "NIST CSF Controls"
                : selectedFrameworkId === "cfw_cis_v8_1"
                  ? "CIS Safeguards"
                  : selectedFrameworkId === "cfw_soc2_type2"
                    ? "SOC 2 Criteria"
                    : selectedFrameworkId === "cfw_cert_in_2022"
                      ? "CERT-In Controls"
                      : selectedFrameworkId === "cfw_pci_dss_v4"
                        ? "PCI-DSS v4.0 Requirements"
                        : selectedFrameworkId === "cfw_dpdp_2023"
                          ? "DPDP Act 2023 Controls"
                          : selectedFrameworkId === "cfw_gdpr"
                            ? "EU GDPR Controls"
                            : selectedFrameworkId === "cfw_nist_800_53_r5"
                              ? "NIST SP 800-53 R5 Controls"
                              : "ISO 27001 Controls"
          }
        >
          <dl className="cwv-kpis">
            <div className="cwv-kpis__item">
              <dt>Passed</dt>
              <dd className="cwv-kpis__value cwv-kpis__value--success">
                {summary.kpis?.passed || 0}
              </dd>
            </div>
            <div className="cwv-kpis__item">
              <dt>Failed</dt>
              <dd className="cwv-kpis__value cwv-kpis__value--danger">
                {summary.kpis?.failed || 0}
              </dd>
            </div>
            <div className="cwv-kpis__item">
              <dt>Active Waivers</dt>
              <dd className="cwv-kpis__value cwv-kpis__value--info">
                {summary.kpis?.exceptions || 0}
              </dd>
            </div>
          </dl>
        </CcureCard>
      </div>

      {/* Executive Compliance Reports & SoA Hub */}
      <CcureCard
        title="Executive Compliance Reports & SoA Hub"
        subtitle="Generate audit-grade Statement of Applicability (SoA) and regulatory assessment reports in PDF & DOCX formats."
      >
        <div className="cwv-reports">
          <CcureSelect
            label="Report"
            fieldClassName="cwv-reports__menu"
            value={reportFw}
            onChange={(e) => setReportFw(e.target.value)}
          >
            {activeFrameworks
              .filter((fw) => fw.reportSlug)
              .map((fw) => (
                <option key={`rep_${fw.id}`} value={fw.reportSlug}>
                  {fw.reportLabel}
                </option>
              ))}
            <option value="executive">
              Multi-Framework Executive Briefing
            </option>
          </CcureSelect>

          <div
            className="cwv-segmented"
            role="group"
            aria-label="Report format"
          >
            <CcureButton
              variant="secondary"
              size="sm"
              className="cwv-segmented__option"
              aria-pressed={reportFmt === "pdf"}
              onClick={() => setReportFmt("pdf")}
            >
              PDF
            </CcureButton>
            <CcureButton
              variant="secondary"
              size="sm"
              className="cwv-segmented__option"
              aria-pressed={reportFmt === "docx"}
              onClick={() => setReportFmt("docx")}
            >
              Word (.docx)
            </CcureButton>
          </div>

          <CcureButton
            variant="primary"
            disabled={loading}
            onClick={() => {
              let ep = `/compliance/reports/${reportFw}?fmt=${reportFmt}`;
              let fname = `${reportFw}_report.${reportFmt}`;
              if (reportFw === "soa") {
                // A Statement of Applicability covers one standard.
                // Without this the export emitted the controls of
                // every installed framework under an ISO 27001 title.
                const soaFw =
                  selectedFrameworkId && selectedFrameworkId !== "all"
                    ? selectedFrameworkId
                    : "cfw_iso27001_2022";
                ep += `&framework_id=${soaFw}`;
                fname = `soa_${soaFw}.${reportFmt}`;
              }
              if (reportFw === "pci_dss_v4") {
                if (saqProfileFilter !== "all")
                  ep += `&saq_profile=${saqProfileFilter}`;
                if (cdeScopeFilter) ep += "&cde_scope_only=true";
              } else if (reportFw === "dpdp_2023" && sdfScopeFilter !== "all") {
                ep += `&sdf_scope=${sdfScopeFilter}`;
              } else if (reportFw === "gdpr" && privacyRoleFilter !== "all") {
                ep += `&privacy_role=${privacyRoleFilter}`;
              } else if (reportFw === "nist_800_53_r5") {
                if (impactLevelFilter !== "all")
                  ep += `&impact_level=${impactLevelFilter}`;
                if (zeroTrustOnly) ep += "&zero_trust_only=true";
              } else if (reportFw === "iec_62443") {
                if (purdueLevelFilter !== "all")
                  ep += `&purdue_level=${purdueLevelFilter}`;
                if (componentTypeFilter !== "all")
                  ep += `&component_type=${componentTypeFilter}`;
                if (slLevelFilter !== "all") ep += `&sl_level=${slLevelFilter}`;
              } else if (reportFw === "nist_800_82") {
                if (purdueLevelFilter !== "all")
                  ep += `&purdue_level=${purdueLevelFilter}`;
                if (componentTypeFilter !== "all")
                  ep += `&component_type=${componentTypeFilter}`;
              } else if (reportFw === "nerc_cip") {
                ep += `&regional_entity=${regionalEntityFilter}`;
                if (besImpactLevelFilter !== "all")
                  ep += `&bes_impact_level=${besImpactLevelFilter}`;
                if (standardNumberFilter !== "all")
                  ep += `&standard_number=${standardNumberFilter}`;
                if (purdueLevelFilter !== "all")
                  ep += `&purdue_level=${purdueLevelFilter}`;
                if (componentTypeFilter !== "all")
                  ep += `&component_type=${componentTypeFilter}`;
              } else if (reportFw === "nis2") {
                ep += `&nis2_entity_type=${nis2EntityTypeFilter}`;
                if (nis2SectorFilter !== "all")
                  ep += `&nis2_sector=${nis2SectorFilter}`;
              } else if (reportFw === "executive") {
                ep = "/compliance/reports/executive";
                fname = "executive_compliance_report.pdf";
              }
              handleDownloadReport(ep, fname);
            }}
          >
            {loading ? (
              "Generating..."
            ) : (
              <>
                <CcureIcon name="download" />
                {" Download"} {reportFmt.toUpperCase()}
                {" Report"}
              </>
            )}
          </CcureButton>
        </div>

        <div
          className="cwv-reports__quick"
          role="group"
          aria-label="Quick downloads"
        >
          <span className="cwv-reports__quick-label" aria-hidden="true">
            Quick Downloads:
          </span>
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() =>
              handleDownloadReport(
                "/compliance/reports/soa?fmt=pdf",
                "statement_of_applicability.pdf",
              )
            }
          >
            SoA PDF
          </CcureButton>
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() =>
              handleDownloadReport(
                "/compliance/reports/soa?fmt=docx",
                "statement_of_applicability.docx",
              )
            }
          >
            SoA Word
          </CcureButton>
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() =>
              handleDownloadReport(
                "/compliance/reports/executive",
                "executive_compliance_report.pdf",
              )
            }
          >
            Executive Brief (PDF)
          </CcureButton>
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() =>
              handleDownloadReport(
                "/compliance/reports/nist_csf?fmt=pdf",
                "nist_csf_v2_report.pdf",
              )
            }
          >
            NIST CSF PDF
          </CcureButton>
        </div>
      </CcureCard>

      <CcureCard
        title={
          !selectedFrameworkId || selectedFrameworkId === "all"
            ? "Compliance Score by Framework"
            : selectedFrameworkId === "cfw_nist_csf_v2"
              ? "NIST CSF 2.0 Core Functions Breakdown"
              : selectedFrameworkId === "cfw_cis_v8_1"
                ? "CIS Controls v8.1 Safeguards Breakdown"
                : selectedFrameworkId === "cfw_soc2_type2"
                  ? "SOC 2 Trust Services Criteria Breakdown"
                  : selectedFrameworkId === "cfw_cert_in_2022"
                    ? "CERT-In Directions & CCMP Themes Breakdown"
                    : selectedFrameworkId === "cfw_pci_dss_v4"
                      ? "PCI-DSS v4.0 12 Principal Requirements Breakdown"
                      : selectedFrameworkId === "cfw_dpdp_2023"
                        ? "DPDP Act 2023 6 Key Governance Principles Breakdown"
                        : selectedFrameworkId === "cfw_gdpr"
                          ? "EU GDPR 7 Core Privacy Principles Breakdown"
                          : selectedFrameworkId === "cfw_nist_800_53_r5"
                            ? "NIST SP 800-53 R5 20 Control Families Breakdown"
                            : selectedFrameworkId === "cfw_nis2"
                              ? "EU NIS 2 Directive 10 Risk Management Domains (Art. 21.2)"
                              : "ISO 27001 Themes Quadrant Breakdown"
        }
      >
        {/* ── All Frameworks: per-framework comparison chart ── */}
        {!selectedFrameworkId || selectedFrameworkId === "all" ? (
          perFrameworkScores.length === 0 ? (
            <p className="cwv-muted">
              No enabled frameworks with scored controls yet. Install and run a
              compliance scan to populate scores.
            </p>
          ) : (
            <ul className="cwv-bars">
              {perFrameworkScores.map((fw) => (
                <li key={fw.id} className="cwv-bars__item">
                  <CcureProgress
                    label={fw.name}
                    value={fw.score}
                    showValue={false}
                  />
                  <span className="cwv-bars__value">{fw.score}%</span>
                </li>
              ))}
            </ul>
          )
        ) : (
          /* ── Single Framework: per-theme breakdown ── */
          <div className="cwv-breakdown">
            {selectedFrameworkId === "cfw_nis2" && (
              <CcureCard
                headingLevel={3}
                title={
                  <>
                    <CcureIcon name="flag" /> EU NIS 2 Regulatory Fine Risk
                    Exposure Calculator (Article 32 & 34)
                  </>
                }
                actions={
                  <CcureBadge
                    variant={
                      nis2EntityTypeFilter === "important" ? "warning" : "info"
                    }
                  >
                    {nis2EntityTypeFilter === "important"
                      ? "Important Entity (Art. 3.2)"
                      : "Essential Entity (Art. 3.1)"}
                  </CcureBadge>
                }
              >
                <div className="cwv-nis2">
                  <CcureInput
                    type="number"
                    label="Annual Global Turnover (EUR €)"
                    value={nis2AnnualTurnover}
                    onChange={(e) =>
                      setNis2AnnualTurnover(Number(e.target.value))
                    }
                  />
                  <div className="cwv-nis2__fact">
                    <p className="cwv-nis2__label">Statutory Fine Ceiling:</p>
                    <p className="cwv-nis2__ceiling">
                      €
                      {nis2EntityTypeFilter === "important"
                        ? Math.max(
                            7000000,
                            nis2AnnualTurnover * 0.014,
                          ).toLocaleString()
                        : Math.max(
                            10000000,
                            nis2AnnualTurnover * 0.02,
                          ).toLocaleString()}
                    </p>
                  </div>
                  <div className="cwv-nis2__fact">
                    <p className="cwv-nis2__label">
                      Executive Board Liability Exposure:
                    </p>
                    <p className="cwv-nis2__liability">
                      Article 20 Personal Liability & Operational Ban
                    </p>
                  </div>
                </div>
              </CcureCard>
            )}

            {selectedFrameworkId === "cfw_nis2" && (
              <CcureCard
                headingLevel={3}
                title={
                  <>
                    <CcureIcon name="alert-octagon" /> Article 23 CSIRT
                    Mandatory Incident Reporting SLA Readiness Tracker
                  </>
                }
                actions={
                  <CcureBadge variant="success">
                    Directive SLA Enforced
                  </CcureBadge>
                }
              >
                <ul className="cwv-sla">
                  <li className="cwv-sla__item">
                    <p className="cwv-sla__deadline cwv-sla__deadline--danger">
                      <CcureIcon name="zap" /> Early Warning (≤ 24 Hours)
                    </p>
                    <p className="cwv-sla__text">
                      Submit initial CSIRT warning indicating whether incident
                      is suspect/unlawful or has cross-border impact.
                    </p>
                  </li>
                  <li className="cwv-sla__item">
                    <p className="cwv-sla__deadline cwv-sla__deadline--warning">
                      <CcureIcon name="clock" /> Incident Notification (≤ 72
                      Hours)
                    </p>
                    <p className="cwv-sla__text">
                      Submit formal incident notification updating initial
                      assessment, severity metrics, and technical IoC
                      indicators.
                    </p>
                  </li>
                  <li className="cwv-sla__item">
                    <p className="cwv-sla__deadline cwv-sla__deadline--info">
                      <CcureIcon name="clipboard" /> Final Report (≤ 1 Month)
                    </p>
                    <p className="cwv-sla__text">
                      Provide complete root-cause analysis, forensic evidence,
                      technical remediations applied, and cross-border impact.
                    </p>
                  </li>
                </ul>
              </CcureCard>
            )}
            <ul className="cwv-bars">
              {Object.entries(summary.quadrant_scores || {}).map(
                ([key, val]) => (
                  <li key={key} className="cwv-bars__item">
                    <CcureProgress
                      label={
                        ["GV", "ID", "PR", "DE", "RS", "RC"].includes(key) ? (
                          <CcureBadge variant={NIST_FUNCTION_BADGE[key]} mono>
                            {THEME_LABELS[key] || key}
                          </CcureBadge>
                        ) : (
                          THEME_LABELS[key] || key
                        )
                      }
                      value={val}
                      showValue={false}
                    />
                    <span className="cwv-bars__value">{val}%</span>
                  </li>
                ),
              )}
            </ul>
          </div>
        )}
      </CcureCard>
    </div>
  );
}
