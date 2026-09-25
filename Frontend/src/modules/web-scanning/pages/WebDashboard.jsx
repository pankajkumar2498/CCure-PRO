/**
 * modules/web-scanning/pages/WebDashboard.jsx
 * DAST overview: four counters, an OWASP Top 10 scorecard, a 30-day trend.
 *
 * ── Contract, unchanged by the Checkpoint 3C batch-6 migration ──────────────
 * Every request, fallback and navigation target below is what it was before.
 * The migration changed presentation only. Specifically preserved:
 *
 *   * all three requests are still issued together via `Promise.all`;
 *   * a counter with no data still reads **0**, not blank — `summary?.x || 0`
 *     is the page's own choice and it is recorded so a migration cannot change
 *     it silently;
 *   * the scorecard is still capped at five rows;
 *   * a zero trend count is still omitted rather than printed as "0 Crit";
 *   * the page does not poll.
 *
 * ── What the migration changed ──────────────────────────────────────────────
 * One thing beyond presentation, and it is a reporting defect rather than a
 * cosmetic one. All three requests share a single try/catch, so a failure in
 * *any* of them left every widget in its placeholder state — and the scorecard
 * placeholder reads "No OWASP findings detected yet". That is good news about a
 * target nobody was able to ask about. The page now distinguishes "we asked and
 * there was nothing" from "we could not ask", because on a security dashboard
 * those are opposite facts.
 *
 * The scorecard's clean/breached distinction was also colour alone — red for
 * count > 0, green for 0, with text identical apart from the number. It carries
 * a severity badge now.
 */
import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { useAuth } from "../../../context/AuthContext";
import { can } from "../../../auth/permissions";
import { webDashboardApi } from "../api/webScansApi";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureSeverityBadge,
  CcureSkeleton,
} from "../../../design-system";
import "../styles/web-scanning-pages.css";

function MetricCard({ title, value, to }) {
  const body = (
    /* CcureCard supplies the heading, and the heading is what names the
       counter. The pre-migration version paired a styled <span> with a styled
       <div> and nothing tied them together programmatically, so a screen
       reader read four labels and four unattached numbers. */
    <CcureCard title={title} headingLevel={3}>
      <div className="wsp-metric-value">{value}</div>
    </CcureCard>
  );
  // A counter that drills into its records is a link; one that does not (or is
  // zero) stays plain, so a click never lands on an empty filtered page.
  return to ? (
    <Link
      to={to}
      className="wsp-metric-link"
      aria-label={`${title}: ${value} — view details`}
    >
      {body}
    </Link>
  ) : (
    body
  );
}

export default function WebDashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();
  // Launching sends active attack traffic at the target; the API requires
  // scans:execute, so the control is not offered to a role that lacks it.
  const canLaunch = can(user, "scans", "execute");
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState(null);
  const [scorecard, setScorecard] = useState(null);
  const [trends, setTrends] = useState(null);
  // Distinguishes "asked, nothing found" from "could not ask". Without it the
  // scorecard's own empty state reports a clean target after a failed request.
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    async function fetchData() {
      try {
        setLoading(true);
        setLoadFailed(false);
        const [sumRes, scoreRes, trendRes] = await Promise.all([
          webDashboardApi.getSummary(),
          webDashboardApi.getOwaspScorecard(),
          webDashboardApi.getTrends(),
        ]);
        // The API returns nested objects; read the documented shapes:
        //   summary   → { scans:{…}, severity:{…}, endpoints:{…}, … }
        //   scorecard → { scorecard: [{ code, name, total, … }] }
        //   trends    → { data: [{ date, critical, high, … }] }
        setSummary(sumRes.data);
        setScorecard(scoreRes.data?.scorecard || []);
        setTrends(trendRes.data?.data || []);
      } catch (err) {
        console.error("Failed to load web dashboard data", err);
        setLoadFailed(true);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  const unavailable = (
    <p className="wsp-placeholder">
      Could not be loaded — this is not a statement about the target.
    </p>
  );

  return (
    <AppLayout pageTitle="Web Application Scanning">
      <div className="page-inner wsp-page">
        <div className="wsp-header">
          <div>
            <h1 className="page-title">Web Application Security</h1>
            <p className="page-subtitle">
              Dynamic Application Security Testing (DAST) Overview
            </p>
          </div>
          <div className="wsp-actions">
            <CcureButton
              variant="secondary"
              onClick={() => navigate("/web-scans/list")}
            >
              View All Scans
            </CcureButton>
            {canLaunch && (
              <CcureButton onClick={() => navigate("/web-scans/new")}>
                + New Web Scan
              </CcureButton>
            )}
          </div>
        </div>

        {loading ? (
          <div className="wsp-loading" role="status" aria-live="polite">
            <span className="cc-sr-only">Loading web scanning overview…</span>
            <div className="wsp-metrics">
              <CcureSkeleton height="120px" radius="12px" />
              <CcureSkeleton height="120px" radius="12px" />
              <CcureSkeleton height="120px" radius="12px" />
              <CcureSkeleton height="120px" radius="12px" />
            </div>
            <div className="wsp-widgets">
              <CcureSkeleton height="300px" radius="12px" />
              <CcureSkeleton height="300px" radius="12px" />
            </div>
          </div>
        ) : (
          <>
            {loadFailed && (
              <CcureAlert variant="danger">
                Some dashboard data could not be loaded. The figures below are
                incomplete and must not be read as an assessment of the estate.
              </CcureAlert>
            )}

            <div className="wsp-metrics">
              <MetricCard
                title="Active Web Scans"
                value={summary?.scans?.active || 0}
                to={
                  summary?.scans?.active
                    ? "/web-scans/list?status=running"
                    : undefined
                }
              />
              <MetricCard
                title="Critical Vulnerabilities"
                value={summary?.severity?.critical || 0}
                to={
                  summary?.severity?.critical
                    ? "/web-scans/all-findings?severity=critical&status=open"
                    : undefined
                }
              />
              <MetricCard
                title="Total Endpoints Discovered"
                value={summary?.endpoints?.total || 0}
                to={
                  summary?.endpoints?.total
                    ? "/web-scans/all-endpoints"
                    : undefined
                }
              />
              <MetricCard
                title="Scans Last 30 Days"
                value={summary?.scans?.last_30d || 0}
                to={summary?.scans?.last_30d ? "/web-scans/list" : undefined}
              />
            </div>

            <div className="wsp-widgets">
              <CcureCard title="OWASP Top 10 Coverage" headingLevel={2}>
                {loadFailed ? (
                  unavailable
                ) : scorecard && scorecard.length > 0 ? (
                  <div className="wsp-rows">
                    {/* Categories with findings first, so the five shown are the
                        ones that matter rather than A01–A05 by number. */}
                    {[...scorecard]
                      .sort((a, b) => (b.total || 0) - (a.total || 0))
                      .slice(0, 5)
                      .map((item) =>
                        item.total > 0 ? (
                          // A category with findings drills into exactly them.
                          <Link
                            className="wsp-row wsp-row--link"
                            key={item.code}
                            to={`/web-scans/all-findings?owasp=${item.code}&status=open`}
                            aria-label={`${item.name}: ${item.total} findings — view`}
                          >
                            <span>
                              {item.code} — {item.name}
                            </span>
                            <CcureSeverityBadge
                              severity="high"
                              score={`${item.total} findings`}
                              showLabel={false}
                            />
                          </Link>
                        ) : (
                          <div className="wsp-row" key={item.code}>
                            <span>
                              {item.code} — {item.name}
                            </span>
                            <CcureBadge variant="success">
                              0 findings — clear
                            </CcureBadge>
                          </div>
                        ),
                      )}
                  </div>
                ) : (
                  <p className="wsp-placeholder">
                    No OWASP findings detected yet.
                  </p>
                )}
              </CcureCard>

              <CcureCard
                title="Vulnerability Trends (30 Days)"
                headingLevel={2}
              >
                {loadFailed ? (
                  unavailable
                ) : trends && trends.length > 0 ? (
                  <div className="wsp-rows">
                    {trends.slice(0, 5).map((trend) => (
                      <div className="wsp-row" key={trend.date}>
                        <Link
                          to={`/web-scans/all-findings?date=${trend.date}`}
                          className="wsp-trend-date"
                        >
                          {trend.date}
                        </Link>
                        <div className="wsp-bands">
                          {trend.critical > 0 && (
                            <Link
                              to={`/web-scans/all-findings?date=${trend.date}&severity=critical`}
                              aria-label={`${trend.critical} critical on ${trend.date}`}
                            >
                              <CcureSeverityBadge
                                severity="critical"
                                score={trend.critical}
                              />
                            </Link>
                          )}
                          {trend.high > 0 && (
                            <Link
                              to={`/web-scans/all-findings?date=${trend.date}&severity=high`}
                              aria-label={`${trend.high} high on ${trend.date}`}
                            >
                              <CcureSeverityBadge
                                severity="high"
                                score={trend.high}
                              />
                            </Link>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="wsp-placeholder">No trend data available.</p>
                )}
              </CcureCard>
            </div>
          </>
        )}
      </div>
    </AppLayout>
  );
}
