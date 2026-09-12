/**
 * modules/web-scanning/pages/FindingsExplorer.jsx
 * The findings a DAST scan produced, and their triage state.
 *
 * ── Contract, unchanged by the Checkpoint 3C batch-6 migration ──────────────
 * Every request, payload and state transition below is what it was before.
 * The migration changed presentation only. Specifically preserved:
 *
 *   * `getFindings(id, { per_page: 200 })`, where `id` is the route parameter
 *     and is the whole scoping;
 *   * `updateFindingStatus(id, findingId, { status })` — the scan id from the
 *     route, the finding id from the row. Sending the wrong pairing would
 *     triage a finding belonging to a different scan;
 *   * the local list is updated **only after** the request resolves, so a
 *     refused triage leaves the finding where it was rather than showing it as
 *     handled;
 *   * the same five triage values, in the same order;
 *   * response evidence is still truncated at 2,000 characters with an explicit
 *     `...[truncated]` marker;
 *   * both response shapes are still accepted; the page does not poll.
 *
 * ── What the migration changed ──────────────────────────────────────────────
 * The finding rows were `<div onClick>`: no role, no tab stop, no key handler.
 * A keyboard user could not open a single finding on this page — on the screen
 * where this product presents the vulnerabilities it found. They are real
 * buttons now, carrying `aria-pressed` so the selected one is reported rather
 * than merely tinted.
 *
 * Severity was `getSeverityColor`, which mapped critical onto danger and high
 * onto warning — and the tint it produced was built as
 * `` `${getSeverityColor(s)}20` ``, i.e. `var(--danger)20`, which is not a
 * colour: the browser dropped the declaration and the tint never rendered.
 * `CcureSeverityBadge` keeps all five bands distinct and puts the band's name
 * in the accessible name.
 *
 * ── Deliberately preserved, though it is not good ───────────────────────────
 * A failed triage still calls `window.alert`. Changing it to a toast would
 * change this page's error *behaviour*, which this batch's rules place out of
 * scope. It is recorded in the checkpoint report instead.
 */
import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import {
  CcureBadge,
  CcureCard,
  CcureEmptyState,
  CcureSelect,
  CcureSeverityBadge,
  CcureSkeleton,
  normalizeSeverity,
} from "../../../design-system";
import "../styles/web-scanning-pages.css";

const TRIAGE_STATUSES = [
  { value: "open", label: "Open" },
  { value: "confirmed", label: "Confirmed" },
  { value: "false_positive", label: "False Positive" },
  { value: "accepted_risk", label: "Accepted Risk" },
  { value: "fixed", label: "Fixed" },
];

const RESPONSE_LIMIT = 2000;

export default function FindingsExplorer() {
  const { id } = useParams();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    async function fetchFindings() {
      try {
        setLoading(true);
        const res = await webScansApi.getFindings(id, { per_page: 200 });
        setFindings(res.data?.data || res.data?.items || []);
      } catch (err) {
        console.error("Failed to load findings", err);
      } finally {
        setLoading(false);
      }
    }
    fetchFindings();
  }, [id]);

  const handleStatusChange = async (findingId, newStatus) => {
    try {
      await webScansApi.updateFindingStatus(id, findingId, {
        status: newStatus,
      });
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f)),
      );
      if (selectedFinding?.id === findingId) {
        setSelectedFinding({ ...selectedFinding, status: newStatus });
      }
    } catch (err) {
      console.error("Failed to update status", err);
      alert("Failed to update finding status.");
    }
  };

  return (
    <AppLayout pageTitle="Findings Explorer">
      <div className="page-inner wsp-page wsp-page--wide">
        <div className="wsp-header">
          <div>
            <Link to={`/web-scans/${id}`} className="wsp-back">
              ← Back to Scan Detail
            </Link>
            <h1 className="page-title">Findings Explorer</h1>
            <p className="page-subtitle">
              Vulnerabilities discovered during this assessment
            </p>
          </div>
        </div>

        <div className="wsp-split">
          <div className="wsp-panel">
            <CcureCard
              title={`Vulnerabilities (${findings.length})`}
              headingLevel={2}
              flush
              bodyFlush
            >
              {loading ? (
                <div className="wsp-loading" role="status" aria-live="polite">
                  <span className="cc-sr-only">Loading findings…</span>
                  <CcureSkeleton height="64px" radius="6px" />
                  <CcureSkeleton height="64px" radius="6px" />
                  <CcureSkeleton height="64px" radius="6px" />
                  <CcureSkeleton height="64px" radius="6px" />
                  <CcureSkeleton height="64px" radius="6px" />
                </div>
              ) : findings.length === 0 ? (
                <CcureEmptyState
                  title="No findings"
                  description="This scan reported no vulnerabilities."
                />
              ) : (
                <div className="wsp-finding-list">
                  {findings.map((finding) => {
                    const band = normalizeSeverity(finding.severity);
                    const selected = selectedFinding?.id === finding.id;
                    return (
                      /* A real button. `aria-pressed` reports which finding is
                         open, which the previous tinted background did not. */
                      <button
                        key={finding.id}
                        type="button"
                        className={`wsp-finding wsp-finding--${band}`}
                        aria-pressed={selected}
                        onClick={() => setSelectedFinding(finding)}
                      >
                        <span className="wsp-finding-top">
                          <span className="wsp-finding-title">
                            {finding.title}
                          </span>
                          <CcureSeverityBadge severity={finding.severity} />
                        </span>
                        <span className="wsp-finding-url">
                          {finding.request_method} {finding.request_url}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </CcureCard>
          </div>

          <div className="wsp-panel">
            {selectedFinding ? (
              <CcureCard
                title={selectedFinding.title}
                headingLevel={2}
                actions={
                  <CcureSeverityBadge severity={selectedFinding.severity} />
                }
              >
                <div className="wsp-meta">
                  {selectedFinding.finding_type && (
                    <CcureBadge variant="neutral">
                      {selectedFinding.finding_type}
                    </CcureBadge>
                  )}
                  {selectedFinding.cve_id && (
                    <CcureBadge variant="danger" mono>
                      {selectedFinding.cve_id}
                    </CcureBadge>
                  )}
                  {selectedFinding.owasp_category && (
                    <CcureBadge variant="warning">
                      OWASP: {selectedFinding.owasp_category}
                    </CcureBadge>
                  )}
                </div>

                <CcureSelect
                  label="Triage status"
                  value={selectedFinding.status}
                  onChange={(e) =>
                    handleStatusChange(selectedFinding.id, e.target.value)
                  }
                >
                  {TRIAGE_STATUSES.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </CcureSelect>

                <h3>Description</h3>
                <p>
                  {selectedFinding.description || "No description provided."}
                </p>

                {(selectedFinding.request_method ||
                  selectedFinding.request_url) && (
                  <>
                    <h3>Request</h3>
                    <p className="wsp-finding-url">
                      {selectedFinding.request_method}{" "}
                      {selectedFinding.request_url}
                    </p>
                  </>
                )}

                {/* Evidence captured from a scanned target. `<pre>` renders it
                    as characters; nothing on this page interprets it, which is
                    why the module carries no dangerouslySetInnerHTML. */}
                {selectedFinding.request_body && (
                  <>
                    <h3>Request Body Evidence</h3>
                    <pre className="wsp-evidence">
                      {selectedFinding.request_body}
                    </pre>
                  </>
                )}

                {selectedFinding.response_body && (
                  <>
                    <h3>Response Evidence</h3>
                    <pre className="wsp-evidence">
                      {selectedFinding.response_body.substring(
                        0,
                        RESPONSE_LIMIT,
                      )}
                      {selectedFinding.response_body.length > RESPONSE_LIMIT
                        ? "\n...[truncated]"
                        : ""}
                    </pre>
                  </>
                )}

                {selectedFinding.curl_command && (
                  <>
                    <h3>Reproduction (cURL)</h3>
                    <pre className="wsp-evidence">
                      {selectedFinding.curl_command}
                    </pre>
                  </>
                )}
              </CcureCard>
            ) : (
              <p className="wsp-empty-detail">
                Select a finding to see its detail.
              </p>
            )}
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
