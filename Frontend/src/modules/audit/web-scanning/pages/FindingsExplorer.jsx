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
 * B.6 keeps the triage failure text and request contract while delivering
 * the error through the shared, dismissible live alert.
 */
import { useState, useEffect } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useAuth } from "@shell/auth/AuthContext";
import { can } from "@shell/auth/permissions";
import { webScansApi } from "../api/webScansApi";
import {
  CcureLoader,
  CcureAlert,
  CcureBadge,
  CcureCard,
  CcureEmptyState,
  CcureSelect,
  CcureSeverityBadge,
  CcureSkeleton,
  normalizeSeverity,
  CcureButton,
  CcurePage,
  CcurePageHeader,
} from "../../../../design-system";
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
  const { user } = useAuth();
  // The API requires Update findings to triage, and findings:accept_risk
  // on top of it to accept a risk — the same split as network findings.
  const canTriage = can(user, "audit.finding.update");
  const canAcceptRisk = can(user, "audit.finding.accept_risk");
  const [searchParams] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [actionError, setActionError] = useState("");
  // Proof screenshot (Codex item 10) — fetched as a blob (auth header) and
  // shown as an object URL; revoked when the selection changes.
  const [screenshotUrl, setScreenshotUrl] = useState(null);

  useEffect(() => {
    let objUrl = null;
    let active = true;
    if (selectedFinding?.screenshot_path && selectedFinding?.id) {
      webScansApi
        .getFindingScreenshot(id, selectedFinding.id)
        .then((res) => {
          if (!active) return;
          objUrl = window.URL.createObjectURL(res.data);
          setScreenshotUrl(objUrl);
        })
        .catch((err) => console.error("Failed to load screenshot", err));
    } else {
      setScreenshotUrl(null);
    }
    return () => {
      active = false;
      if (objUrl) window.URL.revokeObjectURL(objUrl);
    };
  }, [id, selectedFinding]);

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
      setActionError("Failed to update finding status.");
    }
  };

  // Filters carried in the URL by a drill-down from the Scan Detail counts, so
  // clicking "Critical Findings" lands here showing exactly the critical ones.
  const fSeverity = searchParams.get("severity");
  const fType = searchParams.get("finding_type") || searchParams.get("type");
  const fOwasp = searchParams.get("owasp");
  const activeChips = [];
  if (fSeverity) activeChips.push(["Severity", fSeverity]);
  if (fType) activeChips.push(["Type", fType]);
  if (fOwasp) activeChips.push(["OWASP", fOwasp]);
  const visible = findings.filter((f) => {
    if (
      fSeverity &&
      (f.severity || "").toLowerCase() !== fSeverity.toLowerCase()
    )
      return false;
    if (fType && f.finding_type !== fType) return false;
    if (
      fOwasp &&
      !(f.owasp_category || "").toUpperCase().startsWith(fOwasp.toUpperCase())
    )
      return false;
    return true;
  });

  return (
    <AppLayout pageTitle="Findings Explorer">
      <CcurePage>
        {actionError && (
          <CcureAlert variant="danger" onClose={() => setActionError("")}>
            {actionError}
          </CcureAlert>
        )}
        <CcurePageHeader
          title="Findings Explorer"
          subtitle={<>Vulnerabilities discovered during this assessment</>}
          breadcrumb={
            <Link to={`/web-scans/${id}`} className="wsp-back">
              ← Back to Scan Detail
            </Link>
          }
        />

        {activeChips.length > 0 && (
          <div className="wsp-meta wsp-filter-bar">
            <span className="wsp-muted">Filtered by:</span>
            {activeChips.map(([label, val]) => (
              <CcureBadge key={label} variant="info">
                {label}: {val}
              </CcureBadge>
            ))}
            <Link to={`/web-scans/${id}/findings`} className="wsp-back">
              Clear filters
            </Link>
          </div>
        )}

        <div className="wsp-split">
          <div className="wsp-panel">
            <CcureCard
              title={`Vulnerabilities (${visible.length})`}
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
              ) : visible.length === 0 ? (
                <CcureEmptyState
                  title="No findings"
                  description={
                    activeChips.length
                      ? "No findings match the current filter."
                      : "This scan reported no vulnerabilities."
                  }
                />
              ) : (
                <div className="wsp-finding-list">
                  {visible.map((finding) => {
                    const band = normalizeSeverity(finding.severity);
                    const selected = selectedFinding?.id === finding.id;
                    return (
                      /* A real button. `aria-pressed` reports which finding is
                         open, which the previous tinted background did not. */
                      <CcureButton
                        variant="ghost"
                        size="sm"
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
                      </CcureButton>
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
                  {selectedFinding.cwe_id && (
                    <CcureBadge variant="neutral" mono>
                      {selectedFinding.cwe_id}
                    </CcureBadge>
                  )}
                  {selectedFinding.owasp_category && (
                    <CcureBadge variant="warning">
                      OWASP: {selectedFinding.owasp_category}
                    </CcureBadge>
                  )}
                  {/* Proof-based evidence (Codex item 10): how sure the
                      detection is, and the identity it was tested under. */}
                  {selectedFinding.confidence && (
                    <CcureBadge
                      variant={
                        selectedFinding.confidence === "high"
                          ? "success"
                          : selectedFinding.confidence === "low"
                            ? "neutral"
                            : "info"
                      }
                    >
                      Confidence: {selectedFinding.confidence}
                    </CcureBadge>
                  )}
                  {selectedFinding.auth_context && (
                    <CcureBadge variant="neutral">
                      Tested as: {selectedFinding.auth_context}
                    </CcureBadge>
                  )}
                </div>

                {canTriage ? (
                  <CcureSelect
                    label="Triage status"
                    value={selectedFinding.status}
                    onChange={(e) =>
                      handleStatusChange(selectedFinding.id, e.target.value)
                    }
                  >
                    {TRIAGE_STATUSES.map((s) => (
                      <option
                        key={s.value}
                        value={s.value}
                        disabled={s.value === "accepted_risk" && !canAcceptRisk}
                      >
                        {s.value === "accepted_risk" && !canAcceptRisk
                          ? `${s.label} (requires findings:accept_risk)`
                          : s.label}
                      </option>
                    ))}
                  </CcureSelect>
                ) : (
                  <p>
                    Triage status:{" "}
                    <strong>
                      {TRIAGE_STATUSES.find(
                        (s) => s.value === selectedFinding.status,
                      )?.label ?? selectedFinding.status}
                    </strong>
                    . Your role can view this finding but not change its status,
                    which requires <code>Update findings</code>.
                  </p>
                )}

                <h3>Description</h3>
                <p>
                  {selectedFinding.description || "No description provided."}
                </p>

                {selectedFinding.remediation && (
                  <>
                    <h3>Remediation</h3>
                    <p>{selectedFinding.remediation}</p>
                  </>
                )}

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

                {/* Proof of execution — a screenshot captured at the moment the
                    payload fired (e.g. a rendered XSS). Shown only when the
                    scanner captured one and the image loaded. */}
                {selectedFinding.screenshot_path && (
                  <>
                    <h3>Proof Screenshot</h3>
                    {screenshotUrl ? (
                      <img
                        src={screenshotUrl}
                        alt={`Proof of execution for ${selectedFinding.title}`}
                        className="wsp-screenshot"
                      />
                    ) : (
                      <CcureLoader label="Loading screenshot…" />
                    )}
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
      </CcurePage>
    </AppLayout>
  );
}
