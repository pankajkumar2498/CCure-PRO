/**
 * modules/web-scanning/pages/ScanDetail.jsx
 * The live view of one web scan.
 *
 * ── The lifecycle contract, preserved exactly (Checkpoint 3C batch 8) ───────
 * `useScanPolling(id, 5000)` is untouched — the hook file is not modified by
 * this batch — and this page's use of it is unchanged. What that contract
 * actually is, because it is easy to assume wrongly:
 *
 *   * ONE `getScan` on mount;
 *   * the **WebSocket is the primary channel**. While it is healthy there is
 *     no polling at all — this page does not "poll every 5 seconds";
 *   * timed polling is a FALLBACK, armed only after the socket errors, closes,
 *     or the ticket request fails;
 *   * the fallback re-arms only while status is running / pending / queued, so
 *     a terminal state stops it;
 *   * a terminal status over the socket triggers one final `getScan` and closes
 *     the socket;
 *   * unmount clears both timers and closes the socket.
 *
 * Also preserved without change: `cancelScan` behind a confirmation followed
 * by `refresh()` — the question is now asked in `CcureConfirmDialog` rather
 * than `window.confirm`, with the same words and the same call;
 * `downloadReport` → Blob → anchor click, with `alert()` on
 * failure; the `ACTIVE_STATUSES` / `COMPLETE_STATUSES` sets that decide which
 * actions are offered; the `PIPELINE_PHASES` order; the progress derivation
 * (`live_progress.percentage`, else 100 when complete, else phase index × 33.33);
 * the `liveStatus` → label map; and the coverage-caveat logic in full.
 *
 * ── The one branch that had to keep its exact shape ─────────────────────────
 * `if (loading && !scan)`. The hook sets `loading` true on EVERY refetch, so a
 * skeleton branch keyed on `loading` alone would blank the whole page back to
 * placeholders on every poll — over settled results, every five seconds. The
 * condition is unchanged and is asserted directly.
 *
 * ── Intentionally changed: presentation and accessibility ───────────────────
 * The progress bar was a bare `<div>` with a width percentage: no
 * `role="progressbar"`, no value, no name. The error branch was a plain
 * `<div>`, so a scan that failed to load was never announced. The pipeline
 * stepper conveyed done / active / pending through a tick glyph, a spinner and
 * a number — none of which carries text. The status badge was a two-way branch
 * that dressed any unrecognised status as an active scan.
 */
import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { useScanPolling } from "../hooks/useScanPolling";
import { webScansApi } from "../api/webScansApi";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureConfirmDialog,
  CcureScanProgress,
  CcureScanStatus,
  CcureSkeleton,
} from "../../../design-system";
import "../styles/web-scanning-pages.css";

const PIPELINE_PHASES = ["RECON", "CRAWL", "DETECT", "AUDIT"];
const ACTIVE_STATUSES = new Set(["queued", "pending", "running"]);
const COMPLETE_STATUSES = new Set(["complete", "completed"]);

/* The live-channel indicator. This is the transport's health, NOT the scan's
   status, and the two must not read alike — an operator who confuses "we lost
   the socket" with "the scan failed" goes looking in the wrong place. */
const LIVE_LABEL = {
  connected: "Live",
  connecting: "Connecting",
  reconnecting: "Reconnecting",
  degraded: "Polling",
  closed: "Closed",
};

/** Each pipeline step's state, in words. The pre-migration stepper carried
 *  this only as a tick, a spinner or a number. */
const stepState = (isDone, isActive) =>
  isDone ? "Done" : isActive ? "In progress" : "Pending";

export default function ScanDetail() {
  const { id } = useParams();
  const { scan, loading, error, refresh, liveStatus, liveEvents } =
    useScanPolling(id, 5000);
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    try {
      setDownloading(true);
      const res = await webScansApi.downloadReport(id);
      const url = window.URL.createObjectURL(
        new Blob([res.data], { type: "application/pdf" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `WebScanReport_${id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("Failed to download PDF", err);
      alert("Failed to generate report.");
    } finally {
      setDownloading(false);
    }
  };

  /* Cancelling a scan cannot be undone, so it asks first — in the design
     system's confirmation dialog rather than window.confirm, which is
     unstyled, blocks the event loop and cannot be driven by the tests. The
     question, the cancelScan call and the refresh that follows it are
     unchanged, and nothing is sent until the dialog is answered. */
  const [confirmCancel, setConfirmCancel] = useState(false);

  const handleCancel = () => setConfirmCancel(true);

  const performCancel = async () => {
    setConfirmCancel(false);
    await webScansApi.cancelScan(id);
    refresh();
  };

  /* `loading && !scan`, unchanged. Keyed on "nothing to show yet" rather than
     on `loading`, which the hook raises on every refetch. */
  if (loading && !scan) {
    return (
      <AppLayout pageTitle="Scan Details">
        <div
          className="page-inner wsp-page sd-loading"
          role="status"
          aria-live="polite"
        >
          <span className="cc-sr-only">Loading scan details…</span>
          <CcureSkeleton height="60px" radius="8px" />
          <CcureSkeleton height="150px" radius="12px" />
          <div className="sd-stat-grid">
            <CcureSkeleton height="100px" radius="12px" />
            <CcureSkeleton height="100px" radius="12px" />
            <CcureSkeleton height="100px" radius="12px" />
            <CcureSkeleton height="100px" radius="12px" />
          </div>
          <div className="sd-links">
            <CcureSkeleton height="120px" radius="12px" />
            <CcureSkeleton height="120px" radius="12px" />
          </div>
        </div>
      </AppLayout>
    );
  }

  if (error) {
    return (
      <AppLayout pageTitle="Scan Details">
        <div className="page-inner wsp-page">
          {/* Was a plain <div>. A scan detail that could not be loaded is now
              announced rather than merely coloured red. */}
          <CcureAlert variant="danger">{error}</CcureAlert>
        </div>
      </AppLayout>
    );
  }

  if (!scan) return null;

  const normalizedStatus = String(scan.status || "").toLowerCase();
  const normalizedPhase = String(scan.pipeline_phase || "").toUpperCase();
  const isActiveScan = ACTIVE_STATUSES.has(normalizedStatus);
  const isCompleteScan = COMPLETE_STATUSES.has(normalizedStatus);
  const currentPhaseIndex = PIPELINE_PHASES.indexOf(normalizedPhase);
  const progressPercent =
    scan.live_progress?.percentage ??
    (isCompleteScan ? 100 : Math.max(0, currentPhaseIndex) * 33.33);
  const liveStatusLabel = LIVE_LABEL[liveStatus] || "Polling";

  const coverage = scan.options?.tool_coverage;
  const coveragePhases = coverage ? Object.entries(coverage) : [];
  const unavailable = [
    ...new Set(coveragePhases.flatMap(([, c]) => c.tools_unavailable || [])),
  ];
  const incomplete = coveragePhases.some(
    ([, c]) => c.assessment_complete === false,
  );
  // A depth that narrowed the scan is disclosed even when every tool ran —
  // otherwise a quick pass reads as a thorough one that found nothing.
  const narrowed = coveragePhases.find(([, c]) => c.scan_depth_caveat);
  const showCoverage =
    Boolean(coverage) && (unavailable.length > 0 || incomplete || narrowed);

  const stats = [
    {
      key: "endpoints",
      label: "Discovered Assets",
      value: scan.total_endpoints || 0,
    },
    {
      key: "critical",
      label: "Critical Findings",
      value: scan.critical_count || 0,
      tone: scan.critical_count > 0 ? "critical" : null,
    },
    {
      key: "high",
      label: "High Findings",
      value: scan.high_count || 0,
      tone: scan.high_count > 0 ? "high" : null,
    },
    { key: "total", label: "Total Findings", value: scan.total_findings || 0 },
  ];

  return (
    <AppLayout pageTitle={`Scan: ${scan.scan_name}`}>
      <div className="page-inner wsp-page">
        <div className="wsp-header">
          <div>
            <div className="sd-title-row">
              <h1 className="page-title">{scan.scan_name}</h1>
              {/* The canonical vocabulary. The previous badge was a two-way
                  branch — complete, else "info" — so an unrecognised status was
                  dressed as an active scan. CcureScanStatus reports an unknown
                  value as Unknown and keeps the raw string in its title. */}
              <CcureScanStatus status={scan.status} />
              {/* Transport health, labelled as such so it cannot be read as the
                  scan's own state. */}
              <CcureBadge
                variant={liveStatus === "connected" ? "success" : "warning"}
                aria-label={`Live updates: ${liveStatusLabel}`}
              >
                {liveStatusLabel}
              </CcureBadge>
            </div>
            <p className="page-subtitle">
              Target:{" "}
              {/* Preserved as a link, including target/rel, because changing it
                  would change this page's navigation behaviour. */}
              <a
                href={scan.target_url}
                target="_blank"
                rel="noreferrer"
                className="sd-target"
              >
                {scan.target_url}
              </a>
            </p>
          </div>

          <div className="wsp-actions">
            {isActiveScan && (
              <CcureButton variant="danger" onClick={handleCancel}>
                Cancel Scan
              </CcureButton>
            )}
            {isCompleteScan && (
              <CcureButton
                onClick={handleDownload}
                loading={downloading}
                aria-busy={downloading ? "true" : undefined}
              >
                {downloading ? "Generating PDF..." : "Download Report"}
              </CcureButton>
            )}
          </div>
        </div>

        <CcureCard title="Pipeline Progress" headingLevel={2}>
          {isActiveScan && (
            <div className="sd-live-note" role="status" aria-live="polite">
              {scan.live_progress?.message ||
                `Scan is ${normalizedStatus === "queued" ? "queued" : "running"} in the ${normalizedPhase.toLowerCase() || "initializing"} phase.`}{" "}
              This page updates automatically.
            </div>
          )}

          {/* Was a bare <div> with a width percentage: no role, no value, no
              name. CcureScanProgress supplies all three and resolves a complete
              scan to 100 even if the last update landed short. */}
          <CcureScanProgress
            value={progressPercent}
            status={scan.status}
            label="Overall scan progress"
          />

          <ol className="sd-steps">
            {PIPELINE_PHASES.map((phase, idx) => {
              const isActive = normalizedPhase === phase && isActiveScan;
              const isDone =
                idx < currentPhaseIndex ||
                isCompleteScan ||
                normalizedPhase === "COMPLETE";
              const state = stepState(isDone, isActive);
              return (
                <li
                  key={phase}
                  className={`sd-step sd-step--${state.toLowerCase().replace(/\s+/g, "-")}`}
                  aria-current={isActive ? "step" : undefined}
                >
                  <span className="sd-step-marker" aria-hidden="true">
                    {isDone ? "✓" : idx + 1}
                  </span>
                  <span className="sd-step-name">{phase}</span>
                  {/* The state in words. The glyphs above are decorative; this
                      is what a reader without them actually gets. */}
                  <span className="sd-step-state">{state}</span>
                </li>
              );
            })}
          </ol>
        </CcureCard>

        {isActiveScan && (
          <CcureCard title="Live Activity" headingLevel={2}>
            {liveEvents.length === 0 ? (
              <p className="wsp-placeholder">Waiting for scanner activity...</p>
            ) : (
              <ul className="sd-events">
                {liveEvents.map((event) => (
                  <li key={event.id} className="sd-event">
                    <span className="sd-event-phase">
                      {event.phase || "scan"}
                    </span>
                    <span className="sd-event-message">{event.message}</span>
                  </li>
                ))}
              </ul>
            )}
          </CcureCard>
        )}

        {/* Which scanners actually ran. A phase that could not run its primary
            detector produces an empty result that reads exactly like a clean
            one, so the gap is stated next to the counts it would distort.
            CcureAlert variant="warning" carries role="alert", because this
            changes what the numbers below mean. */}
        {showCoverage && (
          <CcureAlert
            variant="warning"
            title={
              unavailable.length || incomplete
                ? "This assessment is incomplete"
                : "This scan ran at reduced depth"
            }
            className="sd-coverage"
          >
            {narrowed && (
              <p>
                <b>{narrowed[1].scan_depth_label}</b>
                {" — "}
                {narrowed[1].scan_depth_caveat}
              </p>
            )}
            {/* Only claimed when something actually failed. A scan that merely
                ran at reduced depth has not "failed to complete", and saying so
                would send an operator hunting a problem that is not there. */}
            {(unavailable.length > 0 || incomplete) && (
              <p>
                {unavailable.length > 0 ? (
                  <>
                    <code>{unavailable.join(", ")}</code>{" "}
                    {unavailable.length === 1 ? "was" : "were"} not available on
                    the scanner, so the checks{" "}
                    {unavailable.length === 1 ? "it performs" : "they perform"}{" "}
                    did not run. The counts below reflect only what was actually
                    tested — they are not evidence that nothing else is present.
                  </>
                ) : (
                  <>
                    One or more phases could not complete their checks. The
                    counts below reflect only what was actually tested.
                  </>
                )}
              </p>
            )}
            <ul className="sd-coverage-list">
              {coveragePhases.map(([phase, c]) =>
                (c.tools || [])
                  .filter((t) => t.status !== "ran")
                  .map((t) => (
                    <li key={`${phase}-${t.tool}`}>
                      <code>{phase}</code> · <b>{t.tool}</b> — {t.status}
                      {t.detail ? `: ${t.detail}` : ""}
                    </li>
                  )),
              )}
            </ul>
          </CcureAlert>
        )}

        <div className="sd-stat-grid">
          {stats.map((s) => (
            /* CcureCard supplies the heading, and the heading is what names the
               counter. The previous markup paired a styled label div with a
               styled value div and tied them together with nothing. */
            <CcureCard key={s.key} title={s.label} headingLevel={2}>
              <div
                className={`sd-stat-value${s.tone ? ` sd-stat-value--${s.tone}` : ""}`}
              >
                {s.value}
              </div>
            </CcureCard>
          ))}
        </div>

        <div className="sd-links">
          <Link to={`/web-scans/${scan.id}/findings`} className="sd-link-card">
            <span className="sd-link-title">Explore Findings →</span>
            <span className="sd-link-desc">
              Deep dive into discovered vulnerabilities, HTTP evidence, and
              remediation steps.
            </span>
          </Link>
          <Link to={`/web-scans/${scan.id}/assets`} className="sd-link-card">
            <span className="sd-link-title">Asset Inventory →</span>
            <span className="sd-link-desc">
              Review discovered endpoints, APIs, forms, and technologies.
            </span>
          </Link>
        </div>

        <CcureConfirmDialog
          open={confirmCancel}
          title="Cancel this scan?"
          warning="Are you sure you want to cancel this scan?"
          confirmLabel="Cancel Scan"
          cancelLabel="Keep Scanning"
          tone="danger"
          onConfirm={performCancel}
          onCancel={() => setConfirmCancel(false)}
        />
      </div>
    </AppLayout>
  );
}
