/**
 * pages/scan/ConfigurationChecks.jsx
 * ───────────────────────────────────────────────────────────────────────────
 * What the configuration audit checks, and what this build can actually check.
 *
 * A read-only catalogue, deliberately. Configuration checks run inside the
 * credentialed scan — there is no "run" button here, because a second way to
 * start a scan against a named target would need its own scope check, quota
 * check and audit entry, and would produce scan rows that Scan History and the
 * reports would have to learn about.
 *
 * Two things this page exists to make visible:
 *
 * **The absence policy.** Every check states what a successful reading of "the
 * item is not present" means for it, because that is the column a reviewer
 * lands on when a control comes back as Manual review. A Windows setting
 * missing from the registry is at a platform default that varies by build —
 * neither a pass nor a failure, and saying which would be inventing an answer.
 *
 * **The capability gap.** The rule vocabulary admits check types and platforms
 * ahead of the phases that implement them, so a rule can exist that nothing in
 * this build can execute. The engine reports that as an error rather than
 * skipping it, but only after a scan has run. The banner says it up front.
 *
 * ── Migration note (Checkpoint 3C, batch 10) ────────────────────────────────
 * Read-only is the contract, and it is unchanged: same two endpoints, same
 * platform parameter, same severity ordering, no mutation of any kind. What
 * changed is the surface — every colour literal was a light-theme palette on a
 * page that renders in whichever theme the account chose — plus one correctness
 * fix recorded in full below.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { ToastContainer, useToasts } from "../../components/common/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureLoader,
} from "../../design-system";
import "../../styles/configuration-checks.css";
import { getConfigCapabilities, listConfigChecks } from "../../api/configAudit";

/** Severity is a CCure vocabulary; the page no longer keeps a private palette. */
const SEVERITY_VARIANT = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  none: "neutral",
  unscored: "neutral",
};

/**
 * Each policy needs its own wording. Collapsing them into "absent handling"
 * would hide the fact that absence is a pass for one rule and a failure for
 * another, which is the single most misread property of a hardening check.
 *
 * The variant carries the same meaning a second way, for a reader who cannot
 * distinguish the colours — the label is the authority, never the colour.
 */
const ABSENCE_TEXT = {
  pass: {
    label: "Absent = compliant",
    variant: "success",
    hint: "The thing not being there satisfies this check.",
  },
  fail: {
    label: "Absent = finding",
    variant: "danger",
    hint: "The thing is required, so its absence is the finding.",
  },
  not_applicable: {
    label: "Absent = out of scope",
    variant: "neutral",
    hint: "This check only applies to hosts that have the component.",
  },
  manual_review: {
    label: "Absent = review",
    variant: "warning",
    hint: "The setting was not explicitly configured, so the platform default applies and a person has to decide whether it is acceptable here.",
  },
};

const CheckRow = ({ check }) => {
  const [open, setOpen] = useState(false);
  const absence =
    ABSENCE_TEXT[check.absent_policy] || ABSENCE_TEXT.manual_review;

  return (
    <div className="cfg-row">
      <button
        type="button"
        className="cfg-row-toggle"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <CcureBadge variant={SEVERITY_VARIANT[check.severity] || "neutral"}>
          {check.severity}
        </CcureBadge>
        <span className="cfg-row-title">{check.title}</span>
        <CcureBadge variant="neutral">{check.check_type}</CcureBadge>
        {/* The policy travels as words. `title` is a convenience for a mouse
            user, never the carrier of the meaning. */}
        <CcureBadge variant={absence.variant} title={absence.hint}>
          {absence.label}
        </CcureBadge>
        <span className="cfg-row-caret" aria-hidden="true">
          {open ? "−" : "+"}
        </span>
      </button>

      {open && (
        <div className="cfg-detail">
          <dl className="cfg-dl">
            <div>
              <dt>Expected state</dt>
              <dd className="cfg-mono">{check.expected}</dd>
            </div>
            {check.description && (
              <div>
                <dt>What it reads</dt>
                <dd>{check.description}</dd>
              </div>
            )}
            {check.rationale && (
              <div>
                <dt>Why it matters</dt>
                <dd>{check.rationale}</dd>
              </div>
            )}
            {check.remediation && (
              <div>
                <dt>Remediation</dt>
                <dd>{check.remediation}</dd>
              </div>
            )}
            <div>
              <dt>If the item is not present</dt>
              <dd>{absence.hint}</dd>
            </div>
            <div className="cfg-meta">
              <code>{check.check_id}</code> · {check.platforms.join(", ")} · QoD{" "}
              {check.qod}
              {check.requires_credentials ? " · needs credentials" : ""}
            </div>
            {check.references?.length > 0 && (
              <div className="cfg-refs">
                {check.references.map((url) => (
                  <a key={url} href={url} target="_blank" rel="noreferrer">
                    Reference
                  </a>
                ))}
              </div>
            )}
          </dl>
        </div>
      )}
    </div>
  );
};

const PLATFORMS = ["windows", "linux"];

const ConfigurationChecks = () => {
  /* `useToasts()` returns { toasts, push, dismiss }. This page destructured
     `addToast`/`removeToast`, so both were undefined and the toast call threw.

     That was not a missing toast. The call is the page's ONLY error surface,
     and it sits in a `catch` whose `finally` clears the loading flag — so a
     failed load rendered the EMPTY state, "No configuration checks for this
     platform". That is a false statement about the product's capability rather
     than about the data, on the page whose whole purpose is to report what this
     build can and cannot check.

     Fixed by renaming on the way in, so the call sites stay byte-identical, and
     paired with a real error state below. Recorded rather than folded in
     silently. `ScanSchedules` carries the same defect and is NOT in this batch;
     it is untouched and reported. */
  const { toasts, push: addToast, dismiss: removeToast } = useToasts();
  const [checks, setChecks] = useState([]);
  const [capabilities, setCapabilities] = useState(null);
  const [platform, setPlatform] = useState("windows");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [rows, caps] = await Promise.all([
        listConfigChecks({ platform }),
        getConfigCapabilities(),
      ]);
      setChecks(rows);
      setCapabilities(caps);
    } catch (err) {
      const detail =
        err?.response?.data?.detail || "Could not load configuration checks";
      /* Held in state as well as announced. A toast disappears; the reason the
         catalogue is empty must not. */
      setError(detail);
      setChecks([]);
      addToast(detail, "error");
    } finally {
      setLoading(false);
    }
  }, [platform, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  const bySeverity = useMemo(() => {
    const order = ["critical", "high", "medium", "low", "none", "unscored"];
    return [...checks].sort(
      (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
    );
  }, [checks]);

  const supported = capabilities?.supported?.[platform] || [];
  const unimplemented = capabilities?.declared_without_collector || [];

  return (
    <AppLayout>
      <ToastContainer toasts={toasts} dismiss={removeToast} />

      <div className="page-inner cfg-page">
        <h1 className="page-title">Configuration Checks</h1>

        <p className="page-subtitle cfg-lede">
          Host hardening controls evaluated during a credentialed scan. Each one
          reads a specific setting and compares it against a required state, and
          its result travels the same path as a CVE finding — severity, risk,
          remediation and the scan report. There is nothing to start here: these
          run automatically on every credentialed scan, over the session the
          collectors already opened.
        </p>

        {/* A pair of buttons, not a tab strip: they re-query the same catalogue
            rather than switching between two panels. `aria-pressed` is what
            states the choice — the raised styling is the sighted half of the
            same fact, not the whole of it. */}
        <div
          className="cfg-platforms"
          role="group"
          aria-label="Target platform"
        >
          {PLATFORMS.map((name) => (
            <CcureButton
              key={name}
              variant={platform === name ? "primary" : "secondary"}
              size="sm"
              className="cfg-platform-btn"
              aria-pressed={platform === name}
              onClick={() => setPlatform(name)}
            >
              {name}
            </CcureButton>
          ))}
        </div>

        {capabilities && (
          <CcureAlert
            variant="info"
            live={false}
            className="cfg-capability"
            title={`What this build can read on ${platform}`}
          >
            {supported.join(", ") || "nothing"}.
            {unimplemented.length > 0 && (
              <>
                {" "}
                <strong>Not yet implemented:</strong> {unimplemented.join(", ")}{" "}
                — a rule using one of these reports as not assessed rather than
                being silently skipped.
              </>
            )}
          </CcureAlert>
        )}

        {/* The error is its own state, above the list. Before this it did not
            exist: a failed load rendered as "this platform has no checks". */}
        {error && (
          <CcureAlert variant="danger" className="cfg-error">
            {error}
          </CcureAlert>
        )}

        {loading ? (
          <div className="cfg-loading">
            <CcureLoader label="Loading configuration checks…" />
          </div>
        ) : error ? null : bySeverity.length === 0 ? (
          <CcureEmptyState
            title="No configuration checks for this platform"
            description="Checks are registered per platform; none is defined for this one yet."
          />
        ) : (
          <>
            <p className="cfg-count">
              {bySeverity.length} check{bySeverity.length === 1 ? "" : "s"}
            </p>
            {bySeverity.map((check) => (
              <CheckRow key={check.check_id} check={check} />
            ))}
          </>
        )}
      </div>
    </AppLayout>
  );
};

export default ConfigurationChecks;
