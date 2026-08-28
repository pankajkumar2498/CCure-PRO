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
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import AppLayout from "../../components/layout/AppLayout";
import EmptyState from "../../components/common/EmptyState";
import Loader from "../../components/common/Loader";
import { ToastContainer, useToasts } from "../../components/common/Toast";
import { getConfigCapabilities, listConfigChecks } from "../../api/configAudit";

const SEVERITY_STYLE = {
  critical: { bg: "#fee2e2", tone: "#991b1b" },
  high: { bg: "#ffedd5", tone: "#9a3412" },
  medium: { bg: "#fef3c7", tone: "#92400e" },
  low: { bg: "#e0f2fe", tone: "#075985" },
  none: { bg: "#f1f5f9", tone: "#475569" },
  unscored: { bg: "#f1f5f9", tone: "#475569" },
};

/**
 * Each policy needs its own wording. Collapsing them into "absent handling"
 * would hide the fact that absence is a pass for one rule and a failure for
 * another, which is the single most misread property of a hardening check.
 */
const ABSENCE_TEXT = {
  pass: {
    label: "Absent = compliant",
    tone: "#166534",
    bg: "#dcfce7",
    hint: "The thing not being there satisfies this check.",
  },
  fail: {
    label: "Absent = finding",
    tone: "#991b1b",
    bg: "#fee2e2",
    hint: "The thing is required, so its absence is the finding.",
  },
  not_applicable: {
    label: "Absent = out of scope",
    tone: "#475569",
    bg: "#f1f5f9",
    hint: "This check only applies to hosts that have the component.",
  },
  manual_review: {
    label: "Absent = review",
    tone: "#92400e",
    bg: "#fef3c7",
    hint: "The setting was not explicitly configured, so the platform default applies and a person has to decide whether it is acceptable here.",
  },
};

const Pill = ({ bg, tone, children, title }) => (
  <span
    title={title}
    style={{
      background: bg,
      color: tone,
      borderRadius: 999,
      padding: "2px 10px",
      fontSize: 12,
      fontWeight: 600,
      whiteSpace: "nowrap",
    }}
  >
    {children}
  </span>
);

const CheckRow = ({ check }) => {
  const [open, setOpen] = useState(false);
  const severity = SEVERITY_STYLE[check.severity] || SEVERITY_STYLE.unscored;
  const absence =
    ABSENCE_TEXT[check.absent_policy] || ABSENCE_TEXT.manual_review;

  return (
    <div
      style={{
        border: "1px solid #e2e8f0",
        borderRadius: 8,
        marginBottom: 8,
        background: "#fff",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          width: "100%",
          padding: "12px 14px",
          background: "none",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
        }}
        aria-expanded={open}
      >
        <Pill bg={severity.bg} tone={severity.tone}>
          {check.severity}
        </Pill>
        <span style={{ flex: 1, fontWeight: 600 }}>{check.title}</span>
        <Pill bg="#f1f5f9" tone="#475569">
          {check.check_type}
        </Pill>
        <Pill bg={absence.bg} tone={absence.tone} title={absence.hint}>
          {absence.label}
        </Pill>
        <span style={{ color: "#94a3b8" }}>{open ? "−" : "+"}</span>
      </button>

      {open && (
        <div
          style={{
            borderTop: "1px solid #e2e8f0",
            padding: "12px 14px",
            fontSize: 14,
            color: "#334155",
          }}
        >
          <dl style={{ margin: 0, display: "grid", gap: 8 }}>
            <div>
              <dt style={{ fontWeight: 600 }}>Expected state</dt>
              <dd style={{ margin: 0, fontFamily: "monospace" }}>
                {check.expected}
              </dd>
            </div>
            {check.description && (
              <div>
                <dt style={{ fontWeight: 600 }}>What it reads</dt>
                <dd style={{ margin: 0 }}>{check.description}</dd>
              </div>
            )}
            {check.rationale && (
              <div>
                <dt style={{ fontWeight: 600 }}>Why it matters</dt>
                <dd style={{ margin: 0 }}>{check.rationale}</dd>
              </div>
            )}
            {check.remediation && (
              <div>
                <dt style={{ fontWeight: 600 }}>Remediation</dt>
                <dd style={{ margin: 0 }}>{check.remediation}</dd>
              </div>
            )}
            <div>
              <dt style={{ fontWeight: 600 }}>If the item is not present</dt>
              <dd style={{ margin: 0 }}>{absence.hint}</dd>
            </div>
            <div style={{ color: "#64748b", fontSize: 13 }}>
              <code>{check.check_id}</code> · {check.platforms.join(", ")} · QoD{" "}
              {check.qod}
              {check.requires_credentials ? " · needs credentials" : ""}
            </div>
            {check.references?.length > 0 && (
              <div>
                {check.references.map((url) => (
                  <a
                    key={url}
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: 13, marginRight: 12 }}
                  >
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

const ConfigurationChecks = () => {
  const { toasts, addToast, removeToast } = useToasts();
  const [checks, setChecks] = useState([]);
  const [capabilities, setCapabilities] = useState(null);
  const [platform, setPlatform] = useState("windows");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rows, caps] = await Promise.all([
        listConfigChecks({ platform }),
        getConfigCapabilities(),
      ]);
      setChecks(rows);
      setCapabilities(caps);
    } catch (error) {
      addToast(
        error?.response?.data?.detail || "Could not load configuration checks",
        "error",
      );
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
      <ToastContainer toasts={toasts} removeToast={removeToast} />

      <h1 style={{ margin: 0 }}>Configuration Checks</h1>

      <p style={{ color: "#475569", maxWidth: 820 }}>
        Host hardening controls evaluated during a credentialed scan. Each one
        reads a specific setting and compares it against a required state, and
        its result travels the same path as a CVE finding — severity, risk,
        remediation and the scan report. There is nothing to start here: these
        run automatically on every credentialed scan, over the session the
        collectors already opened.
      </p>

      <div style={{ display: "flex", gap: 8, margin: "16px 0" }}>
        {["windows", "linux"].map((name) => (
          <button
            key={name}
            type="button"
            onClick={() => setPlatform(name)}
            style={{
              padding: "6px 16px",
              borderRadius: 6,
              border: "1px solid #cbd5e1",
              background: platform === name ? "#0f172a" : "#fff",
              color: platform === name ? "#fff" : "#334155",
              cursor: "pointer",
              textTransform: "capitalize",
            }}
          >
            {name}
          </button>
        ))}
      </div>

      {capabilities && (
        <div
          style={{
            background: "#f8fafc",
            border: "1px solid #e2e8f0",
            borderRadius: 8,
            padding: "12px 14px",
            fontSize: 13,
            color: "#475569",
            marginBottom: 16,
          }}
        >
          <strong>What this build can read on {platform}:</strong>{" "}
          {supported.join(", ") || "nothing"}.
          {unimplemented.length > 0 && (
            <>
              {" "}
              <strong>Not yet implemented:</strong> {unimplemented.join(", ")} —
              a rule using one of these reports as not assessed rather than
              being silently skipped.
            </>
          )}
        </div>
      )}

      {loading ? (
        <Loader />
      ) : bySeverity.length === 0 ? (
        <EmptyState
          title="No configuration checks for this platform"
          message="Checks are registered per platform; none is defined for this one yet."
        />
      ) : (
        <>
          <div style={{ color: "#64748b", fontSize: 13, marginBottom: 8 }}>
            {bySeverity.length} check{bySeverity.length === 1 ? "" : "s"}
          </div>
          {bySeverity.map((check) => (
            <CheckRow key={check.check_id} check={check} />
          ))}
        </>
      )}
    </AppLayout>
  );
};

export default ConfigurationChecks;
