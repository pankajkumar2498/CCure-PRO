/**
 * src/modules/audit/pages/scan/Phase3Results.jsx
 *
 * UNIFIED AUTO-PIPELINE PAGE
 * ─────────────────────────────────────────────────────────────────────────────
 * After the user clicks "Start Discovery Scan" and Phase 1 completes,
 * this page automatically runs the entire pipeline:
 *
 *   Phase 2 (Port Scan) → Phase 3 (Vulnerability Audit) → Report Ready
 *
 * NO manual buttons between phases. The pipeline runs seamlessly.
 *
 * Features:
 *   • Automatic sequential phase execution
 *   • Live progress with animated stepper
 *   • Progressive result reveal as each phase completes
 *   • Cancel / Retry support
 *   • Scan intensity selector (before pipeline starts)
 *   • Failure handling with phase-specific retry
 *
 * Checkpoint 3C batch 24 — on the design system. The automatic start, the
 * dispatch requests, the ticket and progress sockets, cancel, retry and restart
 * are unchanged, and pinned by src/__tests__/pages/scan/Phase3Results.test.jsx,
 * written against the page before migration.
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import ScanStepper from "@audit/components/layout/ScanStepper";
import CVELink from "@audit/components/common/CVELink";
import { describeAffected } from "@audit/utils/affectedSoftware";
import { useScan, PIPELINE_STATES } from "@audit/context/ScanContext";
import api from "@shell/api/axiosInstance";
import { stopScan } from "@audit/api/scans";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureModal,
  CcureProgress,
  CcureSeverityBadge,
  CcureTable,
  CcurePage,
  CcurePageHeader,
  CcureIcon,
} from "../../../../design-system";
import "../../styles/phase3-results.css";

/** Progress-socket URL for a scan. Derived from the axios base URL only. */
function buildScanProgressUrl(scanId, ticket) {
  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");
  return `${wsPrefix}/scans/${scanId}/progress?ticket=${encodeURIComponent(ticket)}`;
}

/**
 * Wait for one pipeline phase to report complete over the progress socket.
 *
 * Module scope: it closes over nothing from the component, and as a
 * component-local arrow it was rebuilt every render, which made it an unstable
 * dependency of the `runFullPipeline` callback below.
 */
async function waitForPhase(scanId, phase, signal) {
  const { data } = await api.post("/auth/ticket", null, { signal });
  const ticket = data.ticket;

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(buildScanProgressUrl(scanId, ticket));

    const handleAbort = () => {
      ws.close();
      reject(new DOMException("Aborted", "AbortError"));
    };
    if (signal) {
      if (signal.aborted) {
        reject(new DOMException("Aborted", "AbortError"));
        return;
      }
      signal.addEventListener("abort", handleAbort);
    }

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.phase === phase) {
        if (
          data.progress?.status === "complete" ||
          data.progress?.status === "failed"
        ) {
          ws.close();
          if (signal) signal.removeEventListener("abort", handleAbort);
          resolve(data.progress);
        }
      }
    };
    ws.onerror = () => {
      ws.close();
      if (signal) signal.removeEventListener("abort", handleAbort);
      reject(new Error(`Phase ${phase} WebSocket failed`));
    };
    setTimeout(() => {
      ws.close();
      if (signal) signal.removeEventListener("abort", handleAbort);
      reject(new Error(`Phase ${phase} timed out`));
    }, 1200000); // 20 mins
  });
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

// GAP-07: device category → { icon, label } for the device badge
const DEVICE_CAT_META = {
  router: { icon: "shuffle", label: "Router" },
  switch: { icon: "link", label: "Switch" },
  firewall: { icon: "shield", label: "Firewall" },
  wireless_ap: { icon: "radio", label: "Wireless AP" },
  printer: { icon: "printer", label: "Printer" },
  iot: { icon: "settings", label: "IoT/ICS" },
  server: { icon: "monitor", label: "Server" },
  endpoint: { icon: "monitor", label: "Endpoint" },
  voip: { icon: "phone", label: "VoIP" },
  storage: { icon: "hard-drive", label: "Storage" },
  network_appliance: { icon: "link", label: "Net Appliance" },
  scada_ics: { icon: "settings", label: "Industrial/OT" },
  virtual_machine: { icon: "globe", label: "Virtual Machine" },
  unknown: { icon: "help-circle", label: "Unknown" },
};

// GAP-06 + Deep Probes: count all active exploit / misconfiguration conditions on a host
const countActiveFindings = (host) => {
  let n = 0;
  // Original checks
  if (host.heartbleed_info?.vulnerable) n++;
  if (host.smb_ms17010_info?.ms17010_likely) n++;
  if (host.ldap_info?.anonymous_bind?.allowed) n++;
  if (host.dns_info?.zone_transfer?.vulnerable) n++;
  if (host.default_creds_info?.ftp_anon?.allowed) n++;
  if (host.default_creds_info?.redis_noauth?.vulnerable) n++;
  if (host.default_creds_info?.mongo_noauth?.vulnerable) n++;
  if (host.default_creds_info?.mqtt_noauth?.vulnerable) n++;
  if (host.default_creds_info?.http_default_creds?.found) n++;
  // FTP deep-probe findings
  if (host.ftp_info?.anonymous_login) n++;
  if (host.ftp_info?.write_access) n++;
  if (host.ftp_info?.weak_credentials?.length)
    n += host.ftp_info.weak_credentials.length;
  // HTTP deep-probe findings
  if (host.http_audit?.exposed_paths?.length)
    n += host.http_audit.exposed_paths.length;
  if (host.http_audit?.admin_panels?.length)
    n += host.http_audit.admin_panels.length;
  if (host.http_audit?.dangerous_methods?.length) n++;
  return n;
};

const fmtSec = (v) => {
  if (typeof v === "number") return v.toFixed(1);
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(1) : "—";
};

const safeArr = (v) => (Array.isArray(v) ? v : []);

const usefulText = (value) => {
  const text = String(value ?? "").trim();
  if (!text || text.toLowerCase() === "unknown" || text.toLowerCase() === "n/a")
    return "";
  return text;
};

const truncateEvidence = (value, max = 120) => {
  const text = usefulText(value);
  if (!text) return "";
  return text.length > max ? `${text.slice(0, max)}...` : text;
};

const maskCredential = (cred) => `${cred?.user || "user"}/********`;

/* ── Phase progress messages ──────────────────────────────────────────────── */
const PHASE_MESSAGES = {
  [PIPELINE_STATES.DISCOVERY]: {
    title: "Running Discovery…",
    desc: "Probing the network for live hosts.",
  },
  [PIPELINE_STATES.PORT_SCAN]: {
    title: "Running Port Scan…",
    desc: "Mapping open TCP services and grabbing banners.",
  },
  [PIPELINE_STATES.VULN_SCAN]: {
    title: "Running Vulnerability Audit…",
    desc: "Analyzing services for CVEs and security risks.",
  },
};

/* ── Presentation ─────────────────────────────────────────────────────────── */

/* A glyph repeats what its text already says, so assistive technology skips
   it. It stays on screen. */
function Glyph({ children }) {
  return (
    <span className="p3-glyph" aria-hidden="true">
      {children}
    </span>
  );
}

/* The host name a result table shows: the hostname, else the mDNS name, else
   the first NetBIOS name. "Unknown" stays when there is nothing better. */
const displayHostName = (host) => {
  let displayHost = host.hostname;
  if (!displayHost || displayHost === "Unknown") {
    if (host.mdns_name) displayHost = host.mdns_name;
    else if (host.netbios_names && host.netbios_names.length)
      displayHost = host.netbios_names[0].name;
  }
  return displayHost;
};

const Muted = ({ children = "—" }) => (
  <span className="p3-muted">{children}</span>
);

function FilterGroup({ label, value, onChange, options }) {
  return (
    <div className="p3-filter" role="group" aria-label={label}>
      {options.map(([val, lbl]) => (
        <CcureButton
          key={val}
          variant="secondary"
          size="sm"
          className="p3-filter__option"
          aria-pressed={value === val}
          onClick={() => onChange(val)}
        >
          {lbl}
        </CcureButton>
      ))}
    </div>
  );
}

function SectionHeading({ number, title, description, timing }) {
  return (
    <div className="p3-section__header">
      <div>
        <h2 className="p3-section__title">
          <span className="p3-section__badge" aria-hidden="true">
            ✓
          </span>{" "}
          {number}. {title}
        </h2>
        <p className="p3-section__desc">{description}</p>
      </div>
      {timing ? <span className="p3-timing">{timing}s</span> : null}
    </div>
  );
}

const severityCount = (hosts, band) => {
  let count = 0;
  hosts.forEach((h) => {
    (h.cves || []).forEach((cve) => {
      const sev = (cve.severity || "Info").toLowerCase();
      if (sev === band) count++;
    });
  });
  return count;
};

/* Findings a host's deep probes established, in the order they are listed. */
const misconfigurationBadges = (host) => {
  const badges = [];
  const ftp = host.ftp_info || {};
  const http = host.http_audit || {};
  const smb = host.smb_info || {};
  const tls = host.tls_info || {};

  if (host.heartbleed_info?.vulnerable)
    badges.push({ label: "Heartbleed", tone: "danger", icon: "alert-octagon" });
  if (host.smb_ms17010_info?.ms17010_likely)
    badges.push({
      label: "EternalBlue",
      tone: "danger",
      icon: "alert-octagon",
    });
  if (host.ldap_info?.anonymous_bind?.allowed)
    badges.push({ label: "LDAP Anon Bind", tone: "warning", icon: "unlock" });
  if (host.dns_info?.zone_transfer?.vulnerable)
    badges.push({ label: "DNS Zone Transfer", tone: "warning", icon: "radio" });
  if (ftp.anonymous_login)
    badges.push({ label: "FTP Anon Login", tone: "warning", icon: "folder" });
  if (ftp.write_access)
    badges.push({ label: "FTP Write Access", tone: "danger", icon: "edit" });
  if (ftp.weak_credentials?.length)
    badges.push({
      label: `FTP Weak Creds (${ftp.weak_credentials.length})`,
      tone: "warning",
      icon: "key",
    });
  if (http.exposed_paths?.length)
    badges.push({
      label: `Exposed Paths (${http.exposed_paths.length})`,
      tone: "warning",
      icon: "folder",
    });
  if (http.admin_panels?.length)
    badges.push({
      label: `Admin Panels (${http.admin_panels.length})`,
      tone: "warning",
      icon: "settings",
    });
  if (http.dangerous_methods?.length)
    badges.push({
      label: "Dangerous HTTP Methods",
      tone: "warning",
      icon: "tool",
    });
  if (smb.open && smb.null_session)
    badges.push({ label: "SMB Null Session", tone: "warning", icon: "folder" });
  if (tls.cert_expired)
    badges.push({ label: "TLS Cert Expired", tone: "warning", icon: "lock" });
  return badges;
};

/**
 * CcureModal's own outside-click handling never fires (it reads the React
 * event's currentTarget after dispatch, when React has already cleared it).
 * The legacy report dialog closed on a click outside it, so the page listens
 * for a click on this dialog's own overlay, as ScanHistory does.
 */
function useCloseOnOverlayClick(active, dialogClass, onClose) {
  useEffect(() => {
    if (!active) return undefined;
    const onClick = (event) => {
      const target = event.target;
      if (
        target instanceof Element &&
        target.classList.contains("cc-modal__overlay") &&
        target.firstElementChild?.classList.contains(dialogClass)
      ) {
        onClose();
      }
    };
    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, [active, dialogClass, onClose]);
}

function RiskReport({
  open,
  onClose,
  scanNo,
  target,
  hosts,
  phase1Summary,
  phase3Summary,
  pipelinePhaseTimings,
}) {
  useCloseOnOverlayClick(open, "p3-report", onClose);

  const totalCves = hosts.reduce((sum, h) => sum + (h.cves?.length ?? 0), 0);
  const hostsWithCves = hosts.filter((h) => (h.cves?.length ?? 0) > 0);

  return (
    <CcureModal
      open={open}
      onClose={onClose}
      title="Risk Report - Full Assessment"
      subtitle={`Scan No. ${scanNo ?? "-"} - Target: ${target}`}
      size="lg"
      closeLabel="Close"
      closeOnOverlayClick={false}
      className="p3-report"
    >
      <div className="p3-report__intro">
        <h3 className="p3-report__heading">
          <Glyph>✓</Glyph> Full Pipeline Complete
        </h3>
        <p className="p3-report__lead">
          All scan phases finished successfully. Complete vulnerability analysis
          and risk assessment below.
        </p>
      </div>

      <dl className="p3-stats">
        <div className="p3-stat p3-stat--success">
          <dt className="p3-stat__label">Total Hosts Audited</dt>
          <dd className="p3-stat__value">
            {phase3Summary?.total_hosts ?? hosts.length}
          </dd>
        </div>
        <div className="p3-stat p3-stat--danger">
          <dt className="p3-stat__label">Total CVEs Found</dt>
          <dd className="p3-stat__value">{totalCves}</dd>
        </div>
        <div className="p3-stat p3-stat--danger">
          <dt className="p3-stat__label">Critical Risk Hosts</dt>
          <dd className="p3-stat__value">
            {
              hosts.filter(
                (h) => (h.host_risk_level || "").toLowerCase() === "critical",
              ).length
            }
          </dd>
        </div>
        <div className="p3-stat p3-stat--warning">
          <dt className="p3-stat__label">High Risk Hosts</dt>
          <dd className="p3-stat__value">
            {
              hosts.filter(
                (h) => (h.host_risk_level || "").toLowerCase() === "high",
              ).length
            }
          </dd>
        </div>
      </dl>

      <section className="p3-report__block">
        <h3 className="p3-report__heading">
          <CcureIcon name="bar-chart" /> Scan Timeline
        </h3>
        <dl className="p3-timeline">
          <div className="p3-timeline__item">
            <dt>Phase 1: Discovery</dt>
            <dd>{fmtSec(phase1Summary?.scan_duration)}s</dd>
          </div>
          <div className="p3-timeline__item">
            <dt>Phase 2: Port Scan</dt>
            <dd>
              {pipelinePhaseTimings.portScan
                ? fmtSec(pipelinePhaseTimings.portScan)
                : "—"}
              s
            </dd>
          </div>
          <div className="p3-timeline__item">
            <dt>Phase 3: Vulnerability Audit</dt>
            <dd>
              {pipelinePhaseTimings.vulnScan
                ? fmtSec(pipelinePhaseTimings.vulnScan)
                : "—"}
              s
            </dd>
          </div>
        </dl>
      </section>

      <section className="p3-report__block">
        <h3 className="p3-report__heading">
          <CcureIcon name="alert-triangle" /> Vulnerability Severity
          Distribution
        </h3>
        <ul className="p3-distribution">
          {[
            ["critical", "Critical"],
            ["high", "High"],
            ["medium", "Medium"],
            ["low", "Low"],
            ["info", "Info"],
          ].map(([band, label]) => (
            <li
              key={band}
              className={`p3-distribution__item p3-distribution__item--${band}`}
            >
              <span className="p3-distribution__count">
                {severityCount(hosts, band)}
              </span>
              <span className="p3-distribution__label">{label}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="p3-report__block">
        <h3 className="p3-report__heading">
          <CcureIcon name="monitor" /> Affected Hosts ({hosts.length} total)
        </h3>
        <CcureTable
          caption="Affected hosts"
          density="compact"
          rows={hosts}
          rowKey={(host) => host.ip_address}
          columns={[
            {
              key: "ip_address",
              header: "IP Address",
              isRowHeader: true,
              mono: true,
            },
            {
              key: "hostname",
              header: "Hostname",
              cell: (host) =>
                usefulText(host.hostname) || <Muted>Not detected</Muted>,
            },
            {
              key: "open_ports",
              header: "Open Ports",
              cell: (host) =>
                (host.open_ports || []).length > 0
                  ? `${(host.open_ports || []).length}`
                  : "—",
            },
            {
              key: "os",
              header: "OS",
              cell: (host) =>
                usefulText(host.os_guess) || <Muted>Not detected</Muted>,
            },
            {
              key: "cves",
              header: "Vulnerabilities",
              align: "center",
              cell: (host) => (
                <span className="p3-strong">{host.cves?.length ?? 0}</span>
              ),
            },
            {
              key: "risk",
              header: "Risk",
              cell: (host) => (
                <CcureSeverityBadge severity={host.host_risk_level || "Info"} />
              ),
            },
            {
              key: "status",
              header: "Status",
              cell: (host) => (
                <CcureBadge variant={host.is_active ? "success" : "neutral"}>
                  <Glyph>{host.is_active ? "✓" : "○"}</Glyph>{" "}
                  {host.is_active ? "Active" : "Inactive"}
                </CcureBadge>
              ),
            },
          ]}
        />
      </section>

      <section className="p3-report__block">
        <h3 className="p3-report__heading">
          <CcureIcon name="search" /> Detailed Vulnerability Analysis
        </h3>
        {hostsWithCves.map((host) => {
          const badges = misconfigurationBadges(host);
          return (
            <article key={host.ip_address} className="p3-host">
              <div className="p3-host__header">
                <div className="p3-host__identity">
                  <span className="p3-mono p3-strong">{host.ip_address}</span>{" "}
                  <span className="p3-muted">
                    {usefulText(host.hostname) || <Muted>Not detected</Muted>}
                  </span>
                </div>
                <span className="p3-host__risk">
                  <CcureSeverityBadge severity={host.host_risk_level} /> Risk
                </span>
              </div>

              <div className="p3-host__body">
                {badges.length > 0 && (
                  <div className="p3-findings">
                    <p className="p3-findings__label">
                      <CcureIcon name="zap" /> Active Misconfiguration Findings
                    </p>
                    <ul className="p3-badges">
                      {badges.map((b, i) => (
                        <li key={i}>
                          <CcureBadge variant={b.tone}>
                            <CcureIcon name={b.icon} /> {b.label}
                          </CcureBadge>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {host.ftp_info?.open && (
                  <div className="p3-probe p3-probe--ftp">
                    <p className="p3-probe__title">
                      <CcureIcon name="folder" /> FTP Service
                    </p>
                    {truncateEvidence(host.ftp_info.banner) && (
                      <p className="p3-probe__line">
                        Banner:{" "}
                        <code className="p3-code">
                          {truncateEvidence(host.ftp_info.banner)}
                        </code>
                      </p>
                    )}
                    {(host.ftp_info.issues || []).length > 0 && (
                      <ul className="p3-probe__issues">
                        {(host.ftp_info.issues || []).map((issue, i) => (
                          <li key={i}>
                            <Glyph>•</Glyph> {issue}
                          </li>
                        ))}
                      </ul>
                    )}
                    {(host.ftp_info.weak_credentials || []).length > 0 && (
                      <p className="p3-probe__line">
                        <strong className="p3-tone-warning">
                          Weak credentials accepted:
                        </strong>{" "}
                        {host.ftp_info.weak_credentials.map((c, i) => (
                          <code key={i} className="p3-code p3-cred">
                            {maskCredential(c)}
                          </code>
                        ))}
                      </p>
                    )}
                  </div>
                )}

                {host.http_audit &&
                  (host.http_audit.exposed_paths?.length ||
                    host.http_audit.admin_panels?.length ||
                    host.http_audit.dangerous_methods?.length ||
                    host.http_audit.issues?.length) && (
                    <div className="p3-probe p3-probe--http">
                      <p className="p3-probe__title">
                        <CcureIcon name="globe" /> HTTP Service
                      </p>
                      {truncateEvidence(host.http_audit.server_header) && (
                        <p className="p3-probe__line">
                          Server:{" "}
                          <code className="p3-code">
                            {truncateEvidence(host.http_audit.server_header)}
                          </code>
                        </p>
                      )}
                      {(host.http_audit.issues || []).length > 0 && (
                        <ul className="p3-probe__issues">
                          {(host.http_audit.issues || [])
                            .slice(0, 4)
                            .map((issue, i) => (
                              <li key={i}>
                                <Glyph>•</Glyph> {issue}
                              </li>
                            ))}
                        </ul>
                      )}
                      {(host.http_audit.exposed_paths || []).length > 0 && (
                        <div className="p3-probe__group">
                          <p className="p3-probe__subtitle">Exposed Paths:</p>
                          <ul className="p3-paths">
                            {host.http_audit.exposed_paths.map((p, i) => (
                              <li key={i}>
                                <code className="p3-code">
                                  {p.path} [{p.status}]
                                  {p.note?.includes("directory") ? (
                                    <>
                                      {" "}
                                      <CcureIcon name="folder" />
                                    </>
                                  ) : null}
                                </code>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {(host.http_audit.admin_panels || []).length > 0 && (
                        <div className="p3-probe__group">
                          <p className="p3-probe__subtitle">
                            Admin Panels Detected:
                          </p>
                          <ul className="p3-probe__issues">
                            {host.http_audit.admin_panels.map((p, i) => (
                              <li key={i}>
                                <CcureIcon name="settings" />{" "}
                                <strong>{p.product}</strong> @{" "}
                                <code className="p3-code">{p.path}</code> (HTTP{" "}
                                {p.status})
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {(host.http_audit.dangerous_methods || []).length > 0 && (
                        <div className="p3-probe__group">
                          <p className="p3-probe__subtitle">
                            Dangerous Methods:
                          </p>
                          <p className="p3-probe__line">
                            {host.http_audit.dangerous_methods.join(" | ")}
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                {(host.cves || []).length > 0 && (
                  <p className="p3-cves__label">CVEs</p>
                )}
                <ul className="p3-cves">
                  {(host.cves || []).map((cve, idx) => {
                    const affected = describeAffected(cve);
                    return (
                      <li key={idx} className="p3-cve">
                        <div className="p3-cve__head">
                          <span className="p3-cve__id">
                            <CVELink cveId={cve.cve_id || "Unknown CVE"} />
                          </span>
                          <CcureSeverityBadge
                            severity={cve.severity || "Info"}
                          />
                        </div>
                        {cve.cvss_score && (
                          <p className="p3-cve__line">
                            CVSS Score:{" "}
                            <strong>
                              {Number(cve.cvss_score || cve.cvss || 0).toFixed(
                                1,
                              )}
                            </strong>
                            /10
                          </p>
                        )}
                        {cve.description && (
                          <p className="p3-cve__desc">
                            {cve.description ||
                              cve.desc ||
                              "No description available"}
                          </p>
                        )}
                        {/* affected_software is a list of CPE records on the
                          credentialed path; rendered raw, it is an object
                          child and React refuses the whole report. */}
                        {affected && (
                          <p className="p3-cve__line">
                            <strong>Affected:</strong> {affected}
                          </p>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            </article>
          );
        })}

        {hostsWithCves.length === 0 && (
          <p className="p3-empty">No vulnerabilities found in this scan.</p>
        )}
      </section>

      <section className="p3-report__block p3-report__summary">
        <h3 className="p3-report__heading">
          <CcureIcon name="trending-up" /> Report Summary
        </h3>
        <ul className="p3-report__list">
          <li>
            Total hosts scanned: {phase3Summary?.total_hosts ?? hosts.length}
          </li>
          <li>Hosts with vulnerabilities: {hostsWithCves.length}</li>
          <li>Total CVEs identified: {totalCves}</li>
          <li>Critical severity: {severityCount(hosts, "critical")}</li>
          <li>High severity: {severityCount(hosts, "high")}</li>
          <li>
            FTP misconfigurations:{" "}
            {
              hosts.filter(
                (h) =>
                  h.ftp_info?.anonymous_login ||
                  h.ftp_info?.write_access ||
                  h.ftp_info?.weak_credentials?.length,
              ).length
            }{" "}
            host(s)
          </li>
          <li>
            HTTP exposed paths:{" "}
            {hosts.reduce(
              (sum, h) => sum + (h.http_audit?.exposed_paths?.length ?? 0),
              0,
            )}
          </li>
          <li>
            HTTP admin panels found:{" "}
            {hosts.reduce(
              (sum, h) => sum + (h.http_audit?.admin_panels?.length ?? 0),
              0,
            )}
          </li>
          <li>
            Active misconfiguration findings:{" "}
            {hosts.reduce((sum, h) => sum + countActiveFindings(h), 0)}
          </li>
        </ul>
      </section>

      <p className="p3-tip">
        <CcureIcon name="file-text" /> <strong>Tip:</strong> Close this modal
        and navigate to Scan History to export full PDF/XML reports with
        additional formatting and charts.
      </p>
    </CcureModal>
  );
}

/* ── Main Component ───────────────────────────────────────────────────────── */

export default function Phase3Results() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();
  const canExecuteScans = can(user, "audit.scan.run");
  const {
    phase1Hosts,
    phase1Summary,
    phase2Results,
    phase2Summary,
    phase3Results,
    phase3AuditResults,
    phase3Summary,
    scanId,
    scanNo,
    target,
    intensity,
    setPhase2Results,
    setPhase2Summary,
    setPhase3Summary,
    setPhase3AuditResults,
    pipelineMode,
    pipelineState,
    setPipelineState,
    pipelineError,
    setPipelineError,
    pipelinePhaseTimings,
    setPipelinePhaseTimings,
    saveStatus,
    setSaveStatus,
    abortRef,
  } = useScan();

  // Track whether the auto-pipeline has been triggered
  const pipelineStarted = useRef(false);
  const [localPortHosts, setLocalPortHosts] = useState(() =>
    safeArr(phase2Results),
  );
  const [localVulnResults, setLocalVulnResults] = useState(() =>
    safeArr(phase3AuditResults),
  );
  const [, setExpanded] = useState(new Set());

  // Filter states for each result section (active/all)
  const [filter1, setFilter1] = useState("active"); // Discovery Results
  const [filter2, setFilter2] = useState("active"); // Port Scan Results
  const [filter3, setFilter3] = useState("active"); // Vulnerability Results

  // Modal state for Risk Report
  const [showReportModal, setShowReportModal] = useState(false);

  const safePhase1Hosts = safeArr(phase1Hosts);
  const activeDiscoveryHosts = safePhase1Hosts.filter((h) => h.is_active);
  const auditQueueHosts = safeArr(phase3Results);
  const vulnerabilityProfile =
    location.state?.vulnerabilityProfile || "recommended";
  const requestedStartPhase = location.state?.startPhase;

  // Redirect if no hosts exist
  useEffect(() => {
    if (!safePhase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [safePhase1Hosts.length, navigate]);

  // Sync from context when results change externally
  useEffect(() => {
    setLocalPortHosts(safeArr(phase2Results));
  }, [phase2Results]);
  useEffect(() => {
    setLocalVulnResults(safeArr(phase3AuditResults));
  }, [phase3AuditResults]);

  /* ── Auto-start pipeline on mount ───────────────────────────────────────── */
  // A one-shot: `pipelineStarted` latches on the first start, so re-running
  // this is pure waste. The values it inspects to decide *how* to start are
  // read through a ref rather than named as dependencies — naming them would
  // re-evaluate the guards as the pipeline itself produced phase 2 and phase 3
  // results, i.e. the effect would react to its own output. The ref is
  // assigned during the same render that creates the effect closure, so the
  // body still sees exactly the values the old closure captured.
  const autoStartRef = useRef(null);
  useEffect(() => {
    const snap = autoStartRef.current;
    if (
      pipelineStarted.current ||
      !safePhase1Hosts.length ||
      !activeDiscoveryHosts.length ||
      snap.pipelineState === PIPELINE_STATES.REPORT_READY ||
      snap.pipelineState === PIPELINE_STATES.COMPLETE
    )
      return;

    // A route-level start request means this page owns the next transition,
    // even if the previous page left a stale PORT_SCAN state in context.
    if (
      !requestedStartPhase &&
      [
        PIPELINE_STATES.PORT_SCAN,
        PIPELINE_STATES.VULN_SCAN,
        PIPELINE_STATES.REPORT_READY,
        PIPELINE_STATES.COMPLETE,
      ].includes(snap.pipelineState)
    )
      return;

    if (safeArr(snap.phase3AuditResults).length > 0) return;
    if (
      !requestedStartPhase &&
      !snap.auditQueueHosts.length &&
      safeArr(snap.phase2Results).length > 0
    )
      return;

    pipelineStarted.current = true;
    snap.runFullPipeline(
      requestedStartPhase ||
        (snap.auditQueueHosts.length ? "VULN_SCAN" : "PORT_SCAN"),
    );
  }, [
    safePhase1Hosts.length,
    activeDiscoveryHosts.length,
    requestedStartPhase,
  ]);

  /* ── The automated pipeline executor ────────────────────────────────────── */
  const runFullPipeline = useCallback(
    async (retryFromPhase = null) => {
      if (!canExecuteScans) {
        setPipelineError({ phase: "AUTHORIZATION", message: denyMessage });
        setPipelineState(PIPELINE_STATES.ERROR);
        return;
      }
      const controller = new AbortController();
      abortRef.current = controller;

      const signal = controller.signal;
      const timings = { ...pipelinePhaseTimings };

      // Determine starting phase
      const startPhase = retryFromPhase || "PORT_SCAN";
      let portHosts =
        retryFromPhase === "PORT_SCAN" ? [] : safeArr(phase2Results);

      /* ── Phase 2: Port Scan ───────────────────────────────────────────────── */
      if (startPhase === "PORT_SCAN") {
        setPipelineState(PIPELINE_STATES.PORT_SCAN);
        setPipelineError(null);
        setSaveStatus("saving");
        const phaseStart = Date.now();

        try {
          if (signal.aborted) throw new DOMException("Aborted", "AbortError");

          const { data: assetDataTrigger } = await api.post(
            "/scan/asset-discovery",
            {
              hosts: activeDiscoveryHosts,
              intensity,
              scan_id: scanId,
              pipeline_mode: pipelineMode,
              phases: [1, 2],
            },
            { signal },
          );

          if (!assetDataTrigger.success)
            throw new Error(
              assetDataTrigger.error || "Port scan trigger failed",
            );

          const p2Result = await waitForPhase(scanId, 2, signal);
          if (p2Result?.status === "failed") {
            throw new Error("Port scan background task failed.");
          }

          const { data: fullScan } = await api.get(`/scans/${scanId}`, {
            signal,
          });
          const assetData = {
            data: fullScan?.results?.phase2?.data || [],
            summary: fullScan?.results?.phase2?.summary || {},
          };

          portHosts = safeArr(assetData.data);
          if (!portHosts.length) {
            throw new Error("Port scan completed but returned no hosts.");
          }

          setPhase2Results(portHosts);
          setPhase2Summary(assetData.summary || null);
          setLocalPortHosts(portHosts);
          timings.portScan = ((Date.now() - phaseStart) / 1000).toFixed(1);
          setPipelinePhaseTimings({ ...timings });
        } catch (err) {
          if (err.name === "AbortError") {
            setPipelineState(PIPELINE_STATES.CANCELLED);
            setSaveStatus("");
            return;
          }
          const detail =
            err.response?.data?.detail || err.message || "Port scan failed";
          setPipelineError({ phase: "PORT_SCAN", message: detail });
          setPipelineState(PIPELINE_STATES.ERROR);
          setSaveStatus("error");
          setTimeout(() => setSaveStatus(""), 4000);
          return;
        }
      }

      /* ── Phase 3: Vulnerability Audit ─────────────────────────────────────── */
      setPipelineState(PIPELINE_STATES.VULN_SCAN);
      const phase3Start = Date.now();

      try {
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");

        const hostsForAudit = portHosts.length
          ? portHosts
          : safeArr(phase3Results).length
            ? safeArr(phase3Results)
            : safeArr(phase2Results);

        const { data: auditDataTrigger } = await api.post(
          "/scan/vulnerability-audit",
          {
            hosts: hostsForAudit,
            scan_id: scanId,
            pipeline_mode: pipelineMode,
            vulnerability_profile: vulnerabilityProfile,
            phases: [1, 2, 3],
          },
          { signal },
        );

        if (!auditDataTrigger.success)
          throw new Error(
            auditDataTrigger.error || "Vulnerability audit trigger failed",
          );

        const p3Result = await waitForPhase(scanId, 3, signal);
        if (p3Result?.status === "failed") {
          throw new Error("Vulnerability audit background task failed.");
        }

        const { data: fullScan } = await api.get(`/scans/${scanId}`, {
          signal,
        });
        const auditData = {
          data: fullScan?.results?.phase3?.data || [],
          summary: fullScan?.results?.phase3?.summary || {},
          reports: {
            executive_pdf: fullScan?.report_executive_path,
            technical_pdf: fullScan?.report_technical_path,
          },
        };

        const auditHosts = safeArr(auditData.data);
        if (!auditHosts.length) {
          throw new Error(
            "Vulnerability audit completed but returned no hosts.",
          );
        }

        setPhase3Summary(auditData.summary || null);
        setPhase3AuditResults(auditHosts);
        setLocalVulnResults(auditHosts);
        setExpanded(
          new Set(
            auditHosts.filter((h) => h.is_active).map((h) => h.ip_address),
          ),
        );
        timings.vulnScan = ((Date.now() - phase3Start) / 1000).toFixed(1);
        setPipelinePhaseTimings({ ...timings });

        // Pipeline complete — transition to REPORT_READY
        setPipelineState(PIPELINE_STATES.REPORT_READY);
        setSaveStatus("saved");
        setTimeout(() => setSaveStatus(""), 4000);
      } catch (err) {
        if (err.name === "AbortError") {
          setPipelineState(PIPELINE_STATES.CANCELLED);
          setSaveStatus("");
          return;
        }
        const detail =
          err.response?.data?.detail ||
          err.message ||
          "Vulnerability audit failed";
        setPipelineError({ phase: "VULN_SCAN", message: detail });
        setPipelineState(PIPELINE_STATES.ERROR);
        setSaveStatus("error");
        setTimeout(() => setSaveStatus(""), 4000);
      }
    },
    [
      activeDiscoveryHosts,
      intensity,
      scanId,
      pipelineMode,
      phase2Results,
      phase3Results,
      vulnerabilityProfile,
      canExecuteScans,
      setPipelineState,
      setPipelineError,
      setSaveStatus,
      setPhase2Results,
      setPhase2Summary,
      setPhase3Summary,
      setPhase3AuditResults,
      setPipelinePhaseTimings,
      pipelinePhaseTimings,
      abortRef,
    ],
  );

  // Assigned here, below `runFullPipeline`: a dependency of the auto-start
  // effect above, but declared after it, so filling the ref any earlier would
  // read the `const` in its temporal dead zone.
  autoStartRef.current = {
    pipelineState,
    phase3AuditResults,
    auditQueueHosts,
    phase2Results,
    runFullPipeline,
  };

  /* ── Event handlers ─────────────────────────────────────────────────────── */

  const handleRetry = () => {
    pipelineStarted.current = true;
    runFullPipeline(pipelineError?.phase || "PORT_SCAN");
  };

  const handleCancel = async () => {
    // 1. Abort the local frontend request
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }

    // 2. Call the backend to actually stop the worker task
    if (scanId) {
      try {
        await stopScan(scanId);
      } catch (err) {
        console.error("Failed to stop scan in backend:", err);
      }
    }

    // 3. Update local UI state
    setPipelineState(PIPELINE_STATES.CANCELLED);
  };

  const handleRestart = () => {
    setLocalPortHosts([]);
    setLocalVulnResults([]);
    setPhase2Results([]);
    setPhase2Summary(null);
    setPhase3AuditResults([]);
    setPhase3Summary(null);
    setExpanded(new Set());
    setPipelineError(null);
    pipelineStarted.current = true;
    runFullPipeline("PORT_SCAN");
  };

  const proceedToReport = () => {
    // Open the report modal instead of navigating
    setShowReportModal(true);
  };

  /* ── Guard ──────────────────────────────────────────────────────────────── */
  if (!safePhase1Hosts.length) return null;

  /* ── Derived state ──────────────────────────────────────────────────────── */
  const isScanning = [
    PIPELINE_STATES.PORT_SCAN,
    PIPELINE_STATES.VULN_SCAN,
  ].includes(pipelineState);
  const isDone = [
    PIPELINE_STATES.REPORT_READY,
    PIPELINE_STATES.COMPLETE,
  ].includes(pipelineState);
  const isError = pipelineState === PIPELINE_STATES.ERROR;
  const isCancelled = pipelineState === PIPELINE_STATES.CANCELLED;
  const currentStep = localVulnResults.length
    ? 3
    : localPortHosts.length
      ? 2
      : 1;
  const activeMsg = PHASE_MESSAGES[pipelineState];

  // PHASE 4: Reachability Validation
  const isUnreachable =
    phase1Summary &&
    (phase1Summary.status === "unreachable" ||
      (Number(phase1Summary.active_hosts) === 0 &&
        Number(phase1Summary.total_hosts) > 0));

  // Filter display logic for each section
  const displayDiscoveryHosts =
    filter1 === "active" ? activeDiscoveryHosts : safePhase1Hosts;
  const activePortHosts = localPortHosts.filter((h) => h.is_active);
  const displayPortHosts =
    filter2 === "active" ? activePortHosts : localPortHosts;
  const activeVulnHosts = localVulnResults.filter((h) => h.is_active);
  const displayVulnHosts =
    filter3 === "active" ? activeVulnHosts : localVulnResults;

  const failedPhaseLabel =
    pipelineError?.phase === "PORT_SCAN" ? "Port Scan" : "Vulnerability Audit";

  return (
    <AppLayout pageTitle="Vulnerability Audit" saveStatus={saveStatus}>
      <ScanStepper current={currentStep} />

      <CcurePage className="p3-page">
        {/* ── Header ──────────────────────────────────────────────────────── */}
        <CcurePageHeader
          title="Vulnerability Audit"
          subtitle={
            <>
              Full pipeline execution from{" "}
              <code className="p3-code">{target}</code>
            </>
          }
          actions={
            <div className="p3-header__actions">
              {isScanning && (
                <CcureButton variant="danger" onClick={handleCancel}>
                  <Glyph>✕</Glyph> Cancel Scan
                </CcureButton>
              )}
              <CcureButton
                variant="secondary"
                onClick={() => navigate("/scan")}
              >
                <Glyph>←</Glyph> Back
              </CcureButton>
            </div>
          }
        />

        {/* PHASE 4: Unreachable Banner */}
        {isUnreachable && (
          <CcureAlert
            variant="warning"
            title="Host is unavailable/down/unreachable"
          >
            The automated pipeline stopped because Phase 1 (Discovery) found no
            active hosts. Verify the target network and probes before
            re-scanning.
          </CcureAlert>
        )}

        {/* ── Discovery Summary ───────────────────────────────────────────── */}
        <ul className="p3-summary" aria-label="Discovery summary">
          <li className="p3-summary__item">
            <strong>
              {phase1Summary?.total_hosts ?? safePhase1Hosts.length}
            </strong>{" "}
            Total discovered
          </li>
          <li className="p3-summary__item p3-summary__item--active">
            <strong>
              {phase1Summary?.active_hosts ?? activeDiscoveryHosts.length}
            </strong>{" "}
            Active
          </li>
          <li className="p3-summary__item">
            <strong>
              {phase1Summary?.inactive_hosts ??
                safePhase1Hosts.length - activeDiscoveryHosts.length}
            </strong>{" "}
            Inactive
          </li>
          <li className="p3-summary__item">
            <strong>{fmtSec(phase1Summary?.scan_duration)}s</strong> Discovery
            time
          </li>
        </ul>

        {/* ── Error State ─────────────────────────────────────────────────── */}
        {isError && pipelineError && (
          <div className="p3-outcome">
            <CcureAlert
              variant="danger"
              title={`Pipeline failed at ${failedPhaseLabel}`}
            >
              {pipelineError.message}
            </CcureAlert>
            <div className="p3-actions">
              <CcureButton onClick={handleRetry}>
                <CcureIcon name="refresh-cw" /> Retry from {failedPhaseLabel}
              </CcureButton>
              <CcureButton variant="secondary" onClick={handleRestart}>
                <CcureIcon name="rotate-ccw" /> Restart Full Pipeline
              </CcureButton>
            </div>
          </div>
        )}

        {/* ── Cancelled State ─────────────────────────────────────────────── */}
        {isCancelled && (
          <div className="p3-outcome">
            <CcureAlert variant="info" title="Scan Cancelled">
              The pipeline was stopped by user request.
            </CcureAlert>
            <div className="p3-actions">
              <CcureButton onClick={handleRestart}>
                <CcureIcon name="rotate-ccw" /> Restart Pipeline
              </CcureButton>
              <CcureButton
                variant="secondary"
                onClick={() => navigate("/scan")}
              >
                <Glyph>←</Glyph> New Scan
              </CcureButton>
            </div>
          </div>
        )}

        {/* ── Active Phase Progress ───────────────────────────────────────── */}
        {isScanning && activeMsg && (
          <section className="p3-running" role="status">
            <div className="p3-running__head">
              <span className="p3-pulse" aria-hidden="true" />
              <div>
                <h2 className="p3-running__title">{activeMsg.title}</h2>
                <p className="p3-running__desc">{activeMsg.desc}</p>
              </div>
            </div>
            <CcureProgress
              value={null}
              label={activeMsg.title}
              showValue={false}
              className="p3-running__bar"
            />
            <p className="p3-running__meta">
              {pipelineState === PIPELINE_STATES.PORT_SCAN && (
                <>
                  Phase 2 of 3 · Intensity: <strong>{intensity}</strong>
                </>
              )}
              {pipelineState === PIPELINE_STATES.VULN_SCAN && (
                <>
                  Phase 3 of 3 · {localPortHosts.length} host
                  {localPortHosts.length !== 1 ? "s" : ""} queued for audit
                </>
              )}
            </p>
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* SECTION 1: Discovery Results                                      */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        <section className="p3-section">
          <SectionHeading
            number={1}
            title="Discovery Results"
            description="Live hosts detected during Phase 1."
          />

          <FilterGroup
            label="Show discovered hosts"
            value={filter1}
            onChange={setFilter1}
            options={[
              ["active", `Active (${activeDiscoveryHosts.length})`],
              ["all", `All (${safePhase1Hosts.length})`],
            ]}
          />

          <CcureTable
            caption="Discovered hosts"
            density="compact"
            rows={displayDiscoveryHosts}
            rowKey={(host) => host.ip_address}
            columns={[
              {
                key: "ip_address",
                header: "IP Address",
                isRowHeader: true,
                mono: true,
              },
              {
                key: "hostname",
                header: "Hostname",
                cell: (host) => displayHostName(host) || <Muted />,
              },
              {
                key: "mac_address",
                header: "MAC",
                mono: true,
                cell: (host) => host.mac_address || <Muted />,
              },
              {
                key: "vendor",
                header: "Vendor",
                cell: (host) => host.vendor || <Muted />,
              },
              {
                key: "discovery_method",
                header: "Method",
                cell: (host) => host.discovery_method || <Muted />,
              },
              {
                key: "status",
                header: "Status",
                cell: (host) => (
                  <span
                    className={`p3-status ${host.is_active ? "p3-status--up" : "p3-status--down"}`}
                  >
                    <span className="p3-status__dot" aria-hidden="true" />
                    {host.is_active ? "Active" : "Inactive"}
                  </span>
                ),
              },
            ]}
          />
        </section>

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* SECTION 2: Port Scan Results (appears after Phase 2 completes)    */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {localPortHosts.length > 0 && (
          <section className="p3-section">
            <SectionHeading
              number={2}
              title="Port Scan Results"
              description="Open services discovered during Phase 2."
              timing={pipelinePhaseTimings.portScan}
            />

            <ul className="p3-summary" aria-label="Port scan summary">
              <li className="p3-summary__item">
                <strong>
                  {phase2Summary?.total_hosts ?? localPortHosts.length}
                </strong>{" "}
                Hosts scanned
              </li>
              <li className="p3-summary__item p3-summary__item--active">
                <strong>
                  {phase2Summary?.hosts_with_ports ??
                    localPortHosts.filter((h) => h.open_ports?.length).length}
                </strong>{" "}
                Have open ports
              </li>
              <li className="p3-summary__item">
                <strong>{fmtSec(phase2Summary?.scan_duration)}s</strong>{" "}
                Duration
              </li>
            </ul>

            <FilterGroup
              label="Show port-scanned hosts"
              value={filter2}
              onChange={setFilter2}
              options={[
                ["active", `Active (${activePortHosts.length})`],
                ["all", `All (${localPortHosts.length})`],
              ]}
            />

            <CcureTable
              caption="Port scan results"
              density="compact"
              rows={displayPortHosts}
              rowKey={(host) => host.ip_address}
              columns={[
                {
                  key: "ip_address",
                  header: "IP Address",
                  isRowHeader: true,
                  mono: true,
                },
                {
                  key: "hostname",
                  header: "Hostname",
                  cell: (host) => displayHostName(host) || <Muted />,
                },
                {
                  key: "open_ports",
                  header: "Open Ports",
                  cell: (host) =>
                    (host.open_ports || [])
                      .map((p) => `${p.port}/${p.service}`)
                      .join(", ") || <Muted />,
                },
                {
                  key: "os",
                  header: "OS (Guess)",
                  cell: (host) =>
                    host.os_fingerprint_full?.os || host.os_guess || <Muted />,
                },
              ]}
            />
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* SECTION 3: Vulnerability Results (appears after Phase 3)          */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {localVulnResults.length > 0 && (
          <section className="p3-section">
            <SectionHeading
              number={3}
              title="Vulnerability Results"
              description="vulnerability findings below."
              timing={pipelinePhaseTimings.vulnScan}
            />

            <ul className="p3-summary" aria-label="Vulnerability audit summary">
              <li className="p3-summary__item">
                <strong>
                  {phase3Summary?.total_hosts ?? localVulnResults.length}
                </strong>{" "}
                Audited
              </li>
              <li className="p3-summary__item p3-summary__item--danger">
                <strong>{phase3Summary?.critical_hosts ?? 0}</strong> Critical
              </li>
              <li className="p3-summary__item p3-summary__item--warning">
                <strong>{phase3Summary?.high_risk_hosts ?? 0}</strong> High risk
              </li>
              <li className="p3-summary__item">
                <strong>{fmtSec(phase3Summary?.scan_duration)}s</strong>{" "}
                Duration
              </li>
              {phase3Summary?.credentialed_hosts > 0 && (
                <li className="p3-summary__item p3-summary__item--success">
                  <CcureIcon name="lock" />{" "}
                  <strong>{phase3Summary.credentialed_hosts}</strong>{" "}
                  Authenticated
                </li>
              )}
            </ul>

            {/* Authenticated coverage. Which hosts were logged into bounds what
                the package-level findings below can possibly cover, and a host
                that was skipped is unassessed rather than clean. */}
            {phase3Summary?.credentialed_hosts !== undefined && (
              <div className="p3-coverage">
                <p className="p3-coverage__title">
                  <CcureIcon name="lock" /> Authenticated checks
                </p>
                <p className="p3-coverage__text">
                  {phase3Summary.credentialed_hosts} host
                  {phase3Summary.credentialed_hosts === 1
                    ? " was"
                    : "s were"}{" "}
                  logged into and assessed against the installed-package
                  inventory. Listening services on those hosts were correlated
                  with the port scan, so exposed services are distinguished from
                  ones that are running but unreachable.
                </p>
                {phase3Summary.credentialed_skipped?.length > 0 && (
                  <details className="p3-coverage__skipped">
                    <summary className="p3-coverage__summary">
                      {phase3Summary.credentialed_skipped.length} host
                      {phase3Summary.credentialed_skipped.length === 1
                        ? ""
                        : "s"}{" "}
                      not authenticated — findings for these are network-only
                    </summary>
                    <ul className="p3-coverage__list">
                      {phase3Summary.credentialed_skipped.map((s) => (
                        <li key={s.target}>
                          <code className="p3-code">{s.target}</code> —{" "}
                          {s.reason}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            )}

            <FilterGroup
              label="Show audited hosts"
              value={filter3}
              onChange={setFilter3}
              options={[
                ["active", `Active (${activeVulnHosts.length})`],
                ["all", `All (${localVulnResults.length})`],
              ]}
            />

            <CcureTable
              caption="Vulnerability audit results"
              density="compact"
              rows={displayVulnHosts}
              rowKey={(host) => host.ip_address}
              columns={[
                {
                  key: "ip_address",
                  header: "IP Address",
                  isRowHeader: true,
                  cell: (host) => {
                    let hName = host.hostname;
                    if (!hName || hName === "Unknown") {
                      if (host.mdns_name) hName = host.mdns_name;
                      else if (host.netbios_names && host.netbios_names.length)
                        hName = host.netbios_names[0].name;
                    }
                    return (
                      <>
                        <span className="p3-mono">{host.ip_address}</span>
                        {/* Whether this host's findings rest on an
                            authenticated read of the OS or only on what the
                            network exposed. The two are not comparable. */}
                        {host.credentialed && (
                          <CcureBadge
                            variant="success"
                            className="p3-auth"
                            title={
                              host.exposure_summary?.correlated_with_port_scan
                                ? `Authenticated — ${host.exposure_summary.listeners_exposed ?? 0} listening service(s) confirmed reachable, ${host.exposure_summary.listeners_host_only ?? 0} host-only`
                                : "Authenticated audit of the installed package inventory"
                            }
                          >
                            <CcureIcon name="lock" /> AUTH
                          </CcureBadge>
                        )}
                        {hName && hName !== "Unknown" ? (
                          <span className="p3-host-name">{hName}</span>
                        ) : null}
                      </>
                    );
                  },
                },
                {
                  key: "device",
                  header: "Device",
                  cell: (host) => {
                    const devCat =
                      host.snmp_device_type ||
                      host.device_category ||
                      "unknown";
                    const catMeta =
                      DEVICE_CAT_META[devCat] || DEVICE_CAT_META.unknown;
                    // GAP-07: device category badge with icon
                    return devCat !== "unknown" ? (
                      <CcureBadge
                        variant="neutral"
                        title={`Classified via: ${host.device_category_signal || "unknown"}`}
                      >
                        <CcureIcon name={catMeta.icon} /> {catMeta.label}
                      </CcureBadge>
                    ) : (
                      <Muted />
                    );
                  },
                },
                {
                  key: "os",
                  header: "Operating System",
                  cell: (host) =>
                    host.os_fingerprint_full?.os || host.os_guess || <Muted />,
                },
                {
                  key: "cves",
                  header: "CVEs / Active",
                  cell: (host) => {
                    const activeFindings = countActiveFindings(host);
                    return (
                      <>
                        {/* GAP-06: CVE count + active exploit findings badge */}
                        <span
                          className={`p3-count ${(host.cves?.length ?? 0) > 0 ? "p3-tone-warning" : "p3-muted"}`}
                        >
                          {(host.cves || []).length}
                        </span>
                        {activeFindings > 0 && (
                          <CcureBadge
                            variant="danger"
                            className="p3-active"
                            title="Active exploit conditions detected (Heartbleed, EternalBlue, LDAP anon, default creds, etc.)"
                          >
                            <CcureIcon name="zap" />
                            {activeFindings} active
                          </CcureBadge>
                        )}
                      </>
                    );
                  },
                },
                {
                  key: "risk",
                  header: "Risk",
                  cell: (host) => (
                    <CcureSeverityBadge
                      severity={host.host_risk_level || "Info"}
                    />
                  ),
                },
              ]}
            />
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* PIPELINE COMPLETE — View Risk Report CTA                          */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {isDone && localVulnResults.length > 0 && (
          <div className="p3-cta">
            <CcureButton size="lg" onClick={proceedToReport}>
              <CcureIcon name="bar-chart" /> View Risk Report <Glyph>→</Glyph>
            </CcureButton>
          </div>
        )}
      </CcurePage>

      {/* ════════════════════════════════════════════════════════════════════════ */}
      {/* RISK REPORT MODAL                                                       */}
      {/* ════════════════════════════════════════════════════════════════════════ */}
      <RiskReport
        open={showReportModal}
        onClose={() => setShowReportModal(false)}
        scanNo={scanNo}
        target={target}
        hosts={localVulnResults}
        phase1Summary={phase1Summary}
        phase3Summary={phase3Summary}
        pipelinePhaseTimings={pipelinePhaseTimings}
      />
    </AppLayout>
  );
}
