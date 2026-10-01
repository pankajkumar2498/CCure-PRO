/**
 * src/modules/audit/components/scan/ExportPanel.jsx
 * Export options for Phase 1 (discovery) and Phase 3 (vulnerability) results:
 *   • JSON  — client-side Blob download (full scan data)
 *   • CSV   — client-side Blob download (host summary, adapts to data available)
 *   • PDF   — GET /reports/download/{scanId}?fmt=JSON|XML  (backend FileResponse;
 *             JSON is the executive report, XML the technical one — both PDF)
 *   • Copy  — copies plain-text summary to clipboard
 *
 * Automatically detects phase 1 vs phase 3 data based on available fields.
 *
 * Checkpoint 3C batch 15: rendered on CcureCard, CcureButton and CcureAlert.
 * Every builder below — CSV rows, JSON payload, clipboard lines, filenames,
 * the PDF request — is unchanged and pinned byte for byte by
 * __tests__/components/scan/ExportPanel.test.jsx.
 */
import { useState } from "react";
import api from "@shell/api/axiosInstance";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import { CcureAlert, CcureButton, CcureCard } from "../../../../design-system";
import "../../styles/export-panel.css";

export default function ExportPanel({
  results,
  summary,
  scanId,
  scanNo,
  target,
  pipelineMode,
  phase1Hosts = [],
  phase1Summary = null,
  phase2Results = [],
  phase2Summary = null,
}) {
  const { user } = useAuth();
  const canReadReports = can(user, "reports", "read");
  const [copied, setCopied] = useState(false);
  // Which PDF format is being fetched, or null. Both PDF exports are disabled
  // while either is in flight; only the one asked for is marked busy.
  const [pdfLoadingFmt, setPdfLoadingFmt] = useState(null);
  const pdfLoading = pdfLoadingFmt !== null;
  const [pdfError, setPdfError] = useState("");
  const displayNo = scanNo ?? "N/A";
  const fileNo = scanNo ?? Date.now();

  // Detect if this is Phase 1 (discovery), Phase 2 (port scan), or Phase 3 (vulnerability) data
  const isPhase3 = pipelineMode
    ? pipelineMode === "advanced" || pipelineMode === "vulnerability_audit"
    : results.length > 0 &&
      !!results[0].host_risk_level &&
      results[0].host_risk_score !== undefined &&
      results[0].host_risk_score > 0;
  const isPhase2 = pipelineMode
    ? pipelineMode === "asset"
    : results.length > 0 && !isPhase3 && !!results[0].open_ports;
  const isPhase1 = pipelineMode
    ? pipelineMode === "basic"
    : results.length > 0 && !isPhase2 && !isPhase3;
  const isFinalAdvancedExport =
    (pipelineMode === "advanced" || pipelineMode === "vulnerability_audit") &&
    isPhase3 &&
    phase1Hosts.length > 0 &&
    phase2Results.length > 0;

  // Scanner placeholders mean "nothing was found". Exporting them verbatim put
  // the word "Unknown" in spreadsheets as if it were an observed value — and it
  // disagreed with the on-screen table, which already renders these as "—".
  const PLACEHOLDERS = new Set([
    "unknown",
    "n/a",
    "none",
    "not determined",
    "-",
    "--",
  ]);
  const cell = (value) => {
    if (value === null || value === undefined) return "";
    const text = String(value).trim();
    return PLACEHOLDERS.has(text.toLowerCase()) ? "" : text;
  };

  // "22/ssh" alone loses the two things a service scan exists to establish:
  // which transport answered, and what is actually running there. Mirrors the
  // backend host-inventory exporter so both CSVs describe a port the same way.
  const portLabel = (p) => {
    const proto = (p.protocol || "tcp").toLowerCase();
    let label = `${p.port}/${proto}`;
    const service = cell(p.service);
    if (service) label += ` ${service}`;
    const detail = [cell(p.product), cell(p.version)].filter(Boolean).join(" ");
    if (detail) label += ` (${detail})`;
    return label;
  };

  // Resolve descriptive scan type for client-side downloads
  const getDescriptiveScanType = () => {
    if (
      isPhase3 ||
      pipelineMode === "advanced" ||
      pipelineMode === "vulnerability_audit"
    ) {
      return "vulnerability_audit";
    }
    if (isPhase2 || pipelineMode === "asset") {
      return "asset_discovery";
    }
    return "host_discovery";
  };

  // Generate descriptive timestamped filename
  const getExportFilename = (ext) => {
    const scanType = getDescriptiveScanType();
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const dateStr = `${pad(now.getDate())}-${pad(now.getMonth() + 1)}-${now.getFullYear()}`;
    const timeStr = `${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;

    return `${scanType}_scan-${fileNo}_${dateStr}_${timeStr}.${ext}`;
  };

  /* ── JSON ─────────────────────────────────────────────────────────── */
  const downloadJSON = () => {
    if (!canReadReports) {
      setPdfError(denyMessage);
      setTimeout(() => setPdfError(""), 3000);
      return;
    }
    // `results` holds whatever phase this panel is showing. Filing it under
    // phase3 unconditionally meant a Basic Network Scan exported
    // `phase1: {hosts: []}` with its hosts hidden under `phase3` — so anything
    // reading the obvious key for a Phase 1 scan got nothing.
    const phases = {
      phase1: { summary: phase1Summary, hosts: phase1Hosts },
      phase2: { summary: phase2Summary, hosts: phase2Results },
      phase3: { summary: null, hosts: [] },
    };
    const currentKey = isPhase1 ? "phase1" : isPhase2 ? "phase2" : "phase3";
    phases[currentKey] = {
      summary: summary ?? phases[currentKey].summary,
      hosts: results,
    };

    const payload = {
      scan_no: scanNo ?? null,
      target,
      exported_at: new Date().toISOString(),
      pipeline_mode: pipelineMode,
      // Names the phase these results came from, so a consumer never has to
      // guess which key to read.
      result_phase: currentKey,
      summary,
      hosts: results,
      ...phases,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    trigger(blob, getExportFilename("json"));
  };

  /* ── CSV ──────────────────────────────────────────────────────────── */
  const downloadCSV = () => {
    if (!canReadReports) {
      setPdfError(denyMessage);
      setTimeout(() => setPdfError(""), 3000);
      return;
    }
    let rows = [];

    if (isFinalAdvancedExport) {
      rows.push(["Vulnerability Audit Export"]);
      rows.push([`Scan No: ${displayNo}`]);
      rows.push([`Target: ${target || "N/A"}`]);
      rows.push([`Exported: ${new Date().toLocaleString()}`]);
      rows.push([]);

      if (phase1Summary) {
        rows.push(["Phase 1 — Discovery Summary"]);
        rows.push(["Total hosts", phase1Summary.total_hosts ?? ""]);
        rows.push(["Active hosts", phase1Summary.active_hosts ?? ""]);
        rows.push(["Inactive hosts", phase1Summary.inactive_hosts ?? ""]);
        rows.push([
          "Duration (s)",
          phase1Summary.scan_duration?.toFixed(1) ?? "",
        ]);
        rows.push([]);
      }

      if (phase2Summary) {
        rows.push(["Phase 2 — Port Scan Summary"]);
        rows.push(["Hosts scanned", phase2Summary.total_hosts ?? ""]);
        rows.push(["Hosts with ports", phase2Summary.hosts_with_ports ?? ""]);
        rows.push([
          "Duration (s)",
          phase2Summary.scan_duration?.toFixed(1) ?? "",
        ]);
        rows.push([]);
      }

      rows.push(["Phase 3 — Vulnerability Audit Summary"]);
      rows.push(["Hosts audited", summary?.total_hosts ?? ""]);
      rows.push(["Critical hosts", summary?.critical_hosts ?? ""]);
      rows.push(["High risk hosts", summary?.high_risk_hosts ?? ""]);
      rows.push(["Duration (s)", summary?.scan_duration?.toFixed(1) ?? ""]);
      rows.push([]);

      rows.push([
        "IP",
        "Hostname",
        "MAC Address",
        "Vendor",
        "Open Ports",
        "OS",
        "CVE Count",
        "Device Category",
        "Risk Level",
        "Risk Score",
        "Status",
      ]);
      results
        .filter((h) => h.is_active)
        .forEach((h) => {
          rows.push([
            h.ip_address,
            h.hostname || "",
            h.mac_address || "",
            h.vendor || "",
            (h.open_ports || []).map(portLabel).join("; "),
            h.os_guess || "",
            (h.cves || []).length,
            h.device_category || h.snmp_device_type || "",
            h.host_risk_level || "Info",
            h.host_risk_score || 0,
            h.is_active ? "Active" : "Inactive",
          ]);
        });
    } else if (isPhase1) {
      if (pipelineMode === "basic") {
        // Same columns as the non-basic discovery branch. Dropping Device
        // Category here meant the export you got depended on which pipeline
        // ran, for identical underlying data.
        rows = [
          [
            "IP",
            "Hostname",
            "MAC Address",
            "Vendor",
            "Device Category",
            "Discovery Method",
            "Status",
          ],
        ];
        results
          .filter((h) => h.is_active)
          .forEach((h) => {
            rows.push([
              h.ip_address,
              cell(h.hostname),
              cell(h.mac_address),
              cell(h.vendor),
              cell(h.device_category || h.snmp_device_type),
              cell(h.discovery_method || h.scan_method),
              h.is_active ? "Active" : "Inactive",
            ]);
          });
      } else {
        rows = [
          [
            "IP",
            "Hostname",
            "MAC Address",
            "Vendor",
            "Device Category",
            "Status",
          ],
        ];
        results
          .filter((h) => h.is_active)
          .forEach((h) => {
            rows.push([
              h.ip_address,
              cell(h.hostname),
              cell(h.mac_address),
              cell(h.vendor),
              cell(h.device_category || h.snmp_device_type),
              h.is_active ? "Active" : "Inactive",
            ]);
          });
      }
    } else if (isPhase2) {
      rows = [
        [
          "IP",
          "Hostname",
          "MAC Address",
          "Vendor",
          "Device Category",
          "Open Ports",
          "Critical Ports",
          "Status",
        ],
      ];
      results
        .filter((h) => h.is_active)
        .forEach((h) => {
          rows.push([
            h.ip_address,
            h.hostname || "",
            h.mac_address || "",
            h.vendor || "",
            h.device_category || h.snmp_device_type || "",
            (h.open_ports || []).map(portLabel).join("; "),
            (h.open_ports || []).filter((p) => p.risk === "Critical").length,
            h.is_active ? "Active" : "Inactive",
          ]);
        });
    } else {
      rows = [
        [
          "IP",
          "Hostname",
          "MAC Address",
          "Vendor",
          "Open Ports",
          "OS",
          "CVE Count",
          "Device Category",
          "Risk Level",
          "Risk Score",
          "Status",
        ],
      ];
      results
        .filter((h) => h.is_active)
        .forEach((h) => {
          rows.push([
            h.ip_address,
            h.hostname || "",
            h.mac_address || "",
            h.vendor || "",
            (h.open_ports || []).map(portLabel).join("; "),
            h.os_guess || "",
            (h.cves || []).length,
            h.device_category || h.snmp_device_type || "",
            h.host_risk_level || "Info",
            h.host_risk_score || 0,
            h.is_active ? "Active" : "Inactive",
          ]);
        });
    }

    const csv = rows
      .map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    trigger(new Blob([csv], { type: "text/csv" }), getExportFilename("csv"));
  };

  /* ── PDF (backend) ────────────────────────────────────────────────── */
  const downloadPDF = async (fmt = "JSON") => {
    if (!canReadReports) {
      setPdfError(denyMessage);
      setTimeout(() => setPdfError(""), 3000);
      return;
    }
    if (!scanId) {
      setPdfError("No scan ID — complete a scan first.");
      setTimeout(() => setPdfError(""), 3000);
      return;
    }
    setPdfLoadingFmt(fmt);
    setPdfError("");
    try {
      const res = await api.get(`/reports/download/${scanId}`, {
        params: { fmt },
        responseType: "blob",
      });
      const disp = res.headers["content-disposition"] || "";
      const match = disp.match(/filename="?([^";\n]+)"?/i);
      const filename = match ? match[1] : `ccure-report-${fileNo}-${fmt}.pdf`;
      trigger(new Blob([res.data], { type: "application/pdf" }), filename);
    } catch (err) {
      const detail =
        err?.response?.data instanceof Blob
          ? await err.response.data.text().then((t) => {
              try {
                return JSON.parse(t).detail;
              } catch {
                return t;
              }
            })
          : err?.response?.data?.detail || "Failed to download PDF.";
      setPdfError(detail);
      setTimeout(() => setPdfError(""), 4000);
    } finally {
      setPdfLoadingFmt(null);
    }
  };

  /* ── Copy summary ─────────────────────────────────────────────────── */
  const copySummary = () => {
    if (!canReadReports) {
      setPdfError(denyMessage);
      setTimeout(() => setPdfError(""), 3000);
      return;
    }
    // A debug `console.log` of the first host — address, MAC, hostname — used
    // to sit here and ran on every click. Nothing reads the browser console
    // on purpose, which is exactly why scan data must not be written there.
    let lines;
    if (isPhase1) {
      // Phase 1 summary
      lines = [
        "CCure Audit PRO — Network Discovery Report",
        `Target:   ${target}`,
        `Scan No:  ${displayNo}`,
        `Date:     ${new Date().toLocaleString()}`,
        "",
        "── Summary ──────────────────────────",
        `Total hosts:    ${summary?.total_hosts ?? "—"}`,
        `Active hosts:   ${summary?.active_hosts ?? "—"}`,
        `Inactive hosts: ${summary?.inactive_hosts ?? "—"}`,
        `Duration:       ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
        "",
        "── Active Hosts ──────────────────────",
        ...results
          .filter((h) => h.is_active)
          .map((h) => {
            if (pipelineMode === "basic") {
              return `${h.ip_address.padEnd(16)} ${(h.hostname || "—").padEnd(20)} MAC: ${(h.mac_address || "—").padEnd(17)}`;
            }
            return `${h.ip_address.padEnd(16)} ${(h.hostname || "—").padEnd(20)} MAC: ${(h.mac_address || "—").padEnd(17)} Type: ${(h.device_category || h.snmp_device_type || "—").padEnd(10)} Domain: ${h.netbios_workgroup || "—"}`;
          }),
      ];
    } else if (isPhase2) {
      // Calculate risk counts across ports/services for Phase 2 (Asset Discovery)
      let criticalPorts = 0;
      let highPorts = 0;
      let mediumPorts = 0;
      let lowPorts = 0;
      let totalCves = 0;

      results
        .filter((h) => h.is_active)
        .forEach((h) => {
          const ports = h.open_ports || [];
          const udps = h.udp_services || [];
          [...ports, ...udps].forEach((p) => {
            const r = (p.risk || "Info").toLowerCase();
            if (r === "critical") criticalPorts++;
            else if (r === "high") highPorts++;
            else if (r === "medium") mediumPorts++;
            else if (r === "low") lowPorts++;
          });
          totalCves += (h.cves || []).length;
        });

      lines = [
        "CCure Audit PRO — Asset Discovery Report",
        `Target:   ${target}`,
        `Scan No:  ${displayNo}`,
        `Date:     ${new Date().toLocaleString()}`,
        "",
        "── Summary ──────────────────────────",
        `Total hosts:           ${summary?.total_hosts ?? "—"}`,
        `Hosts with open ports: ${summary?.hosts_with_ports ?? "—"}`,
        `Critical risks:        ${criticalPorts}`,
        `High risk:             ${highPorts}`,
        `Medium risk:           ${mediumPorts}`,
        `Low risk:              ${lowPorts}`,
        `Total CVEs:            ${totalCves}`,
        `Duration:              ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
        "",
        "── Host Risk Overview ────────────────",
        ...results
          .filter((h) => h.is_active)
          .map((h) => {
            const ports = h.open_ports || [];
            const udps = h.udp_services || [];
            const hostCrit =
              ports.filter((p) => (p.risk || "").toLowerCase() === "critical")
                .length +
              udps.filter((p) => (p.risk || "").toLowerCase() === "critical")
                .length;
            const hostHigh =
              ports.filter((p) => (p.risk || "").toLowerCase() === "high")
                .length +
              udps.filter((p) => (p.risk || "").toLowerCase() === "high")
                .length;
            const cveCount = (h.cves || []).length;
            const portsStr = ports.map(portLabel).join(", ");

            return `${h.ip_address.padEnd(16)} ${(h.device_category || h.snmp_device_type || "Info").padEnd(10)} CVEs: ${cveCount.toString().padEnd(4)} Critical: ${hostCrit.toString().padEnd(2)} High: ${hostHigh.toString().padEnd(2)} Ports: ${portsStr}`;
          }),
      ];
    } else {
      // Phase 3 summary
      lines = [
        "CCure Audit PRO — Vulnerability Audit Report",
        `Target:   ${target}`,
        `Scan No:  ${displayNo}`,
        `Date:     ${new Date().toLocaleString()}`,
        "",
        "── Summary ──────────────────────────",
        `Total hosts: ${summary?.total_hosts ?? "—"}`,
        `Critical:    ${summary?.critical_hosts ?? "—"}`,
        `High risk:   ${summary?.high_risk_hosts ?? "—"}`,
        `Duration:    ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
        "",
        "── Host Risk Overview ────────────────",
        ...results
          .filter((h) => h.is_active)
          .map(
            (h) =>
              `${h.ip_address.padEnd(16)} ${(h.host_risk_level || "Info").padEnd(10)} ${h.host_risk_score ?? 0}/100  CVEs: ${(h.cves || []).length.toString().padEnd(4)} Active Findings: ${[h.heartbleed_info?.vulnerable ? "Heartbleed" : "", h.smb_ms17010_info?.ms17010_likely ? "MS17-010" : "", h.ldap_info?.anonymous_bind?.allowed ? "LDAP" : "", h.dns_info?.zone_transfer?.vulnerable ? "AXFR" : ""].filter(Boolean).join(",") || "None"}`,
          ),
      ];
    }
    // A refused write (permission, focus) used to be an unhandled rejection,
    // and a missing Clipboard API a TypeError: either way the button did
    // nothing and said nothing.
    const copyFailed = () => {
      setPdfError("Could not copy the summary to the clipboard.");
      setTimeout(() => setPdfError(""), 4000);
    };
    try {
      navigator.clipboard.writeText(lines.join("\n")).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2500);
      }, copyFailed);
    } catch {
      copyFailed();
    }
  };

  const trigger = (blob, filename) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* Named by what each produces. The PDF exports send the historical format
     names the backend still reads — JSON is the executive report, XML the
     technical one — and both have always produced a PDF, so the old
     "PDF/XML · XML report" described a file nobody ever received. */
  const exportActions = [
    { key: "json", label: "JSON", sub: "Full data", action: downloadJSON },
    { key: "csv", label: "CSV", sub: "Spreadsheet", action: downloadCSV },
    {
      key: "pdf-executive",
      label: "Executive PDF",
      sub: "Summary report",
      action: () => downloadPDF("JSON"),
      fmt: "JSON",
    },
    {
      key: "pdf-technical",
      label: "Technical PDF",
      sub: "Detailed report",
      action: () => downloadPDF("XML"),
      fmt: "XML",
    },
    {
      key: "copy",
      label: copied ? "Copied!" : "Copy",
      sub: "Summary",
      action: copySummary,
    },
  ];

  return (
    <CcureCard className="xp" title="Export results" headingLevel={3}>
      <div className="xp__actions">
        {exportActions.map((b) => {
          const isPdf = b.fmt !== undefined;
          return (
            <CcureButton
              key={b.key}
              variant="secondary"
              className="xp__btn"
              onClick={b.action}
              disabled={!canReadReports || (isPdf && pdfLoading)}
              loading={isPdf && pdfLoadingFmt === b.fmt}
            >
              <span className="xp__label">{b.label}</span>{" "}
              <span className="xp__sub">{b.sub}</span>
            </CcureButton>
          );
        })}
      </div>

      {/* A disabled control that does not say why is a dead end — and a
          disabled button cannot take focus, so nothing else will say it. */}
      {!canReadReports && (
        <p className="xp__note">
          Your role does not include permission to export reports.
        </p>
      )}

      {pdfError && (
        <CcureAlert variant="danger" className="xp__alert">
          {pdfError}
        </CcureAlert>
      )}

      {/* Rendered empty from the start: a live region that appears together
          with its message is frequently not announced. */}
      <span className="cc-sr-only" role="status" aria-live="polite">
        {copied ? "Summary copied to the clipboard." : ""}
      </span>
    </CcureCard>
  );
}
