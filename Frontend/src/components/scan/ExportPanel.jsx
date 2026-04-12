/**
 * src/components/scan/ExportPanel.jsx
 * Export options for Phase 1 (discovery) and Phase 3 (vulnerability) results:
 *   • JSON  — client-side Blob download (full scan data)
 *   • CSV   — client-side Blob download (host summary, adapts to data available)
 *   • PDF   — GET /reports/download/{scanId}?fmt=JSON  (backend FileResponse)
 *   • Copy  — copies plain-text summary to clipboard
 *
 * Automatically detects phase 1 vs phase 3 data based on available fields.
 */
import { useState } from "react";
import api from "../../api/axiosInstance";

export default function ExportPanel({
  results,
  summary,
  scanId,
  target,
  pipelineMode,
  phase1Hosts = [],
  phase1Summary = null,
  phase2Results = [],
  phase2Summary = null,
}) {
  const [copied,     setCopied]     = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError,   setPdfError]   = useState("");

  // Detect if this is Phase 1 (discovery), Phase 2 (port scan), or Phase 3 (vulnerability) data
  const isPhase3 = results.length > 0 && !!results[0].host_risk_level;
  const isPhase2 = results.length > 0 && !results[0].host_risk_level && !!results[0].open_ports;
  const isPhase1 = results.length > 0 && !isPhase2 && !isPhase3;
  const isFinalAdvancedExport = pipelineMode === "advanced" && isPhase3 && phase1Hosts.length > 0 && phase2Results.length > 0;

  /* ── JSON ─────────────────────────────────────────────────────────── */
  const downloadJSON = () => {
    const payload = {
      scan_id: scanId,
      target,
      exported_at: new Date().toISOString(),
      pipeline_mode: pipelineMode,
      summary,
      phase1: {
        summary: phase1Summary,
        hosts: phase1Hosts,
      },
      phase2: {
        summary: phase2Summary,
        hosts: phase2Results,
      },
      phase3: {
        summary,
        hosts: results,
      },
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    trigger(blob, `ccure-scan-${scanId || Date.now()}.json`);
  };

  /* ── CSV ──────────────────────────────────────────────────────────── */
  const downloadCSV = () => {
    let rows = [];

    if (isFinalAdvancedExport) {
      rows.push(["Advanced Scan Export"]);
      rows.push([`Scan ID: ${scanId || "N/A"}`]);
      rows.push([`Target: ${target || "N/A"}`]);
      rows.push([`Exported: ${new Date().toLocaleString()}`]);
      rows.push([]);

      if (phase1Summary) {
        rows.push(["Phase 1 — Discovery Summary"]);
        rows.push(["Total hosts", phase1Summary.total_hosts ?? ""]);
        rows.push(["Active hosts", phase1Summary.active_hosts ?? ""]);
        rows.push(["Inactive hosts", phase1Summary.inactive_hosts ?? ""]);
        rows.push(["Duration (s)", phase1Summary.scan_duration?.toFixed(1) ?? ""]);
        rows.push([]);
      }

      if (phase2Summary) {
        rows.push(["Phase 2 — Port Scan Summary"]);
        rows.push(["Hosts scanned", phase2Summary.total_hosts ?? ""]);
        rows.push(["Hosts with ports", phase2Summary.hosts_with_ports ?? ""]);
        rows.push(["Duration (s)", phase2Summary.scan_duration?.toFixed(1) ?? ""]);
        rows.push([]);
      }

      rows.push(["Phase 3 — Vulnerability Audit Summary"]);
      rows.push(["Hosts audited", summary?.total_hosts ?? ""]);
      rows.push(["Critical hosts", summary?.critical_hosts ?? ""]);
      rows.push(["High risk hosts", summary?.high_risk_hosts ?? ""]);
      rows.push(["Duration (s)", summary?.scan_duration?.toFixed(1) ?? ""]);
      rows.push([]);

      rows.push(["IP", "Hostname", "Risk Level", "Risk Score", "Open Ports", "CVE Count", "OS Guess"]);
      results.filter(h => h.is_active).forEach(h => {
        rows.push([
          h.ip_address,
          h.hostname || "",
          h.host_risk_level || "Info",
          h.host_risk_score || 0,
          (h.open_ports || []).map(p => `${p.port}/${p.service}`).join("; "),
          (h.cves || []).length,
          h.os_guess || "",
        ]);
      });
    } else if (isPhase1) {
      rows = [["IP", "Hostname", "Status", "MAC Address", "Vendor"]];
      results.filter(h => h.is_active).forEach(h => {
        rows.push([
          h.ip_address,
          h.hostname || "",
          h.is_active ? "Active" : "Inactive",
          h.mac_address || "",
          h.vendor || "",
        ]);
      });
    } else if (isPhase2) {
      rows = [["IP", "Hostname", "Open Ports", "Critical Ports", "Vendor"]];
      results.filter(h => h.is_active).forEach(h => {
        rows.push([
          h.ip_address,
          h.hostname || "",
          (h.open_ports || []).map(p => `${p.port}/${p.service}`).join("; "),
          (h.open_ports || []).filter(p => p.risk === "Critical").length,
          h.vendor || "",
        ]);
      });
    } else {
      rows = [["IP", "Hostname", "Risk Level", "Risk Score", "Open Ports", "CVE Count", "OS Guess"]];
      results.filter(h => h.is_active).forEach(h => {
        rows.push([
          h.ip_address,
          h.hostname || "",
          h.host_risk_level || "Info",
          h.host_risk_score || 0,
          (h.open_ports || []).map(p => `${p.port}/${p.service}`).join("; "),
          (h.cves || []).length,
          h.os_guess || "",
        ]);
      });
    }

    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    trigger(new Blob([csv], { type: "text/csv" }), `ccure-scan-${scanId || Date.now()}.csv`);
  };

  /* ── PDF (backend) ────────────────────────────────────────────────── */
  const downloadPDF = async (fmt = "JSON") => {
    if (!scanId) {
      setPdfError("No scan ID — complete a scan first.");
      setTimeout(() => setPdfError(""), 3000);
      return;
    }
    setPdfLoading(true);
    setPdfError("");
    try {
      const res      = await api.get(`/reports/download/${scanId}`, { params: { fmt }, responseType: "blob" });
      const disp     = res.headers["content-disposition"] || "";
      const match    = disp.match(/filename="?([^";\n]+)"?/i);
      const filename = match ? match[1] : `ccure-report-${scanId}-${fmt}.pdf`;
      trigger(new Blob([res.data], { type: "application/pdf" }), filename);
    } catch (err) {
      const detail = err?.response?.data instanceof Blob
        ? await err.response.data.text().then(t => { try { return JSON.parse(t).detail; } catch { return t; } })
        : err?.response?.data?.detail || "Failed to download PDF.";
      setPdfError(detail);
      setTimeout(() => setPdfError(""), 4000);
    } finally {
      setPdfLoading(false);
    }
  };

  /* ── Copy summary ─────────────────────────────────────────────────── */
  const copySummary = () => {
    let lines;
    if (isPhase1) {
      // Phase 1 summary
      lines = [
        "CCure Audit PRO — Network Discovery Report",
        `Target:   ${target}`,
        `Scan ID:  ${scanId || "N/A"}`,
        `Date:     ${new Date().toLocaleString()}`,
        "",
        "── Summary ──────────────────────────",
        `Total hosts:    ${summary?.total_hosts ?? "—"}`,
        `Active hosts:   ${summary?.active_hosts ?? "—"}`,
        `Inactive hosts: ${summary?.inactive_hosts ?? "—"}`,
        `Duration:       ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
        "",
        "── Active Hosts ──────────────────────",
        ...results.filter(h => h.is_active).map(h =>
          `${h.ip_address.padEnd(16)} ${(h.hostname || "—").padEnd(20)} MAC: ${(h.mac_address || "—").padEnd(17)} Vendor: ${h.vendor || "—"}`
        ),
      ];
    } else if (isPhase2) {
      lines = [
        "CCure Audit PRO — Port Scan Results",
        `Target:   ${target}`,
        `Scan ID:  ${scanId || "N/A"}`,
        `Date:     ${new Date().toLocaleString()}`,
        "",
        "── Summary ──────────────────────────",
        `Hosts scanned: ${summary?.total_hosts ?? "—"}`,
        `Hosts with open ports: ${summary?.hosts_with_ports ?? "—"}`,
        `Duration: ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
        "",
        "── Open Hosts ───────────────────────",
        ...results.filter(h => h.is_active).map(h =>
          `${h.ip_address.padEnd(16)} ${(h.hostname || "—").padEnd(20)} Open ports: ${(h.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ")}`
        ),
      ];
    } else {
      // Phase 3 summary
      lines = [
        "CCure Audit PRO — Vulnerability Audit Report",
        `Target:   ${target}`,
        `Scan ID:  ${scanId || "N/A"}`,
        `Date:     ${new Date().toLocaleString()}`,
        "",
        "── Summary ──────────────────────────",
        `Total hosts: ${summary?.total_hosts ?? "—"}`,
        `Critical:    ${summary?.critical_hosts ?? "—"}`,
        `High risk:   ${summary?.high_risk_hosts ?? "—"}`,
        `Duration:    ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
        "",
        "── Host Risk Overview ────────────────",
        ...results.filter(h => h.is_active).map(h =>
          `${h.ip_address.padEnd(16)} ${(h.host_risk_level || "Info").padEnd(10)} ${h.host_risk_score ?? 0}/100  CVEs: ${(h.cves || []).length}`
        ),
      ];
    }
    navigator.clipboard.writeText(lines.join("\n")).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    });
  };

  const trigger = (blob, filename) => {
    const url = URL.createObjectURL(blob);
    const a   = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };

  const btnStyle = {
    display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
    padding: "10px 16px", borderRadius: 8,
    border: "1px solid var(--border)", background: "var(--bg-white)",
    cursor: "pointer", fontFamily: "var(--font)", transition: "all 0.15s",
    minWidth: 80,
  };

  return (
    <div className="export-panel">
      <p className="section-title" style={{ marginBottom: 12 }}>⬇ Export Results</p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {[
          { label: "JSON",     icon: "{ }",   sub: "Full data",    action: downloadJSON },
          { label: "CSV",      icon: "⊞",     sub: "Spreadsheet",  action: downloadCSV },
          { label: "PDF",      icon: pdfLoading ? "⏳" : "📄", sub: "Report",  action: () => downloadPDF("JSON"), disabled: pdfLoading },
          { label: "PDF/XML",  icon: pdfLoading ? "⏳" : "🗂", sub: "XML report", action: () => downloadPDF("XML"),  disabled: pdfLoading },
          { label: copied ? "Copied!" : "Copy", icon: copied ? "✓" : "⎘", sub: "Summary", action: copySummary },
        ].map((b) => (
          <button
            key={b.label}
            style={{ ...btnStyle, opacity: b.disabled ? 0.6 : 1, cursor: b.disabled ? "not-allowed" : "pointer" }}
            onClick={b.action}
            disabled={b.disabled}
            onMouseEnter={e => { if (!b.disabled) e.currentTarget.style.background = "var(--bg-app)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-white)"; }}
          >
            <span style={{ fontSize: "1.1rem" }}>{b.icon}</span>
            <span style={{ fontSize: "0.8rem", fontWeight: 700, color: "var(--text-mid)" }}>{b.label}</span>
            <span style={{ fontSize: "0.7rem", color: "var(--text-faint)" }}>{b.sub}</span>
          </button>
        ))}
      </div>
      {pdfError && (
        <div className="alert alert--error" style={{ marginTop: 10 }}>⚠ {pdfError}</div>
      )}
    </div>
  );
}
