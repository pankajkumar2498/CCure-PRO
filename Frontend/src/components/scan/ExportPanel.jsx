/**
 * src/components/scan/ExportPanel.jsx
 *
 * Export options for Phase 3 results:
 *   • Download JSON  — client-side Blob download
 *   • Download PDF   — calls GET /scans/{id} and triggers backend PDF if available
 *   • Copy summary   — copies risk summary to clipboard
 */

import { useState } from "react";
import api from "../../api/axiosInstance";

export default function ExportPanel({ results, summary, scanId, target }) {
  const [copied, setCopied] = useState(false);

  /* ── JSON download ── */
  const downloadJSON = () => {
    const payload = {
      scan_id:   scanId,
      target,
      exported_at: new Date().toISOString(),
      summary,
      hosts: results,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `ccure-scan-${scanId || Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ── CSV download ── */
  const downloadCSV = () => {
    const rows = [
      ["IP", "Hostname", "Risk Level", "Risk Score", "Open Ports", "CVE Count", "OS Guess"],
    ];
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
    const csv  = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `ccure-scan-${scanId || Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ── Copy summary ── */
  const copySummary = () => {
    const lines = [
      `Ccure Audit PRO — Scan Report`,
      `Target:     ${target}`,
      `Scan ID:    ${scanId || "N/A"}`,
      `Date:       ${new Date().toLocaleString()}`,
      ``,
      `── Summary ──────────────────────────`,
      `Total hosts audited:  ${summary?.total_hosts ?? "—"}`,
      `Critical risk hosts:  ${summary?.critical_hosts ?? "—"}`,
      `High risk hosts:      ${summary?.high_risk_hosts ?? "—"}`,
      `Scan duration:        ${summary?.scan_duration?.toFixed(1) ?? "—"}s`,
      ``,
      `── Host Risk Overview ────────────────`,
      ...results.filter(h => h.is_active).map(h =>
        `${h.ip_address.padEnd(16)} ${(h.host_risk_level || "Info").padEnd(10)} ${h.host_risk_score ?? 0}/100  CVEs: ${(h.cves || []).length}`
      ),
    ];
    navigator.clipboard.writeText(lines.join("\n")).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    });
  };

  return (
    <div className="export-panel">
      <h4 className="section-title">⬇ Export Results</h4>
      <div className="export-btns">
        <button className="export-btn" onClick={downloadJSON}>
          <span className="export-icon">{ }</span>
          <span className="export-label">JSON</span>
          <span className="export-sub">Full data</span>
        </button>

        <button className="export-btn" onClick={downloadCSV}>
          <span className="export-icon">⊞</span>
          <span className="export-label">CSV</span>
          <span className="export-sub">Spreadsheet</span>
        </button>

        <button className="export-btn" onClick={copySummary}>
          <span className="export-icon">{copied ? "✓" : "⎘"}</span>
          <span className="export-label">{copied ? "Copied!" : "Copy"}</span>
          <span className="export-sub">Summary text</span>
        </button>
      </div>
    </div>
  );
}
