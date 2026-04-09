/**
 * src/components/scan/ExportPanel.jsx
 *
 * Export options for Phase 3 results:
 *   • Download JSON  — client-side Blob download
 *   • Download CSV   — client-side Blob download
 *   • Download PDF   — calls GET /reports/download/{scanId}?fmt=JSON (backend FileResponse)
 *   • Copy summary   — copies risk summary to clipboard
 */

import { useState } from "react";
import api from "../../api/axiosInstance";

export default function ExportPanel({ results, summary, scanId, target }) {
  const [copied,      setCopied]      = useState(false);
  const [pdfLoading,  setPdfLoading]  = useState(false);
  const [pdfError,    setPdfError]    = useState("");

  /* ── JSON download ── */
  const downloadJSON = () => {
    const payload = {
      scan_id:     scanId,
      target,
      exported_at: new Date().toISOString(),
      summary,
      hosts:       results,
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

  /* ── PDF download — authenticated request → backend FileResponse ── */
  const downloadPDF = async (fmt = "JSON") => {
    if (!scanId) {
      setPdfError("No scan ID — complete a scan first.");
      setTimeout(() => setPdfError(""), 3000);
      return;
    }

    setPdfLoading(true);
    setPdfError("");

    try {
      // Use axios so the auth token is included automatically (via axiosInstance interceptor).
      // responseType: "blob" tells axios to keep the binary data intact.
      const response = await api.get(`/reports/download/${scanId}`, {
        params:       { fmt },
        responseType: "blob",
      });

      // Extract filename from Content-Disposition header if present
      const disposition = response.headers["content-disposition"] || "";
      const match        = disposition.match(/filename="?([^";\n]+)"?/i);
      const filename     = match ? match[1] : `ccure-report-${scanId}-${fmt}.pdf`;

      const url = URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
      const a   = document.createElement("a");
      a.href     = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      const detail =
        err?.response?.data instanceof Blob
          ? await err.response.data.text().then(t => {
              try { return JSON.parse(t).detail; } catch { return t; }
            })
          : err?.response?.data?.detail || "Failed to download PDF.";
      setPdfError(detail);
      setTimeout(() => setPdfError(""), 4000);
    } finally {
      setPdfLoading(false);
    }
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

        {/* JSON */}
        <button className="export-btn" onClick={downloadJSON}>
          <span className="export-icon">{"{}"}</span>
          <span className="export-label">JSON</span>
          <span className="export-sub">Full data</span>
        </button>

        {/* CSV */}
        <button className="export-btn" onClick={downloadCSV}>
          <span className="export-icon">⊞</span>
          <span className="export-label">CSV</span>
          <span className="export-sub">Spreadsheet</span>
        </button>

        {/* PDF — tabular (JSON-format PDF) */}
        <button
          className={`export-btn${pdfLoading ? " export-btn--loading" : ""}`}
          onClick={() => downloadPDF("JSON")}
          disabled={pdfLoading}
          title="Download professional PDF report (tabular format)"
        >
          <span className="export-icon">{pdfLoading ? "⏳" : "📄"}</span>
          <span className="export-label">{pdfLoading ? "Generating…" : "PDF"}</span>
          <span className="export-sub">Full report</span>
        </button>

        {/* PDF — XML data report */}
        <button
          className={`export-btn${pdfLoading ? " export-btn--loading" : ""}`}
          onClick={() => downloadPDF("XML")}
          disabled={pdfLoading}
          title="Download raw XML data as PDF"
        >
          <span className="export-icon">{pdfLoading ? "⏳" : "🗂️"}</span>
          <span className="export-label">{pdfLoading ? "Generating…" : "PDF/XML"}</span>
          <span className="export-sub">XML report</span>
        </button>

        {/* Copy */}
        <button className="export-btn" onClick={copySummary}>
          <span className="export-icon">{copied ? "✓" : "⎘"}</span>
          <span className="export-label">{copied ? "Copied!" : "Copy"}</span>
          <span className="export-sub">Summary text</span>
        </button>

      </div>

      {/* Inline error banner */}
      {pdfError && (
        <p className="export-error" role="alert">
          ⚠ {pdfError}
        </p>
      )}
    </div>
  );
}
