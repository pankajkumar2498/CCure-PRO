/**
 * Reports and exports for one scan.
 *
 * Two capabilities the backend has always had and the UI reached neither of:
 * the CSV and XLSX arms of `/reports/download`, and the whole of
 * `/reports/export` — three formats, four datasets and eleven filters.
 *
 * They are presented together rather than as two screens because they answer
 * the same operator question ("get this scan out of the product"), but the
 * distinction between them is real and is stated:
 *
 * * **Reports** are whole-scan deliverables. No filters, counts are the
 *   scan's own, and the two PDFs are documents a person reads.
 * * **Data export** assembles one dataset and can narrow it. Filters only ever
 *   narrow — a framework the scan's policy excluded cannot be named back in,
 *   because the rest of it was never assessed.
 *
 * Three behaviours worth keeping:
 *
 * * **A combination the API refuses is disabled, not attempted.** `csv` +
 *   everything is refused ("A CSV holds one table"), so the option is
 *   unselectable and says why, rather than letting the operator earn a 400.
 * * **One request at a time, per action.** Both endpoints are rate limited —
 *   20/minute and 10/minute — and a workbook takes seconds to assemble, so an
 *   impatient second click is how an operator spends their own budget and
 *   collects a 429.
 * * **The server names the file.** `Content-Disposition` carries the scan
 *   number; a client-invented name loses the scan an artefact came from.
 */

import { useState } from "react";
import {
  CcureAlert,
  CcureButton,
  CcureSelect,
  useCcureToast,
  CcureCheckbox,
} from "../../../../design-system";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import {
  DOWNLOAD_FORMATS,
  EXPORT_DATASETS,
  EXPORT_FORMATS,
  EXPORT_SCOPES,
  UNSUPPORTED_REASON,
  downloadReport,
  exportScanDataset,
  isUnsupportedCombination,
} from "@audit/api/reports";
import { saveResponseAsFile } from "@audit/utils/download";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const VERDICTS = ["pass", "fail", "not_applicable", "manual_review", "error"];
const STATUSES = ["open", "fixed", "accepted"];

/**
 * Turn an axios failure into something an operator can act on.
 *
 * The backend answers with a uniform envelope — `{success, error_code,
 * message, detail, request_id}` — so its own wording is preferred over
 * anything invented here. Only the cases where the status carries meaning the
 * message does not are special-cased.
 */
function describeFailure(error) {
  const status = error?.response?.status;
  const body = error?.response?.data;
  const fromServer =
    (typeof body === "object" && (body?.message || body?.detail)) || null;

  if (status === 401) {
    return "Your session has expired. Sign in again to download this report.";
  }
  if (status === 403) {
    return fromServer || denyMessage;
  }
  if (status === 404) {
    return fromServer || "That scan no longer exists, or produced no results.";
  }
  if (status === 429) {
    const wait = body?.retry_after_seconds;
    return wait
      ? `Too many report requests. Try again in ${wait} seconds.`
      : fromServer || "Too many report requests. Try again shortly.";
  }
  if (status === 503) {
    // XlsxUnavailable: the deployment is missing openpyxl. Deliberately not
    // degraded into another format -- an export that silently changes shape is
    // worse than one that refuses.
    return fromServer || "Workbook export is unavailable on this deployment.";
  }
  if (status === 400 || status === 422) {
    return fromServer || "That export combination is not supported.";
  }
  return fromServer || "The report could not be generated. Please try again.";
}

/**
 * A blob error body is still a blob. Axios honours `responseType: "blob"` even
 * for a 4xx, so the JSON envelope arrives unreadable unless it is read back.
 */
async function readBlobError(error) {
  const data = error?.response?.data;
  if (data instanceof Blob && data.type?.includes("json")) {
    try {
      const text = await data.text();
      error.response.data = JSON.parse(text);
    } catch {
      // Leave it; describeFailure falls back to the status.
    }
  }
  return error;
}

function CheckboxGroup({ legend, options, selected, onChange, disabled }) {
  return (
    <fieldset className="rx-group" disabled={disabled}>
      <legend className="rx-group__legend">{legend}</legend>
      <div className="rx-group__options">
        {options.map((value) => (
          <CcureCheckbox
            key={value}
            className="rx-check"
            checked={selected.includes(value)}
            onChange={(e) =>
              onChange(
                e.target.checked
                  ? [...selected, value]
                  : selected.filter((v) => v !== value),
              )
            }
          >
            {value.replace(/_/g, " ")}
          </CcureCheckbox>
        ))}
      </div>
    </fieldset>
  );
}

export default function ReportExportPanel({ scanId, scanNo, baselineScanId }) {
  const { user } = useAuth();
  const toast = useCcureToast();
  const canReadReports = can(user, "audit.report.read");

  /** Which download is in flight, or null. */
  const [downloading, setDownloading] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");

  const [fmt, setFmt] = useState("xlsx");
  const [dataset, setDataset] = useState("all");
  const [scope, setScope] = useState("scan");
  const [severity, setSeverity] = useState([]);
  const [verdict, setVerdict] = useState([]);
  const [status, setStatus] = useState([]);
  const [overdueOnly, setOverdueOnly] = useState(false);

  const unsupported = isUnsupportedCombination(fmt, dataset);
  const busy = Boolean(downloading) || exporting;

  const handleDownload = async (format) => {
    if (!canReadReports) {
      toast.danger(denyMessage);
      return;
    }
    // Duplicate-click protection. Not merely cosmetic: this endpoint is
    // 20/minute and regenerates a missing PDF inside the request.
    if (busy) return;

    setDownloading(format.value);
    setError("");
    try {
      const response = await downloadReport(scanId, format.value);
      saveResponseAsFile(
        response,
        `scan_${scanNo ?? scanId}_${format.value.toLowerCase()}.${format.ext}`,
      );
      toast.success(`${format.label} downloaded.`);
    } catch (err) {
      const message = describeFailure(await readBlobError(err));
      setError(message);
      toast.danger(message);
    } finally {
      // Always restored, including on failure — a control left spinning is
      // indistinguishable from a request that never returns.
      setDownloading(null);
    }
  };

  const handleExport = async () => {
    if (!canReadReports) {
      toast.danger(denyMessage);
      return;
    }
    if (busy || unsupported) return;

    setExporting(true);
    setError("");
    try {
      const response = await exportScanDataset(scanId, {
        fmt,
        dataset,
        scope,
        severity,
        verdict,
        status,
        overdueOnly,
        // Phase 2 deferred this for want of a scan picker. The comparison page
        // now has one, so a comparison exported from here is against the same
        // baseline the operator was looking at rather than whichever scan the
        // backend would have defaulted to.
        baseline:
          dataset === "comparison" || dataset === "all"
            ? baselineScanId
            : undefined,
      });
      saveResponseAsFile(
        response,
        `scan_${scanNo ?? scanId}_${dataset}.${fmt}`,
      );
      toast.success("Export downloaded.");
    } catch (err) {
      const message = describeFailure(await readBlobError(err));
      setError(message);
      toast.danger(message);
    } finally {
      setExporting(false);
    }
  };

  if (!canReadReports) {
    return (
      <CcureAlert variant="info" live={false} title="Reports unavailable">
        {denyMessage} Exporting a scan needs the <code>reports:read</code>{" "}
        permission, which is separate from permission to view the scan itself.
      </CcureAlert>
    );
  }

  const datasetHint = EXPORT_DATASETS.find((d) => d.value === dataset)?.hint;
  const scopeHint = EXPORT_SCOPES.find((s) => s.value === scope)?.hint;

  return (
    <div className="rx-root">
      {error ? (
        <CcureAlert variant="danger" title="Export failed">
          {error}
        </CcureAlert>
      ) : null}

      <section className="rx-section">
        <h3 className="rx-section__title">Reports</h3>
        <p className="rx-note">
          The whole scan, unfiltered. Counts are the scan&apos;s own.
        </p>
        <div className="rx-actions">
          {DOWNLOAD_FORMATS.map((format) => (
            <CcureButton
              key={format.value}
              variant="secondary"
              disabled={busy}
              onClick={() => handleDownload(format)}
              title={format.hint}
            >
              {downloading === format.value
                ? `Generating ${format.label}…`
                : format.label}
            </CcureButton>
          ))}
        </div>
      </section>

      <section className="rx-section">
        <h3 className="rx-section__title">Data export</h3>
        <p className="rx-note">
          One dataset, in a form something other than a person can read. Filters
          only ever narrow what the scan already assessed.
        </p>

        <div className="rx-controls">
          <CcureSelect
            label="Format"
            value={fmt}
            onChange={(e) => setFmt(e.target.value)}
            disabled={busy}
            fieldClassName="rx-field"
          >
            {EXPORT_FORMATS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </CcureSelect>

          <CcureSelect
            label="Content"
            value={dataset}
            onChange={(e) => setDataset(e.target.value)}
            disabled={busy}
            fieldClassName="rx-field"
            hint={datasetHint}
          >
            {EXPORT_DATASETS.map((d) => (
              <option
                key={d.value}
                value={d.value}
                // Disabled rather than absent: the operator can see the option
                // exists and read why it is unavailable for this format.
                disabled={isUnsupportedCombination(fmt, d.value)}
              >
                {d.label}
                {isUnsupportedCombination(fmt, d.value) ? " — not for CSV" : ""}
              </option>
            ))}
          </CcureSelect>

          <CcureSelect
            label="Findings from"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            disabled={busy}
            fieldClassName="rx-field"
            hint={scopeHint}
          >
            {EXPORT_SCOPES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </CcureSelect>
        </div>

        {unsupported ? (
          <CcureAlert
            variant="warning"
            live={false}
            title="Not a valid combination"
          >
            {UNSUPPORTED_REASON}
          </CcureAlert>
        ) : null}

        <details className="rx-filters">
          <summary>Filters</summary>
          <CheckboxGroup
            legend="Severity"
            options={SEVERITIES}
            selected={severity}
            onChange={setSeverity}
            disabled={busy}
          />
          <CheckboxGroup
            legend="Compliance verdict"
            options={VERDICTS}
            selected={verdict}
            onChange={setVerdict}
            disabled={busy}
          />
          <CheckboxGroup
            legend="Finding status"
            options={STATUSES}
            selected={status}
            onChange={setStatus}
            disabled={busy}
          />
          <CcureCheckbox
            className="rx-check rx-check--standalone"
            checked={overdueOnly}
            disabled={busy}
            onChange={(e) => setOverdueOnly(e.target.checked)}
          >
            Overdue findings only
          </CcureCheckbox>
        </details>

        <div className="rx-actions">
          <CcureButton
            variant="primary"
            disabled={busy || unsupported}
            onClick={handleExport}
          >
            {exporting ? "Generating export…" : "Export"}
          </CcureButton>
        </div>
      </section>
    </div>
  );
}
