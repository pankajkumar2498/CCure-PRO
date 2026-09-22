/**
 * Configuration Audit results for one credentialed host.
 *
 * The backend has produced this since Phase 3 and nothing rendered it. Its
 * failures did reach the operator — they are minted `CCURE-CFG-*` /
 * `CCURE-PRV-*` and appear in the findings list — but the *denominator* did
 * not. On a real Windows 11 host that is 110 failures shown against 254 checks
 * run, with the 106 passes, 32 not-applicables and 6 manual reviews invisible.
 * Failures without coverage are the same defect one layer up from the one this
 * codebase already refuses: an operator could not tell whether 254 checks ran
 * or twelve did.
 *
 * Three rules this component exists to keep:
 *
 * * **ERROR is its own state and is never folded into another.** "The check
 *   could not run" is not a pass, not a failure, and not a thing for a human
 *   to review. Collapsing it is the entire class of bug the engine's
 *   four-state model was built to prevent, and a report that hides it claims
 *   an assessment nobody performed.
 *
 * * **"Not assessed" is not "zero findings".** A host whose audit never ran
 *   renders as such, with the engine's own reason, rather than as a tidy set
 *   of zeroes that reads like a clean machine.
 *
 * * **The counts come from the API, never from the rows.** `counts` and
 *   `score_pct` are authoritative; recomputing them here would produce a
 *   second answer that agrees until the day the page is filtered, truncated,
 *   or the payload gains a state this build does not know about.
 */

import { useMemo, useState } from "react";
import {
  CcureAlert,
  CcureBadge,
  CcureInput,
  CcurePagination,
  CcureTable,
} from "../../design-system";
import usePagedRows from "../../hooks/usePagedRows";

/** The engine's vocabulary, in the order an operator triages. */
const OUTCOMES = [
  { key: "fail", label: "Failed", tone: "danger" },
  { key: "pass", label: "Passed", tone: "success" },
  { key: "manual_review", label: "Manual review", tone: "warning" },
  { key: "not_applicable", label: "Not applicable", tone: "muted" },
  { key: "error", label: "Error", tone: "danger" },
];

const OUTCOME_LABEL = Object.fromEntries(OUTCOMES.map((o) => [o.key, o.label]));

const BADGE_VARIANT = {
  fail: "danger",
  pass: "success",
  manual_review: "warning",
  not_applicable: "neutral",
  error: "danger",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "info"];

function severityRank(value) {
  const i = SEVERITY_ORDER.indexOf(String(value || "").toLowerCase());
  return i === -1 ? SEVERITY_ORDER.length : i;
}

function Metric({ label, value, tone = "", hint = "" }) {
  return (
    <div className={`ca-metric ${tone ? `ca-metric--${tone}` : ""}`.trim()}>
      <dt className="ca-metric__label">{label}</dt>
      <dd className="ca-metric__value">{value}</dd>
      {hint ? <p className="ca-metric__hint">{hint}</p> : null}
    </div>
  );
}

/** One evidence record, as the collector wrote it. */
function Evidence({ item }) {
  return (
    <dl className="ca-evidence">
      {item.description ? (
        <>
          <dt>Description</dt>
          <dd>{item.description}</dd>
        </>
      ) : null}
      {item.expected !== undefined && item.expected !== null ? (
        <>
          <dt>Expected</dt>
          <dd className="ca-mono">{String(item.expected)}</dd>
        </>
      ) : null}
      {item.observed !== undefined && item.observed !== null ? (
        <>
          <dt>Observed</dt>
          <dd className="ca-mono">{String(item.observed)}</dd>
        </>
      ) : null}
      {item.raw ? (
        <>
          <dt>Raw reading</dt>
          <dd>
            <pre className="ca-raw">{item.raw}</pre>
          </dd>
        </>
      ) : null}
      {item.collector ? (
        <>
          <dt>Collector</dt>
          <dd className="ca-mono">{item.collector}</dd>
        </>
      ) : null}
      {item.collected_at ? (
        <>
          <dt>Collected</dt>
          <dd>{item.collected_at}</dd>
        </>
      ) : null}
    </dl>
  );
}

/** The expanded body for one check: everything the API carries about it. */
function CheckDetail({ row }) {
  const meta = row.metadata || {};
  return (
    <div className="ca-detail">
      {row.error ? (
        <CcureAlert
          variant="warning"
          live={false}
          title="Could not be assessed"
        >
          {row.error}
        </CcureAlert>
      ) : null}

      <dl className="ca-detail__grid">
        <div>
          <dt>Check ID</dt>
          <dd className="ca-mono">{row.check_id || "—"}</dd>
        </div>
        <div>
          <dt>Target</dt>
          <dd className="ca-mono">{row.target || "—"}</dd>
        </div>
        <div>
          <dt>Check type</dt>
          <dd className="ca-mono">{meta.check_type || "—"}</dd>
        </div>
        <div>
          <dt>Domain</dt>
          <dd>{meta.domain || "—"}</dd>
        </div>
        <div>
          <dt>Finding type</dt>
          <dd className="ca-mono">{meta.finding_type || "—"}</dd>
        </div>
        <div>
          <dt>Collection status</dt>
          <dd>{meta.collection_status || "—"}</dd>
        </div>
        <div>
          <dt>Detection method</dt>
          <dd>{row.detection_method || "—"}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{row.confidence || "—"}</dd>
        </div>
        <div>
          {/* Quality of Detection: how far the engine trusts this reading. */}
          <dt>QoD</dt>
          <dd>
            {row.qod === undefined || row.qod === null ? "—" : `${row.qod}%`}
          </dd>
        </div>
        {meta.asset_id ? (
          <div>
            <dt>Asset</dt>
            <dd className="ca-mono">{meta.asset_id}</dd>
          </div>
        ) : null}
      </dl>

      {row.remediation ? (
        <section className="ca-detail__block">
          <h4>Remediation</h4>
          <p>{row.remediation}</p>
        </section>
      ) : null}

      {(row.evidence || []).length > 0 ? (
        <section className="ca-detail__block">
          <h4>Evidence</h4>
          {row.evidence.map((item, i) => (
            <Evidence key={i} item={item} />
          ))}
        </section>
      ) : null}

      {(row.cve_ids || []).length > 0 ? (
        <section className="ca-detail__block">
          <h4>Related CVEs</h4>
          <p className="ca-mono">{row.cve_ids.join(", ")}</p>
        </section>
      ) : null}

      {(row.references || []).length > 0 ? (
        <section className="ca-detail__block">
          <h4>References</h4>
          <ul className="ca-refs">
            {row.references.map((ref, i) => (
              <li key={i}>{ref}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

export default function ConfigAuditSection({ configAudit }) {
  const [outcomeFilter, setOutcomeFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState({ key: "severity", direction: "ascending" });
  const [expanded, setExpanded] = useState(() => new Set());

  const audit = configAudit || null;
  const counts = audit?.counts || {};
  const results = useMemo(() => audit?.results || [], [audit]);

  const needle = search.trim().toLowerCase();

  const filter = (row) => {
    if (outcomeFilter !== "all" && row.outcome !== outcomeFilter) return false;
    if (!needle) return true;
    return (
      String(row.title || "")
        .toLowerCase()
        .includes(needle) ||
      String(row.check_id || "")
        .toLowerCase()
        .includes(needle) ||
      String(row.remediation || "")
        .toLowerCase()
        .includes(needle)
    );
  };

  const sorter = (a, b) => {
    // CcureTable's vocabulary is "ascending"/"descending", not asc/desc;
    // matching on the wrong spelling silently sorts one way for ever.
    const dir = sort.direction === "descending" ? -1 : 1;
    if (sort.key === "severity") {
      return (severityRank(a.severity) - severityRank(b.severity)) * dir;
    }
    const av = String(a[sort.key] ?? "").toLowerCase();
    const bv = String(b[sort.key] ?? "").toLowerCase();
    return av.localeCompare(bv) * dir;
  };

  const paged = usePagedRows(results, {
    filter,
    sorter,
    resetKey: `${outcomeFilter}|${needle}|${sort.key}|${sort.direction}`,
  });

  // ── "Not assessed" is a different fact from "assessed and found nothing" ──
  // A host whose configuration audit never ran must not render as a tidy set
  // of zeroes, which reads as a clean machine.
  if (!audit || audit.assessed === false) {
    return (
      <CcureAlert
        variant="info"
        live={false}
        title="Configuration audit — not assessed"
      >
        No configuration checks were run against this host, so there is nothing
        to pass or fail here. This is not a statement that the host is correctly
        configured.
        {audit?.policy_name ? ` Policy: ${audit.policy_name}.` : ""}
      </CcureAlert>
    );
  }

  const toggle = (id) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const score =
    audit.score_pct === null || audit.score_pct === undefined
      ? null
      : Number(audit.score_pct);

  return (
    <div className="ca-root">
      {/* Summary. Every number here is the API's own — see the file header. */}
      <dl className="ca-metrics">
        <Metric
          label="Compliance score"
          value={score === null ? "—" : `${score.toFixed(1)}%`}
          tone={
            score === null
              ? ""
              : score >= 80
                ? "success"
                : score >= 50
                  ? "warning"
                  : "danger"
          }
          hint="Passed ÷ checks that reached a verdict"
        />
        <Metric label="Checks assessed" value={audit.checks_assessed ?? "—"} />
        <Metric label="Checks run" value={audit.checks_run ?? "—"} />
        <Metric
          label="Benchmark checks"
          value={audit.benchmark_checks ?? "—"}
          hint="From loaded benchmark content"
        />
        <Metric label="Passed" value={counts.pass ?? 0} tone="success" />
        <Metric label="Failed" value={counts.fail ?? 0} tone="danger" />
        <Metric
          label="Not applicable"
          value={counts.not_applicable ?? 0}
          hint="Out of scope for this target"
        />
        <Metric
          label="Manual review"
          value={counts.manual_review ?? 0}
          tone="warning"
          hint="The benchmark wants a human"
        />
        <Metric
          label="Errors"
          value={counts.error ?? 0}
          tone={(counts.error ?? 0) > 0 ? "danger" : ""}
          hint="Could not be assessed — not a verdict"
        />
        <Metric label="Platform" value={audit.platform || "—"} />
        <Metric
          label="Policy"
          value={audit.policy_name || "None named"}
          hint={
            audit.policy_fingerprint
              ? `Fingerprint ${String(audit.policy_fingerprint).slice(0, 12)}…`
              : "Built from the scan's own request parameters"
          }
        />
      </dl>

      <div className="ca-toolbar">
        <div className="ca-filters" role="group" aria-label="Filter by outcome">
          <button
            type="button"
            className={`ca-chip ${outcomeFilter === "all" ? "is-active" : ""}`}
            aria-pressed={outcomeFilter === "all"}
            onClick={() => setOutcomeFilter("all")}
          >
            All ({results.length})
          </button>
          {OUTCOMES.map((o) => (
            <button
              key={o.key}
              type="button"
              className={`ca-chip ca-chip--${o.tone} ${outcomeFilter === o.key ? "is-active" : ""}`}
              aria-pressed={outcomeFilter === o.key}
              onClick={() => setOutcomeFilter(o.key)}
            >
              {o.label} ({counts[o.key] ?? 0})
            </button>
          ))}
        </div>
        <CcureInput
          type="search"
          label="Search checks"
          placeholder="Title, check ID or remediation…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          fieldClassName="ca-search"
        />
      </div>

      {paged.total === 0 ? (
        <p className="ca-note">
          {results.length === 0
            ? "This audit recorded no individual check results."
            : "No checks match the current filter."}
        </p>
      ) : (
        <>
          <CcureTable
            caption="Configuration check results"
            density="compact"
            sort={sort}
            onSortChange={setSort}
            rows={paged.rows}
            rowKey={(row, i) => row.check_id || i}
            columns={[
              {
                key: "outcome",
                header: "Verdict",
                sortable: true,
                cell: (row) => (
                  <CcureBadge variant={BADGE_VARIANT[row.outcome] || "neutral"}>
                    {OUTCOME_LABEL[row.outcome] || row.outcome}
                  </CcureBadge>
                ),
              },
              {
                key: "severity",
                header: "Severity",
                sortable: true,
                cell: (row) => (
                  <span
                    className={`ca-sev ca-sev--${String(row.severity || "none").toLowerCase()}`}
                  >
                    {row.severity || "—"}
                  </span>
                ),
              },
              {
                key: "title",
                header: "Check",
                isRowHeader: true,
                sortable: true,
                cell: (row) => (
                  <>
                    <span className="ca-title">
                      {row.title || row.check_id}
                    </span>
                    <span className="ca-checkid">{row.check_id}</span>
                  </>
                ),
              },
              {
                key: "details",
                header: "Details",
                cell: (row) => {
                  const id = row.check_id;
                  const open = expanded.has(id);
                  return (
                    <button
                      type="button"
                      className="ca-expand"
                      aria-expanded={open}
                      onClick={() => toggle(id)}
                    >
                      {open ? "Hide" : "Show"}
                    </button>
                  );
                },
              },
            ]}
          />

          {/* Expanded bodies sit below the table rather than inside it: a
              details row inside <tbody> breaks the column contract for a
              screen reader, which reads it as a malformed data row. */}
          {paged.rows
            .filter((row) => expanded.has(row.check_id))
            .map((row) => (
              <section key={row.check_id} className="ca-detail-card">
                <h3 className="ca-detail-card__title">
                  <CcureBadge variant={BADGE_VARIANT[row.outcome] || "neutral"}>
                    {OUTCOME_LABEL[row.outcome] || row.outcome}
                  </CcureBadge>{" "}
                  {row.title || row.check_id}
                </h3>
                <CheckDetail row={row} />
              </section>
            ))}

          <CcurePagination
            page={paged.page}
            pageSize={paged.pageSize}
            total={paged.total}
            onPageChange={paged.setPage}
            onPageSizeChange={paged.setPageSize}
            itemNoun="checks"
          />
        </>
      )}
    </div>
  );
}
