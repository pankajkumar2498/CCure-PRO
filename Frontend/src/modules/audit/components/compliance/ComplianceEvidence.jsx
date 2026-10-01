/**
 * The evidence behind a compliance verdict.
 *
 * `compliance_findings` has always returned an `evidence` block carrying one
 * observation per object the check looked at — what was expected, what was
 * observed, the collector that read it, the raw reading and when — plus the
 * check's own metadata and, for benchmark content, the STIG and CCI
 * identifiers. The workspace rendered none of it: the only appearance of
 * `evidence` anywhere on the page was `JSON.stringify(...)` inside an
 * edit-rule hint.
 *
 * CLAUDE.md, Phase 15: **"on a configuration check the evidence *is* the
 * finding."** A reviewer asked to accept or remediate a FAIL could not see
 * what the scanner actually read.
 *
 * Two states this must keep apart, because the payload does:
 *
 * * **`check_metadata.collection_status`** — whether the reading was
 *   collected at all. `collected` is a reading; anything else means the
 *   verdict rests on something other than a successful read, and it is shown
 *   as its own state rather than left implicit behind the verdict word.
 *
 * * **An observation with no `observed` value.** The engine records the
 *   object it looked at even when nothing came back. Rendering that as an
 *   empty cell would make "the host answered with nothing" look like "nobody
 *   asked".
 */

import { CcureAlert, CcureBadge } from "../../../../design-system";

const STATUS_TONE = {
  collected: "success",
  absent: "warning",
  unsupported: "neutral",
  unavailable: "danger",
};

const when = (iso) => {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
};

const Row = ({ label, children }) =>
  children == null || children === "" ? null : (
    <div className="cwh-ev-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );

/**
 * The benchmark identifiers a reviewer cross-references against the published
 * STIG. They live on the rule's own `check_definition.metadata`, alongside a
 * great deal of OVAL plumbing that is engine input and is deliberately not
 * shown.
 */
function BenchmarkIdentity({ metadata }) {
  if (!metadata) return null;
  const { stig_id, xccdf_rule_id, benchmark, cci } = metadata;
  if (!stig_id && !xccdf_rule_id && !benchmark && !cci?.length) return null;
  return (
    <dl className="cwh-ev-kv">
      <Row label="Benchmark">{benchmark}</Row>
      <Row label="STIG id">{stig_id ? <code>{stig_id}</code> : null}</Row>
      <Row label="XCCDF rule">
        {xccdf_rule_id ? <code>{xccdf_rule_id}</code> : null}
      </Row>
      <Row label="CCI">
        {Array.isArray(cci) && cci.length ? cci.join(", ") : null}
      </Row>
    </dl>
  );
}

export default function ComplianceEvidence({ finding }) {
  const evidence = finding?.evidence || {};
  const meta = evidence.check_metadata || {};
  const observations = Array.isArray(evidence.observations)
    ? evidence.observations
    : [];
  const definitionMeta = finding?.check_definition?.metadata;

  const status = meta.collection_status;

  return (
    <div className="cwh-ev">
      <dl className="cwh-ev-kv">
        <Row label="Check">
          {evidence.check_id ? <code>{evidence.check_id}</code> : null}
        </Row>
        <Row label="Check type">
          {meta.check_type ? <code>{meta.check_type}</code> : null}
        </Row>
        <Row label="Domain">{meta.domain}</Row>
        <Row label="Detection method">
          {evidence.detection_method ? (
            <code>{evidence.detection_method}</code>
          ) : null}
        </Row>
        <Row label="Quality of detection">
          {typeof evidence.qod === "number" ? evidence.qod : null}
        </Row>
        <Row label="Collection status">
          {status ? (
            <CcureBadge variant={STATUS_TONE[status] || "neutral"}>
              {status}
            </CcureBadge>
          ) : null}
        </Row>
        <Row label="Last seen">{when(finding?.last_seen)}</Row>
      </dl>

      <BenchmarkIdentity metadata={definitionMeta} />

      <h4 className="cwh-ev-h">Observations</h4>
      {observations.length === 0 ? (
        <CcureAlert variant="info">
          {/* Not "no problems found". The engine records an observation per
              object it looked at, so none at all means this verdict carries no
              recorded reading. */}
          This finding carries no recorded observation. The verdict was not
          derived from a reading this build stored.
        </CcureAlert>
      ) : (
        <ol className="cwh-ev-obs">
          {observations.map((o, i) => (
            <li
              key={`${o?.collector || "obs"}-${i}`}
              className="cwh-ev-obs__item"
            >
              {o?.description ? (
                <p className="cwh-ev-obs__desc">{o.description}</p>
              ) : null}
              <dl className="cwh-ev-kv">
                <Row label="Expected">{o?.expected}</Row>
                <Row label="Observed">
                  {o?.observed == null || o.observed === "" ? (
                    <em className="cwh-ev-muted">nothing was read</em>
                  ) : (
                    o.observed
                  )}
                </Row>
                <Row label="Collector">
                  {o?.collector ? <code>{o.collector}</code> : null}
                </Row>
                <Row label="Collected at">{when(o?.collected_at)}</Row>
              </dl>
              {o?.raw ? <pre className="cwh-ev-raw">{o.raw}</pre> : null}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
