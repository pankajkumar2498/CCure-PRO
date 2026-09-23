/**
 * One finding's remediation record, and everything a person is permitted to
 * do to it.
 *
 * Shared by the Remediation workspace and the Vulnerability Browser's finding
 * drawer, so the workflow reads the same in both places rather than being
 * implemented twice and drifting.
 *
 * Three things this component is responsible for not overstating:
 *
 * * **`verified_fixed` and `reopened` are not offered.** The backend's human
 *   transition table has no edge into either — only a scan comparison writes
 *   them — so a control for them could do nothing but produce a 400. They are
 *   listed as unavailable with the reason, which is more useful than their
 *   silent absence: "why can I not close this" is the first question an
 *   operator asks.
 *
 * * **An acceptance that has been withdrawn is shown as history.** The API
 *   leaves `reason`, `accepted_by` and `accepted_at` on the finding after a
 *   withdrawal and clears only `expires_at` — so the record is read through
 *   `isRiskAccepted`, which tests the state, and the residue is labelled
 *   "withdrawn" rather than presented as a live exception.
 *
 * * **The event trail is rendered in the order the API returned it.** It is
 *   ordered by `occurred_at` then by id, and the id carries a random tail, so
 *   two events written inside one transaction can appear in an order that is
 *   not the causal one. Re-sorting here would be this UI inventing a sequence;
 *   the timestamps are shown so a reader can see when that has happened.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CcureAlert,
  CcureButton,
  CcureInput,
  CcureSelect,
} from "../../design-system";
import {
  EVENT_LABELS,
  HUMAN_UNREACHABLE_STATES,
  REQUESTABLE_STATES,
  STATE_LABELS,
  acceptFindingRisk,
  addRemediationNote,
  dueDescription,
  getFindingHistory,
  getFindingRemediation,
  hadRiskAccepted,
  isRiskAccepted,
  remediationErrorMessage,
  setRemediationState,
  withdrawFindingAcceptance,
} from "../../api/remediation";
import {
  RemediationStateBadge,
  SeverityBadge,
  SlaStateBadge,
} from "./RemediationBadges";

const when = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
};

const Row = ({ label, children }) => (
  <div className="rm-kv">
    <dt className="rm-kv__key">{label}</dt>
    <dd className="rm-kv__val">
      {children ?? <span className="rm-muted">—</span>}
    </dd>
  </div>
);

/** A value that is genuinely absent reads as absent, never as a zero. */
const Text = ({ value }) =>
  value === null || value === undefined || value === "" ? (
    <span className="rm-muted">—</span>
  ) : (
    <span>{String(value)}</span>
  );

export default function FindingRemediationPanel({
  findingId,
  canUpdate = false,
  canAcceptRisk = false,
  onChanged,
  hostLabel,
}) {
  const [finding, setFinding] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  const [targetState, setTargetState] = useState("");
  const [stateNote, setStateNote] = useState("");
  const [note, setNote] = useState("");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");

  const load = useCallback(async () => {
    if (!findingId) return;
    setLoading(true);
    setError("");
    try {
      const [detail, trail] = await Promise.all([
        getFindingRemediation(findingId),
        getFindingHistory(findingId),
      ]);
      setFinding(detail.data);
      setHistory(trail.data?.events || []);
    } catch (err) {
      setError(
        remediationErrorMessage(err, "Could not read this finding's record."),
      );
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    load();
  }, [load]);

  const accepted = isRiskAccepted(finding);
  const wasAccepted = hadRiskAccepted(finding);

  /* The state the finding is already in is not offered: the backend admits a
     self-transition on some states and refuses it on others, and a control
     that sometimes works is worse than one that is not there. */
  const available = useMemo(
    () =>
      REQUESTABLE_STATES.filter(
        (s) => s !== (finding?.remediation?.state || "open"),
      ),
    [finding],
  );

  const run = async (fn, okMessage) => {
    setBusy(true);
    setNotice(null);
    try {
      const res = await fn();
      if (res?.data?.finding_id) setFinding(res.data);
      const trail = await getFindingHistory(findingId);
      setHistory(trail.data?.events || []);
      setNotice({ variant: "success", text: okMessage });
      onChanged && onChanged();
      return true;
    } catch (err) {
      setNotice({
        variant: "danger",
        // The backend's own wording, which explains *why* rather than
        // reporting that something failed.
        text: remediationErrorMessage(err, "The API refused this change."),
      });
      return false;
    } finally {
      setBusy(false);
    }
  };

  if (loading)
    return <p className="rm-muted">Reading the remediation record…</p>;
  if (error) return <CcureAlert variant="danger">{error}</CcureAlert>;
  if (!finding) return null;

  const rem = finding.remediation || {};
  const sla = finding.sla || {};
  const ver = finding.verification || {};
  const exc = finding.exception || {};

  return (
    <div className="rm-panel">
      <div className="rm-panel__head">
        <div>
          <div className="rm-panel__id">{finding.vuln_id}</div>
          <div className="rm-panel__sub">{hostLabel || finding.asset_id}</div>
        </div>
        <div className="rm-panel__badges">
          <SeverityBadge severity={finding.severity} />
          <RemediationStateBadge state={rem.state} />
          <SlaStateBadge state={sla.state} />
        </div>
      </div>

      {notice ? (
        <CcureAlert variant={notice.variant} onClose={() => setNotice(null)}>
          {notice.text}
        </CcureAlert>
      ) : null}

      <div className="rm-sections">
        <section className="rm-section">
          <h4 className="rm-section__h">Detection</h4>
          <dl className="rm-kvs">
            {/* Kept beside the workflow state and never merged with it:
                "absent from the last scan" and "somebody confirmed a fix" are
                different claims. */}
            <Row label="Status">
              <Text value={finding.status} />
            </Row>
            <Row label="First found">{when(ver.first_found_at)}</Row>
            <Row label="Last found">{when(ver.last_found_at)}</Row>
            <Row label="Asset">
              <Text value={finding.asset_id} />
            </Row>
          </dl>
        </section>

        <section className="rm-section">
          <h4 className="rm-section__h">Ownership</h4>
          <dl className="rm-kvs">
            <Row label="Owner">
              <Text value={rem.owner} />
            </Row>
            <Row label="Assigned at">{when(rem.assigned_at)}</Row>
            <Row label="Assigned by">
              <Text value={rem.assigned_by} />
            </Row>
            <Row label="Latest note">
              <Text value={rem.notes} />
            </Row>
            <Row label="Times reopened">{rem.reopened_count ?? 0}</Row>
            <Row label="Reopened at">{when(rem.reopened_at)}</Row>
          </dl>
        </section>

        <section className="rm-section">
          <h4 className="rm-section__h">Deadline</h4>
          <dl className="rm-kvs">
            <Row label="Due">{when(sla.due_at)}</Row>
            <Row label="Position">{dueDescription(sla)}</Row>
            <Row label="Basis">
              {/* The severity the deadline was derived from, which can differ
                  from the finding's current severity if it was rescored. */}
              <Text value={sla.basis} />
            </Row>
            <Row label="Unit">
              <Text value={sla.unit} />
            </Row>
          </dl>
        </section>

        <section className="rm-section">
          <h4 className="rm-section__h">Verification</h4>
          <dl className="rm-kvs">
            <Row label="Verified at">{when(ver.verified_at)}</Row>
            <Row label="Verified by scan">
              <Text value={ver.verified_scan_id} />
            </Row>
          </dl>
          {!ver.verified_at ? (
            <p className="rm-note">
              A finding becomes verified fixed when a later scan stops detecting
              it. No action on this screen can set that.
            </p>
          ) : null}
        </section>

        {accepted || wasAccepted ? (
          <section className="rm-section rm-section--wide">
            <h4 className="rm-section__h">
              {accepted ? "Accepted risk" : "Accepted risk (withdrawn)"}
            </h4>
            {wasAccepted ? (
              <p className="rm-note">
                This acceptance is no longer in force. The reason and approver
                are kept as the record of a decision that was taken.
              </p>
            ) : null}
            <dl className="rm-kvs">
              <Row label="Reason">
                <Text value={exc.reason} />
              </Row>
              <Row label="Accepted by">
                <Text value={exc.accepted_by} />
              </Row>
              <Row label="Accepted at">{when(exc.accepted_at)}</Row>
              <Row label="Expires">
                {exc.expires_at ? (
                  when(exc.expires_at)
                ) : accepted ? (
                  "Does not expire"
                ) : (
                  <span className="rm-muted">—</span>
                )}
              </Row>
              <Row label="Indefinite">{exc.indefinite ? "Yes" : "No"}</Row>
            </dl>
          </section>
        ) : null}
      </div>

      {canUpdate || canAcceptRisk ? (
        <div className="rm-actions">
          <h4 className="rm-section__h">Remediation actions</h4>

          {canUpdate ? (
            <>
              <div className="rm-actionrow">
                <CcureSelect
                  label="Move to"
                  value={targetState}
                  onChange={(e) => setTargetState(e.target.value)}
                  disabled={busy}
                >
                  <option value="">Choose a state…</option>
                  {available.map((s) => (
                    <option key={s} value={s}>
                      {STATE_LABELS[s]}
                    </option>
                  ))}
                </CcureSelect>
                <CcureInput
                  label="Note (optional)"
                  value={stateNote}
                  onChange={(e) => setStateNote(e.target.value)}
                  maxLength={2000}
                  disabled={busy}
                />
                <CcureButton
                  variant="primary"
                  disabled={busy || !targetState}
                  onClick={async () => {
                    const ok = await run(
                      () =>
                        setRemediationState(findingId, {
                          state: targetState,
                          note: stateNote || null,
                        }),
                      `Moved to ${STATE_LABELS[targetState] || targetState}.`,
                    );
                    if (ok) {
                      setTargetState("");
                      setStateNote("");
                    }
                  }}
                >
                  Change state
                </CcureButton>
              </div>

              <ul className="rm-unavailable">
                {Object.entries(HUMAN_UNREACHABLE_STATES).map(([s, why]) => (
                  <li key={s}>
                    <strong>{STATE_LABELS[s]}</strong> — {why}
                  </li>
                ))}
              </ul>

              <div className="rm-actionrow">
                <CcureInput
                  label="Add a note"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  maxLength={4000}
                  disabled={busy}
                  hint="The finding keeps the most recent note; the trail below keeps every one."
                />
                <CcureButton
                  disabled={busy || !note.trim()}
                  onClick={async () => {
                    const ok = await run(
                      () => addRemediationNote(findingId, { note }),
                      "Note added.",
                    );
                    if (ok) setNote("");
                  }}
                >
                  Add note
                </CcureButton>
              </div>
            </>
          ) : null}

          {canAcceptRisk ? (
            accepted ? (
              <div className="rm-actionrow">
                <CcureButton
                  variant="secondary"
                  disabled={busy}
                  onClick={() =>
                    run(
                      () => withdrawFindingAcceptance(findingId, {}),
                      "Acceptance withdrawn; the finding is back in the queue.",
                    )
                  }
                >
                  Withdraw acceptance
                </CcureButton>
              </div>
            ) : (
              <div className="rm-actionrow">
                <CcureInput
                  label="Accept the risk — reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  maxLength={4000}
                  disabled={busy}
                  hint="Required. Recorded against your account and kept in the trail."
                />
                <CcureInput
                  label="Expires (optional)"
                  type="date"
                  value={expires}
                  onChange={(e) => setExpires(e.target.value)}
                  disabled={busy}
                  hint="Leave empty for an acceptance that does not expire."
                />
                <CcureButton
                  variant="secondary"
                  disabled={busy || !reason.trim()}
                  onClick={async () => {
                    const ok = await run(
                      () =>
                        acceptFindingRisk(findingId, {
                          reason,
                          expires_at: expires
                            ? new Date(`${expires}T00:00:00Z`).toISOString()
                            : null,
                        }),
                      "Risk accepted.",
                    );
                    if (ok) {
                      setReason("");
                      setExpires("");
                    }
                  }}
                >
                  Accept risk
                </CcureButton>
              </div>
            )
          ) : null}
        </div>
      ) : null}

      <section className="rm-section rm-section--wide">
        <h4 className="rm-section__h">History</h4>
        {history.length === 0 ? (
          <p className="rm-muted">
            No remediation events recorded for this finding.
          </p>
        ) : (
          <ol className="rm-timeline">
            {history.map((e) => (
              <li key={e.id} className="rm-timeline__item">
                <div className="rm-timeline__head">
                  <strong>{EVENT_LABELS[e.event_type] || e.event_type}</strong>
                  {e.from_state || e.to_state ? (
                    <span className="rm-timeline__move">
                      {STATE_LABELS[e.from_state] || e.from_state || "—"} →{" "}
                      {STATE_LABELS[e.to_state] || e.to_state || "—"}
                    </span>
                  ) : null}
                  <span className="rm-muted">{when(e.occurred_at)}</span>
                </div>
                <div className="rm-timeline__by">
                  {/* One of these is set and the other is not: a system event
                      carries a label rather than an identity, so a scan's
                      verdict is never presented as a person's decision. */}
                  {e.actor_label ? (
                    <em>{e.actor_label}</em>
                  ) : (
                    <Text value={e.actor_id} />
                  )}
                  {e.scan_id ? <span> · scan {e.scan_id}</span> : null}
                </div>
                {e.note ? (
                  <div className="rm-timeline__note">{e.note}</div>
                ) : null}
                {e.details && Object.keys(e.details).length ? (
                  <dl className="rm-timeline__details">
                    {Object.entries(e.details).map(([k, v]) => (
                      <div key={k}>
                        <dt>{k.replace(/_/g, " ")}</dt>
                        <dd>{v === null ? "—" : String(v)}</dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}
