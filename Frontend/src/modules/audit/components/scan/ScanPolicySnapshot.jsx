/**
 * The configuration a completed scan actually ran under.
 *
 * This renders `GET /scans/{id}/policy`, which serves the scan's **own
 * immutable snapshot** rather than the policy row it names. That distinction
 * is the whole reason the endpoint exists: the policy may have been edited,
 * versioned, archived or deleted since, and none of that changes what the scan
 * assessed. A question an auditor asks about a scan has to be answerable from
 * the scan.
 *
 * So the layout is deliberate about which of the two is authoritative. The
 * snapshot is the body of the panel; the policy's *current* state is a note
 * underneath it, and is never allowed to overwrite a value above. Getting that
 * the wrong way round would show an auditor a configuration the scan never
 * used, which looks identical to a correct one.
 *
 * `recorded: false` is a real answer for a scan predating GAP-12, and is
 * rendered as such. Substituting a default policy would put a claim in front
 * of a reader that nothing supports.
 *
 * Note the two things that can diverge independently, both seen on real data:
 * a policy may be **archived and disabled** while its configuration is
 * unchanged (`matches_snapshot: true`), which is a lifecycle change and not a
 * configuration one. Saying "the policy has changed" there would be wrong.
 */

import { useEffect, useState } from "react";
import { CcureLoader, CcureAlert, CcureBadge } from "../../../../design-system";
import { getScanPolicySnapshot } from "@audit/api/scanPolicies";

/** Config fields that are lists; shown as counts with the values beneath. */
const LIST_FIELDS = new Set([
  "check_families",
  "framework_ids",
  "platforms",
  "sections",
  "custom_ports",
  "exclude_ports",
  "excluded_check_ids",
  "excluded_tags",
  "excluded_targets",
]);

/** Identity fields, shown in the header rather than the configuration grid. */
const IDENTITY_FIELDS = new Set([
  "policy_id",
  "policy_name",
  "policy_family_code",
  "version_number",
  "fingerprint",
  "source",
  "scan_kind",
]);

function renderValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) {
    return value.length === 0 ? "none" : value.join(", ");
  }
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

export default function ScanPolicySnapshot({ scanId }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return undefined;
    let cancelled = false;
    setLoading(true);
    getScanPolicySnapshot(scanId)
      .then(({ data: payload }) => {
        if (!cancelled) setData(payload);
      })
      .catch((err) => {
        if (cancelled) return;
        const body = err?.response?.data;
        setError(
          body?.message ||
            body?.detail ||
            "The policy record could not be read.",
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (loading) {
    return <CcureLoader label="Reading this scan’s policy record…" />;
  }

  if (error) {
    return (
      <CcureAlert variant="danger" title="Policy record unavailable">
        {error}
      </CcureAlert>
    );
  }

  const policy = data?.policy || {};

  // Not recorded is an answer, not a gap to fill with a default.
  if (!policy.recorded) {
    return (
      <CcureAlert variant="info" live={false} title="No policy record">
        This scan ran before assessment configuration was recorded, so what it
        assessed cannot be established from a policy. It is not a statement that
        no policy applied.
      </CcureAlert>
    );
  }

  const effective = data?.effective || {};
  const current = data?.policy_current_state;
  const configEntries = Object.entries(effective)
    .filter(([key]) => !IDENTITY_FIELDS.has(key))
    .sort(([a], [b]) => a.localeCompare(b));

  return (
    <div className="ps-root">
      <CcureAlert
        variant="success"
        live={false}
        title="This is the configuration this scan used"
      >
        Read from the scan&apos;s own record, not from the policy as it stands
        now. Editing, versioning, archiving or deleting the policy since does
        not change what this scan assessed.
      </CcureAlert>

      <dl className="ps-identity">
        <div>
          <dt>Policy</dt>
          <dd>{policy.policy_name || "—"}</dd>
        </div>
        <div>
          <dt>Family / version</dt>
          <dd>
            {policy.policy_family_code || "—"}
            {policy.version_number ? ` v${policy.version_number}` : ""}
          </dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>
            {/* "policy" means a named policy was chosen; "request" means the
                snapshot was built from the scan's own request parameters,
                which is a real configuration record and not an absence. */}
            {policy.source === "request"
              ? "the scan's own request parameters"
              : policy.source || "—"}
          </dd>
        </div>
        <div>
          <dt>Fingerprint</dt>
          <dd className="ps-mono">
            {policy.fingerprint ? String(policy.fingerprint).slice(0, 16) : "—"}
          </dd>
        </div>
      </dl>

      <h4 className="ps-subtitle">Effective configuration</h4>
      <dl className="ps-config">
        {configEntries.map(([key, value]) => (
          <div key={key} className="ps-config__row">
            <dt>{key.replace(/_/g, " ")}</dt>
            <dd className={LIST_FIELDS.has(key) ? "ps-list" : ""}>
              {renderValue(value)}
            </dd>
          </div>
        ))}
      </dl>

      {/* The policy as it stands now — context, never a correction. */}
      {current ? (
        <section className="ps-current">
          <h4 className="ps-subtitle">The policy today</h4>
          {!current.exists ? (
            <CcureAlert variant="warning" live={false} title="Policy deleted">
              {current.note ||
                "The policy that produced this scan has since been deleted. The configuration above is unaffected."}
            </CcureAlert>
          ) : (
            <>
              <dl className="ps-identity">
                <div>
                  <dt>Name</dt>
                  <dd>{current.name || "—"}</dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>
                    <CcureBadge
                      variant={
                        current.status === "active" ? "success" : "warning"
                      }
                    >
                      {current.status}
                    </CcureBadge>{" "}
                    {current.is_enabled ? "enabled" : "disabled"}
                  </dd>
                </div>
                <div>
                  <dt>Version</dt>
                  <dd>v{current.version_number}</dd>
                </div>
                <div>
                  <dt>Configuration</dt>
                  <dd>
                    {current.matches_snapshot
                      ? "unchanged since this scan"
                      : "edited since this scan"}
                  </dd>
                </div>
              </dl>
              {current.note ? (
                <CcureAlert variant="warning" live={false} title="Diverged">
                  {current.note}
                </CcureAlert>
              ) : (
                /* Archived-and-disabled with an unchanged fingerprint is a
                   lifecycle change, not a configuration one. Calling it
                   "changed" would be wrong. */
                <p className="ps-note">
                  The configuration above is still what this policy says. Any
                  difference in status or enablement affects future scans, not
                  this one.
                </p>
              )}
            </>
          )}
        </section>
      ) : null}
    </div>
  );
}
