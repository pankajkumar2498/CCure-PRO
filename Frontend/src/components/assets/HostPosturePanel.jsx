/**
 * What an authenticated scan established about this host.
 *
 * `assets/{id}.custom_attributes` has carried all of this since the
 * credentialed pipeline was built and `AssetDetail` referenced none of it:
 * zero occurrences of `registry_hardening`, `credentialed_status`,
 * `password_policy`, `running_services` and `local_groups`.
 *
 * Three states this panel exists to keep apart, all of them rules from
 * CLAUDE.md's UI semantic integrity section:
 *
 * * **A hardening key that is absent is not `false`.** CLAUDE.md is explicit —
 *   "Do not restore a `False` default anywhere on that path: `False` asserts
 *   the insecure state, which is the same defect pointing at a FAIL." So the
 *   row renders three ways: hardened, **not** hardened, and not assessed.
 *
 * * **`credentialed_status` has three meanings, and one of them is unset.**
 *   `success` and `failed` are both written; a host nothing was attempted
 *   against is left unset, "because 'no credential was in scope' and 'the
 *   credential was refused' are different facts". Rendering the absence as a
 *   failure would accuse a host nobody tried.
 *
 * * **An empty list is not the same as an uncollected one.** `running_services`
 *   arrives as `[]` on a host where the item was not served, so the panel says
 *   which it is by reading whether the key is present at all.
 */

import { CcureBadge, CcureCard } from "../../design-system";

/** The Windows hardening switches, in the order an operator reads them. */
const HARDENING = [
  ["smbv1_disabled", "SMBv1 disabled"],
  ["telnet_disabled", "Telnet disabled"],
  ["netbios_disabled", "NetBIOS disabled"],
  ["legacy_tls_disabled", "Legacy TLS disabled"],
  ["rdp_disabled", "RDP disabled"],
  ["rdp_nla_enforced", "RDP NLA enforced"],
  ["uac_enabled", "UAC enabled"],
  ["firewall_active", "Firewall active"],
  ["audit_configured", "Audit policy configured"],
];

const CREDENTIALED_STATE = {
  success: {
    tone: "success",
    label: "Authenticated",
    hint: "A credentialed session was opened and the host was collected from.",
  },
  failed: {
    tone: "danger",
    label: "Authentication failed",
    hint: "A credential was in scope for this host and the host refused it.",
  },
};

const when = (iso) => {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
};

/** One hardening switch, in whichever of its three states the payload says. */
function HardeningRow({ label, value }) {
  if (value === true) {
    return (
      <li className="ad-posture__row">
        <CcureBadge variant="success">Hardened</CcureBadge>
        <span>{label}</span>
      </li>
    );
  }
  if (value === false) {
    return (
      <li className="ad-posture__row">
        <CcureBadge variant="danger">Not hardened</CcureBadge>
        <span>{label}</span>
      </li>
    );
  }
  return (
    <li className="ad-posture__row">
      {/* The third state, and the reason this component exists. A setting the
          scan never read is not a setting that is switched off. */}
      <CcureBadge variant="neutral">Not assessed</CcureBadge>
      <span className="ad-faint">{label}</span>
    </li>
  );
}

export default function HostPosturePanel({ customAttributes }) {
  const ca = customAttributes || {};
  const status = ca.credentialed_status;
  const hardening = ca.registry_hardening;
  const policy = ca.password_policy;
  const info = ca.credentialed_system_info || {};

  const services = info.running_services;
  const groups = info.local_groups;
  const tasks = info.suspicious_scheduled_tasks;

  const nothingToShow =
    !status && !hardening && !policy && !Object.keys(info).length;
  if (nothingToShow) return null;

  const state = CREDENTIALED_STATE[status];

  return (
    <CcureCard
      title="🔐 Authenticated posture"
      subtitle="What a credentialed scan established about this host"
      headingLevel={2}
    >
      <div className="ad-posture">
        <div className="ad-posture__status">
          {state ? (
            <CcureBadge variant={state.tone} title={state.hint}>
              {state.label}
            </CcureBadge>
          ) : (
            <CcureBadge
              variant="neutral"
              title="No credential was in scope for this host. That is not the same as a credential having been refused."
            >
              Not attempted
            </CcureBadge>
          )}
          {info.synced_at ? (
            <span className="ad-faint">
              {/* The provenance of everything below it. */}
              Collected {when(info.synced_at)}
              {info.source_scan_id ? ` · scan ${info.source_scan_id}` : ""}
            </span>
          ) : null}
        </div>

        {hardening ? (
          <>
            <h3 className="ad-posture__h">Host hardening</h3>
            <ul className="ad-posture__list">
              {HARDENING.map(([key, label]) => (
                <HardeningRow key={key} label={label} value={hardening[key]} />
              ))}
            </ul>
          </>
        ) : null}

        {policy && Object.keys(policy).length ? (
          <>
            <h3 className="ad-posture__h">Password policy</h3>
            <dl className="ad-posture__kv">
              {Object.entries(policy).map(([key, value]) => (
                <div key={key}>
                  <dt>{key.replace(/_/g, " ")}</dt>
                  <dd>{value === null ? "not assessed" : String(value)}</dd>
                </div>
              ))}
            </dl>
          </>
        ) : null}

        <dl className="ad-posture__kv">
          <div>
            <dt>Detected OS</dt>
            <dd>
              {info.detected_os || <span className="ad-faint">—</span>}
              {info.os_version_id ? ` ${info.os_version_id}` : ""}
            </dd>
          </div>
          <div>
            <dt>Running services</dt>
            {/* `[]` from a host that was collected and `undefined` from one
                where the item was never served print differently. */}
            <dd>
              {services === undefined ? (
                <span className="ad-faint">not collected</span>
              ) : (
                `${services.length} collected`
              )}
            </dd>
          </div>
          <div>
            <dt>Local groups</dt>
            <dd>
              {groups === undefined ? (
                <span className="ad-faint">not collected</span>
              ) : (
                `${groups.length} collected`
              )}
            </dd>
          </div>
          <div>
            <dt>Suspicious scheduled tasks</dt>
            <dd>
              {tasks === undefined ? (
                <span className="ad-faint">not collected</span>
              ) : tasks.length === 0 ? (
                "none found"
              ) : (
                <span className="ad-posture__alert">{tasks.length} found</span>
              )}
            </dd>
          </div>
        </dl>

        {Array.isArray(tasks) && tasks.length > 0 ? (
          <ul className="ad-posture__tasks">
            {tasks.map((t, i) => (
              <li key={i}>{typeof t === "string" ? t : JSON.stringify(t)}</li>
            ))}
          </ul>
        ) : null}
      </div>
    </CcureCard>
  );
}
