/**
 * pages/scan/ConfigurationChecks.jsx
 * ───────────────────────────────────────────────────────────────────────────
 * What the configuration audit checks, and what this build can actually check.
 *
 * A read-only catalogue, deliberately. Configuration checks run inside the
 * credentialed scan — there is no "run" button here, because a second way to
 * start a scan against a named target would need its own scope check and
 * audit entry, and would produce scan rows that Scan History and the
 * reports would have to learn about. The rule validator is a separate page for
 * the same reason: this one issues no POST of any kind, and a test drives every
 * control on it to keep that true.
 *
 * Two things this page exists to make visible:
 *
 * **The absence policy.** Every check states what a successful reading of "the
 * item is not present" means for it, because that is the column a reviewer
 * lands on when a control comes back as Manual review. A Windows setting
 * missing from the registry is at a platform default that varies by build —
 * neither a pass nor a failure, and saying which would be inventing an answer.
 *
 * **The capability gap.** The rule vocabulary admits check types and platforms
 * ahead of the phases that implement them, so a rule can exist that nothing in
 * this build can execute. The engine reports that as an error rather than
 * skipping it, but only after a scan has run. The matrix says it up front.
 *
 * ── Phase 6 (API → UI coverage) ─────────────────────────────────────────────
 * The platform selector was a two-entry constant, `["windows", "linux"]`,
 * while `/capabilities` serves six queryable platforms. Measured against the
 * live API: windows returns 56 checks and linux 86, of 155 — so **49 database
 * checks, the whole of the Phase 7 database assessment, could not be reached
 * from this page at all**, and every platform added later would have inherited
 * the same fate. The list is now derived from `capabilities.supported`, whose
 * keys are exactly the platforms that return rows.
 *
 * `any` is excluded and that is not an omission: it is a *targeting* value on
 * a check ("applies to every platform"), not a platform to ask about, and the
 * API answers `platform=any` with zero rows.
 *
 * ── Migration note (Checkpoint 3C, batch 10) ────────────────────────────────
 * Read-only is the contract, and it is unchanged: no mutation of any kind.
 * What changed then was the surface — every colour literal was a light-theme
 * palette on a page that renders in whichever theme the account chose — plus
 * one correctness fix recorded in full below.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { ToastContainer, useToasts } from "@shell/feedback/Toast";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureSelect,
  CcurePage,
  CcurePageHeader,
} from "../../../../design-system";
import "../../styles/configuration-checks.css";
import {
  configAuditErrorMessage,
  getConfigCapabilities,
  getConfigCheck,
  listConfigChecks,
  queryablePlatforms,
} from "@audit/api/configAudit";

/** Severity is a CCure vocabulary; the page no longer keeps a private palette. */
const SEVERITY_VARIANT = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  none: "neutral",
  unscored: "neutral",
};

const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "unscored",
];

/**
 * Each policy needs its own wording. Collapsing them into "absent handling"
 * would hide the fact that absence is a pass for one rule and a failure for
 * another, which is the single most misread property of a hardening check.
 *
 * The variant carries the same meaning a second way, for a reader who cannot
 * distinguish the colours — the label is the authority, never the colour.
 */
const ABSENCE_TEXT = {
  pass: {
    label: "Absent = compliant",
    variant: "success",
    hint: "The thing not being there satisfies this check.",
  },
  fail: {
    label: "Absent = finding",
    variant: "danger",
    hint: "The thing is required, so its absence is the finding.",
  },
  not_applicable: {
    label: "Absent = out of scope",
    variant: "neutral",
    hint: "This check only applies to hosts that have the component.",
  },
  manual_review: {
    label: "Absent = review",
    variant: "warning",
    hint: "The setting was not explicitly configured, so the platform default applies and a person has to decide whether it is acceptable here.",
  },
};

const CheckRow = ({ check, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  const absence =
    ABSENCE_TEXT[check.absent_policy] || ABSENCE_TEXT.manual_review;

  return (
    <div className="cfg-row">
      <CcureButton
        variant="ghost"
        size="sm"
        type="button"
        className="cfg-row-toggle"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <CcureBadge variant={SEVERITY_VARIANT[check.severity] || "neutral"}>
          {check.severity}
        </CcureBadge>
        <span className="cfg-row-title">{check.title}</span>
        <CcureBadge variant="neutral">{check.check_type}</CcureBadge>
        {/* The policy travels as words. `title` is a convenience for a mouse
            user, never the carrier of the meaning. */}
        <CcureBadge variant={absence.variant} title={absence.hint}>
          {absence.label}
        </CcureBadge>
        {/* An intrusive check may disturb the host it runs on, which on an OT
            segment is the difference between an audit and an outage. It is
            shown when true rather than being left to the detail nobody opens. */}
        {check.intrusive ? (
          <CcureBadge variant="danger">Intrusive</CcureBadge>
        ) : null}
        <span className="cfg-row-caret" aria-hidden="true">
          {open ? "−" : "+"}
        </span>
      </CcureButton>

      {open && (
        <div className="cfg-detail">
          <dl className="cfg-dl">
            <div>
              <dt>Expected state</dt>
              <dd className="cfg-mono">{check.expected}</dd>
            </div>
            {check.description && (
              <div>
                <dt>What it reads</dt>
                <dd>{check.description}</dd>
              </div>
            )}
            {check.rationale && (
              <div>
                <dt>Why it matters</dt>
                <dd>{check.rationale}</dd>
              </div>
            )}
            {check.remediation && (
              <div>
                <dt>Remediation</dt>
                <dd>{check.remediation}</dd>
              </div>
            )}
            <div>
              <dt>If the item is not present</dt>
              <dd>{absence.hint}</dd>
            </div>
            <div>
              <dt>Domain</dt>
              {/* The check family the engine files this under, and the field a
                  scan policy selects on. */}
              <dd>{check.domain}</dd>
            </div>
            <div>
              <dt>Disturbs the host</dt>
              <dd>{check.intrusive ? "Yes — intrusive" : "No"}</dd>
            </div>
            {check.tags?.length > 0 && (
              <div>
                <dt>Tags</dt>
                <dd className="cfg-tags">
                  {check.tags.map((tag) => (
                    <CcureBadge key={tag} variant="neutral">
                      {tag}
                    </CcureBadge>
                  ))}
                </dd>
              </div>
            )}
            <div className="cfg-meta">
              <code>{check.check_id}</code> · {check.platforms.join(", ")} · QoD{" "}
              {check.qod}
              {check.requires_credentials ? " · needs credentials" : ""}
            </div>
            {check.references?.length > 0 && (
              <div className="cfg-refs">
                {check.references.map((url) => (
                  <a key={url} href={url} target="_blank" rel="noreferrer">
                    Reference
                  </a>
                ))}
              </div>
            )}
          </dl>
        </div>
      )}
    </div>
  );
};

const ALL = "";

const ConfigurationChecks = () => {
  /* `useToasts()` returns { toasts, push, dismiss }. This page destructured
     `addToast`/`removeToast`, so both were undefined and the toast call threw.

     That was not a missing toast. The call is the page's ONLY error surface,
     and it sits in a `catch` whose `finally` clears the loading flag — so a
     failed load rendered the EMPTY state, "No configuration checks for this
     platform". That is a false statement about the product's capability rather
     than about the data, on the page whose whole purpose is to report what this
     build can and cannot check.

     Fixed by renaming on the way in, so the call sites stay byte-identical, and
     paired with a real error state below. Recorded rather than folded in
     silently. `ScanSchedules` carries the same defect and is NOT in this batch;
     it is untouched and reported. */
  const { toasts, push: addToast, dismiss: removeToast } = useToasts();
  const [checks, setChecks] = useState([]);
  const [capabilities, setCapabilities] = useState(null);
  const [platform, setPlatform] = useState(ALL);
  const [checkType, setCheckType] = useState(ALL);
  const [domain, setDomain] = useState(ALL);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  /* Captured from the first, unfiltered load and never overwritten by a
     filtered one. The API serves no domain vocabulary, so the options have to
     come from the catalogue — and reading them from a filtered response would
     narrow the list to whatever is already selected. */
  const [domains, setDomains] = useState([]);

  const [lookupId, setLookupId] = useState("");
  const [lookup, setLookup] = useState(null);
  const [lookupError, setLookupError] = useState("");
  const [lookingUp, setLookingUp] = useState(false);

  useEffect(() => {
    getConfigCapabilities()
      .then(setCapabilities)
      .catch(() => setCapabilities(null));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const rows = await listConfigChecks({ platform, checkType, domain });
      setChecks(rows);
      if (!platform && !checkType && !domain) {
        setDomains([...new Set(rows.map((r) => r.domain).filter(Boolean))]);
      }
    } catch (err) {
      const detail = configAuditErrorMessage(
        err,
        "Could not load configuration checks",
      );
      /* Held in state as well as announced. A toast disappears; the reason the
         catalogue is empty must not. */
      setError(detail);
      setChecks([]);
      addToast(detail, "error");
    } finally {
      setLoading(false);
    }
  }, [platform, checkType, domain, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const matched = needle
      ? checks.filter((c) =>
          [c.title, c.check_id, c.description, ...(c.tags || [])]
            .filter(Boolean)
            .join(" ")
            .toLowerCase()
            .includes(needle),
        )
      : checks;
    return [...matched].sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );
  }, [checks, search]);

  const platforms = queryablePlatforms(capabilities);
  const supported = capabilities?.supported?.[platform] || [];
  const unimplemented = capabilities?.declared_without_collector || [];

  /* An empty catalogue for a platform this build has no collector for is a
     different statement from an empty catalogue for one it does — the first is
     about the product, the second about the content. */
  const platformHasNoCollector =
    Boolean(platform) &&
    Array.isArray(capabilities?.supported?.[platform]) &&
    capabilities.supported[platform].length === 0;

  const runLookup = async () => {
    const id = lookupId.trim();
    if (!id) return;
    setLookingUp(true);
    setLookupError("");
    setLookup(null);
    try {
      setLookup(await getConfigCheck(id));
    } catch (err) {
      setLookupError(
        configAuditErrorMessage(
          err,
          `No check in this build is called "${id}".`,
        ),
      );
    } finally {
      setLookingUp(false);
    }
  };

  return (
    <AppLayout>
      <ToastContainer toasts={toasts} dismiss={removeToast} />

      <CcurePage>
        <CcurePageHeader
          title="Configuration Checks"
          subtitle={
            <>
              Host hardening controls evaluated during a credentialed scan. Each
              one reads a specific setting and compares it against a required
              state, and its result travels the same path as a CVE finding —
              severity, risk, remediation and the scan report. There is nothing
              to start here: these run automatically on every credentialed scan,
              over the session the collectors already opened.{" "}
              <Link to="/configuration-checks/validate">
                Validate a rule definition
              </Link>
              .
            </>
          }
        />

        {/* A group of buttons, not a tab strip: they re-query the same
            catalogue rather than switching between two panels. `aria-pressed`
            is what states the choice — the raised styling is the sighted half
            of the same fact, not the whole of it. */}
        <div
          className="cfg-platforms"
          role="group"
          aria-label="Target platform"
        >
          <CcureButton
            variant={platform === ALL ? "primary" : "secondary"}
            size="sm"
            className="cfg-platform-btn"
            aria-pressed={platform === ALL}
            onClick={() => setPlatform(ALL)}
          >
            all platforms
          </CcureButton>
          {platforms.map((name) => (
            <CcureButton
              key={name}
              variant={platform === name ? "primary" : "secondary"}
              size="sm"
              className="cfg-platform-btn"
              aria-pressed={platform === name}
              onClick={() => setPlatform(name)}
            >
              {name}
            </CcureButton>
          ))}
        </div>

        <div className="cfg-filters">
          <CcureSelect
            label="Check type"
            value={checkType}
            onChange={(e) => setCheckType(e.target.value)}
          >
            <option value={ALL}>Any type</option>
            {(capabilities?.check_types || []).map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </CcureSelect>
          <CcureSelect
            label="Domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          >
            <option value={ALL}>Any domain</option>
            {domains.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </CcureSelect>
          <CcureInput
            label="Search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            hint="Filters the checks already loaded; the API has no search parameter."
          />
        </div>

        {capabilities && (
          <CcureAlert
            variant="info"
            live={false}
            className="cfg-capability"
            title={
              platform
                ? `What this build can read on ${platform}`
                : "What this build can read, per platform"
            }
          >
            {platform ? (
              <>{supported.join(", ") || "nothing"}.</>
            ) : (
              <ul className="cfg-caplist">
                {platforms.map((name) => (
                  <li key={name}>
                    <strong>{name}</strong>:{" "}
                    {capabilities.supported[name]?.join(", ") || (
                      <em>no collector in this build</em>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {unimplemented.length > 0 && (
              <>
                {" "}
                <strong>Not yet implemented:</strong> {unimplemented.join(", ")}{" "}
                — a rule using one of these reports as not assessed rather than
                being silently skipped.
              </>
            )}
          </CcureAlert>
        )}

        {/* The error is its own state, above the list. Before this it did not
            exist: a failed load rendered as "this platform has no checks". */}
        {error && (
          <CcureAlert variant="danger" className="cfg-error">
            {error}
          </CcureAlert>
        )}

        {loading ? (
          <div className="cfg-loading">
            <CcureLoader label="Loading configuration checks…" />
          </div>
        ) : error ? null : visible.length === 0 ? (
          <CcureEmptyState
            title={
              platformHasNoCollector
                ? `This build has no collector for ${platform}`
                : search.trim()
                  ? "No check matches this search"
                  : "No configuration checks for this platform"
            }
            description={
              platformHasNoCollector
                ? "The platform is named in the rule vocabulary so that content can be written for it, but nothing in this build can execute a check against one. A rule targeting it reports an error rather than a verdict."
                : search.trim()
                  ? "The search filters the checks already loaded. Widening the platform, type or domain filter may bring back more."
                  : "Checks are registered per platform; none is defined for this one yet."
            }
          />
        ) : (
          <>
            <p className="cfg-count">
              {visible.length} check{visible.length === 1 ? "" : "s"}
              {visible.length !== checks.length
                ? ` of ${checks.length} loaded`
                : ""}
            </p>
            {visible.map((check) => (
              <CheckRow key={check.check_id} check={check} />
            ))}
          </>
        )}

        {/* `GET /config-audit/checks/{id}` — the one operation the catalogue
            cannot answer from the list it already holds. A finding names the
            check that produced it, and that check may sit behind a filter the
            reader has not selected, so it is fetched by id rather than
            searched for. */}
        <section className="cfg-lookup">
          <h2 className="cfg-lookup__h">Look up a check by id</h2>
          <p className="cfg-lookup__lede">
            Findings carry the id of the check that produced them. Paste one
            here to read it without knowing which platform or type it belongs
            to.
          </p>
          <div className="cfg-lookup__row">
            <CcureInput
              label="Check id"
              value={lookupId}
              onChange={(e) => setLookupId(e.target.value)}
              placeholder="ccure.win.uac.enabled"
            />
            <CcureButton
              variant="secondary"
              disabled={lookingUp || !lookupId.trim()}
              onClick={runLookup}
            >
              Look up
            </CcureButton>
          </div>
          {lookupError && (
            <CcureAlert variant="warning">{lookupError}</CcureAlert>
          )}
          {lookup && <CheckRow check={lookup} defaultOpen />}
        </section>
      </CcurePage>
    </AppLayout>
  );
};

export default ConfigurationChecks;
