/**
 * pages/admin/EmailDomainRules.jsx
 * ───────────────────────────────────────────────────────────────────────────
 * Manage the platform-wide email domain ALLOW / DENY rules.
 *
 * Superadmin only. These rules affect every organisation on the deployment, so
 * the backend gates them by role rather than by permission — an org_admin
 * denying a domain would be blocking a different tenant's customers.
 *
 * The page leads with the corpus banner rather than the table on purpose. The
 * guard fails open when its blocklist is empty, which is the right behaviour
 * and completely silent: registration keeps working and nothing is screened.
 * The one place that can be noticed is here.
 *
 * ── Contract, unchanged by the Checkpoint 3C migration ──────────────────────
 * Every request, payload, debounce, page calculation and message below is what
 * it was before. The migration changed presentation only. Specifically
 * preserved: the 400 ms search debounce; `skip: page * PAGE_SIZE` with
 * PAGE_SIZE 25; `reason: undefined` rather than an empty string on create; the
 * verdict flip sending the *opposite* value; the two opposite removal warnings
 * (removing an ALLOW can start blocking a domain, removing a DENY does not
 * necessarily unblock it); and the post-removal message reporting what the
 * domain does *now*.
 *
 * ── What the migration changed, and why it mattered here ────────────────────
 * The verdict pill and the corpus banner were both hardcoded light-theme
 * palettes — `#dcfce7`/`#166534` and `#991b1b` on `rgba(220,38,38,0.08)`. In
 * dark theme the banner's dark-red text composited over a dark red-tinted
 * surface, measured at 2.06:1. That banner is the sentence "the blocklist is
 * empty — nothing is being screened": the one visible sign of a guard that has
 * failed open. It is a CcureAlert now, which is theme-aware and, being
 * `role="alert"`, is announced rather than only coloured.
 */

import { useCallback, useEffect, useId, useState } from "react";
import AppLayout from "../../components/layout/AppLayout";
import { useToasts, ToastContainer } from "../../components/common/Toast";
import {
  createEmailDomainRule,
  deleteEmailDomainRule,
  getEmailDomainStats,
  listEmailDomainRules,
  lookupEmailDomain,
  updateEmailDomainRule,
} from "../../api/emailDomains";
import { useDebounce } from "../../hooks/useDebounce";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcurePagination,
  CcureSelect,
  CcureTable,
} from "../../design-system";
import "../../styles/email-domain-rules.css";

const PAGE_SIZE = 25;

const SOURCE_HELP = {
  seed: "Shipped with the application — the never-block floor",
  admin: "Added by an administrator",
  approval: "Created by approving a flagged account",
};

/* ALLOW is a success, DENY is a refusal. Both were hardcoded pastel pairs that
   ignored `data-theme`; the badge variants carry the same meaning and follow
   the theme. An unrecognised verdict is neutral rather than being reported as
   a DENY — the old fallback (`|| VERDICT_STYLE.deny`) labelled any unknown
   value "DENY", which on this page is a claim that a domain is blocked. */
function VerdictBadge({ verdict }) {
  const known = verdict === "allow" || verdict === "deny";
  return (
    <CcureBadge
      variant={verdict === "allow" ? "success" : known ? "danger" : "neutral"}
      title={known ? undefined : `Unrecognised verdict: ${verdict}`}
    >
      {known ? verdict.toUpperCase() : "UNKNOWN"}
    </CcureBadge>
  );
}

function errorText(err, fallback) {
  const d = err?.response?.data;
  if (typeof d?.detail === "string") return d.detail;
  if (typeof d?.message === "string") return d.message;
  if (Array.isArray(d?.detail)) {
    return d.detail.map((x) => x.msg || "").join("; ") || fallback;
  }
  return fallback;
}

export default function EmailDomainRules() {
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const addFormId = useId();
  const probeFormId = useId();

  const [rules, setRules] = useState([]);
  const [counts, setCounts] = useState({ allow: 0, deny: 0 });
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);

  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [verdictFilter, setVerdictFilter] = useState("");

  const [newDomain, setNewDomain] = useState("");
  const [newVerdict, setNewVerdict] = useState("deny");
  const [newReason, setNewReason] = useState("");
  const [saving, setSaving] = useState(false);

  const [probe, setProbe] = useState("");
  const [probeResult, setProbeResult] = useState(null);
  const [probing, setProbing] = useState(false);

  const [confirm, setConfirm] = useState(null);
  const [busyId, setBusyId] = useState(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listEmailDomainRules({
        q: debouncedSearch || undefined,
        verdict: verdictFilter || undefined,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      setRules(data.rules || []);
      setTotal(data.total || 0);
      setCounts(data.counts || { allow: 0, deny: 0 });
    } catch (err) {
      pushToast(errorText(err, "Could not load domain rules."), "error");
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, [debouncedSearch, verdictFilter, page, pushToast]);

  const loadStats = useCallback(async () => {
    try {
      setStats(await getEmailDomainStats());
    } catch {
      setStats(null);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  // Filters change what page 0 means, so keep them from stranding the user on
  // an out-of-range page showing nothing.
  useEffect(() => {
    setPage(0);
  }, [debouncedSearch, verdictFilter]);

  const handleCreate = useCallback(
    async (event) => {
      event.preventDefault();
      const domain = newDomain.trim();
      if (!domain) return;

      setSaving(true);
      try {
        const created = await createEmailDomainRule({
          domain,
          verdict: newVerdict,
          reason: newReason.trim() || undefined,
        });
        pushToast(
          `${created.domain} added as ${created.verdict.toUpperCase()}. Takes effect immediately.`,
          "success",
        );
        setNewDomain("");
        setNewReason("");
        await Promise.all([loadRules(), loadStats()]);
      } catch (err) {
        // 409 is the common one and it is actionable — the domain already has a
        // rule, which the message names along with its current verdict.
        pushToast(errorText(err, "Could not add the rule."), "error");
      } finally {
        setSaving(false);
      }
    },
    [newDomain, newVerdict, newReason, loadRules, loadStats, pushToast],
  );

  const handleFlip = useCallback(
    async (rule) => {
      const next = rule.verdict === "allow" ? "deny" : "allow";
      setBusyId(rule.id);
      try {
        await updateEmailDomainRule(rule.id, { verdict: next });
        pushToast(`${rule.domain} is now ${next.toUpperCase()}.`, "success");
        await Promise.all([loadRules(), loadStats()]);
      } catch (err) {
        pushToast(errorText(err, "Could not change the rule."), "error");
      } finally {
        setBusyId(null);
      }
    },
    [loadRules, loadStats, pushToast],
  );

  const handleDelete = useCallback(async () => {
    const rule = confirm;
    setConfirm(null);
    if (!rule) return;
    setBusyId(rule.id);
    try {
      const result = await deleteEmailDomainRule(rule.id);
      // Say what the domain does *now*. Removing an ALLOW from a domain that is
      // also in the blocklist corpus does not make it neutral — it starts
      // blocking, and that surprise is worth pre-empting.
      const nowBlocked = result?.now?.blocked;
      pushToast(
        nowBlocked
          ? `Rule removed. ${result.domain} is now BLOCKED (${result.now.reason}).`
          : `Rule removed. ${result.domain} is now accepted.`,
        nowBlocked ? "info" : "success",
      );
      await Promise.all([loadRules(), loadStats()]);
    } catch (err) {
      pushToast(errorText(err, "Could not remove the rule."), "error");
    } finally {
      setBusyId(null);
    }
  }, [confirm, loadRules, loadStats, pushToast]);

  const handleProbe = useCallback(
    async (event) => {
      event.preventDefault();
      const q = probe.trim();
      if (!q) return;
      setProbing(true);
      setProbeResult(null);
      try {
        setProbeResult(await lookupEmailDomain(q));
      } catch (err) {
        pushToast(errorText(err, "Could not test that address."), "error");
      } finally {
        setProbing(false);
      }
    },
    [probe, pushToast],
  );

  /* Declared columns, so CcureTable owns the caption, `scope="col"` on every
     header and `scope="row"` on the domain — which is the row's identity and
     the thing a reader needs announced beside every verdict. */
  const columns = [
    {
      key: "domain",
      header: "Domain",
      isRowHeader: true,
      mono: true,
      cell: (rule) => rule.domain,
    },
    {
      key: "verdict",
      header: "Verdict",
      cell: (rule) => <VerdictBadge verdict={rule.verdict} />,
    },
    {
      key: "source",
      header: "Source",
      cell: (rule) => (
        <span className="edr-source" title={SOURCE_HELP[rule.source] || ""}>
          {rule.source}
        </span>
      ),
    },
    {
      key: "reason",
      header: "Reason",
      cell: (rule) => <span className="edr-reason">{rule.reason || "—"}</span>,
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      nowrap: true,
      cell: (rule) => (
        <div className="edr-actions">
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() => handleFlip(rule)}
            loading={busyId === rule.id}
            /* One "Set deny" per row is N identical entries in a reader's
               control list. The domain is the only thing that tells them
               apart, and on this page picking the wrong row changes who can
               register on the whole deployment. */
            aria-label={`Change ${rule.domain} to ${
              rule.verdict === "allow" ? "DENY" : "ALLOW"
            }`}
          >
            {rule.verdict === "allow" ? "Set deny" : "Set allow"}
          </CcureButton>
          <CcureButton
            variant="danger"
            size="sm"
            onClick={() => setConfirm(rule)}
            loading={busyId === rule.id}
            aria-label={`Remove the rule for ${rule.domain}`}
          >
            Remove
          </CcureButton>
        </div>
      ),
    },
  ];

  return (
    <AppLayout>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />

      <div className="page-inner edr-page">
        <h1 className="page-title">Email Domain Rules</h1>
        <p className="page-subtitle edr-lede">
          Decides which email domains may create an account.{" "}
          <strong>ALLOW always wins</strong> — it overrides both a DENY rule and
          the disposable-domain blocklist, and it is how you unblock a real
          customer whose domain an upstream list got wrong. Rules apply to every
          organisation and take effect immediately.
        </p>

        {/* Corpus health. First, because an empty blocklist is silent. */}
        {stats && (
          <CcureAlert
            variant={stats.corpus_healthy ? "info" : "danger"}
            /* A healthy corpus is standing page furniture, not an event, so it
               is not announced. An empty one is the failure this banner exists
               for, and role="alert" is what makes it reach a reader who never
               sees the colour. */
            live={!stats.corpus_healthy}
            className="edr-corpus"
          >
            <span className="edr-corpus-facts">
              <span>
                Mode <strong>{stats.mode}</strong>
              </span>
              <span>
                Blocklist{" "}
                <strong>{(stats.corpus_size || 0).toLocaleString()}</strong>{" "}
                domains
              </span>
              <span>
                Allow <strong>{stats.allow_rules}</strong> · Deny{" "}
                <strong>{stats.deny_rules}</strong>
              </span>
              <span>
                Flagged accounts <strong>{stats.flagged_users}</strong>
              </span>
              {!stats.corpus_healthy && (
                <strong className="edr-corpus-warning">
                  ⚠ The blocklist is empty — nothing is being screened. Run the
                  disposable-domain sync.
                </strong>
              )}
            </span>
          </CcureAlert>
        )}

        {/* Add a rule */}
        <form
          onSubmit={handleCreate}
          className="edr-panel edr-add"
          aria-labelledby={addFormId}
        >
          <h2 className="cc-sr-only" id={addFormId}>
            Add a domain rule
          </h2>
          <CcureInput
            id="new-domain"
            label="Domain"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="acme.com"
            required
            fieldClassName="edr-field edr-field--domain"
          />
          <CcureSelect
            id="new-verdict"
            label="Verdict"
            value={newVerdict}
            onChange={(e) => setNewVerdict(e.target.value)}
            fieldClassName="edr-field"
          >
            <option value="deny">Deny — block this domain</option>
            <option value="allow">Allow — always accept this domain</option>
          </CcureSelect>
          <CcureInput
            id="new-reason"
            label="Reason (optional)"
            value={newReason}
            onChange={(e) => setNewReason(e.target.value)}
            placeholder="Why this rule exists — the next admin will thank you"
            fieldClassName="edr-field edr-field--grow"
          />
          <CcureButton
            type="submit"
            loading={saving}
            disabled={!newDomain.trim()}
          >
            Add rule
          </CcureButton>
        </form>

        {/* Test an address */}
        <form
          onSubmit={handleProbe}
          className="edr-panel edr-probe"
          aria-labelledby={probeFormId}
        >
          <h2 className="edr-probe-title" id={probeFormId}>
            Test an address
          </h2>
          <CcureInput
            value={probe}
            onChange={(e) => setProbe(e.target.value)}
            placeholder="someone@company.com"
            aria-label="Address or domain to test"
            fieldClassName="edr-field edr-field--grow"
          />
          <CcureButton type="submit" variant="secondary" loading={probing}>
            Check
          </CcureButton>
          {probeResult && (
            /* The result replaces itself in place without focus moving, so it
               is announced. Polite: it answers a question the user just asked,
               it does not interrupt. */
            <div className="edr-probe-result" role="status" aria-live="polite">
              <strong>{probeResult.domain}</strong>{" "}
              {probeResult.would_block_registration ? (
                <span className="edr-verdict-blocked">would be BLOCKED</span>
              ) : (
                <span className="edr-verdict-accepted">would be accepted</span>
              )}
              <span className="edr-probe-detail">
                {" "}
                — {probeResult.reason}
                {probeResult.matched_domain
                  ? ` (matched ${probeResult.matched_domain} via ${probeResult.matched_source})`
                  : ""}
                {probeResult.flags?.length
                  ? ` · flags: ${probeResult.flags.join(", ")}`
                  : ""}
              </span>
              {probeResult.blocked && !probeResult.would_block_registration && (
                <div className="edr-probe-detail edr-probe-note">
                  The guard is in <strong>{stats?.mode}</strong> mode, so this
                  is recorded but not enforced.
                </div>
              )}
            </div>
          )}
        </form>

        {/* Filters */}
        <div className="edr-filters">
          <CcureInput
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search domain or reason…"
            aria-label="Search rules"
            fieldClassName="edr-field edr-field--search"
          />
          <CcureSelect
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            aria-label="Filter by verdict"
            fieldClassName="edr-field"
          >
            <option value="">
              All verdicts ({counts.allow + counts.deny})
            </option>
            <option value="allow">Allow ({counts.allow})</option>
            <option value="deny">Deny ({counts.deny})</option>
          </CcureSelect>
        </div>

        {/* Table */}
        {loading ? (
          <div className="edr-loading">
            <CcureLoader label="Loading domain rules…" />
          </div>
        ) : rules.length === 0 ? (
          <CcureEmptyState
            title="No rules match"
            description={
              search || verdictFilter
                ? "Try a different search or filter."
                : "Add a rule above to allow or block a specific email domain."
            }
          />
        ) : (
          <>
            <CcureTable
              caption={`Email domain rules — ${total} rule${total !== 1 ? "s" : ""}`}
              columns={columns}
              rows={rules}
              rowKey={(rule) => rule.id}
              density="comfortable"
            />
            {/* CcurePagination is 1-based, matching every other call site and
                every backend query parameter; this page's own state is 0-based
                because `skip` is computed from it, so the boundary is
                converted here rather than changing either convention. */}
            <CcurePagination
              page={page + 1}
              pageSize={PAGE_SIZE}
              total={total}
              onPageChange={(next) => setPage(next - 1)}
              itemNoun="rules"
              disabled={busyId !== null}
            />
          </>
        )}
      </div>

      <CcureConfirmDialog
        open={Boolean(confirm)}
        title={
          confirm ? `Remove the rule for ${confirm.domain}?` : "Remove rule?"
        }
        subtitle={
          confirm?.verdict === "allow"
            ? `${confirm.domain} is currently allowed.`
            : confirm
              ? `${confirm.domain} is currently denied.`
              : ""
        }
        // Spelled out because it is genuinely counter-intuitive: removing an
        // ALLOW does not return a domain to neutral if the blocklist also lists
        // it — it starts blocking. `test.com` is a live example.
        warning={
          confirm?.verdict === "allow"
            ? "If this domain also appears on the disposable-domain blocklist, removing the rule will start blocking it."
            : "Removing this rule lets the domain register again, unless it is on the blocklist."
        }
        confirmLabel="Remove rule"
        tone="danger"
        onConfirm={handleDelete}
        onCancel={() => setConfirm(null)}
      />
    </AppLayout>
  );
}
