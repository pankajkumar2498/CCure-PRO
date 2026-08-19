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
 */

import { useCallback, useEffect, useState } from "react";
import AppLayout from "../../components/layout/AppLayout";
import Button from "../../components/common/Button";
import ConfirmDialog from "../../components/common/ConfirmDialog";
import EmptyState from "../../components/common/EmptyState";
import Loader from "../../components/common/Loader";
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

const PAGE_SIZE = 25;

const VERDICT_STYLE = {
  allow: { bg: "#dcfce7", fg: "#166534", label: "ALLOW" },
  deny: { bg: "#fee2e2", fg: "#991b1b", label: "DENY" },
};

const SOURCE_HELP = {
  seed: "Shipped with the application — the never-block floor",
  admin: "Added by an administrator",
  approval: "Created by approving a flagged account",
};

function VerdictPill({ verdict }) {
  const s = VERDICT_STYLE[verdict] || VERDICT_STYLE.deny;
  return (
    <span
      style={{
        display: "inline-block",
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: "0.06em",
        padding: "2px 8px",
        borderRadius: 4,
        background: s.bg,
        color: s.fg,
      }}
    >
      {s.label}
    </span>
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

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <AppLayout>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />

      <div style={{ padding: "0 4px 40px" }}>
        <h1 style={{ margin: "0 0 6px", fontSize: 24 }}>Email Domain Rules</h1>
        <p
          style={{
            margin: "0 0 20px",
            fontSize: 14,
            opacity: 0.75,
            maxWidth: 760,
          }}
        >
          Decides which email domains may create an account.{" "}
          <strong>ALLOW always wins</strong> — it overrides both a DENY rule and
          the disposable-domain blocklist, and it is how you unblock a real
          customer whose domain an upstream list got wrong. Rules apply to every
          organisation and take effect immediately.
        </p>

        {/* Corpus health. First, because an empty blocklist is silent. */}
        {stats && (
          <div
            style={{
              display: "flex",
              gap: 20,
              flexWrap: "wrap",
              alignItems: "center",
              border: `1px solid ${stats.corpus_healthy ? "#d1d5db" : "#dc2626"}`,
              background: stats.corpus_healthy
                ? "rgba(0,0,0,0.03)"
                : "rgba(220,38,38,0.08)",
              borderRadius: 10,
              padding: "12px 16px",
              marginBottom: 20,
              fontSize: 13,
            }}
          >
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
              <span style={{ color: "#991b1b", fontWeight: 600 }}>
                ⚠ The blocklist is empty — nothing is being screened. Run the
                disposable-domain sync.
              </span>
            )}
          </div>
        )}

        {/* Add a rule */}
        <form
          onSubmit={handleCreate}
          style={{
            border: "1px solid #d1d5db",
            borderRadius: 10,
            padding: "14px 16px",
            marginBottom: 18,
            display: "flex",
            gap: 10,
            flexWrap: "wrap",
            alignItems: "flex-end",
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <label
              htmlFor="new-domain"
              style={{ fontSize: 12, fontWeight: 600 }}
            >
              Domain
            </label>
            <input
              id="new-domain"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="acme.com"
              style={{ padding: "7px 10px", minWidth: 220 }}
              required
            />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <label
              htmlFor="new-verdict"
              style={{ fontSize: 12, fontWeight: 600 }}
            >
              Verdict
            </label>
            <select
              id="new-verdict"
              value={newVerdict}
              onChange={(e) => setNewVerdict(e.target.value)}
              style={{ padding: "7px 10px" }}
            >
              <option value="deny">Deny — block this domain</option>
              <option value="allow">Allow — always accept this domain</option>
            </select>
          </div>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 4,
              flex: 1,
              minWidth: 220,
            }}
          >
            <label
              htmlFor="new-reason"
              style={{ fontSize: 12, fontWeight: 600 }}
            >
              Reason{" "}
              <span style={{ opacity: 0.6, fontWeight: 400 }}>(optional)</span>
            </label>
            <input
              id="new-reason"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              placeholder="Why this rule exists — the next admin will thank you"
              style={{ padding: "7px 10px", width: "100%" }}
            />
          </div>
          <Button type="submit" disabled={saving || !newDomain.trim()}>
            {saving ? "Adding…" : "Add rule"}
          </Button>
        </form>

        {/* Test an address */}
        <form
          onSubmit={handleProbe}
          style={{
            border: "1px solid #d1d5db",
            borderRadius: 10,
            padding: "14px 16px",
            marginBottom: 22,
            display: "flex",
            gap: 10,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: 13, fontWeight: 600 }}>Test an address</span>
          <input
            value={probe}
            onChange={(e) => setProbe(e.target.value)}
            placeholder="someone@company.com"
            aria-label="Address or domain to test"
            style={{ padding: "7px 10px", minWidth: 260, flex: 1 }}
          />
          <Button
            type="submit"
            variant="secondary"
            disabled={probing || !probe.trim()}
          >
            {probing ? "Checking…" : "Check"}
          </Button>
          {probeResult && (
            <div style={{ fontSize: 13, width: "100%", marginTop: 4 }}>
              <strong>{probeResult.domain}</strong>{" "}
              {probeResult.would_block_registration ? (
                <span style={{ color: "#991b1b", fontWeight: 600 }}>
                  would be BLOCKED
                </span>
              ) : (
                <span style={{ color: "#166534", fontWeight: 600 }}>
                  would be accepted
                </span>
              )}
              <span style={{ opacity: 0.75 }}>
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
                <div style={{ marginTop: 3, opacity: 0.75 }}>
                  The guard is in <strong>{stats?.mode}</strong> mode, so this
                  is recorded but not enforced.
                </div>
              )}
            </div>
          )}
        </form>

        {/* Filters */}
        <div
          style={{
            display: "flex",
            gap: 10,
            marginBottom: 12,
            flexWrap: "wrap",
          }}
        >
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search domain or reason…"
            aria-label="Search rules"
            style={{ padding: "7px 10px", minWidth: 240 }}
          />
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            aria-label="Filter by verdict"
            style={{ padding: "7px 10px" }}
          >
            <option value="">
              All verdicts ({counts.allow + counts.deny})
            </option>
            <option value="allow">Allow ({counts.allow})</option>
            <option value="deny">Deny ({counts.deny})</option>
          </select>
        </div>

        {/* Table */}
        {loading ? (
          <Loader />
        ) : rules.length === 0 ? (
          <EmptyState
            title="No rules match"
            description={
              search || verdictFilter
                ? "Try a different search or filter."
                : "Add a rule above to allow or block a specific email domain."
            }
          />
        ) : (
          <div
            style={{
              overflowX: "auto",
              border: "1px solid #d1d5db",
              borderRadius: 10,
            }}
          >
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: 14,
              }}
            >
              <thead>
                <tr style={{ background: "rgba(0,0,0,0.04)" }}>
                  <th style={{ textAlign: "left", padding: "10px 12px" }}>
                    Domain
                  </th>
                  <th style={{ textAlign: "left", padding: "10px 12px" }}>
                    Verdict
                  </th>
                  <th style={{ textAlign: "left", padding: "10px 12px" }}>
                    Source
                  </th>
                  <th style={{ textAlign: "left", padding: "10px 12px" }}>
                    Reason
                  </th>
                  <th style={{ textAlign: "right", padding: "10px 12px" }}>
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} style={{ borderTop: "1px solid #e5e7eb" }}>
                    <td
                      style={{ padding: "10px 12px", fontFamily: "monospace" }}
                    >
                      {rule.domain}
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <VerdictPill verdict={rule.verdict} />
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span
                        title={SOURCE_HELP[rule.source] || ""}
                        style={{ opacity: 0.8 }}
                      >
                        {rule.source}
                      </span>
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        opacity: 0.8,
                        maxWidth: 340,
                      }}
                    >
                      {rule.reason || "—"}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        textAlign: "right",
                        whiteSpace: "nowrap",
                      }}
                    >
                      <Button
                        variant="ghost"
                        onClick={() => handleFlip(rule)}
                        disabled={busyId === rule.id}
                        title={`Change to ${rule.verdict === "allow" ? "DENY" : "ALLOW"}`}
                      >
                        {rule.verdict === "allow" ? "Set deny" : "Set allow"}
                      </Button>{" "}
                      <Button
                        variant="danger"
                        onClick={() => setConfirm(rule)}
                        disabled={busyId === rule.id}
                      >
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pageCount > 1 && (
          <div
            style={{
              display: "flex",
              gap: 10,
              alignItems: "center",
              marginTop: 14,
            }}
          >
            <Button
              variant="ghost"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              Previous
            </Button>
            <span style={{ fontSize: 13, opacity: 0.75 }}>
              Page {page + 1} of {pageCount} · {total} rules
            </span>
            <Button
              variant="ghost"
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={page >= pageCount - 1}
            >
              Next
            </Button>
          </div>
        )}
      </div>

      <ConfirmDialog
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
        onConfirm={handleDelete}
        onCancel={() => setConfirm(null)}
      />
    </AppLayout>
  );
}
