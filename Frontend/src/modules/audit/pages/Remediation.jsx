/**
 * Remediation and SLA — one workspace over twelve operations.
 *
 * The backend answers four different questions here and they are kept apart
 * rather than merged into one screen-wide table, because merging them would
 * mean inventing a query the API does not offer:
 *
 * * **How much is there** — `GET /summary`, two aggregate queries over every
 *   finding in the organisation. It carries `summary_line`, which the backend
 *   assembles in one place precisely so a report and a dashboard cannot render
 *   it differently. It is printed verbatim for that reason.
 *
 * * **What is late** — `GET /overdue`.
 * * **What is waiting on a scan** — `GET /pending-verification`.
 *
 *   Those two are the *only* server-side queues. There is no
 *   `remediation_state` filter on any listing endpoint, so the other five
 *   states are reported as counts and are not drillable. Fetching every
 *   finding and filtering here would be several thousand rows through the
 *   browser to synthesise a query the API declined to offer, and the count it
 *   produced would disagree with `summary` the moment a page boundary fell
 *   inside it. The limitation is stated on the screen instead.
 *
 * * **What are the deadlines** — `GET/PUT /sla-policy`, which takes
 *   `settings:update` rather than `findings:update`.
 *
 * The listings return ids and nothing else — `asset_id`, `remediation.owner`,
 * `vuln_id`. Hosts are resolved through one `/assets` read and owners through
 * one `/admin/users` read, so a page of 200 rows costs two extra requests
 * rather than 400. Neither is invented: an id that resolves to nothing is
 * shown as the id.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcureModal,
  CcurePagination,
  CcureSelect,
  CcureTable,
  CcureCheckbox,
  CcureTabs,
  CcureTabPanel,
  CcurePage,
  CcurePageHeader,
} from "../../../design-system";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import { getAssets } from "@audit/api/assets";
import { listUsers } from "@shell/api/admin";
import {
  REMEDIATION_STATES,
  STATE_LABELS,
  assignFindings,
  dueDescription,
  getRemediationSummary,
  listOverdue,
  listPendingVerification,
  remediationErrorMessage,
} from "@audit/api/remediation";
import {
  RemediationStateBadge,
  SeverityBadge,
  SlaStateBadge,
} from "@audit/components/remediation/RemediationBadges";
import FindingRemediationPanel from "@audit/components/remediation/FindingRemediationPanel";
import SlaPolicyPanel from "@audit/components/remediation/SlaPolicyPanel";
import "../styles/remediation.css";

const QUEUES = [
  {
    key: "overdue",
    label: "Overdue",
    fetch: listOverdue,
    blurb:
      "Past their due date and still active. Verified-fixed and risk-accepted findings are excluded by the API: nothing further is owed on either, and counting them as late would bury the ones that are.",
  },
  {
    key: "pending",
    label: "Pending verification",
    fetch: listPendingVerification,
    blurb:
      "Somebody has said the work is done. A finding stays here until a later scan stops detecting it — no action on this screen can move it to verified fixed.",
  },
];

const when = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleDateString();
};

export default function Remediation() {
  const { user } = useAuth();
  const canRead = can(user, "audit.finding.read");
  const canUpdate = can(user, "audit.finding.update");
  const canAcceptRisk = can(user, "audit.finding.accept_risk");
  const canEditSla = can(user, "audit.remediation.manage_sla");
  const canListUsers = can(user, "platform.user.read");

  const [params, setParams] = useSearchParams();
  const [queueKey, setQueueKey] = useState(QUEUES[0].key);

  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState("");

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [ownerFilter, setOwnerFilter] = useState("");

  const [hosts, setHosts] = useState({});
  const [people, setPeople] = useState([]);

  const [selected, setSelected] = useState(() => new Set());
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignOwner, setAssignOwner] = useState("");
  const [assignNote, setAssignNote] = useState("");
  const [assignBusy, setAssignBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  const openId = params.get("finding_id") || "";

  const queue = QUEUES.find((q) => q.key === queueKey) || QUEUES[0];

  const loadSummary = useCallback(async () => {
    try {
      const { data } = await getRemediationSummary();
      setSummary(data);
      setSummaryError("");
    } catch (err) {
      setSummaryError(
        remediationErrorMessage(err, "Could not read the remediation summary."),
      );
    }
  }, []);

  const loadList = useCallback(async () => {
    setLoading(true);
    setListError("");
    try {
      const { data } = await queue.fetch({
        limit: pageSize,
        offset: (page - 1) * pageSize,
        ...(ownerFilter ? { owner_id: ownerFilter } : {}),
      });
      setRows(data.findings || []);
      // `total` counts every match and is never truncated by `limit`; only
      // the list is a page.
      setTotal(data.total || 0);
      setSelected(new Set());
    } catch (err) {
      setListError(remediationErrorMessage(err, "Could not read this queue."));
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [queue, page, pageSize, ownerFilter]);

  useEffect(() => {
    if (!canRead) return;
    loadSummary();
  }, [canRead, loadSummary]);

  useEffect(() => {
    if (!canRead) return;
    loadList();
  }, [canRead, loadList]);

  /* One read each, not one per row. An unresolved id is shown as the id. */
  useEffect(() => {
    if (!canRead) return;
    getAssets({ limit: 500 })
      .then(({ data }) => {
        const map = {};
        for (const a of data?.assets || []) {
          map[a.id] = a.hostname
            ? `${a.ip_address} (${a.hostname})`
            : a.ip_address;
        }
        setHosts(map);
      })
      .catch(() => setHosts({}));
  }, [canRead]);

  useEffect(() => {
    if (!canListUsers) return;
    listUsers({ limit: 200 })
      .then((data) => setPeople(data?.users || []))
      .catch(() => setPeople([]));
  }, [canListUsers]);

  /* The assign endpoint refuses an owner outside the caller's organisation,
     so the picker offers only people inside it. A superadmin's user listing
     spans tenants. */
  const assignable = useMemo(() => {
    const org = user?.organization_id || user?.org_id;
    if (!org) return people;
    return people.filter((p) => String(p.organization_id) === String(org));
  }, [people, user]);

  const ownerLabel = useCallback(
    (id) => {
      if (!id) return null;
      const match = people.find((p) => p.id === id);
      return match ? match.full_name || match.username || match.email : id;
    },
    [people],
  );

  if (!canRead) {
    return (
      <AppLayout>
        <CcurePage>
          <CcureAlert variant="warning">
            {denyMessage} Viewing remediation needs the{" "}
            <strong>findings:read</strong> permission.
          </CcureAlert>
        </CcurePage>
      </AppLayout>
    );
  }

  const toggle = (id) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const columns = [
    ...(canUpdate
      ? [
          {
            key: "_sel",
            header: "",
            width: "36px",
            cell: (row) => (
              <CcureCheckbox
                checked={selected.has(row.finding_id)}
                onChange={() => toggle(row.finding_id)}
                aria-label={`Select ${row.vuln_id}`}
              />
            ),
          },
        ]
      : []),
    {
      key: "vuln_id",
      header: "Finding",
      cell: (row) => (
        <CcureButton
          variant="ghost"
          size="sm"
          type="button"
          className="rmd-link"
          onClick={() => {
            const next = new URLSearchParams(params);
            next.set("finding_id", row.finding_id);
            setParams(next);
          }}
        >
          {row.vuln_id}
        </CcureButton>
      ),
    },
    {
      key: "asset_id",
      header: "Host",
      cell: (row) => hosts[row.asset_id] || row.asset_id,
    },
    {
      key: "severity",
      header: "Severity",
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: "state",
      header: "State",
      cell: (row) => <RemediationStateBadge state={row.remediation?.state} />,
    },
    {
      key: "owner",
      header: "Owner",
      cell: (row) =>
        row.remediation?.owner ? (
          ownerLabel(row.remediation.owner)
        ) : (
          <span className="rmd-muted">Unassigned</span>
        ),
    },
    {
      key: "due_at",
      header: "Due",
      cell: (row) => when(row.sla?.due_at),
    },
    {
      key: "sla",
      header: "SLA",
      cell: (row) => (
        <div className="rmd-slacell">
          <SlaStateBadge state={row.sla?.state} />
          <small className="rmd-muted">{dueDescription(row.sla)}</small>
        </div>
      ),
    },
  ];

  const doAssign = async (owner_id) => {
    setAssignBusy(true);
    try {
      const { data } = await assignFindings({
        finding_ids: [...selected],
        owner_id: owner_id || null,
        note: assignNote || null,
      });
      setNotice({
        variant: "success",
        text: `${data.changed} of ${data.requested} findings changed (${data.matched} matched).`,
      });
      setAssignOpen(false);
      setAssignOwner("");
      setAssignNote("");
      await Promise.all([loadList(), loadSummary()]);
    } catch (err) {
      setNotice({
        variant: "danger",
        text: remediationErrorMessage(err, "The API refused this assignment."),
      });
    } finally {
      setAssignBusy(false);
    }
  };

  return (
    <AppLayout>
      <CcurePage className="rmd-page">
        <CcurePageHeader
          title="Remediation"
          subtitle="Who owns a finding, when it is due, and whether a scan has agreed it was fixed."
        />

        {notice ? (
          <CcureAlert variant={notice.variant} onClose={() => setNotice(null)}>
            {notice.text}
          </CcureAlert>
        ) : null}

        {summaryError ? (
          <CcureAlert variant="danger">{summaryError}</CcureAlert>
        ) : null}

        {summary ? (
          <section className="rmd-summary">
            {/* Printed as the backend assembled it. The report renders the
                same string, and two places computing it separately is how
                they come to disagree. */}
            <p className="rmd-summary__line">{summary.summary_line}</p>

            <div className="rmd-metrics">
              {REMEDIATION_STATES.map((s) => (
                <div className="rmd-metric" key={s}>
                  <div className="rmd-metric__n">
                    {summary.by_state?.[s] ?? 0}
                  </div>
                  <div className="rmd-metric__l">{STATE_LABELS[s]}</div>
                </div>
              ))}
            </div>

            <div className="rmd-metrics">
              <div className="rmd-metric rmd-metric--bad">
                <div className="rmd-metric__n">{summary.overdue}</div>
                <div className="rmd-metric__l">Overdue</div>
              </div>
              <div className="rmd-metric">
                <div className="rmd-metric__n">{summary.within_sla}</div>
                <div className="rmd-metric__l">Within SLA</div>
              </div>
              <div className="rmd-metric">
                <div className="rmd-metric__n">{summary.no_sla}</div>
                {/* Deliberately not folded into "within SLA": having no
                    deadline and being comfortably inside one are different
                    facts, and the backend counts them apart. */}
                <div className="rmd-metric__l">No deadline applies</div>
              </div>
            </div>

            <p className="rmd-note">
              The SLA figures cover active findings only. Counts by state are
              over every finding in the organisation.{" "}
              <strong>
                Only Overdue and Pending verification have a listing endpoint
              </strong>
              , so the other states are reported here as totals and are not
              drillable.
            </p>
          </section>
        ) : null}

        <section className="rmd-queues">
          <CcureTabs
            id="remediation-queues"
            label="Remediation queues"
            className="rmd-tabs"
            value={queueKey}
            onChange={(next) => {
              setQueueKey(next);
              setPage(1);
            }}
            tabs={QUEUES.map((q) => ({
              id: q.key,
              label: (
                <>
                  {q.label}
                  {q.key === "overdue" && summary ? (
                    <CcureBadge variant="danger">{summary.overdue}</CcureBadge>
                  ) : null}
                  {q.key === "pending" && summary ? (
                    <CcureBadge variant="warning">
                      {summary.by_state?.pending_verification ?? 0}
                    </CcureBadge>
                  ) : null}
                </>
              ),
            }))}
          />
          <CcureTabPanel id={queueKey} tabsId="remediation-queues" active>
            <p className="rmd-note">{queue.blurb}</p>

            <div className="rmd-toolbar">
              {canListUsers ? (
                <CcureSelect
                  label="Owner"
                  fieldClassName="rmd-owner-field"
                  value={ownerFilter}
                  onChange={(e) => {
                    setOwnerFilter(e.target.value);
                    setPage(1);
                  }}
                >
                  <option value="">Anyone</option>
                  {assignable.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.full_name || p.username || p.email}
                    </option>
                  ))}
                </CcureSelect>
              ) : (
                <CcureInput
                  label="Owner id"
                  fieldClassName="rmd-owner-field"
                  value={ownerFilter}
                  onChange={(e) => {
                    setOwnerFilter(e.target.value);
                    setPage(1);
                  }}
                  hint="Listing people needs users:read; filter by id instead."
                />
              )}

              {canUpdate ? (
                <CcureButton
                  variant="secondary"
                  disabled={selected.size === 0}
                  onClick={() => setAssignOpen(true)}
                >
                  Assign {selected.size || ""}
                </CcureButton>
              ) : null}
            </div>

            {listError ? (
              <CcureAlert variant="danger">{listError}</CcureAlert>
            ) : null}

            <CcureTable
              columns={columns}
              rows={rows}
              loading={loading}
              caption={`${queue.label} findings`}
              emptyMessage={
                queue.key === "overdue"
                  ? "Nothing is past its due date."
                  : "Nothing is waiting on a verification scan."
              }
            />

            <CcurePagination
              page={page}
              pageSize={pageSize}
              total={total}
              itemNoun="findings"
              onPageChange={setPage}
              onPageSizeChange={(n) => {
                setPageSize(n);
                setPage(1);
              }}
            />
          </CcureTabPanel>
        </section>

        <section className="rmd-slasection">
          <h2>SLA policy</h2>
          <SlaPolicyPanel canEdit={canEditSla} />
        </section>
      </CcurePage>

      <CcureModal
        open={assignOpen}
        onClose={() => setAssignOpen(false)}
        title={`Assign ${selected.size} finding${selected.size === 1 ? "" : "s"}`}
        subtitle="Leave the owner empty to unassign."
        footer={
          <>
            <CcureButton variant="ghost" onClick={() => setAssignOpen(false)}>
              Cancel
            </CcureButton>
            <CcureButton
              variant="primary"
              disabled={assignBusy}
              onClick={() => doAssign(assignOwner)}
            >
              {assignOwner ? "Assign" : "Unassign"}
            </CcureButton>
          </>
        }
      >
        {canListUsers ? (
          <CcureSelect
            label="Owner"
            value={assignOwner}
            onChange={(e) => setAssignOwner(e.target.value)}
          >
            <option value="">Nobody (unassign)</option>
            {assignable.map((p) => (
              <option key={p.id} value={p.id}>
                {p.full_name || p.username || p.email}
              </option>
            ))}
          </CcureSelect>
        ) : (
          <>
            <CcureButton
              variant="secondary"
              onClick={() => setAssignOwner(String(user?.id || ""))}
            >
              Assign to me
            </CcureButton>
            <CcureInput
              label="Owner id"
              value={assignOwner}
              onChange={(e) => setAssignOwner(e.target.value)}
              hint="Listing people needs users:read. The API refuses an owner outside this organisation."
            />
          </>
        )}
        <CcureInput
          label="Note (optional)"
          value={assignNote}
          onChange={(e) => setAssignNote(e.target.value)}
          maxLength={2000}
        />
      </CcureModal>

      <CcureModal
        open={Boolean(openId)}
        onClose={() => {
          const next = new URLSearchParams(params);
          next.delete("finding_id");
          setParams(next);
        }}
        title="Finding remediation"
        size="lg"
      >
        {openId ? (
          <FindingRemediationPanel
            findingId={openId}
            canUpdate={canUpdate}
            canAcceptRisk={canAcceptRisk}
            hostLabel={
              hosts[rows.find((r) => r.finding_id === openId)?.asset_id] ||
              undefined
            }
            onChanged={() => {
              loadList();
              loadSummary();
            }}
          />
        ) : null}
      </CcureModal>
    </AppLayout>
  );
}
