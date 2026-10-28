/**
 * The compliance workspace's Policies tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import React from "react";
import {
  CcureTableStatus,
  CcureTable,
  CcureButton,
  CcureBadge,
  CcureIcon,
  CcureSeverityBadge,
} from "../../../../../design-system";
import { PagingControls } from "./shared";

export default function CompliancePoliciesTab({
  expandedPolicyId,
  handleOpenEditRule,
  handleTogglePolicy,
  loading,
  loadingRules,
  policies,
  policiesPagination,
  policyRules,
}) {
  return (
    <section
      ref={policiesPagination.cardRef}
      className="cwv-policies cwv-view"
      aria-labelledby="cwv-policies-title"
    >
      <h2 id="cwv-policies-title" className="cwv-view__title">
        Policies
      </h2>
      <PagingControls
        pagination={policiesPagination}
        total={policies.length}
        loading={loading}
        label="Policies pagination"
        itemNoun="policies"
        sizes={[10, 25, 50, 100]}
      />
      <CcureTableStatus
        loading={loading && policies.length === 0}
        count={policies.length}
        noun="policies"
      />
      <CcureTable
        caption="Baseline policies"
        loading={loading && policies.length === 0}
        columns={[
          { key: "name", header: "Baseline Name" },
          { key: "platform", header: "Platform" },
          { key: "version", header: "Version" },
          { key: "rules", header: "Rules Count" },
          { key: "status", header: "Status" },
        ]}
      >
        {policies.length === 0 && !loading && (
          <tr>
            <td colSpan={5} className="cwv-table-message">
              No baseline policies defined. Click &quot;Create Baseline
              Policy&quot; to define one.
            </td>
          </tr>
        )}
        {policiesPagination.paginatedItems.map((p) => (
          <React.Fragment key={p.id}>
            <tr>
              <th scope="row" className="cwv-policy__name">
                <CcureButton
                  variant="ghost"
                  size="sm"
                  className="cwv-disclosure"
                  aria-expanded={expandedPolicyId === p.id}
                  aria-controls={
                    expandedPolicyId === p.id
                      ? `cwv-policy-rules-${p.id}`
                      : undefined
                  }
                  onClick={() => handleTogglePolicy(p.id)}
                >
                  <span className="cwv-disclosure__chevron" aria-hidden="true">
                    {expandedPolicyId === p.id ? "▼" : "▶"}
                  </span>
                  {p.name}
                </CcureButton>
              </th>
              <td>
                <CcureBadge>{p.target_platform}</CcureBadge>
              </td>
              <td className="cwv-mono">v{p.version_number}</td>
              <td className="cwv-strong">{p.rules_count}</td>
              <td>
                <CcureBadge variant="success">{p.status}</CcureBadge>
              </td>
            </tr>
            {expandedPolicyId === p.id && (
              <tr>
                <td
                  colSpan={5}
                  id={`cwv-policy-rules-${p.id}`}
                  className="cwv-policy__rules"
                >
                  <h3 className="cwv-policy__rules-title">
                    <CcureIcon name="clipboard" /> Policy Rules & Check
                    Parameters
                  </h3>
                  {loadingRules ? (
                    <p className="cwv-muted" role="status">
                      Loading policy rules...
                    </p>
                  ) : policyRules.length === 0 ? (
                    <p className="cwv-muted">No rules linked to this policy.</p>
                  ) : (
                    <div className="cwv-policy__rules-scroll">
                      <CcureTable
                        caption={`Rules in ${p.name}`}
                        stickyHeader
                        rows={policyRules}
                        rowKey={(r) => r.id}
                        columns={[
                          {
                            key: "control",
                            header: "Control ID",
                            isRowHeader: true,
                            mono: true,
                            nowrap: true,
                            cell: (r) =>
                              (() => {
                                // `String.replace` with a
                                // string pattern swaps only the
                                // first match, so a NIST CSF id
                                // like PR_AA_05 rendered as
                                // "PR.AA_05". The framework
                                // prefix is stripped generically
                                // and every separator replaced.
                                const rawNum =
                                  r.control_number ||
                                  (r.control_id
                                    ? r.control_id
                                        .replace(
                                          /^cct_[a-z0-9]+(?:_[a-z0-9]+)*?_(?=\d|[a-z]{2}_)/i,
                                          "",
                                        )
                                        .replace(/_/g, ".")
                                    : "");
                                if (
                                  rawNum.startsWith("A.") ||
                                  rawNum.startsWith("GV.") ||
                                  rawNum.startsWith("ID.") ||
                                  rawNum.startsWith("PR.") ||
                                  rawNum.startsWith("DE.") ||
                                  rawNum.startsWith("RS.") ||
                                  rawNum.startsWith("RC.")
                                ) {
                                  return rawNum;
                                }
                                if (/^\d+\.\d+/.test(rawNum)) {
                                  return `A.${rawNum}`;
                                }
                                return rawNum || "N/A";
                              })(),
                          },
                          {
                            key: "title",
                            header: "Rule & Control Title",
                            cell: (r) => (
                              <>
                                <span className="cwv-cell__title">
                                  {r.control_title}
                                </span>
                                <span className="cwv-cell__detail">
                                  Rule Code:{" "}
                                  <span className="cwv-mono">
                                    {r.rule_name}
                                  </span>
                                </span>
                              </>
                            ),
                          },
                          {
                            key: "severity",
                            header: "Severity",
                            cell: (r) => (
                              <CcureSeverityBadge
                                severity={r.severity || "medium"}
                              />
                            ),
                          },
                          {
                            key: "logic",
                            header: "Checking Logic",
                            cell: (r) =>
                              r.evidence_source === "manual" ? (
                                <CcureBadge>Manual Review</CcureBadge>
                              ) : (
                                <>
                                  <CcureBadge variant="primary">
                                    {r.evidence_source}
                                  </CcureBadge>
                                  {r.check_definition && (
                                    <code className="cwv-code">
                                      {r.check_definition.key}{" "}
                                      {r.check_definition.operator}{" "}
                                      {r.check_definition.expected}
                                    </code>
                                  )}
                                </>
                              ),
                          },
                          {
                            key: "actions",
                            header: "Actions",
                            cell: (r) => (
                              <CcureButton
                                variant="ghost"
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleOpenEditRule({
                                    rule_id: r.id,
                                    rule_name: r.rule_name,
                                    severity: r.severity,
                                    check_definition: r.check_definition,
                                    control_title: r.control_title,
                                    evidence: {},
                                  });
                                }}
                              >
                                Configure
                              </CcureButton>
                            ),
                          },
                        ]}
                      />
                    </div>
                  )}
                </td>
              </tr>
            )}
          </React.Fragment>
        ))}
      </CcureTable>
    </section>
  );
}
