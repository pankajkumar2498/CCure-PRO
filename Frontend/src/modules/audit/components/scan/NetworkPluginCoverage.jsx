import { CcureAlert, CcureTable } from "../../../../design-system";

const LABELS = {
  completed_with_findings: "Completed with findings",
  completed_with_no_findings: "Completed with no findings",
  skipped: "Skipped",
  unsupported: "Unsupported",
  failed: "Failed",
  timed_out: "Timed out",
};

export default function NetworkPluginCoverage({ coverage, hosts = [] }) {
  const outcomes = hosts.flatMap((host) =>
    (host.plugin_outcomes || []).map((outcome) => ({
      host: host.ip_address || host.ip,
      ...outcome,
    })),
  );
  const recorded = coverage?.recorded || outcomes.length > 0;
  const complete =
    recorded &&
    (coverage?.complete ?? outcomes.every((o) => o.coverage_complete));
  const rows = outcomes.length ? outcomes : coverage?.incomplete || [];

  return (
    <section aria-label="Network plugin coverage">
      <CcureAlert
        variant={complete ? "info" : "warning"}
        live={false}
        title={
          complete
            ? "Selected plugin checks completed"
            : recorded
              ? "Plugin coverage incomplete"
              : "Plugin coverage unverified"
        }
      >
        {complete
          ? "The selected plugin checks recorded complete execution outcomes. This does not establish coverage of every vulnerability."
          : recorded
            ? "Some checks failed, timed out, were skipped or lack complete execution evidence. Absence of findings does not establish a clean assessment."
            : "This scan did not record per-plugin execution outcomes. Its coverage cannot be verified."}
      </CcureAlert>
      {rows.length > 0 && (
        <details>
          <summary>View plugin outcomes ({rows.length})</summary>
          <CcureTable
            caption="Plugin execution outcomes"
            rows={rows}
            rowKey={(row) => `${row.host}/${row.plugin}`}
            columns={[
              { key: "host", header: "Host" },
              { key: "plugin", header: "Plugin" },
              {
                key: "status",
                header: "Outcome",
                cell: (row) => LABELS[row.status] || "Unverified",
              },
              {
                key: "coverage",
                header: "Coverage",
                cell: (row) =>
                  row.coverage_complete ? "Complete" : "Incomplete",
              },
              { key: "detail", header: "Detail" },
            ]}
          />
        </details>
      )}
    </section>
  );
}
