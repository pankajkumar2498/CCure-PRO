/**
 * The whole software inventory the credentialed session enumerated.
 *
 * The page already had a *Packages with Vulnerabilities* section, which
 * filters to the subset matching a finding — on a real Windows host, 20 of
 * 191. The other 171 were collected, returned by the API and invisible, so an
 * operator could not answer "is this product installed" from a scan that knew
 * the answer.
 *
 * **The vulnerability column is a join, not an API field.** `packages[]`
 * carries `{name, version, arch, vendor, manager}` and nothing about
 * vulnerabilities; the association comes from matching `cves[].package`, which
 * is the same join the existing section performs. It is labelled as a match
 * rather than a property, because presenting a derived value as though the
 * backend asserted it is how a UI ends up making claims the scan did not.
 *
 * A package with no match is shown as "no match", never as "not vulnerable" —
 * coverage is bounded (see Package Coverage) and most of these were never
 * assessable in the first place.
 */

import { useMemo, useState } from "react";
import {
  CcureBadge,
  CcureInput,
  CcurePagination,
  CcureTable,
} from "../../design-system";
import usePagedRows from "../../hooks/usePagedRows";

export default function PackageInventorySection({
  packages,
  cves,
  packagesEnumerated = null,
}) {
  const [search, setSearch] = useState("");
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [sort, setSort] = useState({ key: "name", direction: "ascending" });

  const rows = useMemo(() => packages || [], [packages]);

  /** package name (lowercased) → the CVE ids matched against it. */
  const cveIndex = useMemo(() => {
    const index = new Map();
    for (const finding of cves || []) {
      const key = String(finding.package || "").toLowerCase();
      if (!key) continue;
      const id = finding.cve_id || finding.cve;
      if (!id) continue;
      if (!index.has(key)) index.set(key, new Set());
      index.get(key).add(id);
    }
    return index;
  }, [cves]);

  const needle = search.trim().toLowerCase();

  const paged = usePagedRows(rows, {
    filter: (pkg) => {
      const name = String(pkg.name || "").toLowerCase();
      if (onlyVulnerable && !cveIndex.has(name)) return false;
      if (!needle) return true;
      return (
        name.includes(needle) ||
        String(pkg.version || "")
          .toLowerCase()
          .includes(needle) ||
        String(pkg.vendor || "")
          .toLowerCase()
          .includes(needle) ||
        String(pkg.manager || "")
          .toLowerCase()
          .includes(needle)
      );
    },
    sorter: (a, b) => {
      const dir = sort.direction === "descending" ? -1 : 1;
      return (
        String(a[sort.key] ?? "")
          .toLowerCase()
          .localeCompare(String(b[sort.key] ?? "").toLowerCase()) * dir
      );
    },
    resetKey: `${needle}|${onlyVulnerable}|${sort.key}|${sort.direction}`,
    initialPageSize: 50,
  });

  if (rows.length === 0) {
    return (
      <p className="pi-empty">
        No software inventory was collected from this host, so nothing can be
        said about what is installed on it.
      </p>
    );
  }

  return (
    <div className="pi-root">
      <div className="pi-toolbar">
        <p className="pi-note">
          {Number(packagesEnumerated ?? rows.length).toLocaleString()} package
          {rows.length === 1 ? "" : "s"} enumerated. The CVE column shows
          findings <em>matched to</em> a package; an empty cell means no match,
          not that the package is free of vulnerabilities.
        </p>
        <div className="pi-controls">
          <label className="pi-toggle">
            <input
              type="checkbox"
              checked={onlyVulnerable}
              onChange={(e) => setOnlyVulnerable(e.target.checked)}
            />
            Only packages with matched findings
          </label>
          <CcureInput
            type="search"
            /* Not "Search packages": the page also has a *Packages with
               Vulnerabilities* section with a box of that name, and two
               searchboxes sharing an accessible name are indistinguishable to
               anyone navigating by label. */
            label="Search installed software"
            placeholder="Name, version, vendor or manager…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            fieldClassName="pi-search"
          />
        </div>
      </div>

      {paged.total === 0 ? (
        <p className="pi-note">No packages match the current filter.</p>
      ) : (
        <>
          <CcureTable
            caption="Installed software inventory"
            density="compact"
            sort={sort}
            onSortChange={setSort}
            rows={paged.rows}
            rowKey={(pkg, i) =>
              `${pkg.name || "pkg"}-${pkg.version || ""}-${i}`
            }
            columns={[
              {
                key: "name",
                header: "Package",
                isRowHeader: true,
                sortable: true,
              },
              { key: "version", header: "Version", mono: true, sortable: true },
              {
                key: "arch",
                header: "Arch",
                cell: (pkg) => pkg.arch || <span className="pi-muted">—</span>,
              },
              {
                key: "vendor",
                header: "Vendor",
                sortable: true,
                cell: (pkg) =>
                  pkg.vendor || <span className="pi-muted">—</span>,
              },
              {
                key: "manager",
                header: "Source",
                sortable: true,
                cell: (pkg) => (
                  <span className="pi-muted">{pkg.manager || "—"}</span>
                ),
              },
              {
                key: "matched",
                header: "Matched findings",
                cell: (pkg) => {
                  const matched = cveIndex.get(
                    String(pkg.name || "").toLowerCase(),
                  );
                  if (!matched || matched.size === 0) {
                    return <span className="pi-muted">No match</span>;
                  }
                  return (
                    <CcureBadge variant="warning">
                      {matched.size} CVE{matched.size === 1 ? "" : "s"}
                    </CcureBadge>
                  );
                },
              },
            ]}
          />
          <CcurePagination
            page={paged.page}
            pageSize={paged.pageSize}
            total={paged.total}
            onPageChange={paged.setPage}
            onPageSizeChange={paged.setPageSize}
            itemNoun="packages"
          />
        </>
      )}
    </div>
  );
}
