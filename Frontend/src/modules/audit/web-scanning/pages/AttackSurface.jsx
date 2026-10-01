/**
 * modules/web-scanning/pages/AttackSurface.jsx
 * The attack surface a DAST scan mapped: parameters (with per-engine coverage),
 * forms, and REST/GraphQL/SOAP API operations.
 *
 * These are the first-class site-map entities the backend now records
 * (web_parameters, web_forms, web_api_operations). The page is read-only and
 * scoped entirely by the route `id`; each section fetches independently so one
 * empty inventory does not blank the others. It does not poll.
 */
import { useState, useEffect, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import {
  CcureBadge,
  CcureCard,
  CcureEmptyState,
  CcureSkeleton,
  CcureTable,
} from "../../../../design-system";
import "../styles/web-scanning-pages.css";

const METHOD_VARIANT = {
  GET: "info",
  POST: "success",
  PUT: "warning",
  PATCH: "warning",
  DELETE: "danger",
};
const KIND_VARIANT = { rest: "info", graphql: "success", soap: "warning" };
const LOCATION_VARIANT = {
  query: "info",
  form: "neutral",
  json: "success",
  path: "warning",
  cookie: "danger",
  header: "danger",
  multipart: "warning",
  soap: "warning",
};

export default function AttackSurface() {
  const { id } = useParams();
  const [params, setParams] = useState([]);
  const [coverage, setCoverage] = useState(null);
  const [forms, setForms] = useState([]);
  const [ops, setOps] = useState([]);
  const [opsByKind, setOpsByKind] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      try {
        const [pRes, fRes, oRes] = await Promise.all([
          webScansApi.getParameters(id, { per_page: 500 }),
          webScansApi.getForms(id, { per_page: 200 }),
          webScansApi.getApiOperations(id, { per_page: 500 }),
        ]);
        if (!active) return;
        setParams(pRes.data?.data || []);
        setCoverage(pRes.data?.coverage || null);
        setForms(fRes.data?.data || []);
        setOps(oRes.data?.data || []);
        setOpsByKind(oRes.data?.by_kind || {});
      } catch (err) {
        console.error("Failed to load attack surface", err);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [id]);

  // The coverage ledger records a parameter per (endpoint, location, name), so
  // the same cookie/header appears once per endpoint. Aggregate by
  // (location, name) for a readable inventory: a parameter is "tested" if any
  // endpoint's copy was tested, the engines are the union, and the endpoint
  // count is shown so the per-endpoint detail is not lost. The raw per-endpoint
  // rows remain available on the /parameters API.
  const aggregatedParams = useMemo(() => {
    const byKey = new Map();
    for (const p of params) {
      const key = `${p.location}|${p.name}`;
      let g = byKey.get(key);
      if (!g) {
        g = {
          id: key,
          location: p.location,
          name: p.name,
          source: p.source,
          endpoints: 0,
          tested: false,
          tested_by: new Set(),
        };
        byKey.set(key, g);
      }
      g.endpoints += 1;
      if (p.tested) {
        g.tested = true;
        (p.tested_by || []).forEach((e) => g.tested_by.add(e));
      }
    }
    return Array.from(byKey.values())
      .map((g) => ({ ...g, tested_by: Array.from(g.tested_by).sort() }))
      .sort(
        (a, b) =>
          Number(a.tested) - Number(b.tested) ||
          a.location.localeCompare(b.location) ||
          a.name.localeCompare(b.name),
      );
  }, [params]);

  const paramColumns = [
    {
      key: "location",
      header: "Location",
      nowrap: true,
      cell: (p) => (
        <CcureBadge variant={LOCATION_VARIANT[p.location] || "neutral"} mono>
          {p.location}
        </CcureBadge>
      ),
    },
    {
      key: "name",
      header: "Parameter",
      isRowHeader: true,
      mono: true,
      cell: (p) => <span className="wsp-target">{p.name}</span>,
    },
    {
      key: "tested",
      header: "Coverage",
      nowrap: true,
      cell: (p) =>
        p.tested ? (
          <CcureBadge variant="success">
            Tested{p.tested_by?.length ? ` · ${p.tested_by.join(", ")}` : ""}
          </CcureBadge>
        ) : (
          <CcureBadge variant="warning" title={p.skipped_reason || ""}>
            Untested
          </CcureBadge>
        ),
    },
    {
      key: "endpoints",
      header: "Endpoints",
      align: "end",
      nowrap: true,
      cell: (p) => <span className="wsp-muted">{p.endpoints}</span>,
    },
    {
      key: "source",
      header: "Source",
      cell: (p) => <span className="wsp-muted">{p.source}</span>,
    },
  ];

  const formColumns = [
    {
      key: "method",
      header: "Method",
      nowrap: true,
      cell: (f) => (
        <CcureBadge
          variant={
            METHOD_VARIANT[(f.method || "GET").toUpperCase()] || "neutral"
          }
          mono
        >
          {(f.method || "GET").toUpperCase()}
        </CcureBadge>
      ),
    },
    {
      key: "action_url",
      header: "Action",
      isRowHeader: true,
      mono: true,
      cell: (f) => <span className="wsp-target">{f.action_url}</span>,
    },
    {
      key: "input_count",
      header: "Inputs",
      align: "end",
      nowrap: true,
      cell: (f) => <span className="wsp-muted">{f.input_count}</span>,
    },
    {
      key: "flags",
      header: "Flags",
      cell: (f) => {
        const flags = [];
        if (f.has_password)
          flags.push(
            <CcureBadge key="pw" variant="warning">
              Password
            </CcureBadge>,
          );
        if (f.has_file_upload)
          flags.push(
            <CcureBadge key="up" variant="danger">
              File upload
            </CcureBadge>,
          );
        return flags.length ? <div className="wsp-flags">{flags}</div> : null;
      },
    },
  ];

  const opColumns = [
    {
      key: "kind",
      header: "Kind",
      nowrap: true,
      cell: (o) => (
        <CcureBadge variant={KIND_VARIANT[o.kind] || "neutral"} mono>
          {o.kind}
        </CcureBadge>
      ),
    },
    {
      key: "identity",
      header: "Operation",
      isRowHeader: true,
      mono: true,
      cell: (o) => <span className="wsp-target">{o.identity}</span>,
    },
    {
      key: "spec_source",
      header: "Source",
      cell: (o) => <span className="wsp-muted">{o.spec_source || "-"}</span>,
    },
    {
      key: "secured",
      header: "Auth",
      nowrap: true,
      cell: (o) =>
        o.secured === true ? (
          <CcureBadge variant="success">Secured</CcureBadge>
        ) : o.secured === false ? (
          <CcureBadge variant="warning">Unsecured</CcureBadge>
        ) : (
          <span className="wsp-muted">—</span>
        ),
    },
  ];

  return (
    <AppLayout pageTitle="Attack Surface">
      <div className="page-inner wsp-page wsp-page--wide">
        <div className="wsp-header">
          <div>
            <Link to={`/web-scans/${id}`} className="wsp-back">
              ← Back to Scan Detail
            </Link>
            <h1 className="page-title">Attack Surface</h1>
            <p className="page-subtitle">
              Parameters, forms and API operations discovered on this target
            </p>
          </div>
        </div>

        {loading ? (
          <div className="wsp-loading" role="status" aria-live="polite">
            <span className="cc-sr-only">Loading attack surface…</span>
            <CcureSkeleton height="120px" radius="12px" />
            <CcureSkeleton height="120px" radius="12px" />
            <CcureSkeleton height="120px" radius="12px" />
          </div>
        ) : (
          <>
            {coverage && (
              <CcureCard title="Parameter Coverage" headingLevel={2}>
                <div className="wsp-meta">
                  <CcureBadge variant="neutral">
                    Surface: {coverage.surface_parameters}
                  </CcureBadge>
                  <CcureBadge variant="success">
                    Tested: {coverage.tested_parameters}
                  </CcureBadge>
                  <CcureBadge
                    variant={
                      coverage.untested_parameters ? "warning" : "neutral"
                    }
                  >
                    Untested: {coverage.untested_parameters}
                  </CcureBadge>
                  <CcureBadge variant="info">
                    Coverage: {coverage.coverage_pct}%
                  </CcureBadge>
                </div>
              </CcureCard>
            )}

            <CcureCard
              title={`Parameters (${aggregatedParams.length})`}
              headingLevel={2}
              flush
              bodyFlush
            >
              {aggregatedParams.length === 0 ? (
                <CcureEmptyState
                  title="No parameters"
                  description="No parameters were recorded for this scan."
                />
              ) : (
                <CcureTable
                  caption={`Discovered parameters — ${aggregatedParams.length} unique (${params.length} across endpoints)`}
                  columns={paramColumns}
                  rows={aggregatedParams}
                  rowKey={(p) => p.id}
                  density="comfortable"
                />
              )}
            </CcureCard>

            <CcureCard
              title={`Forms (${forms.length})`}
              headingLevel={2}
              flush
              bodyFlush
            >
              {forms.length === 0 ? (
                <CcureEmptyState
                  title="No forms"
                  description="No HTML forms were discovered on this target."
                />
              ) : (
                <CcureTable
                  caption={`Discovered forms — ${forms.length}`}
                  columns={formColumns}
                  rows={forms}
                  rowKey={(f) => f.id}
                  density="comfortable"
                />
              )}
            </CcureCard>

            <CcureCard
              title={`API Operations (${ops.length})`}
              headingLevel={2}
              flush
              bodyFlush
              actions={
                <div className="wsp-meta">
                  {Object.entries(opsByKind).map(([k, n]) => (
                    <CcureBadge key={k} variant={KIND_VARIANT[k] || "neutral"}>
                      {k}: {n}
                    </CcureBadge>
                  ))}
                </div>
              }
            >
              {ops.length === 0 ? (
                <CcureEmptyState
                  title="No API operations"
                  description="No REST, GraphQL or SOAP operations were discovered."
                />
              ) : (
                <CcureTable
                  caption={`Discovered API operations — ${ops.length}`}
                  columns={opColumns}
                  rows={ops}
                  rowKey={(o) => o.id}
                  density="comfortable"
                />
              )}
            </CcureCard>
          </>
        )}
      </div>
    </AppLayout>
  );
}
