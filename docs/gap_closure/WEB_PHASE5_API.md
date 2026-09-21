# Web Application Gap-Closure — Phase 5: Structured API Security Testing

Turns the existing ad-hoc API discovery into structured API testing: OpenAPI /
Swagger import, GraphQL discovery + introspection, a normalized API inventory,
and API-specific checks — integrated into the existing pipeline.

## Reuse, not a second scanner

`core/web/api_scan/` runs in the CRAWL phase and converts the API surface into
ordinary `endpoints` and `forms` in the exact shape the crawl already produces.
So the existing DETECT engines — sqlmap (SQLi), the Phase 1 XSS engine, the
Phase 2 injection engine and the Phase 4 access-control engine — test API query
parameters, path identifiers and JSON request bodies with **no per-engine
change**. Only genuinely API-specific conditions are raised here. There is no
second finding store.

## OpenAPI / Swagger

- Sources: an **inline** spec (`options.api_spec`), a **URL**
  (`options.api_spec_url`), or **discovery** at a bounded set of well-known
  paths (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, …).
- Parses **2.x and 3.x**: base URL (`servers` / `host`+`basePath`+`schemes`),
  paths, methods, parameters (query/path/header, and body/formData in 2.x /
  `requestBody` in 3.x, resolving `$ref` schemas), and security schemes.
- Produces a normalized inventory (operation count, secured count, security
  schemes) and concrete endpoints (path params filled, query appended) plus
  body **forms** for POST/PUT/PATCH so injection/XSS test the fields.

## GraphQL

Probes a configured (`options.graphql_url`) or discovered endpoint with a single
introspection query. Introspection is reported **only when the server actually
answers `__schema`** — it is never assumed. A disabled endpoint is inventoried,
not flagged.

## API-specific findings (existing finding model)

- `graphql_introspection` (CWE-200, medium) — introspection enabled.
- `api_missing_auth` (CWE-306) — a spec-declared-secure operation that answers
  an unauthenticated request (high), or a spec with no security scheme at all
  (medium, advisory).
- (`excessive_data_exposure` (CWE-213) is defined for future body-shape checks.)

All map to OWASP (A05/A07/A01) via `standards_mapping`. No CVE invented.

## Authentication

The importer sends the scan's configured session (bearer / cookie / API-key /
custom headers) via the Phase 3 session manager; credentials are never logged
or placed in findings.

## Tests

`tests/web/test_api_scan_engine.py` — 7 tests against a controlled API (OpenAPI
spec + GraphQL + a command-injectable operation): OpenAPI discovered+imported,
import from explicit URL, GraphQL introspection enabled → finding, introspection
disabled → no finding, missing-authentication detected, non-API target clean,
and **an imported endpoint fed to the Phase 2 injection engine yields a
command-injection finding** (proving the reuse). SQLi/XSS/IDOR on API endpoints
are covered by the Phases 1–4 engines the import feeds.

## Regression

web + reports + security suites re-run; existing web scanning unchanged (the new
option fields default on/None so existing request bodies validate unchanged).
