# Web Application Gap-Closure — Phase 7: JavaScript Dependency Security

Dedicated detection of vulnerable front-end JavaScript libraries
(`core/web/js_deps`), a DETECT stage. Matches detected libraries against the
vulnerability intelligence CCureAudit already carries — no new feed, no invented
CVEs.

## Detection

From each page's `<script src>` and inline banners it identifies **library +
version** for common front-end libraries (jQuery, jQuery UI/Migrate, AngularJS,
Vue, React, Lodash, Bootstrap, Moment, Handlebars, Underscore, DOMPurify,
Axios):

- **URL / filename** (no fetch): `jquery-1.12.4.min.js`, cdnjs
  `/ajax/libs/jquery/3.4.1/`, unpkg/jsdelivr `vue@2.6.10`, `?ver=` query.
- **Content banner** (minified-safe): license comments such as
  `/*! jQuery v1.12.4 */`, `@license AngularJS v1.7.8`, `Lodash VERSION=…`.

CDN-hosted libraries are handled: the version is usually in the URL, so most
need no fetch. Network use is bounded — each unique script is fetched at most
once (capped), only when the URL alone did not yield a version.

## Matching (existing intelligence, no invented CVEs)

Detected `(npm package, version)` is matched against the **OSV npm feed** in
`vuln_intel`: an advisory is reported only when one of its affected ranges
`[introduced, fixed)` actually contains the version (semver comparison). CVSS,
severity and CWE are enriched from the NVD-backed `vulnerability_definitions`
catalogue when the CVE is present; when it is not, the finding still reports the
identifier and a conservative severity, stating that no local CVSS was
available — nothing is fabricated.

## Finding (existing model)

`vulnerable_js_library` (OWASP A06), carrying library, version, vulnerability id
(CVE + OSV/GHSA), CWE, CVSS + vector, severity, affected resource URL, evidence,
remediation (upgrade to the fixed version) and source (OSV). Deduplicated by
`(library, version, vulnerability id)` across pages.

## Tests

`tests/web/test_js_deps_engine.py` — 9 tests: URL detection variants, banner
detection, minified-banner detection, version-range logic, vulnerable library
detected + enriched, **non-vulnerable (patched) version → no finding**,
duplicate prevention, unknown library → no finding, and a **live OSV** match of
old jQuery (skipped if the feed is unavailable). OSV/enrichment are injectable
for deterministic unit tests.

## End-to-end (real feeds)

Against jQuery 1.12.4, the live OSV npm feed returned 4 genuine advisories
(CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023), enriched from
the NVD catalogue (e.g. CVSS 6.1, CWE-79); CDN-URL detection resolved the
version without a fetch.

## Regression

web + reports + security re-run green.
