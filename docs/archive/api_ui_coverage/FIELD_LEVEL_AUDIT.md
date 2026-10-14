# Field-level audit — Backend → API → Frontend → UI → Reports

Measured 23 Sep 2026 against the running deployment, on live payloads, at
`05ab46b` / closeout `6585fc8`. **No code was changed.** This is the evidence
and the classification; the implementation plan is §9.

The operation-level sweep (`PHASE7_MASTER_MATRIX.md`) asked _is this endpoint
called_ and answered 206/237. This asks the other half: **of everything the
endpoint returned, how much reaches the operator, and does it reach the
report.** A surface can be 100% reached and still drop most of its content —
and several do.

---

## 1. Method, and its three corrected defects

    docker exec -w /app ccure-api python /tmp/i.py > routes.json     # route table
    bash grab.sh                                                     # live payloads
    python3 scripts/audit/api_field_coverage.py \
        --manifest manifest.json --payloads payloads/

`scripts/audit/api_field_coverage.py` walks each **live** response to its leaf
keys and searches the files that are allowed to render that payload. Leaf keys,
not dotted paths, because JavaScript reaches `a.b.c` by destructuring, optional
chaining and renaming; and scoped to the renderer, because a whole-frontend
grep for `status` matches everything.

**The tool is a narrowing instrument, not a verdict.** Every finding below was
hand-verified against the source and the payload. Three defect classes were
found in the measurement itself and are recorded because a tool's false
negatives are indistinguishable from the gap it is hunting:

| #   | Defect                                                                                                                                                                 | Effect                             | Correction                                                                                     |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------- |
| 1   | **Wrong renderer scoped.** `phase3.data[].credentialed_report.*` was scoped to `Phase3Results.jsx`; it is rendered (on another pipeline) by `CredentialedResults.jsx`. | 77 keys wrongly MISSING            | Re-scoped — and the re-scoping exposed **Finding F-01**, a real gap in the opposite direction. |
| 2   | **Generic iteration.** `Object.entries(httpCoverage).map(...)` renders every child without naming one.                                                                 | 5 HTTP-header keys wrongly MISSING | Hand-checked; reclassified as covered.                                                         |
| 3   | **Wrong page assumed.** `/assets/coverage-stats` is consumed by `pages/admin/AMTIntegration.jsx`, not the asset registry.                                              | 6 keys wrongly MISSING             | Reclassified as covered.                                                                       |

A fourth correction was made against a _finding_, not the tool:
`org_risk_score` looked unrendered, but `dashboard.py` computes it as
`round(float(avg_risk), 1)` — the same number the panel already shows from
`summary.assets.avg_risk_score`. **Not a gap.**

Raw counts after correction, for orientation only:

| Surface         | Distinct keys | Referenced | Low-confidence | Unreferenced |
| --------------- | ------------: | ---------: | -------------: | -----------: |
| dashboard       |           149 |         98 |             17 |           34 |
| compliance      |           184 |         96 |             24 |           64 |
| asset_registry  |           170 |        118 |             15 |           37 |
| vuln_browser    |           107 |         65 |             13 |           29 |
| host_discovery  |            52 |         21 |              2 |           29 |
| asset_discovery |            63 |         22 |              3 |           38 |
| vuln_audit      |           260 |         65 |             10 |          185 |
| credentialed    |           232 |        154 |              9 |           69 |
| scan_envelope   |           102 |         56 |              7 |           39 |

Most of the compliance and vuln_audit totals are OVAL plumbing
(`check_definition.collect.definition.tests.oval:mil.disa.stig.win:tst:…`) and
are **intentional backend-only** — machine inputs to the engine, not audit
information. They are excluded from the findings below.

---

## 2. F-01 — the credentialed report is unreachable on a vulnerability audit

**Severity: highest in this audit. Classification: frontend gap.**

`CredentialedResults.jsx` → `hydrateFromHistory(detail)` reads exactly one
location:

```js
const credentialed = detail?.results?.credentialed;
const report = credentialed?.report;
if (!report) return null;
```

A **standalone credentialed scan** stores its report there. A **vulnerability
audit** does not — it nests one report per host at
`results.phase3.data[].credentialed_report`.

Measured on scan `scn_defa_c522b539_31aug26_sknk`, `pipeline_mode:
vulnerability_audit`:

    results.credentialed present?                    False
    results.phase3.data[0].credentialed              True
    results.phase3.data[0].credentialed_report       12 keys, config_audit present

So `hydrateFromHistory` returns `null`. And the caller's failure handling makes
it worse than an error:

```js
if (normalizedStatus === "completed") {
  const r = hydrateFromHistory(data);
  if (r) { …; return true; }          // ← no else
}
…
return false;                          // keep polling
```

A **successfully completed** scan returns `false`, so the page never resolves:
**an indefinite spinner on a scan that worked.** No error, no empty state, no
explanation.

`Phase3Results.jsx` does not fill the gap — a credentialed host there gets an
`AUTH` badge and nothing else; the word `credentialed_report` does not appear
in the file.

The backend is not at fault and the export layer already solved this:
`reporting/exports.py::_collect_host_audits` _walks_ the payload precisely
because "the same record reaches three shapes — nested under
`_phase_data[i].credentialed_report` on the vulnerability-audit pipeline, in
`options["credentialed_report"]` on the standalone credentialed scan…"
(CLAUDE.md). **The export learned to walk; the UI did not.**

---

## 3. Semantic-integrity violations

Each breaks a rule in CLAUDE.md's **UI semantic integrity** section.

### S-01 `severity.unscored` is dropped from the findings donut — `UNKNOWN ≠ ZERO`

`GET /dashboard/summary` returns:

    critical 370 · high 2102 · medium 2063 · low 193 · info 2 · unscored 10 · total 4740

`SEVERITY_BANDS` lists five bands and omits `unscored`. The donut computes
`slice = count / total * 360` against `sev.total`, which **includes** the
unscored 10. So 370+2102+2063+193+2 = 4730 of 4740: the arc is short by ten
findings' worth and nothing on the page says so. `normalize_severity()` keeps
`unscored` distinct from `none` precisely because "no rating published is a
different fact from a published rating of zero" — the dashboard folds it into
neither.

**Classification: incorrect/semantically misleading representation.**

### S-02 Four fabricated risk bars — invented information

`RiskScorePanel` is subtitled _"Composite: ports + CVE CVSS + HTTP headers +
TLS grade"_ and renders:

```js
<BarRow label="CVE CVSS"  value={Math.round(score * 0.72)} />
<BarRow label="Port risk" value={Math.round(score * 0.55)} />
<BarRow label="HTTP hdrs" value={Math.round(score * 0.38)} />
<BarRow label="TLS grade" value={Math.round(score * 0.6)}  />
```

All four are **constants multiplied by the same single number**. They are
presented as a component breakdown of the risk score and are not one.

The backend supplies real values for two of the four on the very endpoint the
panel already fetches: `http_avg_security_score` and `tls_issues`
(`expired_certs`, `self_signed`, `weak_ciphers`, `grade_f`). Both are ignored.

**Classification: incorrect/semantically misleading representation.** This is
the clearest case in the audit of the UI inferring what the backend did not
say.

### S-03 `collection_errors.item:*` is not shown — `UNASSESSED ≠ PASS`

The credentialed report carries ten entries recording what a transport could
**not** collect:

    item:password_policy · item:privilege_context · item:firewall
    item:telnet_status · item:netbios_status · item:tls_status
    item:open_ports · item:scheduled_tasks · item:failed_logins · item:uptime

CLAUDE.md is explicit that these exist so an unserved item is not "left to look
like an empty reading from the host". `collection_errors` is referenced three
times in the renderers, but no `item:`-prefixed entry is surfaced as a
not-assessed state on the section it belongs to. A host whose password policy
was never collected reads the same as a host with no password-policy finding.

**Classification: frontend gap + report gap** (`collection_errors` appears in
no report generator).

### S-04 `exposure_summary.listeners_undetermined` is dropped — `UNKNOWN ≠ ZERO`

`listeners_total`, `listeners_exposed`, `listeners_host_only` and
`listeners_undetermined` are returned. The undetermined count — listeners the
scan could not place either side of the boundary — is referenced nowhere.

### S-05 HTTP header coverage renders 0% when nothing was assessed — `NO DATA ≠ EMPTY RESULT`

`/dashboard/http-headers` currently returns `total_http_services: 0` with every
coverage bucket at `count 0, pct 0.0`. The panel renders five bars at **0%**,
which reads as "no host sets HSTS". The truth is "no HTTP service was
assessed". `total_http_services` is returned and unused — it is exactly the
field that distinguishes the two.

### S-06 Registry hardening tri-state is absent from the asset record

`assets/{id}.custom_attributes.registry_hardening` carries nine booleans
(`smbv1_disabled`, `rdp_disabled`, `rdp_nla_enforced`, `uac_enabled`,
`telnet_disabled`, `netbios_disabled`, `legacy_tls_disabled`,
`firewall_active`, `audit_configured`). `AssetDetail.jsx` references
`registry_hardening` **zero** times. CLAUDE.md devotes a paragraph to the
tri-state semantics of this exact structure ("Do not restore a `False` default
anywhere on that path"); the UI shows none of the three states.

### S-07 `credentialed_status` is not shown

`custom_attributes.credentialed_status` has one writer and three meanings —
`success`, `failed`, and **unset** ("no credential was in scope" ≠ "the
credential was refused"). `AssetDetail.jsx` references it zero times, so all
three render identically.

---

## 4. Frontend gaps where the **report already carries the field**

Measured directly against `reporting/pdf_generator.py` and
`reporting/csv_generator.py`. These are the cases where **the PDF shows the
operator more than the screen does**:

| Field           | UI               | PDF | CSV |
| --------------- | ---------------- | --- | --- |
| `in_kev`        | ✗                | ✓   | ✓   |
| `kev_due_date`  | ✗                | ✓   | ✓   |
| `epss_score`    | ✗ (credentialed) | ✓   | ✓   |
| `fixed_version` | ✗                | ✓   | ✓   |

`kev_due_date` is the BOD 22-01 mandated remediation deadline and
`fixed_version` is the remediation instruction. Both are in the report and
neither is on the credentialed results screen.

**Classification: frontend gap only. Do not touch the reports.**

---

## 5. Frontend **and** report gaps

Present in the API, absent from both the UI and every report generator:

| Field                                                                     | Why it matters                                                                                                        |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `has_exploit`                                                             | A public exploit exists. CLAUDE.md: 29,287 rows, 27,640 outside KEV — the signal `in_kev` alone cannot carry.         |
| `verified_exploit`                                                        | ExploitDB-confirmed reproducible.                                                                                     |
| `canary_confirmed`                                                        | Observed against VulnCheck honeypots — "the strongest exploitation evidence in any feed here".                        |
| `ransomware_linked`                                                       | Known ransomware campaign use.                                                                                        |
| `priority_level`, `priority_score`                                        | The product's own computed triage order.                                                                              |
| `installed_version`                                                       | Which version is on this host.                                                                                        |
| `matched_by`                                                              | How the match was made — the provenance of the finding.                                                               |
| `vendor_remediation`, `vendor_advisories[]`                               | CLAUDE.md: "the only path that reaches OT software at all… frequently the only remediation instruction in existence". |
| `exploit_sources`                                                         | Which feed asserted exploitation.                                                                                     |
| `collection_errors.item:*`                                                | §S-03.                                                                                                                |
| `hardening_audits.{smbv1,rdp,rdp_nla,telnet,netbios,legacy_tls,firewall}` | Sub-keys below a partially rendered parent.                                                                           |
| `listeners_undetermined`                                                  | §S-04.                                                                                                                |

Verified by direct grep: **all fourteen CVE-enrichment fields score 0
occurrences** across `CredentialedResults.jsx` and all five of its section
components.

---

## 6. Per-surface findings

### 6.1 Dashboard — `SecurityDashboard.jsx`

`Dashboard.jsx` is the scan launcher, not the analytics dashboard. All twelve
`/dashboard/*` endpoints are fetched.

| Field                                                                      | Endpoint        | Class                                 |
| -------------------------------------------------------------------------- | --------------- | ------------------------------------- |
| `severity.unscored`                                                        | summary         | misleading (§S-01)                    |
| `tls_issues.{expired_certs,self_signed,weak_ciphers,grade_f}`              | risk-breakdown  | frontend gap                          |
| `http_avg_security_score`                                                  | risk-breakdown  | frontend gap                          |
| `risk_level_distribution`                                                  | risk-breakdown  | frontend gap                          |
| `total_http_services`, `avg_security_score`                                | http-headers    | frontend gap (§S-05)                  |
| `coverage.*.count`                                                         | http-headers    | frontend gap — only `pct` is rendered |
| `cves[].{epss_score,has_exploit,priority_score,cwe_ids,cvss_version}`      | top-cves        | frontend gap                          |
| `scans[].{started_at,completed_at,duration_seconds,total_hosts,intensity}` | scan-activity   | frontend gap                          |
| `assets[].{device_category,fqdn}`                                          | top-assets      | frontend gap                          |
| `category_distribution`                                                    | asset-breakdown | frontend gap                          |
| `assets.new_7d`, `scans.quota_used_pct`, `plan`                            | summary         | frontend gap (minor)                  |
| `frameworks[].color`                                                       | compliance      | cosmetic — not audit information      |
| `org_risk_score`                                                           | risk-breakdown  | **already covered** (duplicate value) |

### 6.2 Compliance — `ComplianceWorkspace.jsx`

| Field                                                                                 | Class                                                                                                                                                           |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `evidence.observations[].{raw,expected,observed,collector,collected_at,description}`  | **frontend gap — high.** The evidence behind every configuration verdict. CLAUDE.md: "on a configuration check the evidence _is_ the finding." Zero references. |
| `evidence.check_metadata.collection_status`                                           | frontend gap — the assessed/not-assessed state                                                                                                                  |
| `evidence.detection_method`                                                           | frontend gap                                                                                                                                                    |
| `check_definition.metadata.{stig_id,xccdf_rule_id,cci,benchmark}`                     | frontend gap — the STIG/CCI identifier a reviewer cross-references                                                                                              |
| `data[].last_seen`                                                                    | frontend gap                                                                                                                                                    |
| `scans[].{started_at,finished_at,created_at,initiated_by,finding_counts,schedule_id}` | frontend gap                                                                                                                                                    |
| `policies[].{created_at,policy_family_code}`                                          | frontend gap (minor)                                                                                                                                            |
| `remediations[].{approved_by,created_at,remediation_id}`                              | frontend gap                                                                                                                                                    |
| `gap-analysis.summary.pending_manual`                                                 | frontend gap                                                                                                                                                    |
| `marketplace.parked_framework_ids`                                                    | frontend gap — which catalogues are parked                                                                                                                      |
| `check_definition.collect.definition.*` (OVAL tests/objects/states)                   | **intentional backend-only** — engine input                                                                                                                     |

### 6.3 Vulnerability Browser — `VulnerabilityBrowser.jsx`

| Field                                          | Class                                                                                                                                                                                                                               |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `qod`, `confidence`, `detection_method`        | **frontend gap — high.** The quality-of-detection model. A Confirmed active check (QoD 99) and a `service_product` inference (QoD 30, `confidence: potential`) render identically. Live sample: `qod: 30, confidence: "potential"`. |
| `kev_due_date`                                 | frontend gap — the mandated deadline (`in_kev` is shown, the date is not)                                                                                                                                                           |
| `epss_percentile`                              | frontend gap (`epss_score` is shown)                                                                                                                                                                                                |
| `port`                                         | frontend gap — which listener the finding is on (`"5601/tcp"`)                                                                                                                                                                      |
| `attack_surface`                               | frontend gap (`"remote"` vs local)                                                                                                                                                                                                  |
| `cvss_score`, `cvss_vector`, `cvss_version`    | frontend gap — the page reads the catalogue's `cvss_v3_score`; the finding's own score, vector and version are returned and unused                                                                                                  |
| `detected_version`                             | frontend gap                                                                                                                                                                                                                        |
| `vendor_advisory_id/url`, `vendor_remediation` | frontend gap                                                                                                                                                                                                                        |
| `exploit_sources`                              | frontend gap                                                                                                                                                                                                                        |
| `vulnerability.published_at`, `cvss_v2_score`  | frontend gap (minor)                                                                                                                                                                                                                |

### 6.4 Host Discovery — `Phase1Results.jsx`

| Field                                                                                            | Class                                                                                                                      |
| ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `port_states` (port → open/filtered/closed)                                                      | **frontend gap — high.** `filtered` is not `closed`; dropping it renders an undetermined port as absent. `UNKNOWN ≠ ZERO`. |
| `tcp_fingerprint.{ttl,window,mss,df_bit,sack_ok,ts_val,wscale}`                                  | frontend gap — the OS-fingerprint evidence                                                                                 |
| `os_guess`, `os_confidence`, `os_evidence`, `os_fingerprint_full`, `confidence`                  | **frontend gap — high.** An OS guess shown without its confidence reads as fact.                                           |
| `device_category`                                                                                | frontend gap (rendered on phase 2, not phase 1)                                                                            |
| `scan_method`, `scan_timestamp`                                                                  | frontend gap                                                                                                               |
| `summary.{scanner,port_range,service_detection,timing_template,scan_type,discovery_scan_method}` | **frontend + report gap** — the scan parameters. An audit report must state what was actually scanned.                     |
| `snmp_device_type`, `_ot_probed`                                                                 | frontend gap                                                                                                               |

### 6.5 Asset Discovery — `Phase2Results.jsx`

| Field                                                                                  | Class                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `open_ports[].protocol`                                                                | **frontend gap — high.** CLAUDE.md: recording a UDP service as TCP "claims an open TCP port that is usually filtered". The table shows `service` and `version` and not the transport. |
| `open_ports[].version_precision`                                                       | frontend gap — a version shown without its precision reads as exact                                                                                                                   |
| `open_ports[].{product,cpe,extra,fingerprint_source}`                                  | frontend gap                                                                                                                                                                          |
| `port_states`                                                                          | frontend gap (as §6.4)                                                                                                                                                                |
| `tcp_fingerprint.*`                                                                    | frontend gap                                                                                                                                                                          |
| `host_risk_level`, `response_time_ms`                                                  | frontend gap                                                                                                                                                                          |
| `summary.{inactive_hosts,os_detection,ports_probed_spec,port_range,timing_template,…}` | frontend + report gap                                                                                                                                                                 |

### 6.6 Asset Registry — `AssetRegistry.jsx` / `AssetDetail.jsx`

| Field                                                                                                                                          | Class                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `custom_attributes.registry_hardening.*` (9)                                                                                                   | frontend gap (§S-06)                                                                        |
| `custom_attributes.credentialed_status`                                                                                                        | misleading absence (§S-07)                                                                  |
| `credentialed_system_info.{local_groups,running_services,suspicious_scheduled_tasks}`                                                          | **frontend gap — high.** `suspicious_scheduled_tasks` is a security finding with no screen. |
| `credentialed_system_info.{detected_os,os_version_id,synced_at,source_scan_id,hostname_fqdn_raw,hostname_short,credentialed_response_time_ms}` | frontend gap — `synced_at`/`source_scan_id` are the provenance of the whole block           |
| `custom_attributes.password_policy.*`                                                                                                          | frontend gap                                                                                |
| `service_count`                                                                                                                                | frontend gap (list and detail)                                                              |
| `certificates[].service_id`                                                                                                                    | frontend gap (minor)                                                                        |
| `notes_summary`                                                                                                                                | frontend gap                                                                                |
| `provenance.*.scan_id`                                                                                                                         | frontend gap — which scan asserted each field                                               |
| `/assets/coverage-stats`                                                                                                                       | **already covered** — rendered by `AMTIntegration.jsx`                                      |

### 6.7 Credentialed / Vulnerability Audit

Beyond F-01 and §5:

| Field                                              | Class                                                                                           |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `config_audit.results[].metadata.absent_policy`    | frontend gap — what absence means for that check, the field a reviewer needs on a MANUAL_REVIEW |
| `system_info.{os_confidence,os_family,mac_vendor}` | frontend gap                                                                                    |
| `running_services[].start_type`                    | frontend gap                                                                                    |
| `access.use_tls`                                   | frontend gap — tri-state, and `None` is a real answer                                           |
| `coverage.timing_template`                         | frontend gap                                                                                    |
| `cves[].affected_software[]` (CPE ranges)          | frontend gap                                                                                    |

### 6.8 Scan envelope / Scan History

| Field                                                                                           | Class                                  |
| ----------------------------------------------------------------------------------------------- | -------------------------------------- |
| `queued_at`                                                                                     | frontend gap — queue wait is invisible |
| `started_by.full_name`                                                                          | frontend gap — ownership               |
| `summary.{discovery_profile,os_detection,port_range,scanner,service_detection,timing_template}` | frontend + report gap                  |
| `is_deleted`, `completed_at`, `duration_seconds` per row                                        | frontend gap (minor)                   |

---

## 7. Backend / API gaps

Only two, and neither blocks the UI work above:

1. **No `remediation_state` filter on any listing** (carried from Phase 7).
   Five of seven states are counts with no drill-down.
2. **`/dashboard/http-headers` cannot distinguish "assessed and absent" from
   "never assessed" per header.** `total_http_services: 0` implies it globally,
   but a per-header `assessed` count would let the panel render §S-05 correctly
   without inference. The UI can use `total_http_services` today; this is the
   cleaner fix if the panel is revisited.

Everything else in this audit is **backend-complete**.

---

## 8. Permission / RBAC

No finding. Every gap above is reachable with the permission the operator
already holds for that screen; none is hidden by RBAC. `scans:read`,
`assets:read`, `findings:read` and `compliance:read` are held by viewer and
above, and the payloads were captured with those atoms satisfied.

---

## 9. Prioritised implementation plan

Nothing here was implemented. Each item names the files and its acceptance
criteria.

### P0 — data is unreachable or actively wrong

**P0-1 · F-01 credentialed report on the vulnerability-audit pipeline**
_Files:_ `Frontend/src/pages/scan/CredentialedResults.jsx`
(`hydrateFromHistory`, and the `if (r)` branch at ~line 246).
_Change:_ walk the payload the way `reporting/exports.py::_collect_host_audits`
already does — `results.credentialed.report`, then
`results.phase3.data[].credentialed_report`, then
`options.credentialed_report`. Give the completed-but-unhydratable case an
explicit terminal state instead of returning `false`.
_Acceptance:_ opening `/scan/credentialed?scan_id=scn_defa_c522b539_31aug26_sknk`
renders that host's report; a completed scan with no credentialed data anywhere
shows a named empty state within one poll, never an indefinite spinner; a test
covers both shapes from real fixtures.

**P0-2 · S-02 fabricated risk bars**
_Files:_ `Frontend/src/pages/SecurityDashboard.jsx` (`RiskScorePanel`).
_Change:_ delete the four `score * 0.NN` bars. Render `tls_issues` (4 real
counts) and `http_avg_security_score` from the payload already fetched; drop
any component the backend does not supply rather than deriving it.
_Acceptance:_ no rendered value is computed from a constant multiple of another
rendered value; the subtitle names only components that are displayed; a test
asserts no `* 0.` literal remains in the panel.

**P0-3 · S-01 unscored findings**
_Files:_ `SecurityDashboard.jsx` (`SEVERITY_BANDS`, `FindingsDonut`).
_Change:_ add `unscored` as its own band, labelled "Unscored — no rating
published", distinct from Info.
_Acceptance:_ the bands sum to `severity.total`; a fixture with
`unscored > 0` renders the band and the arcs close.

**P0-4 · S-03 / S-04 not-assessed states**
_Files:_ `CredentialedResults.jsx` and the section components.
_Change:_ render each `collection_errors["item:<key>"]` as a not-assessed
marker on the section that would have shown the item; render
`listeners_undetermined`.
_Acceptance:_ a host with `item:password_policy` shows "not assessed" with the
reason on the password-policy section, never an empty or passing one.

### P1 — security-relevant information with no screen

**P1-1 · CVE enrichment on credentialed results** — `in_kev`, `kev_due_date`,
`has_exploit`, `verified_exploit`, `canary_confirmed`, `ransomware_linked`,
`epss_score`/`percentile`, `priority_level`/`score`, `installed_version`,
`fixed_version`, `matched_by`, `vendor_remediation`, `vendor_advisories`,
`exploit_sources`.
_Files:_ `components/scan/FindingsListSection.jsx`.
_Acceptance:_ every field renders where present and is **absent, not zero or
false, when the API omits it**; `has_exploit` is labelled as exploit
availability and never as exploitability (CLAUDE.md); `vendor_remediation` is
prefixed with its advisory id.

**P1-2 · QoD and confidence in the Vulnerability Browser** — `qod`,
`confidence`, `detection_method`, plus `port`, `attack_surface`,
`kev_due_date`, `epss_percentile`, `detected_version`.
_Files:_ `pages/VulnerabilityBrowser.jsx`, `api/findings.js`.
_Acceptance:_ a QoD-99 active check is visually distinguishable from a QoD-30
`potential` inference in the list and the drawer.

**P1-3 · Compliance evidence** — `evidence.observations[]`,
`check_metadata.collection_status`, `detection_method`, and
`metadata.{stig_id,xccdf_rule_id,cci}`.
_Files:_ `pages/ComplianceWorkspace.jsx`.
_Acceptance:_ a configuration finding shows the observation's `expected`,
`observed`, `raw`, `collector` and `collected_at`; `collection_status` renders
as its own state.

**P1-4 · Host posture on the asset record** — `registry_hardening` (tri-state),
`credentialed_status`, `suspicious_scheduled_tasks`, `running_services`,
`local_groups`, `password_policy`, `synced_at`, `source_scan_id`.
_Files:_ `pages/AssetDetail.jsx`.
_Acceptance:_ a hardening key absent from the payload renders as **not
assessed**, never as `False`; `credentialed_status` unset, `failed` and
`success` render as three distinct states.

### P2 — assessment fidelity

**P2-1 · `open_ports[].protocol` and `version_precision`** in
`Phase2Results.jsx`. _Acceptance:_ every port row states tcp/udp; a version
without precision is not shown as exact.

**P2-2 · `port_states`** on phases 1 and 2. _Acceptance:_ `filtered` renders as
its own state, distinct from closed and from absent.

**P2-3 · OS confidence** — `os_guess`, `os_confidence`, `os_evidence`,
`tcp_fingerprint.*` on `Phase1Results.jsx`. _Acceptance:_ no OS string is shown
without its confidence.

**P2-4 · Scan parameters in the UI and the reports** —
`summary.{scanner,port_range,ports_probed_spec,timing_template,service_detection,os_detection,discovery_profile}`.
_Files:_ phase pages + `reporting/pdf_generator.py`. _Acceptance:_ a report
states what was scanned and with what settings.

### P3 — completeness

Dashboard `risk_level_distribution`, `category_distribution`, scan-activity
timings, top-CVE enrichment, `total_http_services` (§S-05), `coverage.*.count`;
compliance scan timestamps and `initiated_by`; `service_count`; `queued_at`;
`started_by.full_name`; `provenance.*.scan_id`.

### Report-side work (only where §5 applies)

Add to `reporting/pdf_generator.py` / `exports.py`: `has_exploit`,
`priority_level`, `installed_version`, `vendor_remediation`,
`collection_errors`, `hardening_audits`, `listeners_undetermined`, and the
scan-parameter summary. **`reporting/csv_generator.py`'s existing columns must
not be reordered** — CLAUDE.md requires appended columns only.

---

## 10. Standing rules for this work

- **Never infer a value the backend did not send.** P0-2 exists because that
  rule was broken.
- **Absence renders as absence.** Every item above must distinguish
  not-collected, not-applicable and false.
- **Do not change existing report columns' order or meaning.**
- **Re-run the measurement rather than trusting this document**:
  `python3 scripts/audit/api_field_coverage.py --manifest … --payloads …`, and
  hand-verify before believing any MISSING verdict — three of this audit's own
  were tool defects.
