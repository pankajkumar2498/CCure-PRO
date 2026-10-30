---
paths:
  - "Backend/core/checks/**"
  - "Backend/engines/vulnerability/**"
  - "Backend/engines/tls/**"
  - "Backend/core/web/sslyze/**"
  - "Backend/scripts/measure_network_check_coverage.py"
  - "Backend/scripts/measure_tls_coverage.py"
---

# Assessment framework, network checks, deep TLS and Nuclei

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 3826–3879, 4122–4209, 4391–4553) and is maintained here. Frozen original: `docs/archive/engineering-record/checks-network-tls.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Assessment framework (`core/checks/`)

The common contract every new assessment speaks. Added in Phase 0 of the
Nessus gap-closure programme; the tracker is
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**It does not replace the fifteen vulnerability plugins and is not meant to.**
Those are stable and produce real findings; rewriting them onto this contract
would be a large refactor with no capability gained. New capabilities —
configuration audit, local privilege checks, database and network-device
assessment — register here. What the plugins gained instead is the guard they
never had (below).

- **`CheckOutcome` reuses the compliance vocabulary, deliberately.** `pass`,
  `fail`, `not_applicable`, `manual_review` are spelled exactly as
  `compliance_findings.status` spells them, so a check result stores as a
  compliance verdict with no translation table — and a translation table is how
  two vocabularies for one idea begin. `error` is the one addition, and it is
  deliberately _not_ storable as a verdict: it is a scan-time condition, and
  writing it as a status would assert something about a host that nothing
  established.

- **`is_verdict` is True for exactly PASS and FAIL, and every roll-up must gate
  on it.** Treating NOT_APPLICABLE, MANUAL_REVIEW or ERROR as a pass inflates a
  compliance score; treating any of them as a fail invents findings on hosts
  nobody could reach. ISO A.8.2 was once reported as _failed_ on hosts the
  scanner could not authenticate to — that is this bug.

- **A FAIL with no evidence is rejected at construction.** Not a lint, not a
  review checklist — `CheckResult.__post_init__` raises. It is the mirror image
  of the synthesised `password_policy` that once made every rule reading it pass
  unconditionally on every host, and it is the direction that reaches a customer
  as a false positive.

- **A check that raises yields an ERROR result**, never a swallowed log line and
  never a FAIL. Swallowing makes a broken check indistinguishable from a clean
  host; returning FAIL invents a finding out of a bug in our own code.

- **Severity has one vocabulary.** `normalize_severity()` maps
  `compliance_rules`' `info` onto `scans.cvss.CANONICAL_SEVERITIES`' `none`.
  Unrecognised input becomes `unscored`, not `none` — no rating published is a
  different fact from a published rating of zero.

- **`tests/scans/test_plugin_contract.py` is the guard the legacy plugins never
  had.** `VulnerabilityEngine` calls serial plugins with three arguments and
  parallel plugins with two, and catches plugin exceptions at DEBUG. A plugin
  with the wrong arity raises `TypeError` on every host, is swallowed, and stays
  in `plugin_names()` and `select_plugins()` while producing **zero findings
  indefinitely**. The test reads `plugin_selector`'s own dispatch tables — not
  `plugins.__all__`, which is the import list and says nothing about arity — and
  checks each signature statically. Verified by mutation: reducing
  `nuclei_probe.run` to two arguments fails it with a message naming the plugin,
  the arity and the call site.


## Network checks (`engines/vulnerability/network_checks.py`)

The catalogue every unauthenticated network plugin turns an observation into a
finding through. Phase 6 of the gap-closure programme, closing GAP-06; tracker
in [`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine.** `VulnerabilityEngine`, `plugin_selector` and the fifteen
probes' own detection logic are unchanged. What changed is that a probe which
has established something now has one correct way to say so.

- **`VulnerabilityEngine._merge` promotes a _top-level_ `cves` key and nothing
  else.** This is the single most important fact about writing a network
  plugin. Six of fifteen returned their findings nested inside `http_audit`,
  `ftp_info` or `smb_info` and every condition they detected was discarded —
  weak SSH algorithms, SMBv1, a `public` SNMP community, an expired
  certificate, anonymous FTP write access. A finding that is not at the top
  level does not exist.

- **`ssh_probe` is the shape to watch for.** It initialised `info["cves"] = []`,
  promoted it with `if info.get("cves")`, and nothing ever appended to it: the
  CVE lookup had been removed and the plumbing left behind. An AST pass over
  the fifteen modules answers "8 plugins emit"; the truth was 7. That is why
  `scripts/measure_network_check_coverage.py` reads a catalogue rather than the
  sources — a measurement fooled by dead plumbing reports the starting point
  too high and every later number inherits the error.

- **A network condition must never become a fabricated CVE.** `asset_syncer`
  set neither `definition_type` nor a NULL `cve_id`, so `MISC-FTP-ANON` and its
  eleven siblings were filed as `cve` rows carrying their own invented string
  in `cve_id` — inheriting KEV lookups, EPSS scores, CVSS bands and an NVD link
  that resolves to nothing. `ck_vuln_def_cve_id_matches_type` could not catch
  it, because the row _did_ carry a `cve_id`, just not a real one. The write
  path now calls `definition_type_for_id`, and `_enrich_findings_with_intel`
  skips anything that is not a real CVE.

- **`cve_id` is `varchar(30)` and the catalogue insert is not inside a
  try/except.** So a fabricated identifier longer than thirty characters raised
  `StringDataRightTruncation` and **aborted the finding sync for the whole
  scan**. All three `MISC-CREDENTIALED-*` markers are over the limit (33, 37, 39) and so are most Nuclei template ids —
  `MISC-NUCLEI-WORDPRESS-DIRECTORY-LISTING` is 39. Minted identifiers go in
  `id`, which is `varchar(120)`, and `cve_id` stays NULL, so the limit no
  longer applies. Do not put a non-CVE string in `cve_id`.

- **A real CVE stays a real CVE.** Heartbleed, Shellshock and EternalBlue keep
  their published identifiers, `definition_type = cve`, their NVD links and
  their KEV and EPSS enrichment, because all of it means something for them.
  `NetworkCheck` refuses a `cve_id` that is not well-formed at construction.

- **Two probes that detect one condition emit one identifier.**
  `default_creds` and `ftp_checker` both test anonymous FTP; both report
  `ftp.anonymous_login`, so `deduplicate_cves` collapses them. Promoting the
  second without matching the first would have started showing the reader the
  same problem twice.

- **`detection_method` must be `active_check`.** It maps to
  `DetectionMethod.CONFIG_CHECK` — QoD 99, Confirmed — and is in the
  normalizer's `AUTHORITATIVE` set, which lets the finding bypass the CPE
  version-range test. These checks observed the condition rather than inferring
  it from a version, so there is no version to range-check and anything else
  would be withheld as unverified.

- **Three detections are deliberately not promoted**, each because it would
  fire on ordinary hosts. They stay in the metadata, so no existing report
  changes:
  - **`smb_probe.null_session`** is the negotiate response's NT status being
    zero — STATUS_SUCCESS, which every reachable SMB server returns. Nothing
    attempts a session setup with an empty username.
  - **`http.admin_interface_exposed`** matches on path plus a 200/401/403
    status with no body check, and a single-page application answers every
    unknown route with 200 and its index document, so all thirteen fingerprints
    match at once.
  - **SMBv1 as CVE-2017-0144.** EternalBlue needs SMBv1 _and_ an unpatched
    implementation. SMBv1 alone is `smb.v1_enabled`; only the MS17-010
    fingerprint claims the CVE. The old companion `CVE-2017-0144-ACTIVE` was a
    CVE-shaped string that is not a CVE.

- **`_http_request` returned an empty body on every request.** It stopped
  reading at `\r\n\r\n` — the end of the _headers_ — so directory-listing
  detection tested `"index of /"` against `""` and could never fire, and
  sensitive-path exposure was decided by status code alone. Pass
  `read_body=True` when you need the body; it stays opt-in because HEAD has no
  body and the method probe only needs a status.

- **`http.sensitive_path_exposed` requires a body fingerprint.**
  `_SENSITIVE_PATHS` probes `/login`, `/admin/`, `/dashboard` and `/console`,
  which an SPA answers with 200 — so a status match alone reports four exposed
  files on every SPA, this product's own frontend included.


## Deep TLS on the network path

`engines/vulnerability/plugins/tls_scanner.py` runs the **existing** sslyze
wrapper (`core/web/sslyze/wrapper.py`), which had driven full TLS audits on the
`/web-scans` path since before Phase 6 while the main network scan got a
140-line socket probe. There is one TLS engine; do not add a second.

- **`tls_scanner` used `log` and never imported it.** Four exception handlers
  called `log.debug(...)`, so any TLS error path raised `NameError` _inside the
  except block_, and `VulnerabilityEngine` catches plugin exceptions at DEBUG.
  Same failure mode as `nuclei_probe`'s arity, reached from the other side.

- **It assessed only the first TLS port.** `for port in _TLS_PORTS: if port in
open_ports: … return`. A host serving 443 and 8443 was assessed on 443 alone.
  It now assesses every endpoint, and `_PORT_MAP` names the same ports the
  plugin does — a port in one list and not the other means the plugin is never
  selected for a host exposing only that port.

- **`"VULNERABLE" in robot_enum.name` matched `NOT_VULNERABLE_NO_ORACLE`.**
  sslyze's ROBOT enum has five members and the substring test passed three of
  them, so **every server sslyze positively cleared was reported vulnerable**,
  including any TLS 1.3-only listener where RSA key exchange does not exist.
  It is `startswith("VULNERABLE_")` now, and `UNKNOWN_INCONSISTENT_RESULTS` is
  deliberately not a finding — "could not determine" is not a verdict.

- **The handshake and the deep engine see different things, and both are
  needed.** A single handshake reports the suite it negotiated, which on a
  modern client is the _strongest_ the server offers; every weak suite the
  server would also accept is invisible to it. Measured on a deliberately weak
  listener: negotiated `ECDHE-RSA-AES256-GCM-SHA384` while the deep engine
  found three weak suites across TLS 1.0, 1.1 and 1.2. The socket probe is kept
  because it is fast and produces the `TLSInfo` shape the findings writer
  (`upsert_tls_details`) and `core/risk.py` already read.

- **Deep assessment is bounded.** It enumerates cipher suites across six
  protocol versions, so it costs many handshakes per endpoint where the socket
  probe costs one. `TLS_DEEP_MAX_ENDPOINTS` (4) and `TLS_DEEP_SCAN` exist
  because this product scans OT segments. Measured at 2.2s per endpoint.

- **STARTTLS is reached through the same wrapper** (Phase 11, GAP-07).
  `STARTTLS_SERVICES` maps six services to their ports — SMTP, IMAP, POP3,
  LDAP, PostgreSQL, FTP — and sslyze performs the negotiation, so no second TLS
  transport exists. The names are looked up against sslyze's own
  `ProtocolWithOpportunisticTlsEnum`, so a service it cannot negotiate is
  impossible to add by mistake: MySQL has no handler in 6.3.1 and is declared
  unimplemented rather than silently producing connection errors.

  **A port in `STARTTLS_SERVICES` must also be in `plugin_selector._PORT_MAP`**,
  or a host exposing only that port never runs the plugin at all. PostgreSQL hit
  exactly this: 5432 already had an entry for `default_creds`, and a second dict
  key for it kept only the last value. A test now asserts selection for every
  port in the table and refuses any duplicate key in the map.

  **A STARTTLS endpoint never becomes `tls_info`.** That key means the first
  _implicit_-TLS endpoint that answered; the findings writer and `core/risk.py` read
  it, and a mail server's certificate appearing there would rewrite an asset's
  TLS identity with something no browser negotiates. They go to
  `tls_endpoints` with a `starttls` marker, and one budget covers both kinds.

- **Three sslyze commands were requested and their results discarded.**
  `TLS_FALLBACK_SCSV` and `SESSION_RENEGOTIATION` since before Phase 6, and
  `path_validation_results` was parsed into a `chain_trusted` boolean nothing
  read. Phase 11 reads them, which is why fourteen findings arrived for very
  little extra time on the wire. Each reading is **tri-state**: True, False, or
  absent because the command did not complete. Every guard is `is True` /
  `is False`, never truthiness — an absent command has established nothing, and
  reading it either way invents a verdict.

- **Classify a public key by type, not by class name.** `_describe_public_key`
  tested `"EllipticCurve" in type(key).__name__`; this build of `cryptography`
  returns `ECPublicKey`, so every EC certificate went unclassified and the
  key-strength check was silently withheld for the whole algorithm. It is
  `isinstance` against the abstract types now. An algorithm it does not
  recognise returns `{}` and the check is withheld rather than compared against
  the wrong floor.

- **`/web-scans` output is deliberately unchanged.** The wrapper's own
  `findings` list was not extended; that path renders it and altering an
  existing report was not Phase 11's business. The network path builds its own
  findings from the structured data the wrapper now returns.

- **`tls_info` keeps its meaning** — the first TLS endpoint that answered.
  `tls_endpoints` is additive and carries the rest. Nothing downstream should
  change because a host happens to expose a second TLS port.

### Active template verification (Nuclei)

`engines/vulnerability/plugins/nuclei_probe.py` runs ProjectDiscovery's
templates and produces the only findings in this product that are _proven_
rather than inferred — a template matched a live response, so the
vulnerability is present and reachable now. They grade as `active_check` →
`CONFIG_CHECK`, QoD 99, Confirmed.

A template with no CVE now mints `CCURE-CHK-NUCLEI-<template>` rather than
`MISC-NUCLEI-<template>` — see the network-checks section above for why the
old form aborted the finding sync outright on any template id over eighteen
characters.

Binary and templates are located via `NUCLEI_BINARY` and
`NUCLEI_TEMPLATES`; the defaults are `nuclei` on PATH and
`~/nuclei-templates`. This repository is shared, so no absolute path is
hardcoded — a machine-specific default silently disables the plugin for
everyone else. ~13,510 templates when fully installed.
and logs it; an unavailable optional probe is a coverage gap, not an error.

Four things measured the hard way, all of which produced _zero findings_
before they were fixed:

- **Serial plugins are called with three arguments** (`ip, open_ports,
port_details`). A two-argument `run` raises TypeError, the engine catches
  plugin exceptions at debug level, and the plugin looks registered while
  never executing.
- **Do not allow-list web ports.** An allow-list gave a web server on 8099
  only a bare `host:port` target, so the HTTP templates — most of the corpus —
  never engaged. Everything not in `_NON_HTTP_PORTS` now gets a URL target too.
- **Do not run the full corpus.** 13,510 templates exceeded 600s against one
  host and returned nothing, which reads as "verified, nothing found". Default
  is `critical,high,medium` (7,460 templates); most of the excluded mass is
  `info`, which is technology _detection_, and grading "nginx present" as
  Confirmed at QoD 99 would bury the real findings.
- **`-exclude-tags dos,fuzz,intrusive,brute-force` and `-no-interactsh` are
  not optional.** This scans production and OT hosts: an audit that causes an
  outage is worse than the finding it would have produced, and out-of-band
  callbacks leak target identity off-site and need egress OT segments lack.

Measured: 129s for one web port, 289s for three ports at `critical,high`.
Nuclei ships overlapping templates, so one exposed `.env` legitimately matches
`generic-env`, `laravel-env` and `codeigniter-env` — three rows for one
problem. They are not false positives; the file really is exposed.

### Test targets

Two disposable containers exist for validating credentialed collection. Both
are deliberately **not** updated after build — an up-to-date target cannot tell
"matching works and the host is clean" apart from "matching is broken", which
is how five separate false negatives survived until they were scanned.

```powershell
docker start ccure-rocky-target    # Rocky 9.8,  ssh 127.0.0.1:2222  root / ccure-test-only
docker start ccure-ubuntu-target   # Ubuntu 24.04, ssh 127.0.0.1:2223  root / ccure-test-only
docker start ccure-nuclei-target   # nginx on 127.0.0.1:8099 serving .env and .git/config
```

`ccure-nuclei-target` exists because neither real host triggers a Nuclei
template — the Windows workstation (10.180.6.30, formerly .14) has no web server, and a
scanner that finds nothing there looks identical to one that is broken. It
serves a deliberately exposed `.env` and `.git/config`, which must produce
**4 findings, all Confirmed at QoD 99**. Zero from it is a regression.

Expected at the time of writing: Rocky 48 findings (4 Critical), Ubuntu 7 (all
with no fix published upstream). A run returning **zero** on either is a
regression, not a clean host.

### Coverage figures

`VulnMatcher.coverage()` reports two percentages and they answer different
questions. `coverage_pct` is over every collected package;
`coverage_pct_software` excludes toolchain components — SDK headers, `vs_*`
resource MSIs, IntelliSense metadata — which NVD publishes no CPE for because
none is independently vulnerable. On a real Windows host 98 of 191 packages
are such components, so the unfiltered figure understates coverage as badly as
counting them assessed would overstate it. Keep reporting both.
