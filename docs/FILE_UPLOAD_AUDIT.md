# File Upload Validation — Full Application Audit

> **Status: all findings remediated on 22 Aug 2026** (branch `validations`).
>
> This document is kept as the record of what was wrong and _why_, so the
> reasoning behind each guard survives the commit that added it. Every finding
> carries a **Fixed** note naming the code that closes it. One item, **S-5**,
> was deliberately not implemented — see _Deferred_ at the end.
>
> Regression cover: [`Backend/tests/security/test_upload_validation.py`](../Backend/tests/security/test_upload_validation.py)
> — 62 tests, all passing. Invariants recorded under **File uploads** in
> [CLAUDE.md](../CLAUDE.md). Shared primitives in
> [`Backend/core/upload_guard.py`](../Backend/core/upload_guard.py).

_Verified against source on 22 Aug 2026. Every line number was re-read; the
first revision of this document cited line numbers from a stale checkout and
attributed one infrastructure control to a container that is not in the request
path._

## Scope

Three file upload surfaces exist, and only three. Confirmed exhaustive by
`grep -rn UploadFile Backend/ --include=*.py` (two hits outside `.venv`) and
`grep -rn 'type="file"\|FileReader' Frontend/src` (three hits).

| #   | Upload Surface                 | Frontend                                                    | Backend                          | File Reaches Server?                                         |
| --- | ------------------------------ | ----------------------------------------------------------- | -------------------------------- | ------------------------------------------------------------ |
| 1   | **Scan Target Upload**         | `Frontend/src/modules/audit/pages/scan/NewScan.jsx`         | `Backend/routers/phase_scans.py` | ❌ No — parsed client-side, only target strings sent as JSON |
| 2   | **Compliance Evidence Upload** | `Frontend/src/modules/audit/pages/ComplianceWorkspace.jsx`  | `Backend/routers/compliance.py`  | ✅ Yes — multipart upload, stored on disk                    |
| 3   | **AMT Inventory Upload**       | `Frontend/src/modules/audit/pages/admin/AMTIntegration.jsx` | `Backend/routers/assets.py`      | ✅ Yes — multipart upload, parsed as JSON                    |

---

## 1. Scan Target Upload (Vulnerability Audit Page)

File is parsed **entirely client-side** via `FileReader.readAsText()`. Only
extracted target strings are sent as `list[str]` in a JSON body. The raw file
**never reaches the server**, so every server-side control here defends the
target list, not the file.

### Findings

| ID  | Finding                                    | Severity | Fixed                                                                                                                                                        |
| --- | ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| S-1 | Drag-and-drop bypassed the `accept` filter | Medium   | ✅ `processFile()` now checks the extension on every path — `accept` is a picker hint that does not apply to a drop, and the drop zone fed the same function |
| S-2 | No file size limit                         | Medium   | ✅ 5 MB guard before `readAsText()`, plus a `reader.onerror` handler                                                                                         |
| S-3 | Binary files produced a misleading error   | Low      | ✅ Now "Unsupported file format: _name_. Upload a .txt or .csv…"; the no-targets message also names the file and the expected shape                          |
| S-4 | No empty file check                        | Low      | ✅ `file.size === 0` refused with a message that says so                                                                                                     |
| S-5 | No Excel (.xlsx) support                   | Low      | ⏸️ **Deferred** — see below                                                                                                                                  |

> **Severity note that survived the fix:** S-1 and S-2 are client-side
> robustness, not security boundaries. Nothing on this surface reaches the
> server except strings that `validate_scan_targets()` re-validates from
> scratch. They were worth fixing for the operator, not for the threat model.

**Server side was already correct and is unchanged:** `validate_scan_targets()`
re-validates every target, `is_safe()` refuses a leading dash (every scanner
here is driven by argv, so such a value would land as an _option_),
`_is_scannable_address()` rejects loopback/link-local/multicast, `MAX_HOSTS`
caps at 4096, `enforce_org_scan_scope()` answers 403, and the endpoint carries
`@limiter.limit("5/minute")`.

---

## 2. Compliance Evidence Upload

`POST /compliance/controls/{control_id}/evidence` — multipart, stored on disk
under `{COMPLIANCE_EVIDENCE_DIR}/{org_id}/`.

### Findings

| ID  | Finding                                               | Severity | Fixed                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | ----------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| E-1 | No `accept` attribute on the frontend                 | Low      | ✅ `accept` now lists the whitelisted extensions, plus a client-side size and empty check so feedback arrives before the upload completes                                                                                                                                                                                                                                                                                                              |
| E-2 | MIME check trusted the client-declared `Content-Type` | Medium   | ✅ `assert_content_matches()` verifies the payload's own magic bytes. Text is confirmed by _exclusion_ (UTF-8 decodable, no NUL/C0), because it has no signature — without that rule, declaring `text/plain` was an unconditional whitelist bypass. A bare ZIP renamed `.docx` is caught by requiring `[Content_Types].xml`                                                                                                                            |
| E-3 | `Content-Disposition` filename was unescaped          | Medium   | ✅ `content_disposition()` emits RFC 6266 — an ASCII `filename=` plus RFC 5987 `filename*=`. `sanitize_filename()` strips both separators, quotes and control characters; `os.path.basename()` alone did not, because the API runs on Linux where `\` is not a separator                                                                                                                                                                               |
| E-4 | No malware scanning                                   | Medium   | ✅ `scan_for_malware()` speaks clamd INSTREAM over a socket, gated on `CLAMAV_HOST`; a `clamav` service sits behind the `av` compose profile. **Only an explicit `OK` is clean** — timeout, dropped connection, unterminated reply, `ERROR` or anything unrecognised is `scanner_unavailable`. Required by default once a scanner is configured; a required scanner that cannot answer gives **503**, distinct from a detection's **400**. See R-1/R-2 |
| E-5 | Download read the whole file into memory              | Low      | ✅ `FileResponse` streams from disk                                                                                                                                                                                                                                                                                                                                                                                                                    |
| E-6 | No rate limit and no storage quota                    | Medium   | ✅ `@limiter.limit("20/minute")` plus a per-tenant byte quota (`COMPLIANCE_EVIDENCE_TENANT_QUOTA_BYTES`, default 2 GiB), serialised per tenant by a Postgres advisory lock. The per-file cap bounded one request; it never bounded a loop. See R-3                                                                                                                                                                                                     |
| E-7 | No negative tests                                     | Low      | ✅ 62 tests in `tests/security/test_upload_validation.py`                                                                                                                                                                                                                                                                                                                                                                                              |

**Design decision worth keeping:** magic-byte detection is implemented natively
rather than via `python-magic` or `filetype`. libmagic is a system library the
API image does not carry, and the whitelist is ten formats with stable, well
published signatures — a sixty-line table a reviewer can read start to finish,
with no supply-chain edge, in a deployment that installs from a pinned
requirements file behind a private CA.

**On E-2's severity:** it was rated High in the first revision on a stored-XSS
rationale that does not hold. The file lands on disk as `cef_<uuid>.pdf` — the
extension comes from the _whitelist_, not the upload — in a directory nothing
serves statically, and is returned with `attachment` + `nosniff` +
`default-src 'none'`. The residual risk was distribution to another auditor,
which is what E-4 addresses. Both are fixed regardless.

---

## 3. AMT Inventory Upload

`POST /assets/import-amt` — multipart, parsed as JSON, **overwrites** the
organisation's AMT reference inventory.

### Findings

| ID  | Finding                                      | Severity | Fixed                                                                                                                                                                                                                                                                                                                                                        |
| --- | -------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A-1 | Unbounded `file.file.read()`                 | **High** | ✅ `read_capped(file, 16 MB)` → 413. The endpoint's memory budget per concurrent request was previously whatever host nginx allowed through — 50 MB, JSON-amplified, on a sync endpoint holding a threadpool worker                                                                                                                                          |
| A-2 | No MIME or extension validation              | Medium   | ✅ `.json` extension required, and `looks_like_text()` refuses a binary payload before decoding — which previously surfaced as a misleading JSON syntax error                                                                                                                                                                                                |
| A-3 | Drag-and-drop bypassed the `accept` filter   | Low      | ✅ Both the picker and the drop path go through one `acceptFile()` helper                                                                                                                                                                                                                                                                                    |
| A-4 | No record count limit                        | Medium   | ✅ `_MAX_AMT_RECORDS = 100_000`, checked before any row is built                                                                                                                                                                                                                                                                                             |
| A-5 | No rate limiting                             | Medium   | ✅ `@limiter.limit("3/minute")`                                                                                                                                                                                                                                                                                                                              |
| A-6 | `data` value not verified to be a list       | Medium   | ✅ `isinstance(records, list)` → 400. `{"data": {...}}` and `{"data": "text"}` both satisfied the old structure check; iterating either yielded dict keys or single characters and `item.get()` raised `AttributeError` outside any handler — a 500 for the wrong file. Non-dict entries inside a valid list are now counted and logged rather than crashing |
| A-7 | Destructive delete ran before any validation | **High** | ✅ The unique-record set is built and validated _first_; an import that would leave the organisation with nothing is refused with "the existing inventory has been left untouched", and the delete only runs once there is a validated replacement                                                                                                           |

**A-7 is the one that mattered most.** The delete came first, so a file that
parsed as JSON but carried the wrong field names — `macAddress1`, or an export
from a different tool — destroyed the entire AMT reference inventory and
returned `{"success": true, "records_imported": 0}`. The caller was told it
worked. `test_amt_import_does_not_wipe_inventory_when_no_record_is_usable`
seeds two records, submits exactly that file, and asserts both survive.

---

## Infrastructure-Level Protections

> ⚠️ **The first revision cited `nginx/gateway.conf` for these.** That file
> configures the `gateway` service, which sits behind the `alt-gateway` Compose
> profile and **is not started in this deployment** — `docker compose up`
> cannot start it. Its settings protect nothing here. The real path is
> `browser → host Nginx (443) → api:8000`; host Nginx handles `location /api/`
> itself, so the frontend container is not a hop for API traffic.

| Control                                   | Status                   | Where it actually is                                                                                                                                                                                                                                              |
| ----------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Nginx body size limit                     | ✅                       | `client_max_body_size 50m`, `scripts/host-nginx/nginx-host.conf:50` — the ceiling A-1 was measured against                                                                                                                                                        |
| Frontend container body limit             | ✅ Fixed                 | Was unset (nginx default 1 MB). Latent, since host Nginx serves `/api/` directly — but a routing change would have 413'd every evidence upload over 1 MB while the API's cap said 25 MB, and the mismatch would read as a backend bug. Now pinned to 50m to match |
| `X-Content-Type-Options: nosniff`         | ✅                       | `nginx-host.conf:96`, `Frontend/nginx.conf:10`, `Backend/main.py:664`                                                                                                                                                                                             |
| CSP on API responses                      | ✅                       | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` at `Backend/main.py:667-669`                                                                                                                                                                        |
| `X-Frame-Options: DENY`                   | ✅                       | `Backend/main.py:665` and both Nginx layers                                                                                                                                                                                                                       |
| `Cross-Origin-Resource-Policy: same-site` | ✅                       | `Backend/main.py:671`                                                                                                                                                                                                                                             |
| HSTS                                      | ⚠️ Conditional by design | `max-age=300`, sent only when `X-Forwarded-Proto` is `https`. Deliberately low for the rollout — see CLAUDE.md                                                                                                                                                    |
| Uploaded evidence excluded from git       | ✅ Fixed                 | `Backend/data/compliance_evidence/` is now gitignored. The API container bind-mounts `./Backend` at `/app`, so the default evidence root wrote tenant data into the working tree; the test suite also points it at a temp directory                               |

---

## Post-review hardening (second pass)

A review of the first remediation pass raised nine points. Five were real
defects or gaps and are fixed below; two were already satisfied and are now
_proven_ by a test rather than argued from the code; two were wording errors in
the report itself.

| ID  | Raised                                                                                         | Verdict                         | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | ---------------------------------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R-1 | clamd protocol/error responses could be read as clean                                          | ✅ **Real bug**                 | `scan_for_malware()` ended with a bare `return "clean"`, so an empty reply, a dropped connection or an unrecognised response reported an **unscanned file as scanned**. Now only a reply that is NUL-terminated _and_ ends in `OK` is clean; everything else routes through one `_unavailable()` exit. The terminator is checked **before** the content, because a truncated reply ending in "OK" would otherwise read as a verdict                                                                                                                                                 |
| R-2 | Fail-open needs to be an explicit architectural decision                                       | ✅ **Changed**                  | It was implicit and defaulted the wrong way. `UPLOAD_AV_REQUIRED` now defaults to **on whenever `CLAMAV_HOST` is set** — deploying a scanner is the act of requiring it. Evidence upload is low-frequency, so refusing it while the scanner is down costs a retry, whereas storing an unscanned file costs the thing the scan exists for. Fail-open remains available as an explicit opt-in for staged rollout. A required scanner that cannot answer raises `MalwareScanUnavailable` → **503**, deliberately not the **400** a detection gets: the file is not accused of anything |
| R-3 | The 2 GiB quota must be concurrency-safe                                                       | ✅ **Real bug**                 | `SUM → compare → insert` is a read-modify-write across three statements: two concurrent uploads each read the same total, each conclude they fit, and the quota is exceeded. `_lock_tenant_evidence_quota()` takes `pg_advisory_xact_lock` keyed on the tenant, making the read and the write one critical section; Postgres releases it at COMMIT or ROLLBACK so no unlock path can be missed. No-op on SQLite, which serialises writers anyway — stated in the docstring rather than hidden, because a silent no-op is how a concurrency guard stops guarding                     |
| R-4 | Schema validation should be bounded, not just byte/record count                                | ✅ **Real gap**                 | The caps bound the _file_; neither bounded a single field. `AMTInventoryRecord` declares `String(100)`/`String(255)`, so a megabyte-long `asset_name` reached Postgres and returned a `DataError` — an unhandled **500** for what is simply a bad field. `_amt_text()` / `_amt_int()` now coerce and bound each field; a dict where a scalar belongs, or an uncoercible integer, becomes absent rather than crashing                                                                                                                                                                |
| R-5 | The AMT replacement should be transactional                                                    | ✅ **Already true, now proven** | The DELETE and the INSERTs share one transaction with a single `db.commit()` at the end, so a failure partway through leaves the old inventory intact. Validating before the delete is necessary but not sufficient on its own — both properties are needed. `test_amt_import_replacement_is_atomic` detonates an insert mid-import and asserts the pre-existing rows survive                                                                                                                                                                                                       |
| R-6 | Extension validation must not be confused with content validation                              | ✅ **Already true**             | The `.json` extension check is the outermost of six layers, not the boundary: extension → `looks_like_text()` on the bytes → `json.loads()` → top-level structure → `isinstance(records, list)` → per-item `isinstance(item, dict)` → `normalize_mac()`. A declared `Content-Type` check was considered and **deliberately not added**: it is client-controlled and adds nothing over a successful parse, so it would be theatre                                                                                                                                                    |
| R-7 | The npm/CDN claim about SheetJS needs evidence                                                 | ⚠️ **Report error**             | "Deprecated" was wrong; the package carries no deprecation flag. Corrected in _Deferred_ below with the verified facts, which make a narrower and stronger point                                                                                                                                                                                                                                                                                                                                                                                                                    |
| R-8 | "Staged" is the wrong word for the git state                                                   | ⚠️ **Report error**             | `git diff --cached` was empty — **nothing was staged**. The correct description was 11 modified (unstaged, worktree only) and 3 untracked                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| R-9 | AV scanning must precede persistence, and no failure path may orphan a file or commit metadata | ✅ **FIXED / CLOSED**           | Ordering was already correct; a post-write gap was real. See the closure record below                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

### R-9 — closure record

**Status: FIXED / CLOSED.** Verified 22 Aug 2026.

**Root cause.** The evidence endpoint wrote the payload to disk and _then_
constructed and committed its metadata row. Those were two independent steps
with no relationship between their outcomes. Any failure in the second — row
construction, `db.add`, or `db.commit` — left the bytes on disk with nothing
pointing at them.

The orphan was worse than a stray file. It was unreachable through the API,
because every read path filters on a `ComplianceEvidenceFile` row; and it was
**invisible to the quota**, because `_MAX_EVIDENCE_BYTES_PER_TENANT` is enforced
against `SUM(size_bytes)` over _rows_. So an orphan consumed disk that nothing
accounted for, nothing would reclaim, and no figure in the system would ever
show. A repeated failure mode would fill the volume silently.

**What was already correct, and was confirmed rather than changed.** No
filesystem mutation occurs before every check has passed. Traced by line number
in `Backend/routers/compliance.py`:

| Step                                      | Line      |
| ----------------------------------------- | --------- |
| Capped read                               | 1661      |
| Empty-payload check                       | 1668      |
| Magic-byte / declared-type agreement      | 1675      |
| **Malware scan**                          | 1684      |
| Per-tenant advisory lock + quota check    | 1719–1731 |
| `os.makedirs` — first filesystem mutation | 1746      |
| `open(...)` + `fh.write(payload)`         | 1752–1753 |
| `db.add` / `db.commit`                    | 1773–1774 |

A grep of the function body for filesystem operations returns only lines 1746
and 1752–1753 — no temp file, no `UploadFile.save()`, no earlier write. So a
refused upload is never briefly present in storage.

**Implemented behaviour.** The write and the row are now one logical unit. Row
construction, `db.add` and `db.commit` sit inside a `try`; the handler calls
`db.rollback()`, `os.unlink(storage_path)`, then re-raises. End state is
therefore all-or-nothing: file and row both present, or neither.

One residual case is deliberate and logged rather than hidden: if `os.unlink`
_itself_ fails, the exception is swallowed, a warning naming the path is
emitted, and the original error still propagates. Removing a file that cannot
be removed is not something this handler can fix, and masking the original
failure to report a cleanup failure would be worse.

**Regression test.** `test_failed_commit_leaves_no_orphaned_file`.

The injection point is load-bearing and was chosen after a first attempt gave a
false pass. Patching `ComplianceEvidenceFile` — the obvious lever — detonates in
the _quota query at line 1721_, above the write, so the test passed while the
file was never created and the cleanup path never ran. It patches
`sanitize_filename` instead, which has exactly one call site in the module
(line 1765, inside the row constructor) and is referenced by no earlier
validation step and not by the quota query.

The test asserts four things, in order:

1. **The post-write path was genuinely reached** — the injected failure captures
   the evidence directory's _contents_ at the instant it fires, and asserts the
   complete payload was already on disk. Without this, "no file at the end" is
   equally consistent with "the file was never written", and the test would
   prove nothing. The bytes are captured rather than the `Path`, because by
   assertion time the cleanup has already unlinked it.
2. **Zero evidence files remain.**
3. **No metadata row was committed** — row count for the tenant is unchanged.
4. **Quota accounting is unchanged** — `SUM(size_bytes)` for the tenant is
   unchanged, so the figure the next upload is checked against has not moved.

**Proof the test has teeth.** The cleanup was temporarily disabled and the test
re-run; it failed on the orphan:

```
E  AssertionError: a failed commit left an orphaned evidence file on disk
E  assert [PosixPath('/...8c0966d.pdf')] == []
```

The implementation was then restored, confirmed byte-identical to the committed
version, and the test re-run green.

**Final verification.** Full suite: **1092 passed, 0 failed**.

---

Two further points from the review were accepted as documentation rather than
code changes:

- **clamd resource controls** were already present — connection timeout, socket
  timeout, `with`-block cleanup, 64 KB bounded streaming, a 4 KB response cap,
  and a payload that is size-capped by the caller _before_ it reaches the
  scanner. The response cap now has its own `truncated` exit rather than
  falling through.
- **The evidence directory default is a development default.** `/app` is the
  API container's mount of `./Backend`, so the default writes real tenant
  evidence into the source tree. Gitignoring it stops it reaching a commit; it
  does not stop it accumulating. `Backend/.env.example` now says so and
  suggests a dedicated volume outside the repository for production.

---

## Deferred

**S-5 — Excel (.xlsx) support for the scan target list.** Not implemented, and
this is a recommendation rather than an oversight.

It needs SheetJS. Verified against the registry on 22 Aug 2026:
`npm view xlsx versions` tops out at **0.18.5**, and the package carries no
`deprecated` flag — an earlier draft of this document called it "deprecated",
which was wrong. The accurate problem is narrower and worse: the fixes for
CVE-2023-30533 (prototype pollution, fixed in 0.19.3) and CVE-2024-22363
(ReDoS, fixed in 0.20.2) both land _above_ the last version npm carries, and
SheetJS publishes those releases only from its own CDN. So the npm-installable
version is permanently unpatched, and the patched one is unreachable from a
deployment that runs behind a private CA with `script-src 'self'` and no
external asset host.

Pulling a parser for binary Office formats into the browser bundle to save
operators a _Save As_ is a poor trade in an application whose own audit finding
was "do not trust file content".

The workable path, if it is wanted: accept `.xlsx` **server-side**, where
`openpyxl` is already a transitive dependency and the payload can be size- and
magic-byte-checked first. That is a different feature from the one S-5
describes, so it should be scoped deliberately rather than folded into this fix.

---

## What's Working Well

Unchanged and worth keeping:

- **Scan target upload architecture** — the file never reaches the server, and
  the target list is re-validated server-side from scratch rather than trusted.
- **`is_safe()` refuses a leading dash** — every scanner here is driven by argv,
  so a target beginning with `-` would land as an _option_.
- **Evidence storage name is fully synthesised** — `{uuid}{whitelisted extension}`.
  The user-supplied filename never touches a path, and none should start.
- **Evidence MIME whitelist excludes archives on purpose** — now actually
  enforceable, since a bare ZIP no longer passes as OOXML.
- **`read(MAX + 1)`** — never trusts a declared `Content-Length`. Now the shared
  primitive both endpoints use.
- **SHA-256 stored at upload, returned as `X-Evidence-SHA256` on download.**
- **Framework gating on evidence upload** — refuses a control belonging to a
  framework the tenant has not enabled.
- **Security headers on API responses** — a downloaded evidence file cannot be
  reinterpreted as a document on the API's own origin, where the session lives.
- **Tenant isolation** — org-scoped directory, and downloads filter on
  `tenant_id`, not by id alone.
- **Rate limiting keyed on the real client IP** — `_rate_limit_key` walks
  `X-Forwarded-For` to the first untrusted hop. The gap was _which_ endpoints
  carried a limit, never how the limit worked.
- **Audit logging on every upload and delete** — now also records
  `blocked_malware` and `scanner_unavailable` outcomes.
