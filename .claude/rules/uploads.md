---
paths:
  - "Backend/core/upload_guard.py"
  - "Backend/routers/compliance_attestation.py"
  - "Backend/routers/assets.py"
  - "Backend/tests/security/test_upload_validation.py"
---

# File uploads

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 4914–5056) and is maintained here. Frozen original: `docs/archive/engineering-record/file-uploads.md`. The repository-wide rules in `CLAUDE.md` still apply.

## File uploads

Exactly **two** endpoints accept a file, and both go through
`core/upload_guard.py`: `POST /compliance/controls/{id}/evidence` and
`POST /assets/import-amt`. A third surface _looks_ like an upload and is not —
the scan target list on `NewScan.jsx` is parsed by `FileReader` in the browser
and only the extracted target strings are POSTed, which
`validate_scan_targets()` re-validates from scratch. Guards there are UX, not a
boundary.

Keep the shared primitives shared. The two endpoints previously carried
different and differently incomplete versions of the same three checks, which
is the shape every finding in the August 2026 upload audit took.

- **The declared `Content-Type` is attacker-controlled.** `UploadFile.content_type`
  is the string from the multipart part header and nothing more. The evidence
  whitelist used to be satisfied by that string alone, so `malware.exe` renamed
  to `malware.pdf` was accepted as a PDF. `assert_content_matches()` checks the
  payload's own signature. There is deliberately **no `python-magic` or
  `filetype` dependency** — libmagic is not in the API image, and ten formats
  with stable signatures is a table a reviewer can read.

- **Text has no magic number**, so `text/plain` and `text/csv` are confirmed by
  _exclusion_: must decode as UTF-8, must carry no NUL or C0 control bytes. Get
  this backwards and declaring `text/plain` becomes an unconditional bypass of
  the whole whitelist — a PE fails on its first NUL.

- **OOXML is a ZIP, and archives are excluded from the whitelist on purpose.**
  A bare ZIP renamed `.docx` has exactly OOXML's magic bytes. `_looks_like_ooxml()`
  requires `[Content_Types].xml` in the central directory. Only the directory is
  read, so a zip bomb costs the directory parse and nothing more.

- **Never build `Content-Disposition` with an f-string.** The filename is
  user-supplied and reaches a response header. `os.path.basename()` is not
  sanitisation: the API runs on Linux, where `\` is not a separator, and it
  strips neither quotes nor control characters. Use `content_disposition()`,
  which emits RFC 6266 — an ASCII `filename=` plus an RFC 5987 `filename*=`.

- **Read with a cap, never `read()`.** `file.file.read()` on the AMT import was
  unbounded, so the endpoint's per-request memory budget was whatever host
  nginx allowed through — 50 MB, JSON-amplified, on a sync endpoint holding a
  threadpool worker. `read_capped()` / `read_capped_async()` read MAX + 1 and
  test for overflow, which never allocates past the limit and cannot be lied to
  by a declared `Content-Length`.

- **Validate before you destroy.** `import-amt` is an overwrite: it deleted the
  organisation's entire AMT inventory _before_ discovering whether any record
  carried a usable MAC. A file that parsed as JSON but used the wrong field
  names — `macAddress1`, or an export from another tool — wiped the inventory
  and returned `{"success": true, "records_imported": 0}`. The unique-record set
  is now built first and an import that would leave nothing is refused. Do not
  reorder these.

- **`{"data": ...}` is not necessarily a list.** `{"data": {...}}` and
  `{"data": "text"}` both satisfied the structure check; iterating either
  yielded dict keys or single characters and `item.get()` raised
  `AttributeError` outside any handler — a 500 for the wrong file. The
  `isinstance(records, list)` check is load-bearing.

- **A per-file cap bounds one request, not a loop of them.** Evidence has a
  25 MB per-file limit _and_ a per-tenant quota
  (`COMPLIANCE_EVIDENCE_TENANT_QUOTA_BYTES`, default 2 GiB), because
  `compliance:attest` was otherwise an unbounded write to the API host's disk.
  Both upload endpoints also carry `@limiter.limit`; `conftest` disables the
  limiter session-wide, so `tests/security/test_upload_validation.py` asserts
  registration in `Limiter._route_limits` rather than exercising a 429.

- **The quota check is a read-modify-write and must stay serialised.**
  SUM → compare → insert spans three statements; two concurrent uploads each
  read the same total, each conclude they fit, and the quota is exceeded.
  `_lock_tenant_evidence_quota()` takes `pg_advisory_xact_lock` keyed on the
  tenant, so the read and the write are one critical section and Postgres
  releases it at COMMIT or ROLLBACK. It is a deliberate no-op on SQLite, which
  serialises writers anyway.

- **Only an explicit `OK` from clamd is `clean`.** A timeout, a dropped
  connection, a reply with no NUL terminator, an `ERROR`, or anything the
  parser does not recognise is `scanner_unavailable`. This is the single most
  important property of `scan_for_malware()`: a scanner failure reported as
  clean is worse than having no scanner, because it launders an unscanned file
  into an audit trail that says it was checked. The NUL is checked _before_ the
  content, because a truncated reply ending in "OK" is otherwise read as a
  verdict.

- **Deploying a scanner means requiring it.** `UPLOAD_AV_REQUIRED` defaults to
  on whenever `CLAMAV_HOST` is set. The email domain guard fails open for a
  blocklist that did not load and that is right there — refusing every signup
  is the worse outage. Malware inverts the trade: evidence upload is
  low-frequency, so refusing it while the scanner is down costs a retry,
  whereas storing an unscanned file costs the thing the scan exists for.
  A required scanner that cannot answer raises `MalwareScanUnavailable` → **503**,
  deliberately not the **400** a detection gets: the file is not accused of
  anything. With no `CLAMAV_HOST` there is no scan and no error, and the
  response says `malware_scan: not_configured` — never a silent clean verdict.
  `docker compose --profile av up -d clamav` starts one.

- **`COMPLIANCE_EVIDENCE_DIR` defaults to a development path.** `/app` is the
  API container's mount of `./Backend`, so the default writes real tenant
  evidence into the source tree. It is gitignored, but a production deployment
  should point it at a dedicated backed-up volume outside the repository. The
  test suite redirects it to `tmp_path` via an autouse fixture.

- **Scan then persist, never persist then scan.** Nothing in the evidence
  endpoint touches the disk until every check has passed: read → empty → magic
  bytes → AV scan → quota → _then_ the first byte is written. Do not move the
  write earlier for convenience; a refused upload must never be briefly present
  in storage where a backup or an indexer can reach it.

- **Evidence filesystem writes and their database rows must behave as one
  logical unit; any failure after the filesystem write must remove the newly
  written file.** The bytes land before `db.commit()`, so a failure between them
  leaves a file nothing points at — unreachable through the API, and **invisible
  to the quota**, which enforces against `SUM(size_bytes)` over _rows_. Such an
  orphan consumes disk that nothing accounts for, nothing reclaims, and no
  figure in the system ever shows. Row construction, `db.add` and `db.commit`
  are therefore wrapped: the handler rolls back, unlinks, and re-raises, so the
  end state is always file-and-row or neither. If the unlink itself fails the
  path is logged and the original error still propagates — masking it to report
  a cleanup failure would be worse.

  `test_failed_commit_leaves_no_orphaned_file` covers it, and **its injection
  point is load-bearing**. Patching `ComplianceEvidenceFile` — the obvious lever
  — detonates in the quota query _above_ the write, so the file is never created
  and the test passes having exercised nothing. It patches `sanitize_filename`,
  which has one call site, inside the row constructor. The test also captures
  the evidence directory's _contents_ at the moment of failure to prove the
  write actually happened first: "no file at the end" is equally consistent with
  "never written". Capture the bytes, not the `Path` — by assertion time the
  cleanup has unlinked it.

Downloads stream with `FileResponse`. The evidence download used to `fh.read()`
the whole file into a `Response`.

The AMT replacement is **atomic**: the DELETE and the INSERTs share one
transaction with a single `db.commit()` at the end, so a failure partway
through leaves the old inventory intact. Validating before the delete (above)
is necessary but not sufficient on its own — both properties are needed, and
`test_amt_import_replacement_is_atomic` proves the second by detonating an
insert. Field values are also bounded by `_amt_text`/`_amt_int` before they
reach the columns: the byte and record caps bound the file, not a single
megabyte-long `asset_name`, which used to reach Postgres and return a
DataError as an unhandled 500.
