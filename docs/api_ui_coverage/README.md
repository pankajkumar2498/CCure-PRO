# API → UI coverage

**Programme complete.** The closeout — baseline, classification, the eleven
genuine gaps, the backend authorisation defect and the backlog — is
[`PROGRAMME_CLOSEOUT.md`](PROGRAMME_CLOSEOUT.md). Read that first; the phase
documents below are the working record behind it.

Seven phases, Sep 2026. The question throughout: **does every operator-relevant
API capability this product implements have a UI representation**, and where it
does not, is that a decision or an omission?

Each phase audited its surface against the _running_ API before any UI was
written, drove every operation including the refusals, and recorded what was
left backend-only with the reason.

| Phase                          | Surface                   | Operations | Outcome                                                                            |
| ------------------------------ | ------------------------- | ---------: | ---------------------------------------------------------------------------------- |
| [1](PHASE1_BASELINE.md)        | Credentialed scan results |          1 | the field-level baseline, and the measurement tool the later phases reuse          |
| [2](PHASE2_REPORTS_EXPORT.md)  | Reports and export        |          3 | the whole export API, not two of its arms; found `severity[]=` silently unfiltered |
| [3](PHASE3_SCAN_COMPARISON.md) | Scan comparison           |          1 | five classifications, and Phase 2's deferred baseline closed                       |
| [4](PHASE4_SCAN_POLICY.md)     | Scan policies             |         11 | plus the immutable snapshot a completed scan actually used                         |
| [5](PHASE5_REMEDIATION.md)     | Remediation and SLA       |         12 | the largest surface; no reference to `/remediation` existed before it              |
| [6](PHASE6_CONFIG_AUDIT.md)    | Configuration audit       |          4 | started from partial coverage; 49 database checks were unreachable                 |
| [7](PHASE7_MASTER_MATRIX.md)   | **every router**          |        237 | **206 reached**; 31 classified, 11 of them real gaps                               |

## The tools

Two measurements, answering two different questions. Both are reproducible and
both are meant to be re-run rather than trusted from this document.

- [`scripts/audit/api_ui_coverage.py`](../../scripts/audit/api_ui_coverage.py) —
  **field level**: of everything one API response contains, how much does the
  page render? Walks a live response rather than a model class, because a
  declared field that is never populated and a populated field that is never
  declared misreport coverage in opposite directions.
- [`scripts/audit/api_surface_inventory.py`](../../scripts/audit/api_surface_inventory.py)
  \+ [`api_ui_matrix.py`](../../scripts/audit/api_ui_matrix.py) —
  **operation level**: of every route the API serves, how many does the
  frontend reach, and with which permission?

## The recurring rule

Most of what these phases fixed was one mistake in different clothes: **an
absent answer rendered as a known one.** "Not assessed" shown as zero findings,
"no deadline applies" folded into "within SLA", a withdrawn risk acceptance
still reading as accepted, a platform with no collector reported as a platform
with no checks. In every case the API had kept the distinction and the UI had
thrown it away.
