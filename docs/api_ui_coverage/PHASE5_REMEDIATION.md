# Phase 5 — Remediation and SLA: API → UI coverage

Audited and implemented 23 Sep 2026. Every operation below was driven against
the running API before any UI was written, including all six writes, driven
through a complete lifecycle on one finding — assign → in remediation → note →
pending verification → back → accept risk → withdraw → unassign — which was
returned to `open` and unassigned afterwards. The refusals were exercised too,
because on this surface the refusals are the feature.

Before this phase the frontend contained **no reference to `/remediation` at
all**: twelve operations, three RBAC atoms and the entire SLA model were
reachable only from the API.

## The twelve operations

| #   | Method | Path                                             | Permission                 | UI                                                                       |
| --- | ------ | ------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------ |
| 1   | GET    | `/remediation/summary`                           | `findings:read`            | the summary band — `summary_line` verbatim, 7 state counts, 3 SLA counts |
| 2   | GET    | `/remediation/overdue`                           | `findings:read`            | **Overdue** queue, owner filter, paging on `limit`/`offset`              |
| 3   | GET    | `/remediation/pending-verification`              | `findings:read`            | **Pending verification** queue, same controls                            |
| 4   | GET    | `/remediation/findings/{id}`                     | `findings:read`            | the finding panel — all 22 serialised fields                             |
| 5   | GET    | `/remediation/findings/{id}/history`             | `findings:read`            | the event timeline, all 9 event fields                                   |
| 6   | GET    | `/remediation/sla-policy`                        | `findings:read`            | the SLA form, read-only without #7's grant                               |
| 7   | PUT    | `/remediation/sla-policy`                        | **`settings:update`**      | **Save deadlines**, sending only what changed                            |
| 8   | POST   | `/remediation/assign`                            | `findings:update`          | row selection → **Assign** / unassign, bulk                              |
| 9   | PATCH  | `/remediation/findings/{id}/state`               | `findings:update`          | **Change state**, offering four targets of seven                         |
| 10  | POST   | `/remediation/findings/{id}/notes`               | `findings:update`          | **Add note**                                                             |
| 11  | POST   | `/remediation/findings/{id}/accept-risk`         | **`findings:accept_risk`** | **Accept risk** — reason required, expiry optional                       |
| 12  | POST   | `/remediation/findings/{id}/withdraw-acceptance` | **`findings:accept_risk`** | **Withdraw acceptance**                                                  |

The finding panel is shared between the Remediation workspace and the
Vulnerability Browser's finding drawer, so the workflow reads identically in
both places and the refusal to offer `verified_fixed` is stated once.

## RBAC, measured on the live role grants

| Permission             | Roles holding it                       |
| ---------------------- | -------------------------------------- |
| `findings:read`        | viewer, analyst, org_admin, superadmin |
| `findings:update`      | analyst, org_admin, superadmin         |
| `findings:accept_risk` | analyst, org_admin, superadmin         |
| `settings:update`      | **org_admin, superadmin only**         |
| `users:read`           | **org_admin, superadmin only**         |

Four consequences, all implemented:

- **`scanner` holds none of these**, so the page is refused outright and names
  `findings:read`. Nothing is fetched for somebody who may not see it.
- **A viewer sees the queues and the record and no write control anywhere** —
  not a disabled one, which tells nobody what they are missing.
- **An analyst can work the queue and accept a risk but cannot set the
  deadlines.** The SLA form is rendered read-only with the permission named,
  rather than hidden: knowing what "late" means is part of working the queue.
- **An analyst cannot list users**, which is a real degradation and not a
  guess. `POST /assign` validates that the owner is in the caller's
  organisation, so an id has to come from somewhere. With `users:read` the
  owner is a picker and the filter is a picker; without it both fall back to
  an id field, plus an **Assign to me** button, and the hint says which
  permission would replace them.

The owner picker offers only people whose `organization_id` matches the
caller's, because the API refuses anyone else with a 400 — a superadmin's user
listing spans tenants.

## Real API verification

Live, against `org_default` (8,633 findings). The read side:

    summary                200  by_state over all 7 states, summary_line,
                                sla_states — 7763 open / 156 overdue /
                                5791 with no deadline at all
    overdue                200  total 156, count 3 at limit=3
    pending-verification   200  total 1
    sla-policy             200  6 severities, defaults beside the current
                                values, unit "calendar days"
    findings/{id}          200  22 fields
    findings/{id}/history  200  the append-only trail

The write side, on one finding, then restored:

    state -> verified_fixed          400  "A finding cannot be marked verified
                                          fixed by hand. It becomes verified
                                          when a subsequent scan…"
    state -> risk_accepted           400  "…needs a reason and an approver.
                                          Use POST …/accept-risk."
    state -> closed                  422  field error naming the vocabulary
    assign (owner outside the org)   400  "The owner must be a user in this
                                          organisation."
    assign (no matching finding)     404
    assign                           200  requested 1 / matched 1 / changed 1
    state -> in_remediation          200
    notes                            200
    state -> pending_verification    200
    state -> in_remediation          200  (the backwards edge is legal)
    accept-risk (empty reason)       422
    accept-risk                      200  state risk_accepted, sla "resolved"
    accept-risk (again)              400  "Cannot move a finding from
                                          'risk_accepted' to 'risk_accepted'."
    withdraw-acceptance              200
    withdraw-acceptance (again)      400  "This finding does not have an
                                          accepted risk."
    unassign                         200  changed 1, state back to open

## Four behaviours the UI had to be built around

Each was measured, and each would have produced a plausible screen that says
something false.

**The exception fields outlive the exception.** A withdrawal moves the state
and clears `expires_at`, and leaves `reason`, `accepted_by` and `accepted_at`
in place. So the only sound test for "this risk is accepted" is
`remediation.state === "risk_accepted"` — `isRiskAccepted` — and the residue is
rendered under **Accepted risk (withdrawn)** with a line saying it is no longer
in force. A panel keying on a non-null reason labels an open finding as one the
organisation decided to carry. The fixture this is asserted against is the live
API's own answer after the withdrawal above.

**Withdrawing returns the finding to `assigned`, not to `open`,** when it has
an owner — it went to `open` only after the unassign. Nothing in the UI
predicts the resulting state; it is read back from the response.

**`sla.days_remaining` keeps counting while a risk is accepted** — 9 days, with
`sla.state` reporting `resolved`. The badge is driven by the state and the
sentence by `dueDescription`, which reads `state` before it reads the number.

**Assigning an unassigned finding moves its state** from `open` to `assigned`
as a side effect, recorded as an `assigned` event. The queue reloads from the
API after every write rather than patching a row locally.

## What is not offered, and why

`PATCH .../state` accepts four of the seven states. The other three are absent
from the control **and named underneath it with the reason**, because "why can
I not close this" is the first question an operator asks:

- **`verified_fixed`** — the backend's human transition table has no edge into
  it from any state. Only `core/remediation/verification.py`, driven by a scan
  comparison, may write it. This is the phase's whole point and the UI must not
  appear to offer a way round it.
- **`reopened`** — likewise assessment-only; no human set contains it.
- **`risk_accepted`** — refused on this path deliberately, for a different
  reason: it needs a reason and an approver, so it has its own endpoint and its
  own permission.

The state a finding is already in is not offered either: the backend admits a
self-transition on some states and refuses it on others, and a control that
sometimes works is worse than one that is not there.

## Backend limitations recorded rather than worked around

- **Only two of the seven states have a listing endpoint.** There is no
  `remediation_state` filter on any `/remediation` listing and none on
  `/findings` either, so `assigned`, `in_remediation`, `verified_fixed`,
  `reopened` and `risk_accepted` are reported as counts and are not drillable.
  Fetching every finding and filtering in the browser would be several
  thousand rows to synthesise a query the API declined to offer, and the count
  it produced would disagree with `/summary` at the first page boundary. The
  screen says which states have a list behind them. **A `states=` parameter on
  `_listing`, which already accepts one internally, would close this in a few
  lines** — recommended as a backend follow-up, not done here.

- **"My work" across all states is likewise unavailable.** `owner_id` filters
  exist only on the two queues.

- **The listings carry ids and nothing else** — `asset_id`, `vuln_id`,
  `remediation.owner`. Hosts are resolved through one `/assets` read and owners
  through one `/admin/users` read, so a page of 200 rows costs two extra
  requests rather than 400. An id that resolves to nothing is shown as the id,
  never as a blank.

- **The event trail's tie-break is not causal.** Events are ordered by
  `occurred_at` then by `id`, and the id carries a random tail, so two events
  written inside one transaction can be returned in an order that is not the
  one they happened in — observed on a finding whose `assigned → in_remediation`
  appeared after `in_remediation → pending_verification`. The UI renders the
  order the API returned and shows the timestamps; re-sorting here would be the
  frontend inventing a sequence.

- **`org_id` on every operation** is not exposed. It is superadmin cross-tenant
  addressing; the workspace acts in the caller's own organisation, which is
  what `_resolve_org` does when it is omitted.

## Where it lives

- `/remediation` — the workspace (nav entry under Intelligence,
  `findings:read`).
- The Vulnerability Browser's finding drawer gained the same record and the
  same actions. The existing status control there is the **detection**
  lifecycle and is deliberately left beside it rather than merged: since
  GAP-14 it no longer stamps `fixed_at`, it routes the finding to pending
  verification, and "absent from the last scan" and "somebody confirmed a fix"
  are different claims.

## Tests

`2606 passed / 79 files` (+59 tests, +4 files over Phase 4's 2547/75), eslint
clean, `vite build` green, every new endpoint path present in the served
bundle. Fixtures are the live API's responses, stored verbatim.

One pre-existing assertion was re-scoped rather than relaxed:
`VulnerabilityBrowser` asserted the triage dialog held exactly two textboxes.
The drawer now carries the remediation panel as well, so the count is scoped to
the triage form (`.vb-triage`) while the labelling property it defends is
asserted over the **whole** dialog — strictly stronger than before.
