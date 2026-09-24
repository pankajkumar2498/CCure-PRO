# Phase 4 — Scan policy: API → UI coverage

Audited and implemented 22 Sep 2026. Every operation below was driven against
the running API through a full create → read → validate → edit → enable →
status → version → usage → delete lifecycle on a throwaway policy, and the
vocabulary was read from `/scan-policies/settings` rather than transcribed.

## The eleven operations

| #   | Method | Path                          | Permission             | UI                                                      |
| --- | ------ | ----------------------------- | ---------------------- | ------------------------------------------------------- |
| 1   | GET    | `/scan-policies`              | `scan_policies:read`   | policy table, with the API's own filters                |
| 2   | GET    | `/scan-policies/settings`     | `scan_policies:read`   | drives every select and checkbox                        |
| 3   | POST   | `/scan-policies/validate`     | `scan_policies:read`   | **Check configuration** in the editor                   |
| 4   | POST   | `/scan-policies`              | `scan_policies:create` | **New policy**                                          |
| 5   | GET    | `/scan-policies/{id}`         | `scan_policies:read`   | list rows carry the full record; detail opens from them |
| 6   | PATCH  | `/scan-policies/{id}`         | `scan_policies:update` | **Edit**                                                |
| 7   | POST   | `/scan-policies/{id}/enable`  | `scan_policies:update` | **Enable / Disable**                                    |
| 8   | POST   | `/scan-policies/{id}/status`  | `scan_policies:update` | **Mark draft / active / archived**                      |
| 9   | POST   | `/scan-policies/{id}/version` | `scan_policies:create` | **New version**                                         |
| 10  | GET    | `/scan-policies/{id}/usage`   | `scan_policies:read`   | schedules and scan count in the detail                  |
| 11  | DELETE | `/scan-policies/{id}`         | `scan_policies:delete` | **Delete**, with the 409 and `force`                    |

Plus `GET /scans/{id}/policy` (`scans:read`) — the per-scan snapshot, which is
a question about a _scan_ and therefore lives on the scan, not here.

## RBAC, measured on the live role grants

| Permission             | Roles holding it                                |
| ---------------------- | ----------------------------------------------- |
| `scan_policies:read`   | viewer, scanner, analyst, org_admin, superadmin |
| `scan_policies:create` | analyst, org_admin, superadmin                  |
| `scan_policies:update` | analyst, org_admin, superadmin                  |
| `scan_policies:delete` | **org_admin, superadmin only**                  |

So an analyst can create, edit and version a policy but cannot delete one, and
the UI hides the control rather than offering an action that will 403. The
whole page is refused without `read`, with the permission named — a row of
disabled buttons tells nobody what they are missing.

`scan_policies:*` is deliberately **not** `scans:*`: "may this person run a
scan" and "may this person decide what every scan assesses" are different
authorisations.

## Real API verification

Full lifecycle against the live deployment, on a throwaway policy that was
deleted afterwards (org back to its original single policy):

    list                       200  total 1 -> 2 during the run -> 1 after
    settings                   200  3 kinds, 3 statuses, 17 config keys,
                                    11 check families, 5 severities
    validate (good)            200  {"valid": true, "errors": [], "warnings": []}
    validate (unknown family)  200  valid false — names the 11 known families
    validate (no framework)    200  valid false — "…the configuration audit
                                    assesses nothing and the host reports as clean"
    create                     201  draft, is_enabled true, is_usable **false**
    create (duplicate name)    409  "A scan policy named '…' already exists."
    create (archived at birth) 422  field error on `status`
    create (bad scan_kind)     422  field error on `scan_kind`
    read                       200
    patch (description)        200
    patch (config)             200
    enable false / true        200  is_enabled flips, is_usable still false
    status -> active           200  is_usable becomes **true**
    status -> bogus            422  field error
    version                    201  v2 active; v1 archived and
                                    superseded_by_policy_id -> v2
    usage                      200  {use_count, scan_count, schedules}
    delete v2, delete v1       200
    read after delete          404

Two derived behaviours worth stating because the UI must not reimplement them:
**`is_usable` is `active` AND `is_enabled`** — it stayed false for an enabled
draft and only became true on activation. And **versioning archives the
predecessor**, which is why it is presented as a separate act from editing.

## The historical-snapshot requirement

`GET /scans/{id}/policy` serves the scan's **own immutable record**, never the
policy row it names. Verified on scan 69, which is exactly the case that makes
it matter:

    policy.recorded          true, fingerprint 4bd5a15f…
    policy_current_state     status "archived", is_enabled false,
                             matches_snapshot **true**

The lifecycle moved and the configuration did not. So the UI renders the
snapshot as the body of the panel and the policy's current state as a note
beneath it, and says _"unchanged since this scan"_ — because announcing "the
policy has changed" there would be as wrong as showing the live policy in place
of the record. Both failure modes are asserted against this fixture.

`recorded: false` is rendered as its own answer. A scan predating GAP-12 has no
configuration record, and substituting a default would put a claim in front of
an auditor that nothing supports.

## Known limitations

- **`org_id` on every operation** is not exposed. It is superadmin
  cross-tenant addressing; the workspace acts in the caller's own
  organisation, which is what `_resolve_org` does when it is omitted.
- **`GET /scan-policies/{id}` is not called separately.** The list returns the
  full serialised record for every policy, so the detail view opens from data
  already held. The endpoint is covered in the sense that its payload is what
  the UI renders; a second fetch would add a round trip and nothing else.
- **Applying a policy when starting a scan** is not part of this page. The
  scan-dispatch forms own that choice, and `POST /scan/credentialed` already
  accepts `policy_id`; wiring the selector into those forms is a change to the
  scan-start flow rather than to policy management.
- **`usable_only` is exposed as a filter** but the list has no pagination —
  the endpoint returns every policy in the organisation and does not accept
  `skip`/`limit`. Not an omission in the UI; the API has no page to ask for.
