# Phase 6 — Configuration audit: API → UI coverage

Audited and implemented 23 Sep 2026. Unlike the earlier phases this one started
from partial coverage: `Frontend/src/api/configAudit.js` and
`pages/scan/ConfigurationChecks.jsx` already existed and already called two of
the four operations. The audit was therefore about what those two calls were
_not_ asking for, and the answer turned out to be a third of the catalogue.

## The four operations

| #   | Method | Path                         | Permission   | Before                                               | Now                                                                |
| --- | ------ | ---------------------------- | ------------ | ---------------------------------------------------- | ------------------------------------------------------------------ |
| 1   | GET    | `/config-audit/checks`       | `scans:read` | `platform` only, and only two of its values          | `platform`, `check_type`, `domain`, plus a local search            |
| 2   | GET    | `/config-audit/capabilities` | `scans:read` | `supported[platform]` + `declared_without_collector` | the whole matrix, and it now drives the platform and type controls |
| 3   | GET    | `/config-audit/checks/{id}`  | `scans:read` | never called                                         | **Look up a check by id**, for the id a finding carries            |
| 4   | POST   | `/config-audit/validate`     | `scans:read` | **not exposed at all**                               | the **Rule validator** page                                        |

`scans:read` is held by every role — viewer, scanner, analyst, org_admin,
superadmin — so there is no permission gate to build here and none was added.
The permission is deliberately `scans:read` rather than one of its own: this is
a read-only description of what a scan checks, and it grants no scan capability.

## The measurement that drove the phase

`ConfigurationChecks.jsx` carried `const PLATFORMS = ["windows", "linux"]`
while `/capabilities` serves six queryable platforms. Counted against the live
API:

    platform=windows          56 checks
    platform=linux            86
    platform=database         49   <- unreachable from the UI
    platform=network_device    0
    platform=container         0
    platform=cloud             0
    (no platform filter)     155

36 checks target both Windows and Linux, so those two buttons reached 106
distinct checks of 155. **The 49 `database` checks — the entire Phase 7
database assessment, PostgreSQL, MySQL/MariaDB and SQL Server — had no route
into the UI at all**, and every platform added after this page was written
would have inherited the same fate.

The selector is now derived from `capabilities.supported`, whose keys are
exactly the platforms that return rows. `any` is excluded and that is not an
omission: it is a _targeting_ value on a check ("applies to every platform"),
not a platform to ask about, and the API answers `platform=any` with zero rows.
A test asserts it is absent, with the reason.

The default changed too, from `windows` to the whole catalogue. Hiding a third
of the content behind a default is the defect, and defaulting to one platform
is a smaller version of the same thing.

## Fields the row was dropping

`ConfigAuditCheckOut` has 16 fields. Three were never rendered:

- **`domain`** — the check family the engine files a result under, and the
  field a GAP-12 scan policy selects on. Now in the detail and a server-side
  filter.
- **`tags`** — now in the detail and searchable.
- **`intrusive`** — a check that may disturb the host it runs on, which on an
  OT segment is the difference between an audit and an outage. It is badged in
  the row when true **and** stated in the detail either way: every check
  shipped today is non-intrusive, so a badge alone would never appear and the
  field would stay invisible until the day it mattered.

## `/validate` is a separate page, deliberately

The catalogue's contract is **read-only, no mutation ever**, pinned by a test
that drives every control on the page and asserts no POST, PATCH or DELETE was
issued — the guard that stops a "run a scan" button being added during a
presentation migration. A second test forbids any button whose name matches
`run|start|scan now|execute`.

`POST /config-audit/validate` writes nothing and contacts no target, so it is
not a mutation in substance. But weakening a negative assertion that exists for
that reason is a worse trade than a second route, so the validator lives at
`/configuration-checks/validate` and the catalogue links to it. The read-only
suite is unchanged and a new test re-proves it with every Phase 6 control
operated.

There is no nav entry for the validator. It is an authoring tool for someone
writing rule content, reached from the catalogue that describes the content;
a top-level item would be clutter for every other reader.

### Three properties the validator must not misrepresent

All three were driven against the live API and all three are the opposite of
what the obvious implementation does:

- **`valid: false` arrives as HTTP 200.** The caller asked whether the rule is
  valid and the errors are the answer, not a fault in the request. Rendering it
  through the error path would tell an author their request was broken when it
  was their rule that was.
- **A warning leaves the rule valid.** A rule whose `check_type` has no
  collector on the named platform comes back `valid: true` with a warning
  saying a scan would report an error rather than a verdict. Authoring content
  ahead of its collector is legitimate, so a warning rendered as a refusal
  would block it. Measured: `check_type=api, platform=cloud` →
  `valid: true`, one warning.
- **`check_definition` is returned only when the rule validates**, so the
  "definition this rule would store" block is absent rather than empty.

Two things the form does on the way in, because the API's types require it:

- **`expected` is typed `Any`**, so a number must reach it as a number:
  `equals 1` and `equals "1"` are different comparisons. It is read as JSON
  where it parses and as text otherwise, which is what a regular expression or
  a bare word needs.
- **`collect` is free-form JSON**, because its shape is decided by the check
  type and the backend is the thing that knows. It is parsed only far enough to
  avoid sending something that cannot be JSON, and a parse failure is reported
  as a parse error — never as a verdict about the rule.

## Empty is not one thing

An empty catalogue for `cloud` and an empty catalogue for a platform that has
collectors are different statements: the first is about the product, the second
about the content. The empty state reads `capabilities.supported[platform]` and
says which one it is —

> **This build has no collector for cloud.** The platform is named in the rule
> vocabulary so that content can be written for it, but nothing in this build
> can execute a check against one. A rule targeting it reports an error rather
> than a verdict.

— and a third message covers "your search matched nothing", which is not a
statement about the product at all.

## Known limitations

- **The domain filter's options come from the catalogue, not from the API.**
  There is no domain vocabulary endpoint. They are captured from the first
  unfiltered load and never overwritten by a filtered one — reading them back
  from a filtered response would leave the select offering only the value
  already selected. A test pins that.
- **Search is client-side over the loaded rows** and the hint says so: the
  endpoint has no search parameter. With 155 checks and no pagination on the
  endpoint, that is the whole catalogue, so the search is not lossy today; it
  would become so if the catalogue were ever paginated.
- **There is no "run a configuration audit" endpoint and no rule write
  surface**, by the backend's own decision — checks run inside the credentialed
  scan and rules are authored through the seeders. Neither is a UI gap.
- **`GET /checks/{id}` returns the same shape as a list row**, so the catalogue
  renders its detail from data it already holds. The endpoint is used for the
  one thing the list cannot answer: fetching a check by an id that sits behind
  a filter the reader has not selected, which is the situation when the id came
  off a finding.

## Tests

`2636 passed / 81 files` (+30 tests, +2 files over Phase 5's 2606/79), eslint
clean, `vite build` green. Fixtures are the live API's responses, including all
three `/validate` outcomes.

Two assertions in the pre-existing suite changed, both because they encoded the
default this phase deliberately replaced — `defaults to the windows platform`
became `defaults to the whole catalogue, not to one platform`, and the
`aria-pressed` assertion gained the "all platforms" control. The suite was also
wrapped in a `MemoryRouter`, since the page now links to the validator. Nothing
else in it was touched.
