# Branch protection for `master`

What GitHub should enforce on `master`, why each setting is there, and the two
ways it goes wrong. The settings live in GitHub, not in this repository, so this
file is the record of what they are meant to be.

## Check the plan first

`pankajkumar2498/CCure-Audit-PRO` is a **private repository on a personal
account**. GitHub enforces branch protection and rulesets on private
repositories only on **GitHub Pro, Team or Enterprise**. On GitHub Free the
settings page still accepts them, and they do nothing.

So after you enable them, test that they are enforced (see
[Verifying it works](#verifying-it-works)). Don't assume it from the settings
page.

## How CI and protection fit together

`.github/workflows/ci.yml` runs on two events. The comments at the top of that
file explain why:

| Event                        | Code it tests                                                           | Question it answers           |
| ---------------------------- | ----------------------------------------------------------------------- | ----------------------------- |
| `pull_request` into `master` | `refs/pull/N/merge`: the branch merged into `master` as `master` is now | Is this change safe to merge? |
| `push` to `master`           | The commit that actually landed                                         | Is `master` green?            |

Branch protection makes the first run a **gate** by marking it required. The
second run is the record for `master`. Both are intended, and neither is
duplicate work: they test different code whenever `master` moves while a PR is
open.

Other CI properties already in place:

- **No run on a plain branch push.** `push` is filtered to `master`, so a
  commit to a PR branch fires `pull_request` alone.
- **Superseded PR runs are cancelled.** On `master`, runs are never cancelled.
- **Read-only token.** The workflow runs with `permissions: contents: read`.
- **Pinned actions.** Every action is pinned to a full commit SHA.
- **Matching PostgreSQL version.** CI uses PostgreSQL 18, the same major
  version as production. `Backend/tests/repo/test_ci_postgres_version.py` fails
  if the two drift apart.

## Settings

**Settings → Rules → Rulesets → New branch ruleset.** Rulesets are the current
mechanism. Classic branch protection rules still work and have the same
fields, but pick one or the other, not both.

- **Name:** `master`
- **Enforcement status:** Active
- **Bypass list:** empty. Leave yourself off it as well. An admin on the bypass
  list skips every rule below, and on a one-person repository that means
  nothing is enforced.
- **Target branches:** _Include default branch_ (`master`)

| Rule                                                  | Now (one developer)                                                                                           | With a team                       | Why                                                                                                                                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Restrict deletions                                    | On                                                                                                            | On                                | `master` must not be deletable by accident.                                                                                                                          |
| Block force pushes                                    | On                                                                                                            | On                                | A force push rewrites the history the deploy record and every review point at.                                                                                       |
| Require a pull request before merging                 | On                                                                                                            | On                                | Every change to `master` passes the PR gate. No direct pushes.                                                                                                       |
| ↳ Required approvals                                  | **0**                                                                                                         | **1**                             | GitHub does not let an author approve their own PR. At 1, a single developer can never merge.                                                                        |
| ↳ Dismiss stale approvals when new commits are pushed | On                                                                                                            | On                                | An approval covers the code that was reviewed, not what was pushed afterwards.                                                                                       |
| ↳ Require approval of the most recent reviewable push | Off                                                                                                           | On                                | Stops a reviewer's approval carrying over to a commit they didn't see. Only meaningful once there are reviewers.                                                     |
| ↳ Require conversation resolution before merging      | On                                                                                                            | On                                | Unresolved review comments block the merge rather than being lost.                                                                                                   |
| Require status checks to pass                         | On                                                                                                            | On                                | This is what makes the PR run a gate.                                                                                                                                |
| ↳ Require branches to be up to date before merging    | On                                                                                                            | On, or replace with a merge queue | Makes the PR run test the current `master`, not the `master` from when the branch was cut.                                                                           |
| ↳ Required checks                                     | `Backend Validation`, `Frontend Validation`, `Secret Scan`, `Python Dependency Audit`, `npm Dependency Audit` | same                              | See below. These are the jobs' `name:` fields in `ci.yml` and `security.yml`. `Bandit Medium-Severity Report` runs only at night and is not a gate, so leave it out. |
| Require linear history                                | Off                                                                                                           | Team decision                     | PRs here have always merged with merge commits. Turning this on removes that button.                                                                                 |
| Require signed commits                                | Off                                                                                                           | Optional                          | Only useful once every contributor has signing configured.                                                                                                           |

## Two ways this fails

**1. Renaming a CI job blocks every PR.** A required check is matched by the
job's `name:` (`Backend Validation`, `Secret Scan`, …), not by its key or by
the workflow it lives in. Rename a job and GitHub keeps waiting for a check with the old name
that will never report again. Every PR shows _"Expected — Waiting for status to
be reported"_ and cannot merge. Change the ruleset in the same change as the
rename.

**2. A skipped workflow leaves a required check waiting forever.** If
`paths:`/`paths-ignore:` filters are added to `ci.yml`, a PR that touches only
excluded files never starts the workflow, and the required checks wait
indefinitely. That is why path filters were left out. If they are wanted later,
filter inside the job (for example `dorny/paths-filter` plus a step-level `if:`)
so the job still runs and reports success.

## Optional: create it from the command line

This is equivalent to the settings table in its "now" column. It needs the `gh`
CLI, logged in as a repository admin. Review the result in the UI afterwards.

```bash
gh api -X POST repos/pankajkumar2498/CCure-Audit-PRO/rulesets --input - <<'JSON'
{
  "name": "master",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Backend Validation" },
          { "context": "Frontend Validation" },
          { "context": "Secret Scan" },
          { "context": "Python Dependency Audit" },
          { "context": "npm Dependency Audit" } ] } }
  ]
}
JSON
```

When a second developer joins, set `required_approving_review_count` to `1` and
`require_last_push_approval` to `true`.

## Verifying it works

A settings page that accepted the rules proves nothing (see
[Check the plan first](#check-the-plan-first)). Test the behaviour instead:

1. **Direct pushes are refused.** From a scratch commit on `master`:

   ```bash
   git push origin master
   ```

   This must be rejected with a message naming the ruleset. If it succeeds,
   nothing is enforced. Undo the scratch commit locally.

2. **The PR is gated.** Open a PR. The merge box must list all five required
   checks as **Required**, and the merge button must stay disabled until every
   one passes.

3. **Stale branches are caught.** Merge something else into `master`, then look
   at the first PR. It must show _"This branch is out-of-date"_ and need an
   update before it can merge.
