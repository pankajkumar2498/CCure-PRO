# Checkpoint 3C — Batch 32: ComplianceWorkspace's shell, and the end of the page's migration

Batch 32 migrates what every tab of ComplianceWorkspace shares, which is what
was left after Batches 26A to 31 took the tabs and dialogs one at a time:

- **the header** — the title, the framework selector, the eleven
  framework-specific filters, the two scope checkboxes and the gap source;
- **its actions** — Gap Analysis, Run Compliance Scan and Create Baseline
  Policy;
- **the tab bar** — now a real tab list with a panel;
- **the error banner and the loading bar**;
- **the dialog container**, with titles written for people rather than the
  dialog's type;
- **the Marketplace's uninstall question**, which was the page's last
  `window.confirm`.

With it the page carries no inline style, colour literal, `dashboard.css`
class, hand-built button or select, and no native confirm.

**Baseline:** HEAD `d9384ea` (Batch 31).

## What changed

| Surface               | Before                                                                       | After                                                                                                                                         |
| --------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Header and filters    | 54 inline style objects, `db-page-header`, 15 bare `<select>`s               | `CcureSelect` with a real label each, two label-wrapped checkboxes, `compliance-workspace.css`                                                |
| Header actions        | `db-btn` with emoji in the accessible name                                   | `CcureButton`; the emoji is hidden, so the names are "Gap Analysis", "Run Compliance Scan", "Create Baseline Policy"                          |
| Page title            | A styled `div`                                                               | The page's `h1`                                                                                                                               |
| Tab bar               | Eight `<div onClick>`; no role, no selected state, not reachable by keyboard | `CcureTabs`: `role="tablist"`, `aria-selected`, roving tabindex, arrow keys, and one `CcureTabPanel` the chosen tab labels                    |
| Error banner          | `db-alert db-alert--critical`                                                | `CcureAlert variant="danger"` (`role="alert"`)                                                                                                |
| Loading bar           | `.loading-bar`, a hand-animated gradient                                     | `CcureProgress`, named "Loading compliance data", still a thin bar at the top of the window                                                   |
| Dialog container      | `components/layout/Modal`, titled `modalType.toUpperCase()`                  | `CcureModal` (portal, focus trap, guarded overlay click) titled "Remediate Finding", "Roll Back Remediation", "Execution Log", "Gap Analysis" |
| Marketplace uninstall | `window.confirm`                                                             | `CcureConfirmDialog`: Cancel focused, Escape backs out, busy while the POST is out                                                            |

Measured on the page: inline style attributes 54 → **0**, hex colour literals
0 → 0, `var(--…)` references 50 → **0**, `db-` class references 15 → **0**,
hand-built buttons 3 → **0**, selects 15 → **0**, `window.confirm` 1 → **0**;
5,287 → 4,943 lines. `compliance.css` is 502 → 467 lines: `.loading-bar`, its
keyframes and `.cw-pagination-select` lost their last consumer and are gone.
`compliance-workspace.css` is 159 token-only lines under `cwh-`.

Behaviour is unchanged: the scan trigger still reads the policies afresh and
posts one `/compliance/scans` per policy of the chosen framework, the gap
analysis and every tab's reads are untouched, the permission gates are
untouched, and tab and filter state still drive the same queries.

## How it was verified

| Gate                | Result                                                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Tests first         | 11 new tests: the 3 contract tests pass on the page before migration, and the 8 batch 32 tests all fail, each for its intended reason                                                |
| ComplianceWorkspace | 9 files, **231 / 231**, including Batches 26A to 31 unchanged                                                                                                                        |
| Full frontend suite | 66 files, **2428** tests — the one failure on the first run was AMTIntegration's known load flake, which passes alone and on a rerun                                                 |
| Lint, Prettier      | Clean                                                                                                                                                                                |
| Build               | `vite build` succeeds                                                                                                                                                                |
| UX4G guardrails     | 0 `ux4g-` classes or selectors outside `src/design-system/` (the one match is `DesignSystemShowcase.jsx`'s header comment), 0 runtime references, 0 external origins in `index.html` |
| CSP and air gap     | `index.html`, `nginx.conf` and `scripts/host-nginx/` untouched; the new stylesheet has no `url()` or `@import`                                                                       |
| Backend and API     | No file under `Backend/`, `Frontend/src/api/`, `Frontend/src/design-system/` or `Frontend/src/components/` changed                                                                   |
| Secrets             | 0 secret-shaped literals in the lines this batch adds; gitleaks passes on the staged content                                                                                         |
| Screenshots         | The header, tab bar, a dialog and a phone width reviewed on the migrated build                                                                                                       |

Three earlier test files were updated for changes this batch was asked to make:
the dialog titles (Batches 26B and 30), the dialog container's body class and
`</Modal>` anchor (Batch 30), the loading bar's selector (Batches 26B, 27, 30),
and the uninstall question, which Batch 27 pinned as `window.confirm` and now
answers through either it or the dialog. Batch 31's source test required
`.cw-pagination-select` to survive; the header's selects were its last consumer,
so it now requires the whole family to be gone.

## Deferred, and found but not fixed

- **The tab panel is one panel, not eight.** Every tab's content shares it, so
  `aria-controls` points at a live element and the panel is labelled by the
  chosen tab, but the panels are not separately addressable.
- **`components/layout/Modal` stays** for `OrganizationManagement`, its last
  consumer, along with its `scan.css` rules.
- **`dashboard.css` keeps the rules this page stopped using** (`.db-page*`,
  `.db-alert*`, `.db-btn*` and the rest): other pages still use them.
- **The loading bar is announced but not visible to a reader's eye as text** —
  its name is hidden, which is what it was before, only now it has one.
- **Arrow keys move focus without choosing a tab** (`activateOnFocus={false}`),
  because choosing one reads its data. Enter, Space or a click chooses.
- **The harness's tab-click helper is out of date but still correct.** Its
  comment in `scripts/ux4g-harness/lib/states.mjs` says the workspace's tabs are
  not buttons and its title is not a heading; after this batch both are. It
  finds the tab bar by its contents, so every state still clicks the tab it
  means to — checked on the migrated build — and the file is outside this
  batch's change set.
- **The gap-analysis and execution findings recorded in Batches 30 and 31 stand**
  — the default parked gap target, the target select that can disagree with the
  result, the dispatch that closes before its result, and the rest.

**Carried:** every item deferred by Batches 16 to 31 stands unchanged, and none
was reopened here.

## Result

**GO.** ComplianceWorkspace is migrated end to end: its eight tabs, its eight
dialogs and now its shell. What remains on the page belongs to other owners —
the legacy `Modal` its other consumer keeps, and the global stylesheets other
pages still read.
