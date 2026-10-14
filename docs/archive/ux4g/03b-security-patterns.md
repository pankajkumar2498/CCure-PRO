# PHASE 3 CHECKPOINT REPORT

## Batch

**Checkpoint 3B — security-specific reusable patterns.** No production page was
migrated or modified.

## Scope

Fifteen candidates surveyed. **Three built, six rejected, six deferred.** One
existing duplicate consolidated.

The survey did the deciding. Where evidence of repetition was absent — and for
half the candidate list it was — nothing was built.

---

## Reuse Survey

Measured against the current tree, not the Phase 3A summary.

| Pattern           |    Consumers | Evidence                                                                                                                                                                                                                                                                                | Decision                                                                                         |
| ----------------- | -----------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **SeverityBadge** | **11 files** | severity-keyed maps in 11 files; **the same band painted differently across them** — Critical is `#ff4d4d` (Phase3Results, RiskBadge), `#ef4444` (SecurityDashboard), `#991b1b`/`#fee2e2` (ConfigurationChecks); Medium is `#f59e0b` vs `#eab308`. `RiskBadge` exists and hardcodes hex | **BUILD + REFACTOR**                                                                             |
| **ScanStatus**    |  **3 files** | three implementations, three mechanisms: `ScanHistory` STATUS_STYLE+LABELS, `ArchivedScans` STATUS_STYLE + local `StatusBadge`, `SecurityDashboard` local `ScanStatus()` with `db-status--*` classes. `ArchivedScans` falls back to **running** for unknown                             | **BUILD**                                                                                        |
| **ScanProgress**  |  **4 sites** | `ScanHistory` ×2 `${progress}%`, `SecurityDashboard` `${scan.progress_pct \|\| 5}%`, `CredentialedResults` `${progress.percentage}%`, `Phase1Results` hardcoded `"65%"`/`"50%"`. Two fabricate a number for unknown progress                                                            | **BUILD**                                                                                        |
| FindingCard       |      5 files | **Findings are rendered as table rows, not cards** — Phase3Results 4 tables / 0 card divs, CredentialedResults 1 table / 0, FindingsExplorer 0 tables / 0 cards. There is no card to extract                                                                                            | **DO NOT BUILD**                                                                                 |
| VulnerabilityCard |            — | Same structure as above and the same evidence. Building both would be two names for one non-existent thing                                                                                                                                                                              | **DO NOT BUILD**                                                                                 |
| CVECard           |      6 files | `CVELink` already exists and is imported by all six. CVEs appear as links inside table rows, not as cards                                                                                                                                                                               | **USE EXISTING** (`CVELink`)                                                                     |
| AssetRiskCard     |            — | No card structure found; asset risk renders as a severity badge in `AssetRegistry` via `SEV_CLASS[a.risk_level]`                                                                                                                                                                        | **DO NOT BUILD**                                                                                 |
| HostStatus        |       1 file | Single inline ternary                                                                                                                                                                                                                                                                   | **DO NOT BUILD** — `CcureBadge` suffices                                                         |
| PortStatus        |      2 sites | `svc.state === "open"` inline ternaries in Phase2Results and AssetRegistry. No shared structure                                                                                                                                                                                         | **DO NOT BUILD** — `CcureBadge` suffices                                                         |
| RiskScore         |      8 files | Thresholds are **business logic and differ per context**: 75/50/25 (asset risk), 70/40 (AMT), 9/7 (CVSS), 3 (password strength). The _display_ is a severity badge                                                                                                                      | **DO NOT BUILD** — §15; band mapping stays in the application, rendering is `CcureSeverityBadge` |
| ScanTimeline      |       1 real | `AuditTimeline.jsx` (400 lines) already exists with one consumer, `AssetDetail`. Other "timeline" matches are incidental                                                                                                                                                                | **DEFER**                                                                                        |
| ComplianceStatus  |        **0** | No `compliance_status` / `control_status` / `pass_rate` matches in any JSX                                                                                                                                                                                                              | **DEFER**                                                                                        |
| ComplianceMatrix  |        **0** | Same — no consumer found                                                                                                                                                                                                                                                                | **DEFER**                                                                                        |
| CredentialStatus  |        **0** | `credentialed_status` appears in **zero** JSX files. The backend writes it; the frontend does not display it                                                                                                                                                                            | **DEFER**                                                                                        |
| SecurityMetric    |           ~1 | No repeated structure; dashboard tiles differ                                                                                                                                                                                                                                           | **DEFER** — `CcureCard` + `CcureBadge` + `CcureProgress`                                         |

Phase 3A's prediction held for `ComplianceMatrix` and `SecurityMetric`, and the
verification found two more zero-consumer candidates (`ComplianceStatus`,
`CredentialStatus`) plus the finding-card result, which was the survey's most
useful outcome — it removed four components from the plan.

---

## Patterns Built

### `CcureSeverityBadge` — 11 consumers waiting

Composes `CcureBadge` and overrides only colour via one `.cc-sev--*` class.
Not a `CcureBadge` variant: the badge has six variants and severity has seven
states, so Critical and High would collapse into "danger" and lose the
distinction that matters most in triage.

Vocabulary taken from the codebase: `critical | high | medium | low | info |
none | unscored`. **`none` and `unscored` are deliberately not folded into
`info`** — "no severity assigned" and "no rating published" are both weaker
claims than "informational", and on a compliance report the difference decides
whether a control counts. Case is normalised because the API returns both
spellings; `Phase3Results` ships a `getSevColor` helper that exists solely to
try `Critical`, then `critical`, then a fallback.

An unrecognised value renders as **Unscored**, not Info. The old `RiskBadge`
did `MAP[level] || MAP.Info`, which asserts a rating that was never published.

### `CcureScanStatus` — 3 consumers waiting

Vocabulary from `ScanHistory.jsx`, the most complete existing map, plus the two
states the dashboard adds: `complete`, `completed`, `running`, `queued`,
`pending`, `failed`, `unreachable`, `cancelled`, `canceled`. Both spellings of
completed and cancelled are carried because the API returns both — dropping
either would render real scans as unknown. `unreachable` stays distinct from
`failed`: "the scanner broke" and "the host never answered" send an operator to
different places.

**The defect it fixes:** `ArchivedScans.jsx` does
`STATUS_STYLE[status] || STATUS_STYLE.running`, so an unrecognised status
displays as a scan in progress — a false statement about a scan on a page whose
job is to report what happened. Unknown now reads "Unknown", neutral, with the
raw value in `title` so an operator can see what the API actually said.

Only a running scan pulses; animating a settled state would suggest work is
still happening.

### `CcureScanProgress` — 4 consumers waiting

Narrow on purpose. The survey found progress rendered with **three different
meanings**, so this represents _scan completion only_ — a severity-distribution
bar is a chart and must not use it.

**The defect it fixes:** two sites fabricate a number when progress is unknown.

```
SecurityDashboard.jsx   width: `${scan.progress_pct || 5}%`
Phase1Results.jsx       width: phase2Polling ? "65%" : "50%"
```

`|| 5` turns a null into "5% complete"; a hardcoded 65% asserts a measurement
never taken. Passing `value={null}` yields an indeterminate bar with
`aria-valuenow` omitted — never a small one.

Terminal states are handled: a completed scan reads 100% whatever the last poll
said (leaving it at 97 suggests something is outstanding), and a stopped scan
stops animating — a bar sliding forever under a scan that failed ten minutes
ago is actively misleading.

---

## Patterns Deferred

`ScanTimeline`, `ComplianceStatus`, `ComplianceMatrix`, `CredentialStatus`,
`SecurityMetric`. Four of the five have **zero or one** consumer. If migrating
several compliance pages in a later checkpoint reveals repetition, the pattern
gets built then — which is cheaper than building it now and discovering the
shape was wrong.

## Patterns Rejected

`FindingCard`, `VulnerabilityCard`, `CVECard`, `AssetRiskCard`, `HostStatus`,
`PortStatus`. Rejected rather than deferred because the evidence says the
concept as listed does not exist in this application: findings are table rows,
CVEs are links inside them, and host/port state is a one-line ternary. The
generic primitives already cover all of it.

---

## Existing Components Refactored

**`src/components/scan/RiskBadge.jsx`** — 56 lines of hardcoded palette reduced
to a 12-line deprecated adapter delegating to `CcureSeverityBadge`. Its two
consumers (`CredentialedResults`, `ScanHistory`) call it unchanged.

This was §7's question, and the measurement settled it. **Every colour it
carried failed WCAG AA against the surface it was drawn on:**

```
Critical  #ff4d4d   3.27:1
High      #f97316   2.80:1
Medium    #f59e0b   2.15:1
Low       #22c55e   2.28:1
Info      #60a5fa   2.54:1
```

The literals also ignored `data-theme`, so the badge rendered identically on a
dark background where it was least readable.

**This is a deliberate visual change on those two pages** — the colours are
darker in light mode — and it is the point: they are now legible and they
invert with the theme. It is the one intentional change to production-rendered
output in this checkpoint, and it was made in a shared component, not in a
page.

---

## Component Mapping

| Existing implementation       | Replacement                                     |    Waiting consumers |
| ----------------------------- | ----------------------------------------------- | -------------------: |
| 11 severity colour/class maps | `CcureSeverityBadge`                            |             11 files |
| `RiskBadge` hardcoded palette | delegates to `CcureSeverityBadge`               |                 done |
| 3 scan-status implementations | `CcureScanStatus`                               |              3 files |
| 4 scan-progress sites         | `CcureScanProgress`                             |              4 files |
| finding "cards"               | `CcureTable` + `CcureSeverityBadge` + `CVELink` | — (no change needed) |
| host/port state ternaries     | `CcureBadge`                                    |                    — |

---

## Before Metrics

| Metric                               |                        Value |
| ------------------------------------ | ---------------------------: |
| Candidate patterns                   |                           15 |
| Files with severity maps             |                           11 |
| Distinct hardcoded severity palettes |   5+ (mutually inconsistent) |
| Scan-status implementations          |                            3 |
| Scan-progress sites                  |     4 (2 fabricating values) |
| Existing security components         |   2 (`RiskBadge`, `CVELink`) |
| Design-system pattern files          |          1 (`CcureAppShell`) |
| Tests                                |                          190 |
| CSS bundle                           |    276.81 kB / 47.56 kB gzip |
| JS bundle                            | 1,701.30 kB / 420.38 kB gzip |

## After Metrics

| Metric                              |      Before |                    After |            Δ |
| ----------------------------------- | ----------: | -----------------------: | -----------: |
| Patterns built                      |           — |                    **3** |           +3 |
| Patterns deferred                   |           — |                        5 |            — |
| Patterns rejected                   |           — |                        6 |            — |
| Components refactored               |           — |      **1** (`RiskBadge`) |            — |
| Hardcoded severity palettes removed |           — | **1 of 5** (`RiskBadge`) |           −1 |
| Design-system pattern files         |           1 |                    **4** |           +3 |
| Tests                               |         190 |                  **230** |          +40 |
| CSS bundle raw                      |   276.81 kB |            **278.00 kB** |     +1.19 kB |
| CSS bundle gzip                     |    47.56 kB |             **47.61 kB** | **+0.05 kB** |
| JS bundle raw                       | 1,701.30 kB |          **1,701.67 kB** |     +0.37 kB |
| JS bundle gzip                      |   420.38 kB |            **420.30 kB** | **−0.08 kB** |

**Application metrics unchanged:** 75 JSX files, 50,716 LOC, 14,547 CSS LOC,
**2,282 inline styles**, 1,791 legacy token references, 0 pages importing the
design system.

The four remaining hardcoded palettes live in pages
(`Phase3Results`, `SecurityDashboard`, `ConfigurationChecks`,
`VulnerabilityBrowser`) and are removed when those pages migrate — not before,
because that would mean editing them.

---

## Accessibility

| Area                           | Result                                                                                                                                                |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity: colour never alone   | band always rendered as text; hidden label still in the accessible name                                                                               |
| Severity: unknown handling     | unrecognised → "Unscored", never Info                                                                                                                 |
| Scan status: unknown handling  | → "Unknown", never "Running"; raw value in `title`                                                                                                    |
| Scan status: motion            | pulse only while running; `aria-hidden`; stopped by `prefers-reduced-motion`                                                                          |
| Scan progress: unknown         | `aria-valuenow` **omitted**, `aria-valuetext` distinguishes "In progress" from "Progress unknown"                                                     |
| Scan progress: no fake numbers | no percentage printed for either unknown case                                                                                                         |
| Contrast                       | **10 new assertions** — severity on its own tint, both themes, all ≥ 4.5:1. That pairing is what a badge actually renders and had never been measured |
| Theme                          | asserted that no pattern emits inline colour in either theme                                                                                          |

No ARIA was added mechanically. `CcureScanStatus` is **not** a live region: a
status badge in a table is content, not an announcement, and marking 200 rows
live would flood a screen reader.

---

## Functional Regression

**N/A — no application behaviour changed.** No page, API module, context, route
or guard was touched. `RiskBadge`'s props and both call signatures are
unchanged, covered by four tests.

No business logic moved into the design system: severity bands, risk
thresholds, scan state and progress percentages are all received, never
computed.

## Visual Regression

Showcase captured in both themes. The three patterns render correctly:
severity across all seven bands with and without scores, nine scan statuses
plus an unrecognised one, and four progress states including both unknown
cases.

**Intentional change:** `RiskBadge` on `CredentialedResults` and `ScanHistory`
now renders in token colours — darker in light mode, and theme-aware. Rationale
and measurements above.

## Dark Mode

**PASS.** Both themes verified. One `data-theme` attribute still drives
everything; `PreferencesContext` untouched; no `prefers-color-scheme`
introduced. A test asserts no pattern pins colour inline in either theme.

## Security Semantics

Preserved and, in three places, made more honest:

- Severity hierarchy Critical → High → Medium → Low → Info intact, with `none`
  and `unscored` kept distinct rather than folded into Info.
- An unrecognised scan status is no longer displayed as running.
- Unknown scan progress is no longer displayed as a number.
- No calculation moved into the design system.

## Tests

**PASS — 230 passed, 12 files** (was 190/11). 40 new: 30 security-pattern
tests + 10 severity-on-tint contrast assertions.

## Lint

**PASS** — ESLint clean at `--max-warnings=0`.

## Build

**PASS** — 0.90 s. Token-only pipeline unchanged: 8,120.4 → 58.5 kB, one font
kept, six dropped.

## CSP

**PASS — byte-for-byte unchanged.** `nginx.conf` not edited in any phase.
Console clean in both themes.

## Air-Gap

**PASS.** One same-origin font requested. Production image carries one font
file. No CDN, Google Fonts, analytics or telemetry; no UX4G runtime marker in
built JS. **No new dependency was added** — the patterns are React plus the
existing design system.

## Unmigrated Page Regression

**PASS — zero pixels.**

```
p3b-baseA   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (no UX4G)
p3b-baseB   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (no UX4G)
p3b-ux4g    428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (Phase 3B)
```

**Fourth consecutive checkpoint at the same hash.**

Two notes on the methodology:

- The Phase 3B brief quotes the expected hash as
  `81BDD19B5730080794B4D1BEA579C9E47`. The actual value, unchanged since Phase
  1, is `81BDD19B5730080794B1FBEA579C9E47` — the quoted form has a
  transcription slip in the middle. Per §35 the repository's actual value was
  used. The Login page was not modified.
- The baseline container restarted during this checkpoint (uptime reset from 29
  h to 2 h). It was re-verified as the genuine pre-UX4G baseline before being
  trusted as a control: it serves `index-978nxLhG.css` at 188,903 bytes — the
  exact Phase 0 hash and size — with **zero** `ux4g-` tokens and zero `cc-`
  classes.

## Bundle Impact

CSS **+0.05 kB gzip**; JS **−0.08 kB gzip**. The JS figure is negative because
`RiskBadge` shrank from a 56-line palette to a 12-line adapter, and it is in
the production bundle via its two live consumers — the consolidation returned
more than the patterns cost.

UX4G's contribution is untouched at 9.6 kB gzip. No UX4G component CSS, runtime
or icon font reappeared; verified by the existing guardrails.

## Files Changed

**Added (5)**

```
Frontend/src/design-system/patterns/CcureSeverityBadge.jsx    ~95
Frontend/src/design-system/patterns/CcureScanStatus.jsx       ~90
Frontend/src/design-system/patterns/CcureScanProgress.jsx     ~85
Frontend/src/design-system/patterns/security-patterns.css     ~110
Frontend/src/__tests__/design-system/security-patterns.test.jsx ~290
docs/ux4g/03b-security-patterns.md                              —
```

**Modified (5)**

```
Frontend/src/components/scan/RiskBadge.jsx      56 → 42   (palette → adapter)
Frontend/src/design-system/components/CcureFeedback.jsx   +`animated` prop
Frontend/src/design-system/index.js             + pattern exports and CSS import
Frontend/src/__tests__/design-system/contrast.test.js     + severity-on-tint pairs
Frontend/src/pages/DesignSystemShowcase.jsx     + 3 sections, dev-only `?section=` filter
```

**Not modified:** every application page, API client, context, route and
stylesheet; `nginx.conf`; `Dockerfile`; `docker-compose.yml`; `package.json`
(no new dependency); the UX4G pipeline and its guardrails.

### One change worth flagging explicitly

`CcureProgress` gained an `animated` prop. It was needed because
`CcureScanProgress` exposed a hole in the 3A component: a **stopped** scan with
unknown progress fell through to `value={0}`, asserting "no progress made" —
the very defect the component was built to prevent. `animated={false}` now
means "unknown and no longer moving": `aria-valuenow` stays omitted, no
percentage is printed, and the track does not slide.

## Commits

None yet — staged for review. Proposed split per §37:

```
refactor(design-system): consolidate severity badge onto one implementation
feat(design-system): add scan status pattern
feat(design-system): add scan progress pattern
fix(design-system): distinguish unknown-and-stopped progress from zero
test(design-system): cover security patterns and severity contrast
docs(ux4g): checkpoint 3B security pattern survey
```

## Open Release Gates

**UX4G licence — unresolved, unchanged.**

```
UX4G README declares MIT
package.json has no license field
package has no LICENSE file
package contains no copyright notice
embedded Noto Sans has OFL requirements
```

Written clarification still required from `support.ux4g@digitalindia.gov.in`
before production release of redistributed UX4G-derived assets. No copyright
notice invented; no legal clearance claimed.

## Remaining Issues

| #   | Issue                                               | Severity              | Position                                                                                                             |
| --- | --------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 1   | UX4G licence                                        | **Open release gate** | Above                                                                                                                |
| 2   | Four hardcoded severity palettes remain in pages    | Expected              | Removed when those pages migrate; editing them now would be page migration                                           |
| 3   | `RiskBadge` still exists as an adapter              | By design             | Deleted in 3H once its two consumers migrate                                                                         |
| 4   | `CVELink` hardcodes `var(--accent, #3b82f6)` inline | Low                   | It is application code with 6 consumers; folding it into the design system is a 3C+ decision, not a 3B one           |
| 5   | Five patterns deferred with 0–1 consumers           | By design             | Built if later migration reveals repetition                                                                          |
| 6   | `CcureScanStatus` vocabulary is the frontend's      | Low                   | The backend may emit statuses the frontend has never displayed. Unknown is handled safely and surfaces the raw value |

---

## Recommendation

**GO for Checkpoint 3C.**

All §34 acceptance criteria are met. The security layer is deliberately thin —
three patterns, ~270 lines of JSX and ~110 of CSS, each composing an existing
primitive and adding only security meaning. Nine candidates were **not** built,
and that is the checkpoint's main result: the survey removed four components
from the plan on the evidence that findings are tables rather than cards, and
found four more candidates with zero consumers.

One thing to decide before 3C. §23 was interpreted as permitting the
`RiskBadge` refactor — it is a shared component, not a page, and §7 and §26
both call for one canonical implementation. It does change how two production
pages render, deliberately, to fix a WCAG failure. If you would rather no
production-rendered output change until its pages are formally migrated, that
commit can be dropped and `RiskBadge` left as it was; everything else stands
independently.

**STOPPING HERE for review.** No production page will be migrated until 3C is
approved.
