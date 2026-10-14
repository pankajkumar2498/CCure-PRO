# Checkpoint 3C — Batch 9 regression instrument

Documented separately from the migration report, per the standing process rule:

> Do NOT casually modify the regression instrument while migrating pages. If the
> instrument requires a correction: stop application migration; fix the harness
> separately; self-test it on the same container twice; require byte-identical
> output; validate that it detects a known intentional difference; validate that
> it reports identical output for an unchanged control; document the harness
> change separately; only then continue.
>
> **A false regression result is worse than no regression result.**

Two defects were found in the instrument during this batch. Both were found by
the validation steps rather than by inspection, and **both would have produced a
clean result for a build that had demonstrably changed.**

---

## 1. What was derived, and from what

`capture-batch9.mjs` is generated from `capture-batch8.mjs` by
`scratchpad/b9-parts.py`, so the derivation is reproducible and every change is
a named, reviewable substitution rather than a hand edit. The driver — one
container per process, pathname-only stubbing under `/api/`, size-stability
readiness scoped to `.page-main`, `data-theme` re-assertion with verification,
the empty-page and marker guards — is **unchanged**.

| Region           | Change                                                                                          |
| ---------------- | ----------------------------------------------------------------------------------------------- |
| Fixtures         | Web-scan fixtures → credential fixtures (`CREDENTIALS`, `CRED_TYPES`, `COMPLIANCE_CREDENTIALS`) |
| `ROUTES`         | 5 ScanDetail lifecycle states → 8 batch-9 states (4 per page)                                   |
| Stub table       | `/web-scans*` → `/credentials`, `/credentials/types`, `/compliance/credentials`                 |
| Probe selectors  | web-scanning surfaces → `cred-*`/`csc-*`/`pass-*` (pre) and `cs-*`/`sc-*`/`cc-*` (post)         |
| Loading guard    | `.skeleton-loader`/`.cc-skeleton` → also `.cc-loader`/`.spinner`                                |
| **Probe census** | **+ ARIA-state census** (defect 1, below)                                                       |
| **Probe scope**  | **+ portal-aware roots** (defect 2, below)                                                      |

`diff-batch9.mjs` additionally **derives its page list from the captures**
instead of carrying a literal. The batch-8 version hardcoded five route names;
pointed at a different capture it throws, which is the lucky outcome. The
dangerous one is a literal list that is a strict _subset_ of the capture — every
page missing from it is silently never compared, and the run reports no
differences for pages it never looked at. The two inputs must now agree on the
page set, and a disagreement is a hard failure rather than an intersection.

### Three markers, and why they are data

Every marker is derived from **fixture data** (`"Prod Linux SSH"`,
`"never logged, stored"`), never from UI copy the migration rewrote. A marker
taken from rewritten copy can never be found on one side of the comparison, and
the capture then fails — or worse, gets relaxed until it passes.

### Two things the stub table refuses on purpose

- **`/credentials/types` is tested before `/credentials`.** Ordered the other
  way, the list pattern swallows the types request, the type `<select>` renders
  empty in _both_ builds, and the form state compares identical having measured
  a form nobody could fill in.
- **No write is ever stubbed as a success.** This instrument drives forms; a
  `POST`/`PATCH`/`DELETE` answering 200 would let a capture navigate away or
  mutate the list, so the two containers would be measured in different states.
  The write paths are covered by the unit suite, not here.

---

## 2. Defect 1 — the instrument was blind to `aria-pressed`

**Step 4 failed on its first run.**

The sensitivity build carried three deliberate changes to `CredentialedScan`:

1. `aria-pressed` removed from the password reveal toggle
2. `<h1>` changed to `<h2>`
3. the `label` prop removed from the Username field

The instrument reported the page as CHANGED — and named only (2) and (3). The
`aria-pressed` removal produced **no difference at all**:

```
clean roles:      group|Authentication method|
perturbed roles:  group|Authentication method|
roles arrays differ: false
```

The batch-8 ARIA census selects `.page-main [role]` — elements carrying an
**explicit `role` attribute**. The reveal toggle is a native `<button>`: its
role is implicit, so it was never in the census, and neither is any other native
control carrying ARIA state. `aria-pressed` on native buttons is precisely what
this batch adds.

This is the batch-8 failure repeating one level down. There, the probe recorded
accessible names for `input`/`select`/`button` only, so an injected
`role="progressbar"` was invisible; the fix was a role census. Here the role
census itself has the same shape of blind spot, and **an instrument blind to the
change it is being used to verify is worse than no instrument** — because the
"identical" it emits is read as evidence.

**Fix.** An ARIA-_state_ census, keyed on the state attributes rather than on
`role`:

```js
out.ariaStates = [
  ...qsa(
    "[aria-pressed],[aria-expanded],[aria-checked],[aria-selected],[aria-current]," +
      "[aria-busy],[aria-invalid],[aria-disabled],[aria-describedby]",
  ),
];
```

recorded as `TAG|accessible-name|states`, sorted. `aria-describedby` is recorded
as **present/absent rather than by value**: the value is a generated `useId`,
which differs between renders and would make every capture differ from every
other one. Whether the description is wired at all is the property worth
measuring.

`roles` and `ariaStates` are also **named in the human-readable summary**, not
merely folded into the raw comparison. The raw comparison says a page CHANGED;
only a named delta says _which property_, and an ARIA regression appearing as an
unexplained "CHANGED" beside nine explained ones is one a reviewer skips past.

After the fix:

```
ariaStates  "BUTTON|Show password|pressed=false | BUTTON|📄 SSH Key|pressed=false |
             BUTTON|🔑 Password|pressed=true | INPUT||describedby"
         -> "BUTTON|📄 SSH Key|pressed=false | BUTTON|🔑 Password|pressed=true |
             INPUT||describedby"
```

---

## 3. Defect 2 — the instrument stopped measuring the form it was pointed at

Found on the first real pre-vs-post run, which reported:

```
credForm   controls  7  ->  0
           headings  "H1:Scan Credentials | H2:New credential" -> "H1:Scan Credentials"
```

The migrated form did not lose its seven controls. `CcureModal` renders through
a **portal into `document.body`**, and every accessibility census in the probe is
scoped to `.page-main`. The probe stopped being able to see the form.

That scoping exists for a good reason — AppLayout's chrome outside `.page-main`
updates on a timer, so a body-wide readiness check never settles — but it
silently excludes portalled content. Left uncorrected, this report would have
claimed **"0 unlabelled controls"** for a form the instrument never examined.
Same false-clean shape as batch 6's empty captures, reached from a third
direction.

It is also the same discovery the unit tests forced, one layer down: the
`ScanCredentials` suite had to stop addressing the form through `container` and
start addressing it through `document.querySelector('[role="dialog"]')` for
exactly this reason.

**Fix.** Portal-aware census roots, with containment de-duplication so a dialog
rendered _inline_ rather than portalled is not counted twice:

```js
const ROOTS = [
  ...document.querySelectorAll('.page-main, .cc-modal, [role="dialog"]'),
]
  .filter((e, i, a) => a.indexOf(e) === i)
  .filter((e, i, a) => !a.some((o, j) => j !== i && o !== e && o.contains(e)));
const qsa = (sel) =>
  ROOTS.flatMap((r) => [...r.querySelectorAll(sel)]).filter(
    (e, i, a) => a.indexOf(e) === i,
  );
```

All ten censuses were re-pointed at `qsa()`. Readiness is deliberately **left on
`.page-main`** — it is answering a different question (has the page settled),
and widening it would reintroduce the never-settling condition.

Confirmed after the fix:

|                             | controls measured | unlabelled  |
| --------------------------- | ----------------- | ----------- |
| pre-migration               | 7                 | 0           |
| post-migration (before fix) | **0**             | 0 (vacuous) |
| post-migration (after fix)  | 7                 | 0           |

The post-migration control names now read back:
`INPUT:Name`, `SELECT:Type`, `INPUT:Username`,
`INPUT:Domain (leave blank for a local account)`,
`SELECT:Authentication method`, `INPUT:Password`, `INPUT:Port`.

Note what this also settles honestly: the **pre-migration form already labelled
its seven controls**. The migration did not fix a labelling defect there; it
fixed one on `CredentialedScan` (5 unlabelled) and on the validate panel (1).

---

## 4. Validation record

Run in order, after the second fix. Every step is against a real container.

### Step 3 — determinism

Two runs of the **same** container, compared byte-for-byte.

| Run pair                    | Container              | Result             |
| --------------------------- | ---------------------- | ------------------ |
| `b9-self2-a` / `b9-self2-b` | pre-migration `:3291`  | **byte-identical** |
| `b9-det-a` / `b9-det-b`     | post-migration `:3292` | **byte-identical** |

### Step 4 — sensitivity

Clean post-migration build vs the three-injection build. All three detected and
named:

| Injected change                           | Detected as                                                |
| ----------------------------------------- | ---------------------------------------------------------- |
| `aria-pressed` removed from reveal toggle | `ariaStates` loses `BUTTON\|Show password\|pressed=false`  |
| `<h1>` → `<h2>`                           | `headings` `H1:Credentialed Scan` → `H2:Credentialed Scan` |
| Username `label` removed                  | `unlabelledControls 0 → 1`, `.cc-field__label 7→6`         |

Detected across all four `CredentialedScan` states, in **both themes**, and
correctly _not_ on `credScanStored` for the label change — that state does not
render the JIT username field.

### Step 5 — unchanged control

The injection touched `CredentialedScan` only. All four `ScanCredentials` states
(`credList`, `credEmpty`, `credForm`, `credValidate`), both themes — **8 states
— reported identical.**

### Step 6 — this document.

---

## 5. Coverage, stated honestly

The batch-9 instrument measures **8 states × 2 themes = 16 captures**:

| Route                | States                                               |
| -------------------- | ---------------------------------------------------- |
| `/scan-credentials`  | list, empty, form open (portal), validate panel open |
| `/scan/credentialed` | JIT default, stored credential, key auth, Windows OS |

The unrelated-page regression reuses the **existing, already-validated** batch
5–8 / auth / gated harnesses unchanged, giving **37 further states across 16
pages**.

**Not covered by any harness route:** `RoleManagement` (migrated in an earlier
checkpoint, no capture route was ever written for it). This is a coverage gap in
the _suite_, not a finding about the page, and it predates this batch. The auth
harness measures its five pages at one theme each, not two.

Also not measured: the "no saved credentials" hint on `CredentialedScan`, which
renders only when `/compliance/credentials` returns empty. The fixture returns
two credentials so the picker is exercised instead; the empty branch is covered
by the unit suite.
