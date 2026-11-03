# Engineering record: STIG and SCAP content

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 3067–3370, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 3067-3370 -->
## STIG and SCAP content (`core/scap/`)

Reading published SCAP content — an XCCDF benchmark and the OVAL definitions
its rules check through — and evaluating it against a credentialed host.
Phase 10 of the gap-closure programme, closing GAP-05; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

    datastream → XCCDF rules + OVAL definitions → compiled definition
      → ConfigCheck(check_type="scap_rule") → BenchmarkPack
      → compliance_frameworks/_controls/_rules → ConfigAuditEngine
      → PASS / FAIL / NOT_APPLICABLE / ERROR → finding → risk → report

**No new engine, no new finding model, no new scan kind, no new route.** The
persistence cost of the whole phase is one value on one CHECK constraint
(migration `c1d2e3f4a5b6`). A benchmark _is_ a framework (Phase 4), a rule _is_
a `ConfigCheck` (Phase 3), a failed check _is_ a finding (Phase 0).

- **What ships is the reader, not the content.** No STIG is committed and none
  needs to be — this is the one content gap where licensing is not the blocker.
  DISA publishes its SCAP benchmarks as US Government works; SCAP Security
  Guide publishes an `xccdf_org.ssgproject.content_profile_stig` profile per OS
  under **BSD-3-Clause** (verified against the project's `LICENSE`, not
  recalled). `scripts/benchmarks/load_stig.py` converts and loads it.

  **An SSG result is not a DISA certification.** SSG renders the STIG's
  requirements as its own automated content. `--publisher` and `--licence` are
  required with no defaults, and both land on the framework record, because
  that distinction has to survive into a report.

- **A definition is compiled, not referenced.** The rule row carries the tests,
  objects, states and _resolved_ variables it needs. The datastream is a 28 MB
  file on an operator's workstation and the rule runs on a Celery worker months
  later; a rule that had to reach back to its source content would be
  unevaluable in exactly the situation it exists for.

- **`UnsupportedConstruct` is the phase's whole honesty mechanism.** OVAL 5.11
  defines well over a hundred tests and this build evaluates ten, chosen by
  measuring which ones the available content actually uses (five test types are
  92.2% of 1,318 test elements). Anything else fails to compile and the
  converter records the control as `unimplemented` **with the reason** — so it
  appears in the register, counts against coverage, and can never be mistaken
  for a control that passed.

- **A refusal knowable from the content belongs at load time, not scan time.**
  Every shape check — unsupported test type, an entity selected by an operation
  that cannot be resolved, a path pattern with no literal root — was moved from
  the probe into the compiler as it was found. The result is that a converted
  benchmark produces **zero scan-time errors** on a real host: a refusal is
  reported once, in the load tally, instead of on every host the benchmark ever
  runs against.

- **Namespaces are read, never stripped** — the opposite of Phase 8. `file_test`
  exists in the OVAL `unix` schema _and_ the `windows` schema; stripping merges
  them and hands a Windows registry rule to a Unix probe. Every element is keyed
  `schema:local_name`.

- **Polarity is asserted.** A `compliance`-class definition is TRUE when the
  host is hardened; a `vulnerability`-class one is TRUE when it is _affected_.
  Scoring the second with the first's polarity reports every vulnerable host as
  compliant, so anything but `compliance` is refused rather than negated on a
  guess.

- **Matching happens in Python, not in the shell.** `textfilecontent54` is 68%
  of the corpus and its object carries a regex with capture groups plus
  behaviour flags. Handing that to `grep` means translating one regex dialect
  into another, on the target, with the rule's own text as input.

### Applicability is not optional, and the measurement says so

A STIG rule is frequently conditional: "if PAM is installed", "if this is a
real system with a kernel rather than a container". Those are XCCDF
`<platform>` elements resolving to CPE 2.0 logical tests over OVAL _inventory_
definitions, and `core/scap/evaluate.evaluate_applicability` runs them with the
same three-valued logic as everything else.

It was originally declared **not planned**, on the reasoning that
benchmark-level `applies_to` targeting already answered it. Cross-checking
against `oscap` on the same host proved that wrong: **without applicability,
128 rules produced verdicts `oscap` correctly skipped, 102 of them failures** —
findings about a kernel, a display manager and a PAM stack the target does not
have.

**The nesting is the semantics, and it was wrong twice.** Platforms declared
side by side are alternatives; platforms inherited from different levels
(Benchmark → Group → Rule) are cumulative. Reading the second as the first left
17 rules applicable that `oscap` skipped — each a Group saying "a system with a
kernel" and a Rule saying "and PAM is installed", which in a container are
false and true. `XccdfRule.platform_levels` keeps the structure; `platforms`
is the flat form and is for tags only.

An applicability that cannot be established is **UNKNOWN → ERROR**, never
"applies". Reading it as applicable puts the verdict back into the
false-positive class; reading it as not-applicable silently drops a control
from the score.

### Six defects real content found, and one a warning found

Every one produced a plausible result and none raised.

- **`<Value>` was read only from the Benchmark's direct children.** XCCDF
  permits it inside a `<Group>` and SSG puts nearly all of them there, so the
  real RHEL 9 datastream yielded **zero values** — every parameterised rule then
  failed to compile for want of a binding and loaded as `unimplemented` with a
  plausible reason.
- **Reference _values_ were discarded in favour of their href.** SSG writes
  `<reference href="…/cci/">CCI-000366</reference>`; the href names the
  catalogue and the **text** is the identifier. Keeping only the href throws
  away every CCI and NIST control in the benchmark.
- **No SSG rule carries `<version>`**, so control ids fell back to the full
  XCCDF rule URI and dozens exceeded the catalogue-key ceiling. Stripping the
  XCCDF 1.2 identifier scaffolding is defined by the specification.
- **The NIST crosswalk emitted controls that do not exist** — `PR.DS-01`, a
  CSF identifier, yielded `DS-1`, and its href says "nist" so a source filter
  let it through. Entries are now validated against the seeded 800-53
  catalogue, so a dangling crosswalk is structurally impossible.
- **`seed_path` returns a `str`.** Calling `.read_text()` on it raised into a
  broad `except` and every crosswalk vanished while the load reported success.
  Failing open is right; failing open _quietly_ is not.
- **An empty `<filename/>` selects the directory itself.** Dropping it made a
  rule about `/var/log/journal` collect nothing, and `check_existence="none_exist"`
  read "no offending directory" off an empty set — a vacuous truth and a false
  **negative**. It was the only rule `oscap` and this build ever disagreed on.
- **Python's `re` does not support POSIX bracket expressions and does not say
  so.** `[[:blank:]]` parses as a set of the literal characters `[ : b l a n k`,
  so a pattern written to match whitespace matches punctuation. Found only
  because a `FutureWarning` about a nested set appeared in scan output nobody
  would normally read. Unknown class names are refused rather than left in
  place, which would reproduce the same silent mis-parse.

Two dialect differences are translated rather than declined, each to the
escape's documented meaning: **inline global flags must lead** in Python
(`^\s*(?i)X` raises), and **`\N` and `\h` do not exist** — `\N` is read as the
start of a named-Unicode escape. Scoped pairs `(?i)X(?-i)` become `(?i:X)`;
handling only the opening half would silently widen the match, which is what
the content wrote `(?-i)` to prevent.

### Validation

Two disposable containers, destroyed after use. The root credential is
generated at run time and never written to source, configuration, logs, Celery
arguments or Git.

```powershell
docker run -d --name ccure-rocky-target  -p 127.0.0.1:2222:22 rockylinux/rockylinux:9 sleep infinity
docker run -d --name ccure-ubuntu-target -p 127.0.0.1:2223:22 ubuntu:24.04           sleep infinity
```

RHEL 9 STIG → Rocky 9: **257 automated, 0 errors**. Ubuntu 24.04 STIG →
Ubuntu: **144 automated, 0 errors**. Nine rules were proven in both directions
across all four probe families, including a three-state demonstration: the
`auditd` rules report NOT_APPLICABLE with the `audit` package absent, FAIL with
a weak `auditd.conf` once installed, PASS when hardened. Writing the config
file by hand does not make the rule apply, and it did not.

**`oscap` 1.3.9 agrees on 144 of 144 rules** — same datastream, same profile,
same host, nothing changed in between. No previous phase has had an independent
implementation of the same standard to check against.

Two things worth knowing before repeating this:

- **`oscap` will not evaluate RHEL content on Rocky.** The first cross-check
  returned `notapplicable` for all 1,532 rules, correctly: the benchmark's CPE
  is `cpe:/o:redhat:enterprise_linux:9`. Running the RHEL STIG against a
  rebuild is a deliberate operator decision, supplied through
  `--applies-to-name`; nothing in the code infers that two distributions are
  interchangeable.
- **A container satisfies few platforms.** Most SSG rules are gated on
  `system_with_kernel`, so a stock container reports them NOT_APPLICABLE —
  correctly. Installing `kernel-core` (Rocky) or `linux-base` (Ubuntu) is what
  makes the rules behind it reachable for validation.

### Coverage

`scripts/measure_scap_coverage.py`, denominator frozen at 52 areas before
implementation with **nineteen** declared unimplemented. **0% → 63.5%** (33/52),
implemented _and_ tested. Two areas were found after the freeze —
`systemdunitdependency` and the OpenSCAP Script Check Engine — and are reported
separately against a corrected denominator of 54, giving **61.1%**; the frozen
list is what was predicted beforehand and editing it afterwards destroys the
only thing it is for.

The converter's own tally is the remaining gap list, produced from real content:
`local_variable` (111 RHEL 9 rules) and object `<set>` (52) are one problem
wearing two hats — both need a second collection pass whose results feed the
first. That is the single change that would move the figure most.

### The Windows OVAL schema (Phase 15)

Phase 10 excluded Windows deliberately. Six test types are implemented now,
measured over the **DISA Microsoft Windows 11 STIG V2R10** — `registry` (117 of
its 219 rules), `auditeventpolicysubcategories` (43), `userright` (25),
`wmi57` (15), `passwordpolicy` (7), `lockoutpolicy` (3). **198 of 219 rules
automate; 63 pass / 126 fail / 9 N/A / 0 errors** against a real Windows 11 Pro
host. `fileeffectiverights53`, `ntuser`, `sid_sid` and `user_sid55` are
declared unimplemented with reasons in `WINDOWS_NOT_IMPLEMENTED`.

- **The pack's platform is read from OVAL's `<affected family>`, never
  assumed.** `to_pack` hardcoded `linux`, which was true of every benchmark
  loaded until the first Windows one. Left alone it files Windows rules against
  Linux hosts — where none can be evaluated — and withholds them from the hosts
  they describe. `BenchmarkPack` refuses a check whose platform disagrees with
  the pack's, which is what caught it.

- **`ScapRuleCollector.platforms` must include `windows`.** It did not, so a
  Windows context selected no collector and every rule reported ERROR. Correct
  direction, zero capability.

- **Four things a live host settled, each of which had shipped looking right:**

  - **`auditpol /get /category:* /r` prints a phrase, not a number** —
    "Success and Failure", not `3`. A table keyed on `"0".."3"` matches no row,
    empties the policy and turns all 43 audit rules into errors.
  - **`pnp_activity` is the one subcategory whose OVAL name is not Windows'.**
    27 of 28 normalise from `auditpol`'s own text; that one is "Plug and Play
    Events".
  - **Windows qualifies built-in trustees and the content does not.**
    `S-1-5-32-544` resolves to `BUILTIN\Administrators`; the STIG compares
    against bare `Administrators`. Left qualified, _every_ user-right rule
    fails on a correctly configured host. Strip `BUILTIN\` and `NT AUTHORITY\`
    only — the content writes `RESTRICTED SERVICES\PrintSpoolerService`
    qualified. Emitting both spellings is not an option: `entity_check`
    defaults to "all", so the second would have to match too.
  - **A user right nobody holds is one item with an empty trustee, not zero
    items.** Every userright rule here uses `at_least_one_exists`, and "must
    not be assigned" is expressed as `trustee_name equals ''`. Zero items makes
    those rules fail on hosts that satisfy them — 0 of 25 could pass.

- **A test's `state_operator` is read, and ANDing alternatives is
  unsatisfiable rather than merely strict.** OVAL lets a test reference several
  states combined by `state_operator`, whose default is AND — but DISA writes
  **OR** wherever a setting has more than one acceptable answer ("this right is
  unassigned _or_ held only by Administrators"). The attribute was not read at
  all, so every multi-state test was ANDed, and where the states are
  alternatives no item can satisfy them both: the rule could not pass on any
  host in any configuration.

  Measured, not inferred. The DISA Windows 11 V2R10 benchmark contains **43
  `state_operator="OR"`** tests against 3 `AND`, and the loaded pack carried 44
  multi-state rules. On a real Windows 11 Pro host those rules passed **2 of
  42**, against 61 of 147 for the single-state rules; after the fix they pass
  **26 of 42** and the single-state figures are untouched. That is **24 false
  FAIL findings on one host**, all reported against a machine that complies.

  `ONE` and `XOR` are refused at compile time rather than approximated —
  `_STATE_OPERATORS` is the vocabulary and `UnsupportedConstruct` is the
  refusal, for the usual reason: a wrong fold is indistinguishable from a right
  one once it reaches the report. **A pack compiled before this was carried has
  no `state_operator` key and defaults to AND, so it stays wrong until it is
  re-loaded** — re-run `scripts/benchmarks/load_stig.py` against the original
  datastream, with `--code` naming the existing framework or the loader creates
  a second one beside it.

- **A well-known SID Windows itself cannot translate still needs a name.**
  Translation is done _on the target_ so a non-English install resolves its own
  group names, which a table could not — but `SecurityIdentifier.Translate`
  throws for the virtual-account families. `S-1-5-83-0` (Hyper-V's
  `NT VIRTUAL MACHINE\Virtual Machines`) holds `SeCreateSymbolicLinkPrivilege`
  on a stock Windows 11, so `WN11-UR-000060` collected an item with a
  `trustee_sid` and **no `trustee_name`**, could not be compared against a state
  naming one, and reported **ERROR on a perfectly readable host**.
  `_WELL_KNOWN_SIDS` fills only what the target left blank, so the on-target
  answer always wins. A SID in neither is still left unnamed and still reads
  UNKNOWN: substituting the SID string would compare a SID against a group name
  and fail every rule it appears in.

- **`record` is an OVAL datatype, and a missing column is UNKNOWN.**
  `wmi57_state` compares a WMI row against `<field name=…>` children.
  `_compare` matches field by field; a column the row does not carry returns
  None, because "this build did not collect that" is not "the host disagrees".

- **One `secedit` export serves password policy, lockout policy and all 28 user
  rights**, memoised per audit. It is the only write any probe performs — a
  GUID-named file in `$env:TEMP`, removed in the same command, the shape
  `WindowsSecurityPolicyCollector._run_secedit` established. **Ages and windows
  are converted**: OVAL states them in seconds, `secedit` exports ages in days
  and lockout figures in minutes, and comparing the raw number reports a 60-day
  maximum password age as 60 seconds.

- **`SMBExecutor.wmi_query` is bound to `root/cimv2`.** A query against another
  namespace — BitLocker's `…\security\microsoftvolumeencryption` — falls
  through to PowerShell rather than being answered about the wrong namespace.

- **The audit probe matches `auditpol`'s subcategory _text_, so a non-English
  host resolves fewer subcategories.** The entity is then absent from the item
  and the rule reads UNKNOWN, which is the safe direction but is not coverage.
  The GUID column is captured and would be the robust key.

### Reporting is part of done

**A gap is not closed until its results appear correctly in the reports** —
recorded in the tracker as a standing rule for every phase. Two defects on that
path were found and fixed in Phase 15, and both affect all configuration
findings rather than only Windows:

- **The OVAL reading must reach the finding.** Evidence carried
  `Observed: non_compliant` — the verdict word alone. `observation.raw` names
  the OVAL object and the existence check it failed, and is appended now with
  duplicate lines collapsed (a rule with seven registry objects that all found
  nothing printed the same sentence seven times).
- **Evidence is refreshed on re-detection.** It was absent from the finding
  upsert's `set_`, so a finding that stayed open kept the text from the day it
  was first seen — the same staleness the version fields beside it already fix.
  On a configuration check the evidence _is_ the finding.

<!-- /verbatim -->
