# Benchmark packs

A **pack** is one hardening benchmark expressed as data: its identity, its
profiles, and its numbered recommendations. Loading one creates a compliance
framework whose controls are the recommendations and whose rules are executed
by the Phase 3 configuration audit engine.

```
pack.json ──> compliance_frameworks / _controls / _rules
          ──> ConfigAuditEngine ──> evidence ──> verdict
          ──> compliance_findings ──> risk ──> remediation ──> report
```

Nothing in the engine knows what CIS is. A CIS Benchmark, a DISA STIG, a vendor
guide and an in-house baseline are the same shape.

## Loading a pack

```bash
python -m scripts.benchmarks.load_benchmark data/benchmarks/*.benchmark.json
python -m scripts.benchmarks.load_benchmark --dir data/benchmarks
python -m scripts.benchmarks.load_benchmark --dry-run <pack>   # validate only
```

Loading is idempotent: the same pack loaded twice updates rather than
duplicating. All packs named in one invocation load in a single transaction, so
a pack that fails halfway cannot leave a framework whose control count is
short — which would score better than the complete one and give no sign of it.

## Loading real CIS Benchmark content

**This repository ships no CIS Benchmark and none should ever be committed to
it.** CIS Benchmark recommendation text, rationale and remediation are the
Center for Internet Security's, distributed under licence.

If you hold a CIS SecureSuite membership, export the benchmark from CIS
WorkBench (or take CIS-CAT's content, or an XCCDF datastream) and convert it
into this format. Set `publisher` and `licence` to CIS's, and keep the
recommendation numbering **verbatim** — it is how a reader cross-references the
published document.

Do not write benchmark content from memory. A rule labelled `2.3.1.1` carrying
an expected value somebody recalled is a false compliance claim in a customer's
audit report, and it is indistinguishable from a correct one until an auditor
checks.

The two packs that ship are CCURE's own baseline, generated from the built-in
rules in `core/config_audit/builtin/`, and say so in `publisher` and `licence`.

## Format

```jsonc
{
  "benchmark": {
    "code": "CCURE_WINDOWS_BASELINE",   // becomes cfw_bm_<code lowercased>
    "name": "CCURE Windows Hardening Baseline",
    "version": "1.0.0",
    "platform": "windows",              // windows | linux | network_device |
                                        // database | container | cloud | any
    "publisher": "CCURE Audit PRO",     // required
    "licence": "…",                     // required — see below
    "source_url": "",                   // optional
    "notes": "",                        // optional
    "profiles": [
      { "id": "L1", "title": "Level 1 — …" },
      { "id": "L2", "title": "Level 2 — …" }
    ]
  },
  "controls": [ /* … */ ]
}
```

`licence` is **required**. Content whose licence nobody recorded is content
nobody can safely redistribute, and the framework record carries it so a report
can attribute the source.

### A control

```jsonc
{
  "control_id": "2.3.1.1",          // the benchmark's own numbering, verbatim
  "section": "2 Local Policies",    // free text, stored as a tag
  "title": "…",
  "assessment": "automated",        // automated | manual | unimplemented
  "severity": "high",               // critical | high | medium | low | info
  "profiles": ["L1"],               // must be declared on the benchmark
  "description": "…",
  "rationale": "…",
  "remediation": "…",
  "references": ["https://…"],
  "crosswalk": ["CIS_V8_1:5.4"],    // controls in other frameworks
  "check": { /* a Phase 3 ConfigCheck — required iff automated */ }
}
```

An empty `profiles` means the control is in scope **whatever profile was
selected**, which is how every pre-Phase-4 control behaves.

### `assessment` is declared, never inferred

The three states are not interchangeable and the loader refuses a mismatch:

| Value           | Meaning                                                      | `check` |
| --------------- | ------------------------------------------------------------ | ------- |
| `automated`     | The benchmark automates it and this product implements it     | required |
| `manual`        | The benchmark itself requires human judgement                 | refused |
| `unimplemented` | The benchmark automates it and **this product does not yet**  | refused |

`unimplemented` additionally requires `unimplemented_reason`.

That third state is what makes the coverage figures honest. Without it the only
way to represent a control this product cannot assess is to leave it out — and
a benchmark that silently drops what it cannot do reports better coverage than
it has. An `unimplemented` control is loaded, counted, and evaluated as *not
assessed*.

Reading "has a check" as "is automated" is the inference this format refuses.
CLAUDE.md records what it cost the last time: eighteen ISO controls claimed
`semi_auto` with no automated rule behind them, and the register, the coverage
figures and the Statement of Applicability all read that as partial automation.

### The `check` object

A Phase 3 `ConfigCheck` definition. See `core/config_audit/spec.py`.

```jsonc
{
  "check_type": "registry",         // registry | file | directory | permission |
                                    // service | process | package | port |
                                    // config_file | command | security_policy
  "collect": { "path": "HKLM\\…", "value": "EnableLUA" },
  "operator": "equals",             // see core/config_audit/operators.py
  "expected": 1,
  "absent": "manual_review",        // required — pass | fail | not_applicable |
                                    //            manual_review
  "platforms": ["windows"]
}
```

`absent` has **no default** and a check without it is refused. It says what a
successful reading of "the item is not present" means for *this* control:

- **`pass`** — "SMBv1 must not be installed": absence satisfies it.
- **`fail`** — "auditd must be installed": absence breaches it.
- **`not_applicable`** — "if IIS is present it must be configured thus".
- **`manual_review`** — a Windows setting absent from the registry is at a
  platform default that varies by build and SKU; neither pass nor fail can be
  asserted from the absence alone.

A default would silently pick whichever answer flatters the score.

`description`, `rationale`, `remediation` and `references` are inherited from
the control when the check does not state its own, so they need writing once.

## What is refused

The parser rejects rather than skipping, because a loader that drops what it
cannot parse produces a benchmark that is quietly short:

- a duplicate `control_id` — one recommendation scored twice;
- a control naming a profile the benchmark does not declare — a typo would
  otherwise create a profile of one member and remove the control from the real
  one;
- `automated` with no check, or `manual`/`unimplemented` with one;
- a missing `licence` or `publisher`;
- a check targeting a platform the benchmark is not for — it would report
  not-applicable on every host;
- a check whose definition will not execute, reported **with its control id**
  so it is findable in a six-hundred-control pack.

## The shipped packs are generated

`ccure_windows_baseline.benchmark.json` and `ccure_linux_baseline.benchmark.json`
are produced from the built-in rules:

```bash
python -m scripts.benchmarks.build_baseline_packs
python -m scripts.benchmarks.build_baseline_packs --check   # drift check
```

**Edit `core/config_audit/builtin/` or the crosswalk table in that script —
never the generated JSON.** A test runs `--check`, so the two cannot diverge.
