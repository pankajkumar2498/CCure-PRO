# What CCure Audit needs from CcurePolicyPro — policy baseline export

|              |                                                                                                                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Audience** | CcurePolicyPro team; project owner                                                                                                                                                               |
| **Date**     | 28 Sep 2026                                                                                                                                                                                      |
| **Status**   | Proposal for review                                                                                                                                                                              |
| **Inputs**   | The PolicyPro libraries `09A_ISO27001_Full_Policy_Library_for_PolicyPro` and `04A_HIPAA_Full_Policy_Library_for_PolicyPro` (CSV/XLSX), and the PCI DSS v4.0.1 PDF, as supplied to the Audit team |
| **Contract** | Contract 1, `ccure.audit.policy_baseline` — [`../contracts/PHASE4_INTEGRATION_CONTRACTS.md`](../contracts/PHASE4_INTEGRATION_CONTRACTS.md) §6                                                    |

## In one paragraph

The libraries are a good **template library** for PolicyPro. They hold the
policy wording, SOPs, questionnaires, Statement of Applicability (SoA) forms
and test cases that PolicyPro uses to help an organisation write its policy.

What Audit needs is the **result** of that work, for one organisation. That
result says:

- which controls the organisation adopted;
- which it excluded, and why;
- which values it chose, such as a session timeout of 15 minutes;
- that the policy was approved, when and by whom.

That result is the `PolicyBaseline` message. It is defined, versioned and
tested, and Audit already answers it with a `BaselineCoverage` report. For
every control, the report says whether Audit checks it automatically, needs an
attestation, or does not recognise it.

This note sets out:

- how the ISO library maps onto that message;
- what Audit's answer to it looks like today;
- seven things we need from PolicyPro to make the exchange complete.

## What Audit receives, and what it answers

**`PolicyBaseline` (PolicyPro → Audit):**

- Identity and approval:
  - `baseline_id` and `baseline_version`, which increases with every change and is never edited in place;
  - the source policy: id, version label and title;
  - `approved_at`, `approver_ref` and `effective_from`.
- `frameworks[]`: framework code and version.
- `controls[]`, one per requirement, each carrying:
  - `requirement_id`: PolicyPro's own id;
  - `control`: framework code, version and the control's published id, e.g. `ISO27001_2022` / `2022` / `A.8.9`;
  - `applicability`, plus a justification when it is not applicable;
  - optional `requirement_text`, which Audit displays but never executes;
  - `parameters[]`: `{name, value, unit}`.
- `scope`: optional CIDRs and asset tags. They can only narrow what the organisation is authorised to scan.

**`BaselineCoverage` (Audit → PolicyPro):**

- per control: `AUTOMATED`, `PARTIALLY_AUTOMATED`, `ATTESTATION_REQUIRED`, `UNKNOWN_CONTROL` or `UNSUPPORTED`, the Audit rules involved, and the reason;
- per parameter: how Audit handled it;
- what happened to the scope.

A received baseline starts as `pending_review`. It governs nothing until an
Audit administrator activates it.

**Never send executable checks.** That means no commands, queries, registry
paths or rule bodies. PolicyPro decides _what_ is required; Audit decides _how_
it is checked. The contract refuses unknown fields, so a check cannot be
smuggled in.

## How the ISO library maps

Each ISO reference appears on 13 rows. Only the **Policy Clause** row carries
requirement content specific to that control. In the other 12 row types — task, SOP,
questionnaire, evidence, audit inquiry, SoA, risk, policy text, import, test,
evidence example and exception — the text is the same for every control once
its title is removed. Those rows are PolicyPro's own working content and do not
belong in a baseline.

| Library column (Policy Clause row) | `PolicyBaseline` field                   | Note                                                                       |
| ---------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------- |
| `clause_id`                        | `controls[].requirement_id`              | e.g. `ISO27001-TECHNOLOGICAL.A.8.9`                                        |
| `iso_reference`                    | `controls[].control.control_id`          | Matches Audit's catalogue exactly: 93 of 93 Annex A ids                    |
| —                                  | `controls[].control.framework`           | `ISO27001_2022` / `2022`, as Audit's Capabilities publish it (decision D3) |
| `detailed_policy_requirement`      | `controls[].requirement_text`            | Display only                                                               |
| SoA: `applicable_yes_no`           | `controls[].applicability`               | **The organisation's answer — not in the library**                         |
| SoA: `justification_for_exclusion` | `controls[].applicability_justification` | Required when not applicable (ISO/IEC 27001 6.1.3(d))                      |
| `policypro_template_fields`        | —                                        | Names of blanks, not values; see ask 3                                     |

**A reference converter** implements this table:
`Backend/scripts/integration/policypro_library_to_baseline.py`.

- It takes the organisation's SoA answers in the library's own field names: `annex_control_id`, `applicable_yes_no` and the two justification columns.
- It refuses to invent a decision. A control with no answer is an error, and so is an exclusion with no justification.
- Management-system clauses 4–10 are always applicable, because they are mandatory for conformity.
- `--demo-all-applicable` produces a baseline for demonstration only, and labels it as such.

We offer it as the specification of the translation for PolicyPro to adopt, in
whatever language suits PolicyPro.

## What Audit answers today

The full ISO library was converted in demonstration mode, with every control
applicable. It was then mapped against Audit's live catalogue for the default
organisation, on a read-only connection. The tool is
`Backend/scripts/integration/baseline_coverage_report.py`.

| Answer                   | Controls | Which                                                                                                   |
| ------------------------ | -------: | ------------------------------------------------------------------------------------------------------- |
| **AUTOMATED**            |       15 | e.g. A.5.18, A.8.1, A.8.2, A.8.5, A.8.7, A.8.8, A.8.9 (3 rules), A.8.13, A.8.15, A.8.16, A.8.17, A.8.18 |
| **ATTESTATION_REQUIRED** |      103 | The other 78 Annex A controls, and the 25 management-system clauses 4.1–10.2                            |
| **UNKNOWN_CONTROL**      |        0 | —                                                                                                       |

Before 28 Sep 2026 the 25 clauses were answered `UNKNOWN_CONTROL`: Audit's ISO
catalogue held Annex A only. They were added as attestation controls, under
their own numbers (`5.1`, not `A.5.1`) and their own `ISMS` theme. They are not
rows of the Statement of Applicability, because clauses 4–10 are mandatory.

Parameters: none were sent, because the library carries none.

## What we need from PolicyPro

1. **Export the organisation's decisions, not the template library.**
   - Applicability and justification per control, from the completed SoA.
   - Policy version, approval date and approver.
   - A new `baseline_version` for every change; the same version is never re-sent with different content.
2. **One export shape for every framework: the `PolicyBaseline` JSON.**
   - The ISO and HIPAA libraries use different columns and row types today (25 against 22 columns, 13 against 9 row types).
   - Framework codes and versions are not in the data today (`policy_id` values such as `ISO27001-TECHNOLOGICAL` are PolicyPro groupings).
   - Take codes and versions from Audit's Capabilities message rather than a list of your own (decision D3).
3. **Agree a parameter vocabulary with Audit, starting small.**

   - The libraries name blanks but carry no values, datatypes or units.
   - Audit's rules already test these settings against fixed values. Once rules take parameters (plan Phase 17), the organisation's value replaces the fixed one:

   | Proposed name             | Datatype | Unit       | Library field it would fill                      | Audit evidence key today    |
   | ------------------------- | -------- | ---------- | ------------------------------------------------ | --------------------------- |
   | `session_timeout_minutes` | integer  | minutes    | HIPAA `timeout_value` (Automatic logoff)         | `session_timeout_minutes`   |
   | `backup_frequency_days`   | integer  | days       | HIPAA `backup_frequency`; ISO A.8.13 `frequency` | `backup_frequency_days`     |
   | `log_retention_days`      | integer  | days       | `retention` (ISO A.8.15, HIPAA audit controls)   | `retention_days`            |
   | `password_min_length`     | integer  | characters | none yet                                         | `minimum_password_length`   |
   | `lockout_threshold`       | integer  | attempts   | none yet                                         | `account_lockout_threshold` |

   - Audit will publish the agreed names in its Capabilities message. Until the rules take parameters, a received value is recorded and reported as not yet honoured, never silently applied.
   - RPO, RTO and review frequencies also appear in the libraries. No Audit check measures them, so they would stay attestation items.

4. **HIPAA identifiers at CFR paragraph level.**
   - Today's ids are PolicyPro's own (`HIPAA-POL-09.001`).
   - `hipaa_reference` is section-level and inconsistent (`164.308(a)(3)-(4)` alongside `164.308(a)(4)`).
   - Specifications repeat: "Risk analysis" and "Audit controls" appear 4 times each.
   - Audit needs one stable id per implementation specification, e.g. Automatic logoff → `164.312(a)(2)(iii)`, before it can hold a HIPAA catalogue at all. Audit has none today, so every HIPAA control would come back `UNKNOWN_CONTROL`, and the converter refuses a HIPAA library for that reason.
5. **ISO titles from the published standard.** Five titles are paraphrased: A.5.10, A.5.20, A.5.21, A.5.24 and A.7.1. Audit uses the published wording. The library itself says it is a working draft to be checked against a licensed copy of the standard.
6. **No product or workflow rows in a framework library.** HIPAA contains 4 `HIPAA-PROD` rows ("CcurePolicyPro project design") and 4 `HIPAA-ADDR` addressable-workflow rows. They describe the product rather than the regulation.
7. **PCI DSS.**
   - There is no PolicyPro PCI library yet.
   - The PDF supplied is the PCI Security Standards Council's own standard ("All Rights Reserved").
   - Audit's PCI catalogue is v4.0 with 62 controls and is not switched on in this installation.
   - A PCI baseline needs a PolicyPro PCI library first, and an Audit decision to update its catalogue to v4.0.1.

## What stays with Audit

Audit keeps:

- its rules;
- its cross-references between frameworks (used by gap analysis and by NIST CSF's automation);
- its framework catalogues, until catalogue ownership moves to PolicyPro through a new contract version, as the project owner has anticipated.

The libraries cannot replace these: they contain no executable checks and no
cross-references.

## Decisions for the project owner — taken 28 Sep 2026

1. **ISO management-system clauses: added.** Clauses 4.1–10.2 are in Audit's ISO catalogue as attestation controls, so no requirement of the ISO library is unknown to Audit any more.
2. **HIPAA catalogue: approved.** Audit holds the HIPAA Security Rule, identified by CFR paragraph. A HIPAA _baseline_ still needs ask 4 — the library's identifiers are not CFR paragraphs.
3. **PCI DSS: approved.** The catalogue moves to v4.0.1 and is switched on.
4. **`CcurePolicyPro Policy Docs/` is not committed.** It is reference material. The PCI PDF is licensed text, and the libraries are PolicyPro's content.
