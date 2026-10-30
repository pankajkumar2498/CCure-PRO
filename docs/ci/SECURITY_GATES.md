# Security gates in CI

The free security checks this repository runs on every change, what each one
blocks, and what to do when one fails. The workflows are
`.github/workflows/ci.yml` and `.github/workflows/security.yml`.

## What runs where

| Check                         | Tool             | Pull request     | Push to `master` | Nightly                         | Blocks on                                    |
| ----------------------------- | ---------------- | ---------------- | ---------------- | ------------------------------- | -------------------------------------------- |
| Secret Scan                   | gitleaks 8.30.1  | the PR's commits | the pushed range | whole history                   | any finding not in `.gitleaksignore`         |
| Python Dependency Audit       | pip-audit 2.10.1 | yes              | yes              | yes, plus a full-backlog report | any advisory not in the accepted backlog     |
| npm Dependency Audit          | `npm audit`      | yes              | yes              | yes                             | high or critical in **runtime** dependencies |
| Bandit (in `ci.yml`)          | Bandit 1.9.4     | yes              | yes              | no                              | any **high**-severity finding                |
| Bandit Medium-Severity Report | Bandit 1.9.4     | no               | no               | yes                             | never (report only)                          |
| Ruff (in `ci.yml`)            | ruff             | yes              | yes              | no                              | unchanged from before                        |

Container images are scanned separately, by Trivy in `images.yml`, against the
image each commit actually builds: nightly, on a release tag, and
on demand, but **not on pull requests**. A PR is gated on what it changes in the
application; the image scan reports on OS packages and binaries whose
advisories arrive with no commit. Its policy and exceptions are in
[CONTAINER_IMAGES.md](CONTAINER_IMAGES.md); which checks are required is in
[BRANCH_PROTECTION.md](BRANCH_PROTECTION.md#what-gates-a-pr-and-what-runs-after-it).

The nightly run exists because advisory databases change while the code does
not. A dependency that was clean when it merged can be vulnerable a week later,
and no commit arrives to trigger a check. When a scheduled run fails, GitHub
emails whoever last edited the schedule.

Every job runs with `permissions: contents: read`, and none of them references
a repository secret.

## Severity policy

| Tool      | Blocks                                 | Reported, doesn't block                                   | Why this line                                                                                                                                                                 |
| --------- | -------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| gitleaks  | everything                             | —                                                         | A committed secret has no low severity. Once it's in history, the only fix is rotating it.                                                                                    |
| npm audit | high, critical in runtime dependencies | moderate and low anywhere; everything in dev dependencies | Runtime dependencies ship inside the JavaScript the browser runs. Dev dependencies (vite, eslint, vitest) run on the build machine against our own sources.                   |
| pip-audit | every advisory not already triaged     | the triaged backlog (nightly summary)                     | PyPI advisories mostly carry no severity rating, so no threshold can be applied honestly. Each new one is triaged instead.                                                    |
| Bandit    | high severity                          | medium (nightly count)                                    | At medium severity there are 60 findings today, 39 of them string-built SQL that each need a person to review. Gating on them would block every PR until that review is done. |

## When a check fails

### Secret scanning

The log names the file, line, rule and commit. The value is redacted: gitleaks
runs with `--redact`, and that was tested by planting a fake AWS key.

1. **If it's a real credential, rotate it first.** Deleting the line doesn't
   help, because the value stays in the commit, and in every clone and fork of
   it, for good. Revoke the credential where it was issued, then remove it from
   the file.
2. **If it's a false positive** (a test vector or a fabricated value), prefer
   changing the value so it no longer looks like a credential, as `09cdd9f`
   did. If it has to stay, add its fingerprint (`commit:file:rule:line`, printed
   in the log) to `.gitleaksignore` with a comment saying what it is. A
   fingerprint names one finding in one commit, so it can never hide a later
   one. Add a regex to `.gitleaks.toml` only when the same false positive will
   keep recurring, and match the exact string.

### Python dependencies

A failure means an advisory that isn't in
`.github/security/pip-audit-accepted.txt`: a new package, a version that
changed because a range in `requirements.txt` resolved differently, or a new
advisory against something already installed. The log names the package,
version, advisory ID and fixed version.

1. Upgrade the package if a fix exists and the upgrade is safe. The backend
   suite is the judge.
2. Otherwise, add the ID under that package's heading in the accepted file, with
   a line saying why it can't be fixed yet. An entry without a reason must not
   be merged.

When a package is upgraded past its advisories, delete its block from the
accepted file. pip-audit doesn't report entries that no longer match anything,
so a stale list only shrinks if someone removes entries.

### npm dependencies

`npm audit fix` resolves most runtime advisories within the ranges in
`package.json`. A fix that needs a major version (the current `react-router`
one does) is a code change and goes through a PR like any other.

### Bandit

For MD5 or SHA-1 used as an identifier, say so in the code:
`hashlib.md5(data, usedforsecurity=False)`. Bandit accepts it, and unlike a
comment, black can't move it. Otherwise suppress **one line**, with the rule
ID: `# nosec B501`, on the line Bandit reports. Put the reason on the line
above if the code around it doesn't make it obvious. Run black before
checking: when it wraps a long line, a trailing `# nosec` can end up on a
line Bandit doesn't read, which is how three of these first went wrong.
Never add `--skip`
to CI or to `.pre-commit-config.yaml`. The global skip list this replaced hid
new findings along with the old ones: a `verify=False` added to an outbound
feed fetch passed the old configuration and fails this one (tested).

## Tools evaluated and not added

- **CodeQL.** The repository is private on a personal account, and code
  scanning on private repositories needs GitHub Advanced Security, which is
  paid. The CodeQL CLI's licence also doesn't cover analysing closed-source
  code without it.
- **GitHub secret scanning and push protection.** These are the same paid
  add-on on a private repository. gitleaks in CI covers the gap.
- **Semgrep (community rules).** Evaluated on 24 Sep 2026 against the frontend,
  which is the part with no security analysis: the `p/react`, `p/javascript`
  and `p/secrets` rulesets over 311 files found **nothing**. A manual check
  agrees: no `dangerouslySetInnerHTML`, `eval`, `new Function` or `innerHTML`
  assignment in `Frontend/src`. There was no gap to justify a second SAST tool.
  Worth re-running if the frontend starts rendering HTML.

**Recommended, free, and a settings change rather than a file:** turn on
**Dependabot alerts** and **Dependabot security updates** (Settings → Code
security). `.github/dependabot.yml` currently updates only the pinned GitHub
Actions.

## Findings when the gates were introduced (24 Sep 2026)

### Secrets: 9 in history, 0 in the current tree

| Finding                                                                                                                                                                                                 | Classification                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.env.example` and `Backend/.env.example`: `POSTGRES_PASSWORD` ×2, `JWT_SECRET_KEY`, `SMTP_PASSWORD`, `DEFAULT_ADMIN_PASSWORD`, `VULN_DB_PASSWORD` (commits `3d0bfb0`, `f4391c1`; removed in `e5c2dfe`) | Real credentials, committed and later removed. None matches a value in the VM's current `.env` files (compared by fingerprint, no value printed). Accepted in `.gitleaksignore`, but see the open actions below.                   |
| An `AWS_SECRET_ACCESS_KEY` assignment in the redaction test and its batch-23 doc (`7166941`)                                                                                                            | False positive: a fabricated test value with the `hx-` prefix every fake value in that test carries, replaced by `placeholder` in `09cdd9f`. Accepted by fingerprint. (It isn't quoted here: this file would then be flagged too.) |

### Bandit: 17 high-severity findings, each now resolved at its own line

| Rule                     | Where                                                                                                       | Classification                                                                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| B324 ×8 (MD5/SHA-1)      | audit event grouping, nmap cache key, topology edge IDs, crawler page and request dedup keys, DOM state IDs | False positive: identifiers, no security property. Now `usedforsecurity=False`.                                                                        |
| B501 ×5 (TLS unverified) | WAF detection, robots/sitemap, security-header, cookie and CORS probes                                      | False positive for a scanner: anonymous requests to the scan target, whose certificate is routinely self-signed. TLS is assessed separately by sslyze. |
| B501 ×3                  | `core/web/auth/session_manager.py`: OAuth token request, form login, scripted login                         | **Accepted risk, pending a decision.** See below.                                                                                                      |
| B507 ×1 (SSH host key)   | `engines/credentialed/ssh_scanner.py`                                                                       | **Accepted risk, pending a decision.** See below.                                                                                                      |

### Accepted risks

These four shipped before CI looked at them. The `# nosec` keeps the gate green
without hiding them; each carries an `ACCEPTED RISK` comment pointing here.
Accepting them is a product decision for the owner, not a lint decision.

1. **Credentials sent over unverified TLS** (3 call sites). The web scanner
   posts the configured login, and for OAuth the `client_secret` and password,
   without checking the certificate. For OAuth the `token_url` is set by the
   operator and may be a third-party identity provider. Anyone who can
   intercept that path can collect the credential. A likely fix is to verify
   the certificate when calling an identity provider, and to make skipping
   verification an explicit per-scan option rather than the default.
2. **SSH accepts any host key** (`AutoAddPolicy`). Anyone who can answer as the
   target receives the password credential. Nessus has the same default. A
   likely fix is to pin each asset's host key on first use and refuse a changed
   key.

### Python dependencies: 48 advisories in 11 packages

pip-audit prints 93 because it lists each advisory twice; the real count is 48.
45 have a fixed release. All are recorded in
`.github/security/pip-audit-accepted.txt` as the pre-existing backlog. They are
classified as dependency issues needing later remediation, not as safe.

| Package          | Installed | Advisories | Fix                | Note                                                                                          |
| ---------------- | --------- | ---------- | ------------------ | --------------------------------------------------------------------------------------------- |
| pillow           | 10.3.0    | 17         | 12.x               | **Paid down.** 13.0.0 since 30 Oct 2026, which also fixes 33 later advisories; block removed. |
| python-multipart | 0.0.9     | 7          | 0.0.31             | Parses the two upload endpoints' request bodies.                                              |
| starlette        | 0.37.2    | 7          | 1.3.1              | Comes with FastAPI; upgrading it means upgrading FastAPI.                                     |
| pyasn1           | 0.5.1     | 4          | 0.6.x              | Held below 0.6 on purpose for pysnmp-lextudio.                                                |
| cryptography     | 46.0.7    | 4          | 50.0.0             | Held below 48 by sslyze's bound.                                                              |
| python-jose      | 3.3.0     | 3          | 3.4.0 (1 has none) | JWT signing and verification for authentication.                                              |
| urllib3          | 2.6.3     | 2          | 2.7.0              | **Paid down.** Pinned 2.8.0 since 7 Oct (`d90bb51`); block removed 9 Oct.                     |
| ecdsa            | 0.19.2    | 1          | none               | Transitive, via python-jose.                                                                  |
| paramiko         | 4.0.0     | 1          | none               | SSH transport for credentialed scanning.                                                      |
| pytest           | 7.4.4     | 1          | 9.0.3              | Installed from `requirements.txt`, so the test runner ships in the runtime image.             |
| python-dotenv    | 1.0.0     | 1          | 1.2.2              |                                                                                               |

### npm: 3 advisories, none blocking

| Package                                 | Severity | Scope    | Classification                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------------------- | -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `react-router` / `react-router-dom` 6.x | moderate | runtime  | Dependency issue; the fix needs a major upgrade to 7.x. The open-redirect advisory needs a navigation target an attacker controls. The only stored-destination navigation (`Login.jsx`) builds its target from router state the app sets itself and a sessionStorage value the app writes, so neither comes from a link. Not exploitable as currently used, as far as inspected. |
| `js-yaml` 4.0.0–4.3.1                   | high     | dev only | Dependency issue, fix available (`npm audit fix`). It's reached only by build tooling parsing this repository's own YAML.                                                                                                                                                                                                                                                        |

## Triage decisions

Advisories added to the accepted backlog after 24 Sep 2026, each with the
analysis behind it. An entry here is a decision with a review trigger, not a
statement that the code is safe in general.

### python-jose: PYSEC-2026-4298

Recorded 30 Oct 2026. It was failing the gate on `master`'s nightly Security
run and on PR #53's.

- **The advisory.** `PYSEC-2026-4298` (CVE-2026-85394, GHSA-3qf3-8w2g-rqmx),
  published 15 Oct 2026, CVSS 3.1 9.1. python-jose through 3.5.0 accepts a
  DER-encoded public key as an HMAC secret: it refuses PEM-armoured and
  `ssh-` keys but not DER. A verifier that lets the token's `alg` header pick
  the algorithm can therefore be given an HS256 token signed with the
  service's public key, which an attacker has from `/auth/jwks.json`. It is an
  incomplete fix for CVE-2024-33663 (`PYSEC-2024-232`, already accepted). No
  fixed release exists: 3.5.0 is the latest and is affected.
- **Where the library is used.** Only `ccure_platform/identity/tokens.py`
  (signing) and `ccure_platform/identity/verification.py` (verification), in
  the API and in `gateway-auth`, whose image carries the same
  `verification.py` and pins the same version
  (`gateway/token_check/requirements.txt`). Nothing uses JWE.
- **Why it does not apply here.** The attack needs a verifier that lets the
  token's header choose HS256. Every verification goes through one of two
  functions in `verification.py`, and neither does:

  - **`decode`**, behind `verify` and `decode_any_kind`: every bearer, ticket,
    refresh and MFA check, the WebSocket ticket logins (`decode_token`) and
    the gateway's `checker.py`. It refuses a token with no `kid` or an
    unknown one, refuses one whose `alg` is not its key's (`alg_mismatch`),
    then calls `jwt.decode(..., algorithms=[key.alg])`. A key's `alg` never
    comes from the token. The API's keyset admits only ES256 P-256 keys
    (`keys.py`). The gateway's key source (`gateway/token_check/jwks.py`)
    skips any JWK that is not `EC` / `P-256` / `ES256` and sets
    `alg="ES256"` itself.
  - **`verify_service_assertion`**, behind `/auth/service-token`: it refuses
    any `alg` but ES256, then decodes with `algorithms=["ES256"]`.

  So a forged HS256 token meets three barriers:

  - the `alg` check;
  - python-jose's algorithm list, which is checked before any key is used;
  - the key material: both functions hand python-jose PEM text, which its
    HMAC key guard refuses. The advisory's bypass needs a verifier holding
    the key as DER bytes.

  The remaining unverified reads (`header_of`, `claims_of`, and the service
  router's `unverified_*` calls) only extract fields for logs and refusals;
  nothing they return reaches a decision.

- **Mitigation, proven by tests.** Two tests in
  `tests/auth/test_token_issuance.py` build the attack with the public key's
  DER and PEM bytes. The HMAC is computed by hand, so python-jose's key guard
  is not what stops it.

  - `test_an_hs256_token_keyed_with_the_public_key_is_refused` takes a real
    access token's claims under the active `kid`. It must be refused by
    `tokens.verify`, by `tokens.decode_any_kind`, by `verification.verify`
    over a key source built from the published JWKS as the gateway builds
    it, and by python-jose with `algorithms=[ES256]`.
  - `test_an_hs256_service_assertion_keyed_with_the_public_key_is_refused`
    does the same to a service's client assertion.

  Each path first accepts the genuine ES256 token. Checked by mutation on
  30 Oct 2026: with the `alg` checks removed and the header's `alg` passed to
  `jwt.decode`, all four cases fail. With DER key material added as well,
  `tokens.verify` accepts the DER-keyed forgery, which is the advisory
  reproduced, and the test fails on it.

- **Decision.** Accept, as `PYSEC-2026-4298` in
  `.github/security/pip-audit-accepted.txt`, next to the three python-jose
  entries already there. Upgrading would not help: 3.4.0 and 3.5.0 fix two of
  those three (`PYSEC-2024-232`, `PYSEC-2024-233`) but not this one, and the
  move is a separate change to the authentication path.
- **Review it when:**
  - python-jose publishes a fixed release;
  - any verifier stops passing an explicit single-algorithm list;
  - a symmetric (HS\*) key or algorithm is reintroduced anywhere;
  - or the decision to stay on python-jose is revisited. It sees few releases,
    and a maintained JOSE library would retire all four entries.

## Open actions

Nothing in CI can close these. They need a person.

1. **Confirm the dev database password is not in use anywhere real.** It is the
   `POSTGRES_PASSWORD` in the historical findings, and it is still named in
   `ci.yml`, `conftest.py`, `README.md` and as the fallback default for
   `VULN_DB_PASSWORD` in `Backend/config.py`. The VM's database refuses it. The
   README tells people to use it when setting up the **Windows deployment**,
   which has not been checked.
2. **Confirm the Gmail app password was revoked** in that Google account. Only
   the account owner can check this.
3. **Decide the four accepted risks** above.
4. **Pay down the Python backlog**, easiest first: python-dotenv,
   python-multipart and python-jose are patch or minor upgrades (urllib3 and
   pillow are done); starlette/FastAPI and cryptography are majors, each
   needing a full backend suite run.
5. **Move pytest out of `requirements.txt`** into a dev requirements file, so
   the test runner stops shipping in the runtime image.
