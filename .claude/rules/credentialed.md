---
paths:
  - "Backend/engines/credentialed/**"
  - "Backend/core/credential_vault.py"
  - "Backend/db/models/credentials.py"
  - "Backend/scans/tasks/credentialed.py"
  - "Backend/scans/tasks/credentialed_sync.py"
  - "Backend/routers/credentialed.py"
  - "Backend/routers/credentials.py"
  - "Backend/core/config_audit/collectors/windows.py"
  - "Backend/core/config_audit/collectors/linux.py"
  - "Backend/tests/credentialed/**"
---

# Credentialed collection: WinRM, SMB, authentication, transport, elevation, Windows patches

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 2101–2448, 4554–4575) and is maintained here. Frozen original: `docs/archive/engineering-record/credentialed-collection.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Windows credentialed collection (`engines/credentialed/winrm_executor.py`)

Native WinRM, added in Phase 2. **Windows targets no longer need OpenSSH
Server installed.**

- **It is a transport, not a collector.** `ssh_scanner.py` already declared a
  `BaseExecutor` protocol, so `WinRMExecutor` drops in and `WindowsCollector`
  is unchanged — the same ~970 lines of PowerShell commands and parsers drive
  either transport, and Windows findings flow through the existing evidence →
  matching → finding → risk → reporting path. If you add a Windows capability,
  add a command to the catalogue; do not add a collector.

- **A pywinrm NTLM session is not thread-safe, and `collect_all` is parallel.**
  Sessions are therefore thread-local. Sharing one corrupts the NTLM security
  context and fails _every_ section with `SpnegoError (6): invalid Message
Integrity Check`, HTTP 400, and — most misleadingly — "the specified
  credentials were rejected by the server" on a credential that just
  authenticated. Measured against a real host: sequential 10/10, concurrent
  shared 0/8, concurrent per-thread 8/8. Do not "simplify" this to one session.

- **Errors are classified into four types and must stay that way.** A refused
  password, an unprivileged account, nothing listening, and a bad certificate
  need four different actions; collapsing them is how a fixable firewall rule
  becomes "host unreachable". Note that pywinrm's literal rejection string
  contains none of `401`, "unauthorized" or "authentication", so it is matched
  explicitly — without that it classified as a connection error.

- **`shell_type` resolves to "powershell" over WinRM and that matters.**
  pywinrm's `run_ps` already base64-encodes UTF-16-LE, which is the same trick
  `_wrap_ps` applies by hand for cmd.exe over SSH. Wrapping twice feeds the
  encoder its own output.

- **Basic auth over plain HTTP is refused.** NTLM encrypts the payload even on
  5985, so there is no reason to send a password in base64. The validation host
  had `AllowUnencrypted=false` and `Basic=false`, which is the normal posture.

- **Nessus's primary Windows transport is SMB + Remote Registry + WMI, not
  WinRM.** WinRM is on by default on Server 2012+ but **off by default on
  client SKUs**, so on a workstation estate this product currently reaches
  fewer hosts out of the box than Nessus does. That is a recorded coverage gap
  needing a second transport, not a defect in this one.

- **Patch assessment does not read installed KBs**, and the real host confirms
  why: `Get-HotFix` returned **4** entries on a fully patched Windows 11
  machine, because cumulative updates supersede one another.
  `windows_patch.py` compares the host's build — UBR included — against MSRC's
  published fixed builds. `os_assessed` distinguishes "no missing patches" from
  "could not assess"; never collapse them.

## Windows over SMB / Remote Registry / WMI (`engines/credentialed/smb_executor.py`)

The second Windows transport, added in Phase 12. **WinRM is off by default on
Windows client editions**, so an estate of workstations was reachable only where
somebody had turned it on. SMB is on by default; this closes that reach gap
without touching WinRM, which remains the default in `_TYPE_DEFAULTS` and is
still the deeper transport.

- **It is a transport, not a collector, and the seam was already there.**
  `WindowsCollector` asked for data by _name_ (`_run("os_info")`), so `_run`
  now consults `executor.run_named(key)` first and falls back to PowerShell.
  Every parser is untouched. If you add a Windows capability, add a command to
  the catalogue and — if it can be answered from WMI or the registry — a
  handler to `_NATIVE_HANDLERS`. Do not add a collector.

- **`run()` refuses, deliberately.** Remote execution over SMB means creating a
  service or a scheduled task, which writes to a host this product only reads
  and is the elevation mechanism the Windows path may not invent. A
  command-shaped check therefore reports UNAVAILABLE → ERROR. **Never make this
  return success**; a test guards it, and `executes_commands` is how the
  collectors ask.

- **Handles are per-thread and must stay that way.** `collect_all` runs its
  sections in a thread pool and neither an impacket `SMBConnection` nor a bound
  DCE/RPC handle is thread-safe. Sharing one made the target reset the
  connection mid-run and cost the software inventory, the share list and the OS
  revision — and **without the UBR every Windows host looks like the day-zero
  release of its version**. Same trap as the pywinrm session, one protocol over.

- **Remote Registry is trigger-started, so the first bind can lose a race** with
  the service's own startup and return `STATUS_PIPE_NOT_AVAILABLE`. It is
  retried. **The service is never started by this code**, and its state is read
  over SCMR _before_ the pipe is bound: binding can trigger-start it, and this
  product's own `ccure.win.remote_registry.not_running` check treats a running
  one as a finding — so without measuring first the scan could report a
  condition it created.

- **Packages come from the registry uninstall hives, never `Win32_Product`.**
  Querying that class triggers an MSI reconfiguration of every installed
  product: a write to the host, and notoriously slow.

- **DCOM needs more than 445.** WMI negotiates a dynamic high port after the
  endpoint mapper on 135, so a firewall permitting SMB alone yields SMB and
  Remote Registry and no WMI. Each subsystem is opened lazily and independently
  so losing one does not lose the others.

- **An item this transport does not serve must not become a security fact.**
  `_run_json` returns `{}` both for "the host answered with nothing" and for
  "nobody asked", and the posture code used to read `{}` as data: an absent
  `telnet_status` became `telnet_disabled = True`, an unearned PASS that reached
  a compliance control, while an absent `netbios_status` and `tls_status` each
  raised a finding on every SMB host. Use `WindowsCollector._reading(key)`,
  which returns `None` when the item was not collected, and **omit the derived
  key** — absence is how this codebase says "not assessed". Do not restore a
  `False` default anywhere on that path (`registry_hardening`, the evidence
  adapter): `False` asserts the insecure state, which is the same defect
  pointing at a FAIL. `_hardening_row()` renders the third state.

- **Registry values arrive as text, and the posture handlers need numbers.**
  `read_registry_value` returns a string because the configuration-audit
  collector compares against the string the WinRM path yields. The posture
  handlers must coerce with `_as_int`: the collector tests
  `smb1_raw.get("SMB1", 0) == 1`, and `"1" == 1` is False, so a host with SMBv1
  genuinely enabled read as SMBv1 disabled.

- **Four error types, as on every other transport** — rejected credential,
  insufficient privilege, nothing listening, subsystem switched off. impacket's
  rejection text contains none of "401", "unauthorized" or "authentication", so
  it is matched explicitly; without that a refused password classifies as a
  connection error and the operator goes looking at the firewall.

- **`query_service` falls back to SCMR, like `_services` does.** It did not, and
  on a host permitting 445 alone — the firewall shape the fallback exists for —
  every service _check_ reported ERROR while the service _inventory_ succeeded.
  Both sources failing is an exception, never "the service is not installed",
  which for a telnet rule would be a pass.

- **`UNSERVED_KEYS` is the honest account of what this transport does not
  collect**, and every entry carries a reason. 18 of 31 collector items are
  served natively; the rest fall through and are recorded in
  `collection_errors` under an `item:` prefix rather than left to look like an
  empty reading from the host.

- **The config-audit `registry` and `service` collectors prefer a native
  answer**, through `_native(ctx, "read_registry_value")` and
  `query_service`. WinRM has neither method and keeps running its PowerShell.
  Rule parameters are bound into WQL with quotes doubled — the rules are
  administrator-editable, so that is an injection boundary inside the product.

## Credential authentication methods

- **`USABLE_AUTH_METHODS` is to `auth_method` what `USABLE_TRANSPORTS` is to
  `transport`.** The column admits a reserved value so a later phase adds a
  mechanism rather than a migration; the API validates against the _usable_ set
  so nobody saves a credential that cannot authenticate. `auth_method` had no
  such split, which is how `kerberos` came to be accepted by the API, the model
  and `WinRMExecutor` while the runtime had none — pywinrm raises
  `requested auth method is kerberos, but pykerberos is not installed` at the
  **first command**, so the credential failed on the customer's network rather
  than when it was saved. It is refused at construction now, and stays in the
  CHECK constraint deliberately.

- **`ntlm_hash` is Pass-the-Hash, and the password is never sent with it.**
  `login(user, "", domain, lmhash=…, nthash=…)` — passing both would let
  impacket fall back to the password when the hash is refused, which is two
  failed logons instead of one and hides which material the target rejected. The
  hash is stored in `encrypted_password` but **must not leave the credential
  vault's `connection_material` as `material["password"]`**: every transport
  would present it as plaintext against the account. A value that is not 32 hex
  characters is refused rather than sent — an unparsed one produces a failed
  logon against a real account, which is a lockout caused by a typo.

- **`paramiko.pkey.load_private_key` does not exist in paramiko 4**, and calling
  it is what made every key-content credential fail as "Failed to parse private
  key content" — a fault that reads as a malformed key from the operator rather
  than a missing function. `_load_private_key` tries Ed25519, RSA then ECDSA,
  because paramiko has no auto-detecting loader for a string. An encrypted key
  with no passphrase says exactly that, which is different from "not a key".

- **Elevation is `sudo`, `dzdo` or `pfexec`; `su`, `pbrun` and `ksu` are
  refused with reasons in `UNSUPPORTED_ELEVATION`.** `pfexec` takes **no
  password** — Solaris RBAC authorises from the account's profile, and writing
  one would leave it unread in the command's stdin where the command could
  consume it. An unsupported method elevates nothing rather than guessing at its
  option syntax. `dzdo` and `pfexec` are implemented and **not target-validated**;
  say so rather than implying otherwise.

## Credentialed transport and port resolution (`engines/credentialed/transport_resolver.py`)

Where an authenticated session is opened. Until this existed the answer was
`compliance_credentials.port`, which is **NOT NULL with a model default of 22** —
so "the operator chose 22" and "nobody said anything" are the same row.

- **The port scan's service identification is evidence, and the resolver reads
  it.** Candidates are the stated port plus every open TCP port positively
  identified as that transport's service. A host running sshd on 2222 used to be
  skipped with "Port 22/tcp not open" on a scan that had already identified sshd
  on 2222 — the evidence was in the same dictionary the guard was reading.

- **A credential is only ever offered a port that is stated on it or identified
  as that transport.** Walking every open port until something authenticates is
  credential spraying against the customer's own estate, and it is what a "try
  harder" resolver becomes the moment identification is dropped. `ssh` is
  matched by service _token_ (so `SSH-Alt` qualifies and `ssl` does not), by the
  RFC 4253 banner, or by product; WinRM by `wsman`/`winrm` or the
  `Microsoft HTTPAPI` product string — which is the only thing identifying a
  listener moved off 5985.

- **Selection is by TCP reachability, never by attempting authentication.** Both
  executors already expose `test_connectivity`. Exactly one authentication
  attempt is made however many candidates were considered. A **rejected**
  credential is never retried on another port; only a transport failure —
  nothing answered — advances, which is what `_is_transport_failure` in
  `scans/tasks/credentialed.py` decides. Retrying a rejection turns one failed logon into
  three against an account the lockout control must not trip.

- **Discovery is authoritative where it exists; a TCP probe is the fallback
  where it does not.** The phase-3.5 enrichment path has the port scan's view
  and opens no socket — a 5-second connect per host is minutes across a large
  scan. The standalone `/scan/credentialed` runs no discovery, so it attempts
  the stated port directly and probes the conventional alternates _only after a
  transport failure_. `FALLBACK_PORTS` is deliberately two entries per
  transport, not a port scan.

- **The transport is discovered too, not only the port.**
  `resolve_access` answers the question in front of "which port": _which
  authentication service does this host actually offer_. Until it existed the
  transport was whatever `compliance_credentials.transport` said, so a Windows
  credential had to be created twice — once for WinRM, once for SMB — by an
  operator who had to know in advance which the target would accept. WinRM is
  off by default on Windows **client** editions and on by default on Server,
  which is exactly the fact the scanner is better placed to establish than the
  person filling in the form.

  Four properties hold it together:

  - **Discovery runs when no port was stated**, and that decision is made in
    the router, not the worker — by the time the worker sees `port` it has
    already fallen back to the stored credential's, which is NOT NULL and
    defaults to 22, so it can no longer tell "the operator asked for 22" from
    "nobody said anything". `discover_transport` overrides either way.
  - **A stored credential's transport is a _preference_, not a pin.** The
    column cannot express "I do not mind", so reading it as a decision would
    override an operator who never made one; ignoring it would discard a
    deliberate choice of SMB on a host where WinRM listens but is
    misconfigured. `prefer=` puts it first and leaves the others behind it. An
    explicitly _stated_ transport is still never second-guessed.
  - **Selection is by TCP reachability, never by attempting authentication** —
    the same rule the port resolver already held, and for the same reason:
    trying the credential against each candidate turns one failed logon into
    several against an account the lockout control must not trip.
  - **A stated port does not pin the transport.** 5985 states WinRM as clearly
    as it states a port; 22 on a Windows credential is the model default and
    states nothing. So a stated port is offered only to the transports it
    conventionally belongs to.

  The resolved mechanism is recorded on the report as `access` and named in the
  UI, because "credentialed access succeeded" is not a useful answer on its
  own — the operator needs to know _what_ accepted the credential. Nothing
  reachable is reported as such, naming every transport considered, rather than
  falling through to an attempt that can only fail with a worse message.

- **`use_tls` is carried, not re-derived.** `WinRMExecutor` infers TLS from
  `port == 5986` when it is not told, which is right for the conventional layout
  and wrong for every other one. 5985/5986 are settled by convention; anything
  else carries `None`, because nmap keeps the TLS fact in a `tunnel` attribute
  this product does not parse and a guess addresses an HTTPS listener as
  `http://`.

- **The stated port leads, except when discovery contradicts it.** Since 22 can
  sit on a Windows credential without anyone having chosen it, a stated port the
  scan identified as _some other_ service goes second. It is never dropped —
  service detection can be wrong. Validated against a real host running sshd on
  22 **and** WinRM on 5985 at once.

- **`_apply_credentialed_enrichment` must pass `transport`, `auth_method`,
  `domain` and `credential_options`.** It resolved all four from the stored
  credential and then called the auditor with none of them, so the auditor's
  `transport="ssh"` default applied to every credential on the main scan path
  and a Windows credential opened an SSH handshake against a WinRM listener. The
  standalone route passed them correctly, which is why the defect was invisible
  to anyone testing that route.

- **That path must also skip `credential_type == database`.** A database
  credential names an instance, not a host; the standalone task branches on this
  and the enrichment path did not.

## Elevation on the credentialed path

- **The sudo password goes on the remote command's stdin, never in the
  command.** `SSHScanner.run_sudo()` owns this and the secret never leaves that
  class. `LinuxCollector._run` previously built
  `echo 'PASSWORD' | sudo -S …` and passed it to `exec_command`, which puts
  the customer's password in the argv of the shell sshd spawns — visible in
  `ps` to every local user on the target, captured permanently by any `execve`
  audit rule, and from there into this scanner's own debug log, which logged
  the full command string on failure.

  `run_sudo` rewrites each `sudo` to `sudo -S -p ''` and writes **one password
  line per invocation**. `-S` reads the password from stdin and `-p ''`
  suppresses the prompt, which would otherwise land in stderr and be read as
  command output. `-n` is stripped wherever it appears, bundled forms such as
  `-ln` included: it means "never prompt" and sudo honours it over `-S`, so
  leaving it makes sudo refuse the password and the failure reads on the target
  as a permissions problem rather than as a scanner bug. One line _per
  invocation_ because `sudo -l || sudo -l` runs at most one of them but which
  is decided on the target, and relying on sudo's credential cache instead
  breaks wherever `timestamp_timeout=0` is set.

  A collector must never read `ssh._password`. `has_password` answers whether
  elevation is worth attempting without exposing the secret, and
  `tests/credentialed/test_sudo_password_safety.py` pins both — including a
  source-level guard against the `echo … | sudo` shape returning.

- **`SSHScanner._redact()` masks the session password in anything logged.**
  With the stdin fix the command no longer carries it, so this is defence in
  depth: a log line is the one place a regression here would be written to disk
  and kept.

- **The configuration-audit collectors do not elevate at all.** `ShellRunner`
  has no sudo path, so every Phase 3+ Linux check reads what the scanning
  account can read. That is a recorded limitation, not an oversight — adding
  elevation there widens what a compromised scanner credential can do on every
  host in the estate, and it needs its own decision.

- **There is no elevation mechanism on the Windows path and none may be
  invented.** WinRM and OpenSSH both run as whoever authenticated; escalating
  by creating a service or a scheduled task changes a host this product is only
  meant to read. `test_windows_privilege_context.py` guards the absence by
  name (`New-Service`, `Register-ScheduledTask`, `schtasks`, `psexec`,
  `runas`, …).

  What is recorded instead is **which token the session held** —
  `system_data["privilege_context"]` carries `account`, `is_administrator` and
  `is_system`, read via `WindowsBuiltInRole.Administrator` (which resolves to
  S-1-5-32-544, so it works on a non-English install where matching the group
  _name_ fails). A probe that could not be read yields `None`, not `False`:
  reading it as "not an administrator" would attribute a complete audit's
  findings to a partial one.

  **Measured, not assumed:** against a real Windows 11 Pro host over WinRM as a
  member of Administrators, all 20 Windows built-in checks completed with
  **zero errors** and no check in the current set needs SYSTEM. The three empty
  fields in the Windows collector — `arp_table_raw`, `env_vars_summary`,
  `login_history_raw` — are hardcoded placeholders in `_collect_network` and
  `_collect_login_history`, not privilege failures.

- **`credentialed_status` has one writer**, `asset_syncer.set_credentialed_status`.
  The standalone audit set the literal inline and the Vulnerability Audit's
  credentialed pass did not, so a host that was authenticated to, collected
  from and configuration-audited still read as `unknown` — and
  `core/compliance_tasks.py` routes every rule in
  `CREDENTIALED_EVIDENCE_SOURCES` to `manual_review` unless it says `success`.
  Measured on the live database: **zero** assets carried the attribute despite
  that path having written eight configuration and privilege findings against a
  real Windows host. `success` and `failed` are both written; a host nothing
  was attempted against is left **unset**, because "no credential was in scope"
  and "the credential was refused" are different facts.


### Windows assessment

Windows is absent from the uninstall registry, so package matching never saw
the OS. `engines/credentialed/windows_patch.py` compares the host's build
against MSRC's published fixed builds instead.

- **Do not match on installed KBs.** `Get-HotFix` returned **4 entries** on a
  fully patched host — cumulative updates supersede one another, so the KB that
  first fixed a CVE is never present. Build comparison is the only reliable
  primitive.
- The collector must supply the **UBR**. `Win32_OperatingSystem.Version` stops
  at `10.0.26200` and omits the revision; without it every host looks like the
  day-zero release. `windows_collector` reads it from the registry and folds it
  into `os_version_id`.
- **Compare only within the host's own build line.** Microsoft lists one
  product against several lines — Windows 11 25H2 carries both `10.0.26100.x`
  and `10.0.26200.x` fixes. Taking the earliest fix across lines picks a
  `26100` build a `26200` host exceeds, silently dismissing real findings. This
  reported 19 missing patches where the truth was 736.
- A build line that maps to no product is reported as **not assessed**, never
  as "no missing patches".
