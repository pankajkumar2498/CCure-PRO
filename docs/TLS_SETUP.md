# TLS for CCure Audit PRO

The application is served over HTTPS at **`https://ccurepro.cdacb.in`**. Host Nginx
terminates TLS on 443 and 301-redirects port 80.

Everything here is done in-house: no certificate purchase, no domain registrar,
no internet access. The only per-client step is installing the root certificate
once.

---

## Why a private CA, and not Let's Encrypt

The application is reached at `10.180.6.14`. CA/Browser Forum baseline
requirements **forbid** any publicly-trusted CA from issuing a certificate for a
reserved (RFC1918) IP range. Let's Encrypt will refuse, and so will every paid
CA. This is not a cost or configuration problem — a publicly-trusted certificate
would require a real registered domain name.

Plain self-signed was rejected for a different reason: it produces a browser
interstitial on every visit. Training the users of a _security audit tool_ to
click through TLS warnings is a worse outcome than the cleartext it replaces —
it is precisely the habit that makes interception work. A private root installed
once produces no warning at all.

## Why a hostname and not just the IP

`https://10.180.6.14` works and is encrypted. But **HSTS does not apply to IP
addresses**: RFC 6797 §8.1.1 requires a browser to discard a
`Strict-Transport-Security` header when the host is an IP literal. Without a
hostname, HSTS is permanently dead config no matter how correct the certificate
is, and an attacker on the path can strip a first visit back to HTTP.

### Name history, and why this one

Two earlier names were used and abandoned; the reasoning is worth keeping.

`ccure.internal` — correct but arbitrary. `.internal` is reserved by ICANN
(2024) for private use and can never collide with a real domain, which makes it
the safe default when no organisational domain is available.

`ccure-pro` — **single-label, and that was the problem.** Browsers treat a
dotless string in the address bar as a search term, so typing `ccure-pro` ran a
Google search instead of navigating; only `https://ccure-pro` worked. Single-label
names are also subject to DNS search-suffix devolution on some networks. HSTS and
cookies both did work (RFC 6797 excludes only IP literals, and the refresh cookie
is host-only), but the usability cost was not worth it.

`ccurepro.cdacb.in` — the current name, and the best of the three:

- It has dots, so browsers navigate normally. Users can type
  `ccurepro.cdacb.in` without a scheme.
- `cdacb.in` is the organisation's own domain, already resolved by **internal
  DNS** — `cdacb.in` answers `10.180.16.60` on this network. So the name belongs
  to a namespace that is actually administered, rather than one invented locally.
- `ccurepro.cdacb.in` was NXDOMAIN before this deployment, so nothing was
  displaced.

### Resolution: hosts entry now, DNS record later

The name currently resolves through a **hosts entry** on each client, because
this machine is not domain-joined (`WORKGROUP`) and nothing has been added to the
`cdacb.in` zone.

**Ask whoever administers `cdacb.in` DNS for an A record:**

```
ccurepro.cdacb.in.    A    10.180.6.14
```

Once that exists, drop the hosts step entirely — run the client script with
`-SkipHostsEntry` and it only installs the root certificate. That halves the
per-machine work and means new machines need nothing but the root.

Until then, note the failure mode: a machine **without** the hosts entry gets
NXDOMAIN and a plain "can't reach this site", not a wrong server. That is a safe
way to fail.

### Could this use a publicly-trusted certificate instead?

Possibly, and it would remove the root-certificate install from every client —
including phones, tablets and Linux machines, which the PowerShell script does
not cover.

It needs all of: `cdacb.in` registered publicly, control of its public DNS to
answer an ACME **DNS-01** challenge (a TXT record — no inbound reachability
needed, which is why this works for a private IP), and outbound internet access
from something that can run the ACME client, every 60–90 days.

The private CA was kept because none of that is established here, the renewal
cadence is 825 days rather than 90, and an audit tool that must reach OT segments
should not depend on an external service to keep serving TLS. Revisit if the
client list grows beyond what hand-installing a root can cover.

---

## Layout

| Path                                    | Contents                                                 |
| --------------------------------------- | -------------------------------------------------------- |
| `C:\CCure-PKI\ca\ccure-internal-ca.key` | **CA private key.** Never copied to the web server.      |
| `C:\CCure-PKI\ca\ccure-internal-ca.crt` | Root certificate. Public — this is what clients install. |
| `C:\nginx\conf\ssl\ccure.key`           | Server private key, read by Nginx.                       |
| `C:\nginx\conf\ssl\ccure-fullchain.crt` | Leaf + root.                                             |

The CA key deliberately lives outside `C:\nginx`. If Nginx is compromised the
attacker gets one host certificate, not the ability to mint certificates for
anything they like.

Both directories have ACL inheritance **disabled** and are restricted to
Administrators and SYSTEM. `C:\` and `D:\` grant broad rights by inheritance on
this machine, so a private key placed under either without that step is readable
by any authenticated user. Do not re-enable inheritance.

Certificate SANs: `DNS:ccurepro.cdacb.in`, `DNS:localhost`, `IP:10.180.6.14`,
`IP:127.0.0.1`. A CN alone has not been accepted by Chrome since version 58 —
the name must be in the SAN.

---

## Server setup (already done)

```powershell
# Run as Administrator, on the server only.
.\scripts\tls\new_internal_ca.ps1
```

Then Nginx picks it up from `scripts\host-nginx\nginx-host.conf`:

```powershell
Copy-Item .\scripts\host-nginx\nginx-host.conf C:\nginx\conf\nginx.conf -Force
C:\nginx\nginx.exe -t -p C:\nginx -c C:\nginx\conf\nginx.conf
Restart-Service CCureNginx
```

## Client setup (once per machine)

Copy `ccure-internal-ca.crt` and `install_client_trust.ps1` to the machine, then
in an elevated PowerShell:

```powershell
.\install_client_trust.ps1 -RootCert .\ccure-internal-ca.crt
```

It installs the root into `LocalMachine\Root`, adds the hosts entry, flushes DNS
and verifies the connection. Re-running is safe.

**Verify the thumbprint out-of-band before trusting it.** Installing a root
grants whoever holds its private key the ability to impersonate any site to that
machine. On the server:

```powershell
Get-PfxCertificate C:\CCure-PKI\ca\ccure-internal-ca.crt | Select-Object Thumbprint
```

**Firefox keeps its own certificate store** and ignores the Windows one. Firefox
users additionally need either an import under
Settings → Privacy & Security → Certificates → View Certificates → Authorities,
or `security.enterprise_roots.enabled = true` in `about:config`, which makes
Firefox read the Windows store.

---

## Two things that look broken and are not

**`curl` and `Invoke-WebRequest` fail with `CRYPT_E_NO_REVOCATION_CHECK`
(0x80092012) / `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`.**

Windows Schannel hard-fails when it cannot determine revocation status, and this
CA publishes no CRL or OCSP responder — normal for small private PKI. Browsers
soft-fail this and are unaffected. For scripts:

```bash
curl --ssl-no-revoke https://ccurepro.cdacb.in/
```

Or validate properly with OpenSSL, which does not consult Windows revocation:

```bash
openssl s_client -connect ccurepro.cdacb.in:443 -servername ccurepro.cdacb.in \
  -CAfile C:/CCure-PKI/ca/ccure-internal-ca.crt -brief
```

Expect `Verification: OK`, TLS 1.3.

**HSTS absent on `https://10.180.6.14`.** Correct — see above. Use the hostname.

---

## HSTS rollout

`max-age` is **300 seconds** in two places, deliberately:

- `scripts/host-nginx/nginx-host.conf` — `add_header Strict-Transport-Security`
- `Backend/main.py` — `_HSTS_VALUE`

HSTS is a one-way door. A client that has cached "HTTPS-only" for a year cannot
reach a broken deployment to be told why. Once every client is confirmed
working, raise **both together** to `31536000`. `includeSubDomains` only if every
subdomain of `ccurepro.cdacb.in` is also served over TLS.

`tests/security/test_cors_and_headers.py::test_hsts_max_age_is_short_during_rollout`
fails if one is raised past an hour, so the change has to be deliberate.

The API only sends HSTS when `X-Forwarded-Proto` is `https`. It is still directly
reachable on `127.0.0.1:8000` without TLS for local tooling, and claiming
HTTPS-only on a listener with no certificate would be a lie.

---

## Renewal

The leaf expires after 825 days (**19 Nov 2028**). The root expires in 2036.

```powershell
.\scripts\tls\new_internal_ca.ps1 -RenewLeafOnly
Restart-Service CCureNginx
```

`-RenewLeafOnly` reuses the existing CA, so **clients do not need to do
anything**. Running the script _without_ it refuses to proceed rather than
creating a second root — a new root would silently invalidate the trust every
client installed.

---

## Configuration that depends on TLS

| Setting                 | Value                       | Consequence if wrong                                                                      |
| ----------------------- | --------------------------- | ----------------------------------------------------------------------------------------- |
| `FRONTEND_URL`          | `https://ccurepro.cdacb.in` | Verification and reset emails link to plain HTTP, and to an IP that cannot be HSTS-pinned |
| `REFRESH_COOKIE_SECURE` | `True`                      | Refresh cookie sent over HTTP; set while HTTP-only it silently breaks every session       |
| `CORS_ALLOW_ORIGINS`    | `https://…` first           | Browser refuses cross-origin API calls                                                    |
| `VITE_API_BASE_URL`     | `/api`                      | Absolute `http://…` would be blocked as mixed content on an HTTPS page                    |

`REFRESH_COOKIE_SAMESITE` is `lax`. `strict` would be tighter and does work for
this app's flows — the SPA refreshes via same-site XHR — but it was left alone
because it could not be verified end-to-end without a live login. Worth testing.

Tests run against `base_url="https://testserver"` so the suite exercises the
same Secure cookie the deployment issues; with the default `http` base URL httpx
discards it and cookie-based flows fail in a way that looks like an app bug.

## PostgreSQL

The database requires TLS and the clients **verify the server certificate**.

`scripts/tls/new_postgres_cert.ps1 -Enable` issues a certificate from the same
internal CA, installs it as `server.crt`/`server.key` in the data directory with
`server.key` readable only by `NT AUTHORITY\NetworkService` (the service
account), and appends the `ssl` settings to `postgresql.auto.conf`.

### What this actually protects

Docker Desktop proxies container connections, so PostgreSQL sees every client as
`127.0.0.1` even though the containers dial `host.docker.internal`. The bytes go
container → Docker's virtual adapter → loopback and **never cross the physical
LAN**. So this closes a local-attacker exposure, not a network one — worth being
accurate about, because the effort is easy to over-justify.

It is still worth having for two reasons beyond confidentiality:

- **`verify-full` authenticates the server.** `sslmode=require` encrypts but
  accepts _any_ certificate, so a local process that got hold of 5432 after a
  PostgreSQL crash could impersonate the database, collect SCRAM exchanges and
  read queries. `verify-full` checks the chain and the hostname; a wrong root is
  rejected, which was verified.
- Credentials for scanned hosts (SSH, WinRM, SNMP) are encrypted at rest by
  `core.security_crypto`, but the **decrypted** values cross this socket during a
  credentialed scan.

### Certificate names must match the connection string

libpq verifies against the hostname **as written in the connection string**, not
the address it resolves to. Three different strings are in use, so all three are
in the SAN:

| String                 | Used by                                             |
| ---------------------- | --------------------------------------------------- |
| `host.docker.internal` | api, worker, web-worker containers (docker-compose) |
| `127.0.0.1`            | host Celery worker (`Backend/.env`)                 |
| `localhost`            | vuln_intel sync scripts                             |

Omit one and `verify-full` fails for that client — at connection time, against a
production database.

### pg_hba.conf

Was:

```
host    all   all   0.0.0.0/0   scram-sha-256
```

With `listen_addresses='*'` behind it, that accepted password authentication from
**any address**, and the only thing preventing access from the 10.180.x LAN was
the absence of a Windows Firewall allow rule for 5432 — one layer, in a
subsystem nothing here controls. Now:

```
hostssl all   all   127.0.0.1/32      scram-sha-256
hostssl all   all   ::1/128           scram-sha-256
hostssl all   all   172.16.0.0/12     scram-sha-256
hostssl all   all   192.168.65.0/24   scram-sha-256
```

`hostssl` rejects any non-TLS connection outright — a plaintext attempt matches
no rule and gets `no pg_hba.conf entry … no encryption`. The Docker ranges are a
deliberate safety margin in case Docker's proxy behaviour changes on upgrade;
losing the database would take the application down. **`10.0.0.0/8` is
deliberately absent.**

Nothing needed changing in the backup script or `pg_dump`: libpq's default
`sslmode=prefer` negotiates TLS on its own. Verified after the change, and the
scheduled **CCure DB Backup** task still reports `LastTaskResult: 0`.

### Two traps worth knowing

**Backslashes in a libpq connection string are escapes.**
`sslrootcert=D:\PostgreSQL\18\data\root.crt` silently becomes
`D:PostgreSQL18dataroot.crt` and the connection fails with "root certificate
file does not exist". Use forward slashes — `D:/PostgreSQL/18/data/root.crt`.

**`ssl = on` alone changes nothing for existing clients.** Enabling it makes TLS
_available_; connections keep using whatever their `sslmode` says, and libpq's
default `prefer` will silently fall back to plaintext if anything is wrong with
the certificate. Always confirm with:

```sql
SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();
```

Enable, verify, _then_ switch `pg_hba` to `hostssl` — in that order, so a
certificate problem surfaces while plaintext is still a working fallback.

## What is still plaintext

Two hops remain, both of them Nginx to the Docker-published ports:
`127.0.0.1:8000` (API) and `127.0.0.1:3200` (SPA). Those ports are bound to
loopback only — they are not reachable from the network — so reading them
requires code already running on this host, at which point the private keys and
`Backend/.env` are equally readable. Encrypting them would add ceremony without
changing what an attacker in that position can do.

The API also deliberately keeps answering plain HTTP on `127.0.0.1:8000` for
local tooling, which is why it sends HSTS only when `X-Forwarded-Proto: https`.

So the current state is: **every hop that crosses a network is encrypted and
authenticated**, and every hop that does not is confined to loopback.

The genuinely open item is not transport at all — it is that
`Backend/.env` holds the database password, SMTP password and
`COMPLIANCE_ENCRYPTION_KEY` in plaintext on disk, readable by any account that
can read the repository. A secret manager (or at minimum tightening the ACL on
`Backend/.env` the way `C:\CCure-PKI` was tightened) is worth more at this point
than encrypting another loopback socket.
