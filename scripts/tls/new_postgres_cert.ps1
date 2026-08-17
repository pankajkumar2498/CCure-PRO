<#
.SYNOPSIS
    Issues a TLS certificate for the host PostgreSQL server from the CCure
    internal CA, installs it, and enables SSL.

.DESCRIPTION
    What this protects, precisely
    ────────────────────────────
    Docker Desktop proxies container connections, so PostgreSQL sees every
    client as 127.0.0.1 even though the API container dials
    `host.docker.internal`. The bytes therefore travel container -> Docker's
    virtual adapter -> loopback, and never cross the physical LAN. This is a
    local-attacker exposure (anything able to read the vEthernet interface or
    loopback on this host), not a network one.

    It is still worth encrypting, for two reasons beyond confidentiality:

      * `verify-full` authenticates the *server*. Without it, a local process
        that managed to bind 5432 — after a PostgreSQL crash, say — could
        impersonate the database and collect scram exchanges and queries.
      * Credentials for scanned hosts (SSH, WinRM, SNMP) move through these
        connections. They are encrypted at rest by core.security_crypto, but
        the decrypted values pass over this socket during a credentialed scan.

    Certificate names
    ─────────────────
    libpq verifies the certificate against the *hostname in the connection
    string*, not the address it resolves to. Three different strings are in use:

      host.docker.internal   API / web-worker containers (docker-compose)
      127.0.0.1              host Celery worker (Backend/.env)
      localhost              vuln_intel sync scripts (VULN_DB_HOST)

    All three go in the SAN, or `sslmode=verify-full` fails for whichever was
    omitted — and it fails at connection time, on a production database.

.PARAMETER Enable
    Also write ssl settings into postgresql.conf and reload. Without it the
    certificate is installed but PostgreSQL is left untouched, so the change can
    be inspected before it takes effect.

.NOTES
    Run as Administrator. The PostgreSQL service account
    (NT AUTHORITY\NetworkService) is granted read on the key; PostgreSQL refuses
    to start if it cannot read its own key, and refuses if the key is too widely
    readable.
#>
[CmdletBinding()]
param(
    [string]$DataDir  = "D:\PostgreSQL\18\data",
    [string]$PkiDir   = "C:\CCure-PKI",
    [string]$Service  = "postgresql-x64-18",
    [string]$PgBin    = "C:\Program Files\PostgreSQL\18\bin",
    [int]$LeafDays    = 825,
    [switch]$Enable
)

$ErrorActionPreference = "Stop"

function Write-Step { param($m) Write-Host "[*] $m"  -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) { throw "Run as Administrator." }

$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) {
    foreach ($c in @("C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
                     "C:\Program Files\Git\usr\bin\openssl.exe")) {
        if (Test-Path $c) { $openssl = $c; break }
    }
}
if (-not $openssl) { throw "OpenSSL not found." }
$script:openssl = $openssl

# See new_internal_ca.ps1 for why native stderr must not decide success here.
function Invoke-OpenSsl {
    param(
        [Parameter(Mandatory, Position = 0)][string]$FailureMessage,
        [Parameter(Mandatory, Position = 1)][string[]]$OpenSslArgs
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $out = & $script:openssl @OpenSslArgs 2>&1 } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "$FailureMessage (exit $LASTEXITCODE): $($out -join '; ')" }
    return $out
}

$caDir  = Join-Path $PkiDir "ca"
$caKey  = Join-Path $caDir "ccure-internal-ca.key"
$caCert = Join-Path $caDir "ccure-internal-ca.crt"
$caSerial = Join-Path $caDir "ccure-internal-ca.srl"

foreach ($f in @($caKey, $caCert)) {
    if (-not (Test-Path $f)) { throw "CA not found at $f. Run new_internal_ca.ps1 first." }
}
if (-not (Test-Path $DataDir)) { throw "PostgreSQL data directory not found: $DataDir" }

$serverKey = Join-Path $DataDir "server.key"
$serverCrt = Join-Path $DataDir "server.crt"
$rootCrt   = Join-Path $DataDir "root.crt"

# ── Issue ─────────────────────────────────────────────────────────────────────
Write-Step "Generating PostgreSQL server key (RSA 2048)..."
$tmpKey = Join-Path $env:TEMP "pg-server.key"
Invoke-OpenSsl "genrsa failed" @("genrsa", "-out", $tmpKey, "2048") | Out-Null

$ext = Join-Path $env:TEMP "pg-server-ext.cnf"
@"
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[dn]
C  = IN
O  = CCure Audit PRO
CN = host.docker.internal

[v3_req]
basicConstraints = CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt

[alt]
DNS.1 = host.docker.internal
DNS.2 = localhost
DNS.3 = ccurepro.cdacb.in
IP.1  = 127.0.0.1
IP.2  = 10.180.6.14
"@ | Set-Content -Path $ext -Encoding ascii

$csr = Join-Path $env:TEMP "pg-server.csr"
Write-Step "Creating CSR (SAN: host.docker.internal, localhost, ccurepro.cdacb.in, 127.0.0.1, 10.180.6.14)..."
Invoke-OpenSsl "req failed" @("req", "-new", "-key", $tmpKey, "-out", $csr, "-config", $ext) | Out-Null

$tmpCrt = Join-Path $env:TEMP "pg-server.crt"
Write-Step "Signing with the internal CA ($LeafDays days)..."
if (-not (Test-Path $caSerial)) { "1000" | Set-Content -Path $caSerial -Encoding ascii }
Invoke-OpenSsl "x509 signing failed" @(
    "x509", "-req", "-in", $csr, "-CA", $caCert, "-CAkey", $caKey,
    "-CAserial", $caSerial, "-out", $tmpCrt, "-days", "$LeafDays",
    "-sha256", "-extfile", $ext, "-extensions", "v3_req") | Out-Null

Invoke-OpenSsl "chain verification failed" @("verify", "-CAfile", $caCert, $tmpCrt) | Out-Null
Write-Ok "Certificate issued and verified against the CA"

# ── Install ───────────────────────────────────────────────────────────────────
# Back up anything already there so a bad cert can be rolled back.
foreach ($existing in @($serverKey, $serverCrt)) {
    if (Test-Path $existing) {
        Copy-Item $existing "$existing.bak-$(Get-Date -Format yyyyMMdd_HHmmss)" -Force
        Write-Warn "Backed up existing $(Split-Path -Leaf $existing)"
    }
}

Copy-Item $tmpCrt $serverCrt -Force
Copy-Item $tmpKey $serverKey -Force
Copy-Item $caCert $rootCrt   -Force
Remove-Item $tmpKey, $tmpCrt, $csr, $ext -Force -ErrorAction SilentlyContinue

# ── Key permissions ───────────────────────────────────────────────────────────
# PostgreSQL refuses to start if the key is readable by accounts beyond the
# owner and administrators, and equally refuses if the service account cannot
# read it at all. Inheritance is dropped so the data directory's ACL — which the
# move to D:\ deliberately restricted — cannot widen this back out.
Write-Step "Restricting server.key to the service account..."
$acl = Get-Acl $serverKey
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
foreach ($p in @("NT AUTHORITY\NetworkService", "BUILTIN\Administrators", "NT AUTHORITY\SYSTEM")) {
    $rights = if ($p -eq "NT AUTHORITY\NetworkService") { "Read" } else { "FullControl" }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $p, $rights, "None", "None", "Allow")))
}
Set-Acl -Path $serverKey -AclObject $acl
Write-Ok "server.key readable only by NetworkService, Administrators, SYSTEM"

Write-Host ""
Invoke-OpenSsl "could not read the certificate back" @(
    "x509", "-in", $serverCrt, "-noout", "-subject", "-dates", "-ext", "subjectAltName")
Write-Host ""

if (-not $Enable) {
    Write-Warn "Certificate installed but PostgreSQL not reconfigured."
    Write-Host "  Re-run with -Enable, or set these in postgresql.conf yourself:"
    Write-Host "    ssl = on"
    Write-Host "    ssl_cert_file = 'server.crt'"
    Write-Host "    ssl_key_file  = 'server.key'"
    Write-Host "    ssl_ca_file   = 'root.crt'"
    Write-Host "    ssl_min_protocol_version = 'TLSv1.2'"
    exit 0
}

# ── Enable ────────────────────────────────────────────────────────────────────
# Appended to postgresql.auto.conf rather than edited into postgresql.conf: the
# last assignment wins, the block is unambiguous to find and remove, and the
# main file — 33 KB of mostly comments — is left byte-for-byte alone.
$autoConf = Join-Path $DataDir "postgresql.auto.conf"
Copy-Item $autoConf "$autoConf.bak-$(Get-Date -Format yyyyMMdd_HHmmss)" -Force

$existingAuto = @([System.IO.File]::ReadAllLines($autoConf))
if ($existingAuto -match "^\s*ssl\s*=") {
    Write-Warn "postgresql.auto.conf already sets ssl; leaving it untouched."
} else {
    $block = @(
        "",
        "# ── CCure TLS (scripts/tls/new_postgres_cert.ps1, $(Get-Date -Format 'yyyy-MM-dd')) ──",
        "# Certificate issued by the CCure internal CA. See docs/TLS_SETUP.md.",
        "ssl = on",
        "ssl_cert_file = 'server.crt'",
        "ssl_key_file = 'server.key'",
        "ssl_ca_file = 'root.crt'",
        "# TLS 1.0/1.1 are deprecated (RFC 8996) and this product's own scanner",
        "# reports them as findings.",
        "ssl_min_protocol_version = 'TLSv1.2'"
    )
    [System.IO.File]::WriteAllLines($autoConf, ($existingAuto + $block))
    Write-Ok "ssl settings appended to postgresql.auto.conf"
}

Write-Step "Reloading PostgreSQL configuration..."
$pgctl = Join-Path $PgBin "pg_ctl.exe"
$prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
$out = & $pgctl reload -D $DataDir 2>&1
$ErrorActionPreference = $prev
Write-Host "  $($out -join ' ')"

Start-Sleep -Seconds 3
Write-Host ""
Write-Ok "Done. Verify with:"
Write-Host "    `"$PgBin\psql.exe`" `"host=127.0.0.1 dbname=ccure_test user=ccure_user sslmode=verify-full sslrootcert=$rootCrt`" -c `"SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()`""
Write-Host ""
Write-Warn "Clients are NOT yet requiring TLS. Plaintext still works until you set"
Write-Warn "sslmode in the connection strings and switch pg_hba to hostssl."
