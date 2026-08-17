<#
.SYNOPSIS
    Creates a private certificate authority for CCure Audit PRO and issues the
    TLS certificate the host Nginx serves.

.DESCRIPTION
    Why a private CA rather than Let's Encrypt: this deployment is reached at
    10.180.6.14, an RFC1918 address. CA/Browser Forum baseline requirements
    prohibit any publicly-trusted CA from issuing a certificate for a reserved
    IP range, so no amount of money or configuration makes a public certificate
    possible here. A publicly-trusted certificate would require a real
    registered domain name.

    Why not plain self-signed: a self-signed certificate produces a browser
    interstitial on every visit. Teaching the users of a security-audit product
    to click through TLS warnings is a worse security outcome than the cleartext
    it replaces — it is precisely the habit that makes interception work. A
    private root installed once per machine produces no warning at all.

    Layout, and why the key lives where it does:

        C:\CCure-PKI\ca\ccure-internal-ca.key   CA private key. NEVER copied to
                                                the web server. If Nginx is
                                                compromised the attacker gets
                                                one host certificate, not the
                                                ability to mint certificates for
                                                anything they like.
        C:\CCure-PKI\ca\ccure-internal-ca.crt   Root certificate. Public. This
                                                is the file clients install.
        C:\nginx\conf\ssl\ccure.key             Leaf private key (Nginx reads).
        C:\nginx\conf\ssl\ccure-fullchain.crt   Leaf + root, in that order.

    Both directories have inheritance disabled and are restricted to
    Administrators and SYSTEM. D:\ and C:\ grant broad rights by inheritance on
    this machine, so a private key placed under either without this step is
    readable by any authenticated user.

.PARAMETER Hostname
    The DNS name the certificate is issued for. Also placed in the SAN.

.PARAMETER IpAddress
    The IPv4 address the application is reached at. Added as an IP SAN so
    https://<ip> keeps working before DNS or hosts entries are in place.
    Browsers require the address in the SAN; a CN alone has not been accepted
    since Chrome 58.

.PARAMETER RenewLeafOnly
    Reuse the existing CA and issue a fresh leaf certificate. Use this when the
    leaf expires. Re-running without it would create a NEW root, which every
    client would then have to install again.

.EXAMPLE
    .\scripts\tls\new_internal_ca.ps1
    .\scripts\tls\new_internal_ca.ps1 -RenewLeafOnly
#>
[CmdletBinding()]
param(
    [string]$Hostname   = "ccurepro.cdacb.in",
    [string]$IpAddress  = "10.180.6.14",
    [string]$PkiDir     = "C:\CCure-PKI",
    [string]$NginxSslDir = "C:\nginx\conf\ssl",
    [int]$CaDays        = 3650,
    # 825 days is the longest lifetime private PKI is conventionally issued for.
    # Chrome's 398-day cap applies to publicly-trusted chains, not to roots
    # installed locally, but a shorter leaf still limits the damage from a key
    # disclosure — hence a renewable leaf rather than a 10-year one.
    [int]$LeafDays      = 825,
    [switch]$RenewLeafOnly
)

$ErrorActionPreference = "Stop"

function Write-Step { param($m) Write-Host "[*] $m"  -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }

# OpenSSL writes progress and success notices to stderr — "Certificate request
# self-signature ok" among them. Under Windows PowerShell 5.1 a native
# command's stderr is wrapped in ErrorRecords, which combined with
# $ErrorActionPreference = "Stop" aborts the script on a *successful* signing.
# Exit code is the only reliable signal, so gather output with preference
# relaxed and judge on $LASTEXITCODE.
#
# Arguments are taken as one explicit array rather than as remaining arguments.
# With ValueFromRemainingArguments, PowerShell tried to bind openssl's own
# `-out` to its common -OutVariable/-OutBuffer parameters and failed with
# "the parameter name 'out' is ambiguous" before openssl was ever invoked.
# An array cannot be reinterpreted as parameter names.
function Invoke-OpenSsl {
    param(
        [Parameter(Mandatory, Position = 0)][string]$FailureMessage,
        [Parameter(Mandatory, Position = 1)][string[]]$OpenSslArgs
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $script:openssl @OpenSslArgs 2>&1
    }
    finally {
        $ErrorActionPreference = $previous
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit $LASTEXITCODE): $($output -join '; ')"
    }
    return $output
}

# ── Preconditions ─────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    throw "Run this as Administrator: it writes to C:\ and sets ACLs on the key material."
}

$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) {
    foreach ($candidate in @(
            "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            "C:\Program Files\Git\usr\bin\openssl.exe")) {
        if (Test-Path $candidate) { $openssl = $candidate; break }
    }
}
if (-not $openssl) { throw "OpenSSL not found. Install it or add it to PATH." }
$script:openssl = $openssl
Write-Ok "Using OpenSSL at $openssl"

$caDir   = Join-Path $PkiDir "ca"
$caKey   = Join-Path $caDir  "ccure-internal-ca.key"
$caCert  = Join-Path $caDir  "ccure-internal-ca.crt"
$caSerial = Join-Path $caDir "ccure-internal-ca.srl"

foreach ($d in @($PkiDir, $caDir, $NginxSslDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ── Lock down the directories holding private keys ───────────────────────────
# Inheritance is removed rather than merely adding a deny entry: the inherited
# grants on this volume include Authenticated Users, and an inherited allow
# beats nothing at all. This is the same reasoning applied to the PostgreSQL
# data directory when it moved to D:\.
function Restrict-Directory {
    param([string]$Path)
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
    foreach ($principal in @("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM")) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $principal, "FullControl",
            "ContainerInherit,ObjectInherit", "None", "Allow")))
    }
    Set-Acl -Path $Path -AclObject $acl
}

Restrict-Directory -Path $PkiDir
Restrict-Directory -Path $NginxSslDir
Write-Ok "Restricted $PkiDir and $NginxSslDir to Administrators + SYSTEM"

# ── Root CA ───────────────────────────────────────────────────────────────────
if ($RenewLeafOnly) {
    if (-not ((Test-Path $caKey) -and (Test-Path $caCert))) {
        throw "-RenewLeafOnly given but no CA exists at $caDir. Run without it first."
    }
    Write-Ok "Reusing existing CA (clients keep trusting it)"
}
elseif ((Test-Path $caKey) -or (Test-Path $caCert)) {
    Write-Warn "A CA already exists at $caDir."
    Write-Warn "Creating a new one would invalidate the root every client installed."
    Write-Warn "To issue a fresh server certificate, re-run with -RenewLeafOnly."
    throw "Refusing to overwrite an existing CA."
}
else {
    Write-Step "Generating CA private key (RSA 4096)..."
    Invoke-OpenSsl "openssl genrsa failed for the CA key" `
        @("genrsa", "-out", $caKey, "4096") | Out-Null

    Write-Step "Self-signing the root certificate ($CaDays days)..."
    # basicConstraints/keyUsage are set explicitly. A root without
    # `CA:TRUE,pathlen:0` and `keyCertSign` is rejected as an issuer by modern
    # verifiers, which surfaces as an opaque handshake failure rather than as a
    # message about the certificate.
    $caExt = Join-Path $env:TEMP "ccure-ca-ext.cnf"
    @"
[req]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no

[dn]
C  = IN
O  = CCure Audit PRO
CN = CCure Audit PRO Internal Root CA

[v3_ca]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
"@ | Set-Content -Path $caExt -Encoding ascii

    Invoke-OpenSsl "openssl req failed for the root certificate" `
        @("req", "-x509", "-new", "-key", $caKey, "-sha256",
          "-days", "$CaDays", "-out", $caCert, "-config", $caExt) | Out-Null
    Remove-Item $caExt -Force -ErrorAction SilentlyContinue
    Write-Ok "Root CA created: $caCert"
}

# ── Leaf certificate ──────────────────────────────────────────────────────────
$leafKey = Join-Path $NginxSslDir "ccure.key"
$leafCsr = Join-Path $env:TEMP    "ccure-leaf.csr"
$leafCrt = Join-Path $NginxSslDir "ccure.crt"
$fullChain = Join-Path $NginxSslDir "ccure-fullchain.crt"

Write-Step "Generating server private key (RSA 2048)..."
Invoke-OpenSsl "openssl genrsa failed for the leaf key" `
    @("genrsa", "-out", $leafKey, "2048") | Out-Null

# localhost and 127.0.0.1 are included so the same certificate serves requests
# made on the host itself — health checks and the smoke tests in this repo hit
# 127.0.0.1 directly and would otherwise fail verification.
$leafExt = Join-Path $env:TEMP "ccure-leaf-ext.cnf"
@"
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[dn]
C  = IN
O  = CCure Audit PRO
CN = $Hostname

[v3_req]
basicConstraints = CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt

[alt]
DNS.1 = $Hostname
DNS.2 = localhost
IP.1  = $IpAddress
IP.2  = 127.0.0.1
"@ | Set-Content -Path $leafExt -Encoding ascii

Write-Step "Creating CSR for $Hostname (SAN: $Hostname, localhost, $IpAddress, 127.0.0.1)..."
Invoke-OpenSsl "openssl req failed for the CSR" `
    @("req", "-new", "-key", $leafKey, "-out", $leafCsr, "-config", $leafExt) | Out-Null

Write-Step "Signing the server certificate ($LeafDays days)..."
if (-not (Test-Path $caSerial)) { "1000" | Set-Content -Path $caSerial -Encoding ascii }
Invoke-OpenSsl "openssl x509 failed to sign the leaf certificate" `
    @("x509", "-req", "-in", $leafCsr, "-CA", $caCert, "-CAkey", $caKey,
      "-CAserial", $caSerial, "-out", $leafCrt, "-days", "$LeafDays",
      "-sha256", "-extfile", $leafExt, "-extensions", "v3_req") | Out-Null

Remove-Item $leafCsr, $leafExt -Force -ErrorAction SilentlyContinue

# Leaf first, then root. Nginx serves the chain in file order, and a client that
# already trusts the root ignores the extra copy — but a client that does not
# gets a complete chain to inspect rather than an incomplete one.
Get-Content $leafCrt, $caCert | Set-Content -Path $fullChain -Encoding ascii
Write-Ok "Server certificate: $fullChain"

# ── Verify before anyone depends on it ───────────────────────────────────────
Write-Step "Verifying the chain..."
Invoke-OpenSsl "chain verification failed" `
    @("verify", "-CAfile", $caCert, $leafCrt) | Out-Null
Write-Ok "Chain verifies against the root"

Write-Host ""
Write-Host "Certificate details:" -ForegroundColor Yellow
Invoke-OpenSsl "could not read the certificate back" `
    @("x509", "-in", $leafCrt, "-noout", "-subject", "-issuer",
      "-dates", "-ext", "subjectAltName")

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  PKI ready" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Root certificate to distribute to clients:" -ForegroundColor White
Write-Host "    $caCert"
Write-Host ""
Write-Host "  Next: install the root on each client machine with" -ForegroundColor White
Write-Host "    scripts\tls\install_client_trust.ps1"
Write-Host ""
Write-Host "  The CA private key stays here and is never copied to Nginx:" -ForegroundColor Yellow
Write-Host "    $caKey"
Write-Host ""
