<#
.SYNOPSIS
    Run once on each machine that will use CCure Audit PRO. Installs the
    internal root certificate and maps the hostname to the server.

.DESCRIPTION
    Two things have to be true on a client before https://<server name> works
    without a warning:

      1. The machine trusts the deployment's internal root CA. A public CA
         cannot issue for a reserved (private) IP range under CA/Browser Forum
         rules, so the server certificate is signed by an internal root that no
         machine trusts until told to.

      2. The server name resolves to the server's address. A machine that is
         not domain-joined has no DNS server to hold an A record and no Group
         Policy to push one, hence a hosts entry.

    Why bother with the name at all, when https://<address> also works:
    HSTS. RFC 6797 §8.1.1 requires a browser to ignore Strict-Transport-Security
    when the host is an IP literal, so the IP form gets encryption but can never
    be pinned to HTTPS. The hostname form can.

    The server is always named on the command line. There is deliberately no
    default: the defaults this script used to carry named the Windows host,
    retired on 9 Oct 2026, and a default silently points a client at whichever
    server the script happened to be written for.

    Safe to re-run. Both steps detect existing state and skip.

.PARAMETER RootCert
    Path to the deployment's root CA certificate (.crt). Copy it off the
    server first; it is public and safe to email or put on a share. The CA
    *private* key must never leave the server.

.PARAMETER Hostname
    The name clients use for the server, as on its certificate.

.PARAMETER IpAddress
    The server's address, for the hosts entry. Not needed with -SkipHostsEntry.

.PARAMETER SkipHostsEntry
    Use if your network already resolves the hostname via DNS.

.EXAMPLE
    # From an elevated PowerShell on the client machine:
    .\install_client_trust.ps1 -RootCert .\<root-ca>.crt -Hostname <server name> -IpAddress <server address>

.EXAMPLE
    # Where DNS already resolves the name:
    .\install_client_trust.ps1 -RootCert .\<root-ca>.crt -Hostname <server name> -SkipHostsEntry

.NOTES
    Firefox maintains its own certificate store and ignores the Windows one.
    Firefox users additionally need either:
      Settings → Privacy & Security → Certificates → View Certificates →
      Authorities → Import, selecting the root certificate file
    or the enterprise policy switch:
      security.enterprise_roots.enabled = true   (in about:config)
    The script prints this reminder if Firefox is detected.
#>
[CmdletBinding(DefaultParameterSetName = "HostsEntry")]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [string]$RootCert,

    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [string]$Hostname,

    [Parameter(Mandatory, ParameterSetName = "HostsEntry")]
    [ValidateScript({ $null -ne ($_ -as [System.Net.IPAddress]) })]
    [string]$IpAddress,

    [Parameter(Mandatory, ParameterSetName = "Dns")]
    [switch]$SkipHostsEntry
)

$ErrorActionPreference = "Stop"

function Write-Step { param($m) Write-Host "[*] $m"  -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    throw "Run as Administrator: writing to the machine trust store and the hosts file both require it."
}

if (-not (Test-Path $RootCert)) {
    throw "Root certificate not found at '$RootCert'. Copy the deployment's root CA certificate off the server first."
}

# ── Sanity-check the file before trusting it ─────────────────────────────────
# Installing a root certificate grants whoever holds its private key the ability
# to impersonate any site to this machine. Refusing anything that is not
# actually a CA certificate is the least this script can do; the thumbprint is
# printed so it can be compared against the server out-of-band.
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $RootCert
if (-not $cert.Extensions["2.5.29.19"]) {
    throw "'$RootCert' has no basicConstraints extension — it is not a CA certificate."
}
$basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$cert.Extensions["2.5.29.19"]
if (-not $basic.CertificateAuthority) {
    throw "'$RootCert' is not a CA certificate (basicConstraints CA:FALSE)."
}

Write-Host ""
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Issuer     : $($cert.Issuer)"
Write-Host "  Valid to   : $($cert.NotAfter)"
Write-Host "  Thumbprint : $($cert.Thumbprint)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Confirm that thumbprint matches the server before continuing." -ForegroundColor Yellow
Write-Host "  On the server:  openssl x509 -in <root-ca>.crt -noout -fingerprint -sha1"
Write-Host "  (the SHA-1 fingerprint is the thumbprint, written with colons)"
Write-Host ""

# ── 1. Trust the root ────────────────────────────────────────────────────────
Write-Step "Installing the root certificate into LocalMachine\Root..."
$existing = Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

if ($existing) {
    Write-Ok "Already trusted (thumbprint $($cert.Thumbprint)). Nothing to do."
} else {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()
    Write-Ok "Root certificate installed."
}

# ── 2. Resolve the hostname ──────────────────────────────────────────────────
if ($SkipHostsEntry) {
    Write-Ok "Skipping hosts entry (-SkipHostsEntry given)."
} else {
    $hostsFile = "$env:WINDIR\System32\drivers\etc\hosts"
    Write-Step "Ensuring $Hostname resolves to $IpAddress..."

    # ── Read and write the hosts file with .NET, not Get-Content/Set-Content ──
    #
    # The hosts file is frequently held open by another process — Docker Desktop
    # rewrites it, and DNS Client and some AV products keep handles on it.
    # `Set-Content` fed from a `Get-Content` pipeline *truncated the file to zero
    # bytes and then failed* on this machine: it opened the target for writing
    # before the read handle was released, so the file was emptied and never
    # rewritten. That silently removed Docker's own
    # `host.docker.internal` mapping along with everything else.
    #
    # ReadAllLines/WriteAllLines each open, act and close deterministically, and
    # the content is materialised into a list before the write begins. The backup
    # is taken first regardless, so the worst case is recoverable.
    if (-not (Test-Path "$hostsFile.bak-ccure")) {
        Copy-Item $hostsFile "$hostsFile.bak-ccure" -Force
        Write-Ok "Backed up hosts to hosts.bak-ccure"
    }

    $existing = @([System.IO.File]::ReadAllLines($hostsFile))

    # Match the hostname as a whole word on a non-comment line, so a stale entry
    # is replaced rather than duplicated — two entries for one name resolve
    # unpredictably.
    $pattern = "^\s*[^#].*\s$([regex]::Escape($Hostname))(\s|$)"
    $already = @($existing | Where-Object { $_ -match $pattern })

    if ($already.Count -gt 0 -and ($already -match [regex]::Escape($IpAddress))) {
        Write-Ok "hosts already maps $Hostname to $IpAddress."
    } else {
        if ($already.Count -gt 0) {
            Write-Warn "hosts maps $Hostname to a different address; replacing:"
            $already | ForEach-Object { Write-Warn "    $_" }
        }

        $kept = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $existing) {
            if ($line -notmatch $pattern) { $kept.Add($line) }
        }
        $kept.Add("$IpAddress`t$Hostname`t# CCure Audit PRO")

        try {
            [System.IO.File]::WriteAllLines($hostsFile, $kept)
        } catch {
            Write-Warn "Could not write the hosts file: $($_.Exception.Message)"
            # Restore rather than leave a partially written or empty file behind.
            if ((Get-Item $hostsFile).Length -eq 0) {
                Copy-Item "$hostsFile.bak-ccure" $hostsFile -Force
                Write-Warn "hosts was left empty and has been restored from the backup."
            }
            throw "Add this line to $hostsFile manually: $IpAddress $Hostname"
        }
        Write-Ok "Added: $IpAddress $Hostname"
    }

    # Refuse to continue silently if the file ended up empty.
    if ((Get-Item $hostsFile).Length -eq 0) {
        Copy-Item "$hostsFile.bak-ccure" $hostsFile -Force
        throw "hosts file ended up empty and was restored from the backup. Nothing was changed."
    }

    ipconfig /flushdns | Out-Null
}

# ── 3. Firefox reminder ──────────────────────────────────────────────────────
$firefox = @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($firefox) {
    Write-Host ""
    Write-Warn "Firefox is installed on this machine."
    Write-Warn "Firefox keeps its own certificate store and ignores the Windows one."
    Write-Warn "For Firefox users, either import the root manually:"
    Write-Warn "  Settings -> Privacy & Security -> Certificates -> View Certificates"
    Write-Warn "  -> Authorities -> Import -> select $RootCert"
    Write-Warn "or set security.enterprise_roots.enabled = true in about:config,"
    Write-Warn "which makes Firefox read the Windows store."
}

# ── 4. Verify ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Step "Verifying the connection..."
try {
    $response = Invoke-WebRequest -Uri "https://$Hostname/" -UseBasicParsing -TimeoutSec 15
    Write-Ok "https://$Hostname/ returned HTTP $($response.StatusCode) with a trusted certificate."
    Write-Host ""
    Write-Host "  Done. Open https://$Hostname/ in your browser." -ForegroundColor Green
} catch {
    Write-Warn "Could not complete a verified request to https://$Hostname/"
    Write-Warn $_.Exception.Message
    Write-Host ""
    Write-Host "  If the certificate itself is fine, the usual causes are:" -ForegroundColor Yellow
    $target = if ($IpAddress) { $IpAddress } else { $Hostname }
    Write-Host "    - the server is unreachable from here (try: Test-NetConnection $target -Port 443)"
    Write-Host "    - a proxy is intercepting TLS"
    Write-Host "  Note that PowerShell and curl on Windows use Schannel, which fails"
    Write-Host "  private-CA certificates with CERT_TRUST_REVOCATION_STATUS_UNKNOWN"
    Write-Host "  because this CA publishes no CRL. Browsers do not do this. If the"
    Write-Host "  browser works, the deployment is fine."
}
Write-Host ""
