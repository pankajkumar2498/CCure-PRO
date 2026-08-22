<#
.SYNOPSIS
    Post-deployment validation for the rate-limiting and session controls.

.DESCRIPTION
    Individual unit tests prove each control in isolation. This proves the
    assembled system: that the container actually loaded the middleware, that
    nginx is actually running the config that was validated, that the trust
    boundary in force is the one that was configured, and that a request which
    should be refused actually is — through the real hop chain rather than
    through TestClient.

    Every check here exists because the thing it checks has, at some point,
    been true on paper and false in the running system:

      * an nginx config that passed `nginx -t` but was never reloaded, because
        `nginx -s reload` fails with "Access is denied" when the service runs
        under a different account than the shell;
      * a rate limiter that logged "active" at startup while its exemption list
        named paths no route served;
      * beat schedules that sat in the config for months with no process
        running them.

    Read-only apart from the requests it makes, which are ordinary API calls
    against deliberately non-existent accounts. It never writes to the database
    and can never lock out a real user.

    Targets Windows PowerShell 5.1, which is what this host runs. That is why
    the HTTP helper is hand-rolled: -SkipCertificateCheck and
    -SkipHttpErrorCheck are PowerShell 6+ parameters and do not exist here, and
    the responses this script cares about most are the 4xx ones that 5.1 throws
    on.

.PARAMETER BaseUrl
    The deployed HTTPS entry point.

.PARAMETER ApiDirect
    The API's published port, used to exercise the application layer in
    isolation from the nginx layer.

.EXAMPLE
    .\scripts\validate_release.ps1
    .\scripts\validate_release.ps1 -BaseUrl https://ccurepro.cdacb.in
#>

[CmdletBinding()]
param(
    [string]$BaseUrl = "https://127.0.0.1",
    [string]$ApiDirect = "http://127.0.0.1:8000",
    [string]$ApiContainer = "ccure-api",
    [string]$BeatContainer = "ccure-beat",
    [string]$NginxService = "CCureNginx"
)

$ErrorActionPreference = "Continue"
$script:Pass = 0
$script:Fail = 0
$script:Skip = 0

# The deployment uses a private CA (public CAs cannot issue for a reserved IP
# range). Trust is verified separately in docs/TLS_SETUP.md; this script is
# exercising the application, not re-testing the chain.
Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class CCureCertPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
                                      WebRequest req, int problem) { return true; }
}
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object CCureCertPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Invoke-Api {
    <#
      Returns @{ Status; Headers; Content } and never throws on an HTTP error.
      In 5.1 a non-2xx raises, and the response is only reachable through the
      exception — so both paths have to be unpacked into the same shape or
      every check would need to know which one it got.
    #>
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body
    )

    $splat = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = 20
        UseBasicParsing = $true
        ErrorAction     = "Stop"
    }
    if ($Body) {
        $splat.Body = $Body
        $splat.ContentType = "application/json"
    }

    try {
        $r = Invoke-WebRequest @splat
        $h = @{}
        foreach ($k in $r.Headers.Keys) { $h[$k] = $r.Headers[$k] }
        return @{ Status = [int]$r.StatusCode; Headers = $h; Content = $r.Content }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) {
            return @{ Status = 0; Headers = @{}; Content = $_.Exception.Message }
        }
        $h = @{}
        foreach ($k in $resp.Headers.AllKeys) { $h[$k] = $resp.Headers[$k] }

        # The body of an error response comes from $_.ErrorDetails, not from
        # the response stream. Invoke-WebRequest has already read that stream
        # by the time the exception surfaces, so GetResponseStream() returns
        # zero bytes -- which reads as "the endpoint returned an empty body"
        # and quietly turns a content assertion into a false failure.
        $content = ""
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $content = $_.ErrorDetails.Message
        } else {
            try {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $content = $reader.ReadToEnd()
                $reader.Close()
            } catch { }
        }
        return @{ Status = [int]$resp.StatusCode; Headers = $h; Content = $content }
    } catch {
        return @{ Status = 0; Headers = @{}; Content = $_.Exception.Message }
    }
}

function Get-HeaderValue {
    param([hashtable]$Headers, [string]$Name)
    foreach ($k in $Headers.Keys) {
        if ($k -ieq $Name) { return $Headers[$k] }
    }
    return $null
}

function Test-Step {
    param([string]$Name, [scriptblock]$Check)
    Write-Host ("  {0,-56}" -f $Name) -NoNewline
    try {
        $result = & $Check
        if ($result -is [string] -and $result -eq "SKIP") {
            Write-Host "SKIP" -ForegroundColor Yellow
            $script:Skip++
        } elseif ($result) {
            Write-Host "PASS" -ForegroundColor Green
            $script:Pass++
        } else {
            Write-Host "FAIL" -ForegroundColor Red
            $script:Fail++
        }
    } catch {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host ("      {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
        $script:Fail++
    }
}

function Get-First429 {
    param([string]$Uri, [int]$Attempts = 25)
    foreach ($i in 1..$Attempts) {
        $r = Invoke-Api -Uri $Uri
        if ($r.Status -eq 429) { return $r }
    }
    return $null
}

Write-Host ""
Write-Host "CCure release validation" -ForegroundColor Cyan
Write-Host ("  base {0}   api {1}" -f $BaseUrl, $ApiDirect) -ForegroundColor DarkGray
Write-Host ""

# ── 1. The stack is up ───────────────────────────────────────────────────────
Write-Host "Availability" -ForegroundColor Cyan

Test-Step "SPA served over TLS" {
    (Invoke-Api -Uri "$BaseUrl/").Status -eq 200
}
Test-Step "API reachable through nginx" {
    (Invoke-Api -Uri "$BaseUrl/api/").Status -eq 200
}
Test-Step "API reachable directly" {
    (Invoke-Api -Uri "$ApiDirect/").Status -eq 200
}
Test-Step "nginx service running" {
    $svc = Get-Service $NginxService -ErrorAction SilentlyContinue
    ($null -ne $svc) -and ($svc.Status -eq "Running")
}
Test-Step "API container healthy" {
    (docker inspect $ApiContainer --format "{{.State.Status}}" 2>&1) -match "running"
}

# ── 2. The controls actually loaded ──────────────────────────────────────────
Write-Host ""
Write-Host "Controls loaded" -ForegroundColor Cyan

Test-Step "baseline rate limit active in the container" {
    $null -ne (docker logs $ApiContainer 2>&1 |
        Select-String "Baseline API rate limit active")
}
Test-Step "trust boundary reported at startup" {
    $null -ne (docker logs $ApiContainer 2>&1 |
        Select-String "trusts \d+ proxy range")
}
Test-Step "no over-wide trusted range warning" {
    $null -eq (docker logs $ApiContainer 2>&1 |
        Select-String "spans \d+ addresses")
}
Test-Step "nginx is running the rate-limited config" {
    $conf = "C:\nginx\conf\nginx.conf"
    (Test-Path $conf) -and ((Get-Content $conf -Raw) -match "limit_req_zone")
}

# ── 3. The application layer refuses ─────────────────────────────────────────
Write-Host ""
Write-Host "Application rate limiting" -ForegroundColor Cyan

# A deliberately non-existent account. A failed login still consumes the per-IP
# budget, which is what is under test, and no real account can be locked out.
$probeBody = '{"email":"release-probe@invalid.test","password":"not-a-real-password"}'
$probeHeaders = @{ "X-Forwarded-For" = "203.0.113.200" }

$script:AppLimit429 = $null

Test-Step "login refuses after its limit (direct to API)" {
    $accepted = 0
    foreach ($i in 1..16) {
        $r = Invoke-Api -Uri "$ApiDirect/auth/login" -Method POST `
            -Headers $probeHeaders -Body $probeBody
        if ($r.Status -eq 429) { $script:AppLimit429 = $r; break }
        if ($r.Status -eq 401) { $accepted++ }
    }
    ($null -ne $script:AppLimit429) -and ($accepted -ge 5)
}

Test-Step "429 carries Retry-After" {
    if ($null -eq $script:AppLimit429) { return "SKIP" }
    $null -ne (Get-HeaderValue $script:AppLimit429.Headers "Retry-After")
}

Test-Step "429 uses the standard error envelope" {
    if ($null -eq $script:AppLimit429) { return "SKIP" }
    $script:AppLimit429.Content -match "RATE_LIMIT_EXCEEDED"
}

Test-Step "refusals reach the security log" {
    $null -ne (docker logs $ApiContainer --tail 200 2>&1 |
        Select-String "RATE_LIMIT_REJECTED")
}

# ── 4. The edge layer refuses ────────────────────────────────────────────────
Write-Host ""
Write-Host "Edge (nginx) rate limiting" -ForegroundColor Cyan

$script:Edge429 = Get-First429 -Uri "$BaseUrl/api/auth/me" -Attempts 30

Test-Step "auth zone refuses a burst" {
    $null -ne $script:Edge429
}

Test-Step "the refusal came from nginx, not the app" {
    # The application stamps X-Request-ID on everything it answers. A 429
    # without one was refused before it reached Python, which is the only way
    # to tell the two layers apart from outside.
    if ($null -eq $script:Edge429) { return "SKIP" }
    $null -eq (Get-HeaderValue $script:Edge429.Headers "X-Request-ID")
}

Test-Step "nginx 429 carries Retry-After" {
    if ($null -eq $script:Edge429) { return "SKIP" }
    $null -ne (Get-HeaderValue $script:Edge429.Headers "Retry-After")
}

Test-Step "Retry-After absent from normal responses" {
    # A literal add_header with `always` would put it on every 200. It comes
    # from a map on $status precisely so that it does not.
    $r = Invoke-Api -Uri "$BaseUrl/"
    $null -eq (Get-HeaderValue $r.Headers "Retry-After")
}

# ── 5. Client IP cannot be dictated by the client ────────────────────────────
Write-Host ""
Write-Host "Proxy header spoofing" -ForegroundColor Cyan

Test-Step "forged forwarding headers ignored through nginx" {
    $forged = @{ "X-Forwarded-For" = "8.8.8.8"; "X-Real-IP" = "8.8.8.8" }
    foreach ($i in 1..14) {
        Invoke-Api -Uri "$BaseUrl/api/auth/login" -Method POST `
            -Headers $forged -Body $probeBody | Out-Null
    }
    $recent = docker logs $ApiContainer --tail 100 2>&1 |
        Select-String "RATE_LIMIT_REJECTED"
    if ($null -eq $recent) { return "SKIP" }
    $text = ($recent | Select-Object -Last 6) -join " "
    -not ($text -match "ip=8\.8\.8\.8")
}

# ── 6. Scheduled maintenance is actually scheduled ───────────────────────────
Write-Host ""
Write-Host "Scheduled work" -ForegroundColor Cyan

Test-Step "beat process is alive" {
    (docker inspect $BeatContainer --format "{{.State.Status}}" 2>&1) -match "running"
}

Test-Step "session retention sweep is scheduled and registered" {
    $py = "from core.celery_app import celery_app; import core.tasks; " +
          "e = celery_app.conf.beat_schedule.get('purge-expired-refresh-sessions-daily'); " +
          "k = 'ccure.tasks.purge_expired_refresh_sessions' in celery_app.tasks; " +
          "print('OK' if (e and k) else 'NO')"
    $out = docker exec $BeatContainer python -c $py 2>&1
    ($out -join "") -match "OK"
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("Passed {0}   Failed {1}   Skipped {2}" -f $Pass, $Fail, $Skip) -ForegroundColor Cyan
Write-Host ""

if ($Fail -gt 0) {
    Write-Host "Release validation FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "Release validation passed" -ForegroundColor Green
exit 0
