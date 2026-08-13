<#
.SYNOPSIS
    Register scheduled tasks that keep the vulnerability feeds current.

.DESCRIPTION
    A vulnerability feed reports "no findings" with exactly the same confidence
    whether it is current or two years stale, so a feed nobody refreshes is
    worse than no feed: it produces clean reports about hosts nobody assessed.

    Two tasks are registered:

      CCure Feed Sync (OSV)   - distribution and language-ecosystem advisories.
                                Publishers push several times a day; daily is
                                enough to stay within one publication cycle.
      CCure Feed Sync (MSRC)  - Microsoft's Security Update Guide. Patch Tuesday
                                is monthly, but out-of-band fixes are not, and
                                Microsoft revises past months in place. The sync
                                only re-fetches documents whose release date
                                moved, so a daily run is nearly free.

      CCure Feed Sync (Exploits)      - ExploitDB, Metasploit and Nuclei.
      CCure Feed Sync (CSAF)          - Siemens ProductCERT and CISA ICS/IT.
      CCure Feed Sync (VulnCheck KEV) - needs VULNCHECK_API_TOKEN.

    All are idempotent and can be run by hand at any time. Downloads are staged
    under CCURE_FEED_DIR (see Backend/.env.example); the default sits beside
    the repository so a fresh checkout works without configuration.

    Must be run from an elevated PowerShell session.

.PARAMETER OsvHour
    Hour of day (0-23) to sync OSV. Default 3.

.PARAMETER MsrcHour
    Hour of day (0-23) to sync MSRC. Default 4 — after OSV, so the two are not
    writing to the same database at once.

.EXAMPLE
    .\scripts\install_feed_schedule.ps1

.EXAMPLE
    Remove them again:
      Unregister-ScheduledTask -TaskName 'CCure Feed Sync (OSV)'  -Confirm:$false
      Unregister-ScheduledTask -TaskName 'CCure Feed Sync (MSRC)' -Confirm:$false
#>
param(
    [ValidateRange(0, 23)][int]$OsvHour = 3,
    [ValidateRange(0, 23)][int]$MsrcHour = 4,
    [ValidateRange(0, 23)][int]$ExploitHour = 5,
    [ValidateRange(0, 23)][int]$CsafHour = 6,
    [ValidateRange(0, 23)][int]$VulnCheckHour = 7
)

$ErrorActionPreference = "Stop"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated PowerShell session."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repoRoot "Backend\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Not found: $python" }

$logDir = Join-Path $repoRoot "Backend\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force $logDir | Out-Null }

function Register-FeedTask {
    param(
        [string]$TaskName,
        [string]$ScriptRelPath,
        [int]$Hour,
        [int]$TimeLimitMinutes,
        [string]$Description
    )

    $script = Join-Path $repoRoot $ScriptRelPath
    if (-not (Test-Path $script)) { throw "Not found: $script" }

    $log = Join-Path $logDir ((Split-Path $ScriptRelPath -Leaf) -replace '\.py$', '_scheduled.log')

    # Redirect both streams: the sync scripts log to stderr, so capturing only
    # stdout would leave a failed run with an empty log and no explanation.
    $inner = "& '$python' '$script' *>&1 | Tee-Object -FilePath '$log'"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$inner`"" `
        -WorkingDirectory $repoRoot

    $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($Hour))

    # StartWhenAvailable matters on a workstation: this machine is not on at
    # 03:00 every night, and without it a missed window is simply skipped and
    # the feed silently ages.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeLimitMinutes) `
        -MultipleInstances IgnoreNew

    $principal = New-ScheduledTaskPrincipal -UserId $id.Name -LogonType S4U -RunLevel Limited

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Replaced existing task '$TaskName'"
    }

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Description $Description | Out-Null

    Write-Host ("Registered '{0}' - daily at {1:00}:00, log: {2}" -f $TaskName, $Hour, $log)
}

Register-FeedTask -TaskName "CCure Feed Sync (OSV)" `
    -ScriptRelPath "Backend\scripts\vuln\sync_osv.py" `
    -Hour $OsvHour -TimeLimitMinutes 120 `
    -Description "Syncs osv.dev advisories into vuln_intel. Archives cache under CCURE_FEED_DIR."

Register-FeedTask -TaskName "CCure Feed Sync (MSRC)" `
    -ScriptRelPath "Backend\scripts\vuln\sync_msrc.py" `
    -Hour $MsrcHour -TimeLimitMinutes 60 `
    -Description "Syncs Microsoft Security Update Guide into vuln_intel. Documents cache under CCURE_FEED_DIR."

Register-FeedTask -TaskName "CCure Feed Sync (Exploits)" `
    -ScriptRelPath "Backend\scripts\vuln\sync_exploit_intel.py" `
    -Hour $ExploitHour -TimeLimitMinutes 45 `
    -Description ("Syncs ExploitDB, Metasploit and Nuclei exploit availability into " +
                  "vuln_intel. Feeds cache under CCURE_FEED_DIR.")

Register-FeedTask -TaskName "CCure Feed Sync (CSAF)" `
    -ScriptRelPath "Backend\scripts\vuln\sync_csaf.py" `
    -Hour $CsafHour -TimeLimitMinutes 120 `
    -Description ("Syncs Siemens ProductCERT, CISA ICS/IT and other CSAF vendor " +
                  "advisories into vuln_intel. Documents cache under CCURE_FEED_DIR.")

# Runs after the exploit sync so its honeypot-confirmed entries settle on top of
# the ExploitDB/Nuclei sources rather than being overwritten by them.
Register-FeedTask -TaskName "CCure Feed Sync (VulnCheck KEV)" `
    -ScriptRelPath "Backend\scripts\vuln\sync_vulncheck.py" `
    -Hour $VulnCheckHour -TimeLimitMinutes 30 `
    -Description ("Syncs VulnCheck KEV (exploited in the wild, ~3x CISA KEV) into " +
                  "vuln_intel. Needs VULNCHECK_API_TOKEN in Backend\.env.")

Write-Host ""
Write-Host "Check them with:"
Write-Host "  Get-ScheduledTask -TaskName 'CCure Feed Sync*' | Get-ScheduledTaskInfo"
Write-Host "Run one now:"
Write-Host "  Start-ScheduledTask -TaskName 'CCure Feed Sync (MSRC)'"
