<#
.SYNOPSIS
    Register a Windows scheduled task that dumps the CCure database regularly.

.DESCRIPTION
    The server runs with archive_mode = off, so the only recovery points that
    exist are the ones a dump creates. This registers backup_db.ps1 to run on a
    schedule, giving a bounded worst-case loss instead of "everything since the
    last time someone remembered".

    Must be run from an elevated PowerShell session.

.PARAMETER IntervalHours
    How often to dump. Default 6 (worst-case loss: 6 hours of scan history).

.PARAMETER Password
    The ccure_user password. Stored in the task's command line, so the task is
    registered to run as the current user and is readable only by them.

.EXAMPLE
    .\scripts\install_backup_schedule.ps1 -Password '<ccure_user password>'

.EXAMPLE
    Remove it again:
      Unregister-ScheduledTask -TaskName 'CCure DB Backup' -Confirm:$false
#>
param(
    [int]$IntervalHours = 6,
    [Parameter(Mandatory = $true)][string]$Password,
    [string]$TaskName = "CCure DB Backup",
    [int]$KeepDays = 30
)

$ErrorActionPreference = "Stop"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated PowerShell session."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$backupScript = Join-Path $PSScriptRoot "backup_db.ps1"
if (-not (Test-Path $backupScript)) { throw "Not found: $backupScript" }

# -SkipReferenceData keeps each dump small and fast. The CVE feed and compliance
# catalogue are re-downloadable; the scans, assets and users are not.
$inner = "`$env:PGPASSWORD='$Password'; & '$backupScript' -SkipReferenceData -KeepDays $KeepDays"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$inner`"" `
    -WorkingDirectory $repoRoot

# Start one interval from now, then repeat indefinitely.
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId $id.Name -LogonType S4U -RunLevel Limited

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Replaced existing task '$TaskName'"
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal `
    -Description "Dumps the CCure application database every $IntervalHours hours (operational data only). Retains $KeepDays days." | Out-Null

Write-Host "Registered '$TaskName' - every $IntervalHours hours, keeping $KeepDays days."
Write-Host "Dumps land in: $(Join-Path $repoRoot 'backups')"
Write-Host ""
Write-Host "Run it now to confirm:  Start-ScheduledTask -TaskName '$TaskName'"
