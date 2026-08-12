<#
.SYNOPSIS
    Dump the CCure application database to a timestamped file.

.DESCRIPTION
    The server runs with archive_mode = off, so there is no point-in-time
    recovery: whatever is in the database right now is all there is. A dump
    taken before any destructive operation — a test run, a migration, a bulk
    delete — is the difference between a ten-minute restore and permanent loss.

    Reference data (the CVE feed, the compliance catalogue) makes the full dump
    large and slow. -SkipReferenceData excludes those tables for a fast dump of
    just the operational data: users, orgs, scans, assets, services, audit logs.

.EXAMPLE
    .\scripts\backup_db.ps1
    Full dump to backups\ccure_test_<timestamp>.dump

.EXAMPLE
    .\scripts\backup_db.ps1 -SkipReferenceData
    Fast dump of operational data only.

.EXAMPLE
    Restore:
      & "C:\Program Files\PostgreSQL\18\bin\pg_restore.exe" `
          -h 127.0.0.1 -p 5432 -U ccure_user -d ccure_test --clean --if-exists `
          backups\ccure_test_20260810_2000.dump
#>
param(
    [string]$Database = "ccure_test",
    [string]$DbHost   = "127.0.0.1",
    [int]$Port        = 5432,
    [string]$User     = "ccure_user",
    [string]$OutDir   = "",
    [switch]$SkipReferenceData,
    [int]$KeepDays    = 30
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $repoRoot "backups" }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force $OutDir | Out-Null }

$pgDump = "C:\Program Files\PostgreSQL\18\bin\pg_dump.exe"
if (-not (Test-Path $pgDump)) {
    $found = (Get-Command pg_dump -ErrorAction SilentlyContinue).Source
    if (-not $found) { throw "pg_dump not found. Install PostgreSQL client tools or edit `$pgDump in this script." }
    $pgDump = $found
}

if (-not $env:PGPASSWORD) {
    throw "Set PGPASSWORD before running, e.g. `$env:PGPASSWORD = '<password>'"
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$suffix = if ($SkipReferenceData) { "_ops" } else { "_full" }
$outFile = Join-Path $OutDir "${Database}_${stamp}${suffix}.dump"

# Custom format (-Fc): compressed, and pg_restore can pick individual tables
# out of it, which matters when you only want the scans back.
$dumpArgs = @("-h", $DbHost, "-p", $Port, "-U", $User, "-d", $Database, "-Fc", "-f", $outFile)

if ($SkipReferenceData) {
    foreach ($t in @("vulnerability_definitions", "compliance_controls", "compliance_rules",
                     "compliance_rule_controls", "compliance_policy_rules")) {
        $dumpArgs += @("--exclude-table-data", "public.$t")
    }
}

Write-Host "Dumping '$Database' -> $outFile"
& $pgDump @dumpArgs
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE" }

$sizeMb = "{0:N1}" -f ((Get-Item $outFile).Length / 1MB)
Write-Host "Done. $sizeMb MB"

# Prune old dumps so the directory does not grow without bound.
if ($KeepDays -gt 0) {
    $cutoff = (Get-Date).AddDays(-$KeepDays)
    $old = Get-ChildItem $OutDir -Filter "${Database}_*.dump" | Where-Object { $_.LastWriteTime -lt $cutoff }
    if ($old) {
        Write-Host "Removing $($old.Count) dump(s) older than $KeepDays days"
        $old | Remove-Item -Force
    }
}
