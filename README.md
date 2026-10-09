# CCure-Audit-PRO

Network Scanning Tool

Frontend development follows the permanent [UX4G standard](docs/ux4g/UX4G_STANDARD.md).
All modules share the exact approved release, central asset pipeline and CCure
adapters. See [Frontend/README.md](Frontend/README.md) for required CI checks
and [the final migration report](docs/ux4g/B7_B10_FINAL_CLOSURE.md) for validation.

**Where it runs.** The application runs on the Linux VM, everything in Docker
([CLAUDE.md](CLAUDE.md), "Deployment: Linux VM"). The Windows-host deployment it
ran on until 17 Sep 2026 was retired on 9 Oct 2026, and its PowerShell start,
host-worker, backup and nginx scripts were removed with it; git history keeps
them. `scripts/tls/*.ps1` remain, for Windows client machines that must trust
the private CA.

## Backend virtual environment

For local tooling and the git hooks. Python 3.11 matches the backend image.

```bash
cd Backend
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install pre-commit
```

## Running the stack

```bash
docker compose up -d       # the whole stack; COMPOSE_PROFILES=container-scanner in .env adds worker and web-worker
docker compose down
docker compose logs -f api
```

- **Python changes** are live in the api (the code is bind-mounted):
  `docker compose restart api`. Restart the scanner worker after changing
  anything under `core/`, `scans/` or `orchestrator/`:
  `docker compose restart worker`.
- **Frontend changes** are baked into the image at build time:
  `docker compose build frontend && docker compose up -d --no-deps frontend`.
- **Scanner worker concurrency** is `SCANNER_WORKER_CONCURRENCY` (default 20),
  and the global Nmap process cap is `MAX_NMAP_PROCESSES` (default 20), both
  read from `.env` by `docker-compose.yml`. Recreate the worker after changing
  them.

## Database migrations

Every API start runs `alembic upgrade heads`, so a merged migration is applied
at the next `docker compose restart api`. To run it by hand, back up first:

```bash
scripts/backup_db.sh --skip-reference-data
docker exec -w /app ccure-api alembic upgrade heads
```

## Backups and restore

A user crontab dumps the database every six hours and in full nightly
(`scripts/install_backup_schedule.sh`). Restoring, and why an operational dump
cannot be restored on its own, is in CLAUDE.md, "Backups on the VM". Restore into
a fresh database and rename it; never restore over `ccure_db` while it is
serving.

## Vulnerability feeds

From `Backend/`, the NVD download runs in batches:

```bash
# Download next 1000 (offset 3300)
python scripts/vuln/download_nvd.py --limit 1000 --offset 3300

# Then next batch (offset shown in output)
python scripts/vuln/download_nvd.py --limit 1000 --offset 4300

# Then next batch (offset shown in output)
python scripts/vuln/download_nvd.py --limit 1000 --offset 12500
# And so on...

python scripts/verification/check_cve_source.py    # Confirm which CVE source is in use
```

The other feeds (OSV, MSRC, CSAF, exploit intelligence, VulnCheck) are the
`scripts/vuln/sync_*.py` scripts; CLAUDE.md, "Vulnerability feeds", says what
each needs.

## Preparing a Windows scan target for credentialed scanning over SSH

Windows targets no longer need OpenSSH: the scanner reaches them natively over
WinRM or SMB (CLAUDE.md, "Windows credentialed collection"). Use the steps below
only where SSH is the transport you want.

```powershell
# Enable OpenSSH Server (manually, on the target machine)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Set PowerShell as default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

# Open Firewall Port 22
New-NetFirewallRule -Name "OpenSSH-In" -DisplayName "Allow OpenSSH Port 22" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -ErrorAction SilentlyContinue

Restart-Service sshd

# Run inside PowerShell (on the target machine)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force
```

To make the change from the scanning side instead (SSH must already be enabled
on the target), connect with `ssh username@IP`, then either:

1. Switch shell: type `powershell` in the SSH session, then run:

   ```powershell
   New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
   Restart-Service sshd
   ```

2. Or run them from the current cmd prompt, wrapped in `powershell -Command`:

   ```
   powershell -Command "New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force"
   powershell -Command "Restart-Service sshd"
   ```

**Important:** because these commands modify registry keys under HKLM and
restart a system service, the account must have Administrator privileges and
UAC must allow remote elevation. If you receive an "Access Denied" error, apply
the `LocalAccountTokenFilterPolicy` registry fix first.

## Local checks and git hooks

The backend tests are **destructive**: they truncate the organisations and
users of whatever database they run against. Point them at a disposable
database whose name matches `^pytest_`, `_pytest` or `_pytest_db`; CLAUDE.md,
"Running the test suite", explains the guards and the 10 Aug 2026 incident
behind them.

```bash
cd Backend
TEST_DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/ccure_pytest_db MOCK_SCANNERS=true \
  .venv/bin/python -m pytest tests/security/test_rbac_routes.py tests/compliance/test_remediation_safety.py tests/reports/test_report_limits.py -v
```

Register the git hooks once, from the repository root, so formatting, linting,
security checks and the OpenAPI contract run before every commit:

```bash
Backend/.venv/bin/python -m pre_commit install
Backend/.venv/bin/python -m pre_commit run --all-files    # optional: check everything now
```
