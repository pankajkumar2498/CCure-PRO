#!/usr/bin/env bash
# Schedule backup_db.sh on this VM — Linux twin of install_backup_schedule.ps1.
#
# The server runs with archive_mode = off, so the only recovery points that
# exist are the ones a dump creates. This puts backup_db.sh in the invoking
# user's crontab, giving a bounded worst-case loss instead of "everything since
# the last time someone remembered".
#
# Two tiers, and the second is not optional. The frequent dump skips reference
# data (--skip-reference-data: the CVE catalogue and compliance catalogue) so
# it takes 3 s and 10 MB — but asset_vulnerabilities.vuln_id is a foreign key
# into vulnerability_definitions, so that dump CANNOT be restored on its own:
# the constraint fails at the end of pg_restore, and `--clean` into the live
# database would first drop the 370k-row catalogue it does not carry. Measured
# on 17 Sep 2026; every 6-hourly dump the Windows task had produced since
# August had this property and it was never noticed because none was ever
# restored. The daily full dump (18 s, ~100 MB) is self-contained and is also
# where an ops dump's missing reference data comes from — see CLAUDE.md,
# "Restoring".
#
# No sudo: it is a user crontab, and the dump needs nothing root has — Docker
# access and the repository. It is idempotent; re-running replaces both entries.
#
# With --remote it also prepares the off-VM copy: a dedicated ed25519 key is
# generated if missing and its public half printed with the exact steps for
# the Windows side. The copy cannot work until that key is authorised there,
# and the first scheduled run will say so in the log.
#
# Usage:
#   scripts/install_backup_schedule.sh
#   scripts/install_backup_schedule.sh --remote cdac@10.180.6.14:D:/ccure-backups
#   scripts/install_backup_schedule.sh --interval-hours 4 --keep-days 14 --full-daily-at 3
#
# Remove it again:
#   crontab -l | grep -v 'ccure-db-backup' | crontab -

set -euo pipefail

INTERVAL_HOURS=6
FULL_DAILY_AT=2
KEEP_DAYS=30
REMOTE=""
SSH_KEY="$HOME/.ssh/ccure_backup_ed25519"
MARKER="# ccure-db-backup"

while [ $# -gt 0 ]; do
    case "$1" in
        --interval-hours) INTERVAL_HOURS="$2"; shift 2 ;;
        --full-daily-at)  FULL_DAILY_AT="$2"; shift 2 ;;
        --keep-days)      KEEP_DAYS="$2"; shift 2 ;;
        --remote)         REMOTE="$2"; shift 2 ;;
        --ssh-key)        SSH_KEY="$2"; shift 2 ;;
        -h|--help)        sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

case "$INTERVAL_HOURS" in 1|2|3|4|6|8|12|24) ;; *)
    echo "--interval-hours must divide 24 evenly (1,2,3,4,6,8,12,24), got $INTERVAL_HOURS" >&2; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/backup_db.sh"
[ -x "$SCRIPT" ] || { echo "not executable: $SCRIPT" >&2; exit 1; }
mkdir -p "$REPO_ROOT/backups"
LOG="$REPO_ROOT/backups/backup.log"

if ! systemctl is-active --quiet cron; then
    echo "cron is not running; ask an administrator for: sudo systemctl enable --now cron" >&2
    exit 1
fi

COMMON="--keep-days $KEEP_DAYS"
if [ -n "$REMOTE" ]; then
    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -q -t ed25519 -N '' -C "ccure-backup@$(hostname)" -f "$SSH_KEY"
        echo "Generated $SSH_KEY"
    fi
    COMMON="$COMMON --remote $REMOTE --ssh-key $SSH_KEY"
fi
OPS_CMD="$SCRIPT --skip-reference-data $COMMON"
FULL_CMD="$SCRIPT $COMMON"

# `0 */6 * * *` fires at 00:00, 06:00, 12:00, 18:00 — a predictable clock, where
# the Windows task ran at "install time + n×6h". The full dump sits at :30 so
# it never coincides with an ops run.
OPS_ENTRY="0 */$INTERVAL_HOURS * * * $OPS_CMD >> $LOG 2>&1 $MARKER"
FULL_ENTRY="30 $FULL_DAILY_AT * * * $FULL_CMD >> $LOG 2>&1 $MARKER"

( crontab -l 2>/dev/null | grep -v -F "$MARKER" || true; echo "$OPS_ENTRY"; echo "$FULL_ENTRY" ) | crontab -

echo "Installed in $(whoami)'s crontab, keeping $KEEP_DAYS days:"
echo "  operational data every $INTERVAL_HOURS h:  $OPS_ENTRY"
echo "  full dump daily at ${FULL_DAILY_AT}:30:        $FULL_ENTRY"
echo "Dumps land in: $REPO_ROOT/backups   Log: $LOG"
echo
echo "Run one now to confirm:   $OPS_CMD"

if [ -n "$REMOTE" ]; then
    REMOTE_HOST="${REMOTE%%:*}"
    REMOTE_PATH="${REMOTE#*:}"
    WIN_PATH="${REMOTE_PATH//\//\\}"
    cat <<MSG

── Windows side (${REMOTE_HOST}) — one-time, in an elevated PowerShell ──────────
The VM will push dumps with this key. Authorise it on the receiving account:

$(cat "$SSH_KEY.pub")

  New-Item -ItemType Directory -Force '$WIN_PATH' | Out-Null

If the receiving account is a member of Administrators, OpenSSH for Windows
reads C:\ProgramData\ssh\administrators_authorized_keys and IGNORES
~\.ssh\authorized_keys — this is the usual reason a key "does not work":

  Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value '$(cat "$SSH_KEY.pub")'
  icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'

For a non-administrator account instead:

  New-Item -ItemType Directory -Force "\$HOME\.ssh" | Out-Null
  Add-Content -Path "\$HOME\.ssh\authorized_keys" -Value '$(cat "$SSH_KEY.pub")'

Then, back here, prove it:   ssh -i $SSH_KEY -o BatchMode=yes $REMOTE_HOST 'echo ok'
MSG
fi
