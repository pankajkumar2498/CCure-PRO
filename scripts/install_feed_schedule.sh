#!/usr/bin/env bash
# Schedule the vulnerability-feed syncs on this VM.
#
# A feed reports "no findings" with the same confidence whether it is current or
# months stale, so a feed nobody refreshes produces clean reports about hosts
# nobody assessed. This carries over the Windows deployment's schedule (its
# PowerShell installer was removed with that deployment): the same
# five syncs, at the same hours (this VM keeps IST, as the Windows host did),
# with the same time limits, one after another so no two write vuln_intel at
# once. The Windows tasks last ran on 16 Sep 2026; nothing refreshed the feeds
# on the VM after that until this schedule.
#
#   03:00  sync_osv            120 min   distribution and language advisories
#   04:00  sync_msrc            60 min   Microsoft Security Update Guide
#   05:00  sync_exploit_intel   45 min   ExploitDB, Metasploit, Nuclei, CISA KEV
#   06:00  sync_csaf           120 min   Siemens ProductCERT, CISA ICS/IT
#   07:00  sync_vulncheck       30 min   VulnCheck KEV; only with a token
#
# Each entry runs scripts/run_feed_sync.sh, which uses Backend/.venv, never
# overlaps a run still going, enforces the limit, and logs each run to
# Backend/logs/<sync>_scheduled.log. VulnCheck is scheduled only when
# VULNCHECK_API_TOKEN is set in Backend/.env: without it the sync refuses (exit
# 2) every night, which is a missing credential rather than a feed result.
#
# No sudo: a user crontab, like install_backup_schedule.sh. Idempotent;
# re-running replaces every entry it owns.
#
# Usage:
#   scripts/install_feed_schedule.sh
#   scripts/install_feed_schedule.sh --dry-run        # print the entries only
#   scripts/install_feed_schedule.sh --osv-hour 2 --msrc-hour 3
#   scripts/install_feed_schedule.sh --remove
#
# Run one now to confirm:   scripts/run_feed_sync.sh sync_msrc 60

set -euo pipefail

OSV_HOUR=3; MSRC_HOUR=4; EXPLOIT_HOUR=5; CSAF_HOUR=6; VULNCHECK_HOUR=7
DRY_RUN=0; REMOVE=0
MARKER="# ccure-feed-sync"

hour() {
    case "$2" in ''|*[!0-9]*) echo "$1 must be an hour 0-23, got '$2'" >&2; exit 1 ;; esac
    [ "$2" -le 23 ] || { echo "$1 must be an hour 0-23, got '$2'" >&2; exit 1; }
    echo "$2"
}
while [ $# -gt 0 ]; do
    case "$1" in
        --osv-hour)       OSV_HOUR="$(hour "$1" "${2-}")"; shift 2 ;;
        --msrc-hour)      MSRC_HOUR="$(hour "$1" "${2-}")"; shift 2 ;;
        --exploit-hour)   EXPLOIT_HOUR="$(hour "$1" "${2-}")"; shift 2 ;;
        --csaf-hour)      CSAF_HOUR="$(hour "$1" "${2-}")"; shift 2 ;;
        --vulncheck-hour) VULNCHECK_HOUR="$(hour "$1" "${2-}")"; shift 2 ;;
        --dry-run)        DRY_RUN=1; shift ;;
        --remove)         REMOVE=1; shift ;;
        -h|--help)        sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ "$REMOVE" = 1 ]; then
    ( crontab -l 2>/dev/null | grep -v -F "$MARKER" || true ) | crontab -
    echo "Removed every '$MARKER' entry from $(whoami)'s crontab."
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$REPO_ROOT/scripts/run_feed_sync.sh"
[ -f "$RUN" ] || { echo "not found: $RUN" >&2; exit 1; }
[ -x "$REPO_ROOT/Backend/.venv/bin/python" ] || {
    echo "no backend virtualenv at Backend/.venv; create it first (README.md)" >&2; exit 1; }

entry() { echo "0 $1 * * * bash $RUN $2 $3 $MARKER"; }
ENTRIES=(
    "$(entry "$OSV_HOUR" sync_osv 120)"
    "$(entry "$MSRC_HOUR" sync_msrc 60)"
    "$(entry "$EXPLOIT_HOUR" sync_exploit_intel 45)"
    "$(entry "$CSAF_HOUR" sync_csaf 120)"
)
# The token's value is read only to test that it is non-empty; it is never printed.
TOKEN_SET="$(sed -n 's/^[[:space:]]*VULNCHECK_API_TOKEN[[:space:]]*=//p' "$REPO_ROOT/Backend/.env" 2>/dev/null \
    | tail -1 | tr -d "\"' \t\r")"
if [ -n "$TOKEN_SET" ]; then
    ENTRIES+=("$(entry "$VULNCHECK_HOUR" sync_vulncheck 30)")
    VULNCHECK_NOTE=""
else
    VULNCHECK_NOTE="sync_vulncheck NOT scheduled: VULNCHECK_API_TOKEN is not set in Backend/.env (free tier at vulncheck.com); re-run this after adding it."
fi

if [ "$DRY_RUN" = 1 ]; then
    printf '%s\n' "${ENTRIES[@]}"
    [ -z "$VULNCHECK_NOTE" ] || echo "$VULNCHECK_NOTE"
    exit 0
fi

if ! systemctl is-active --quiet cron; then
    echo "cron is not running; ask an administrator for: sudo systemctl enable --now cron" >&2
    exit 1
fi

( crontab -l 2>/dev/null | grep -v -F "$MARKER" || true; printf '%s\n' "${ENTRIES[@]}" ) | crontab -

echo "Installed in $(whoami)'s crontab:"
printf '  %s\n' "${ENTRIES[@]}"
[ -z "$VULNCHECK_NOTE" ] || echo "$VULNCHECK_NOTE"
echo "Logs: $REPO_ROOT/Backend/logs/<sync>_scheduled.log"
echo
echo "Run one now to confirm:   bash $RUN sync_msrc 60"
