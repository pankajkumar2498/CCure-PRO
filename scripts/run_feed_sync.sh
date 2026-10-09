#!/usr/bin/env bash
# Run one vulnerability-feed sync the way the schedule does.
#
#   scripts/run_feed_sync.sh <sync> <minutes>
#   scripts/run_feed_sync.sh sync_msrc 60
#
# <sync> is one of the scripts in Backend/scripts/vuln/: sync_osv, sync_msrc,
# sync_exploit_intel, sync_csaf, sync_vulncheck. The job of
# install_feed_schedule.sh's crontab entries, and the VM twin of what the
# Windows scheduled tasks did until 16 Sep 2026:
#
# - runs on the backend's own virtualenv (Backend/.venv), from Backend/, so the
#   sync reads Backend/.env for the vuln_intel credentials and API tokens;
# - never overlaps itself: a run still going when the next is due is left alone
#   and the skip is logged (the Windows tasks' MultipleInstances IgnoreNew);
# - stops after <minutes> (their ExecutionTimeLimit) and says so;
# - writes the run's whole output, both streams, to
#   Backend/logs/<sync>_scheduled.log, ending with its exit status, because a
#   feed that silently stops refreshing still reports "no findings" with full
#   confidence.
#
# Exit status is the sync's own (124 when the time limit stopped it).
set -uo pipefail

NAME="${1:?usage: run_feed_sync.sh <sync> <minutes>}"
MINUTES="${2:?usage: run_feed_sync.sh <sync> <minutes>}"
case "$NAME" in
    sync_osv|sync_msrc|sync_exploit_intel|sync_csaf|sync_vulncheck) ;;
    *) echo "unknown feed sync: $NAME" >&2; exit 2 ;;
esac
case "$MINUTES" in ''|*[!0-9]*) echo "minutes must be a whole number, got $MINUTES" >&2; exit 2 ;; esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$REPO_ROOT/Backend"
PYTHON="$BACKEND/.venv/bin/python"
LOG_DIR="$BACKEND/logs"
LOG="$LOG_DIR/${NAME}_scheduled.log"
[ -x "$PYTHON" ] || { echo "no backend virtualenv at $PYTHON" >&2; exit 2; }
mkdir -p "$LOG_DIR"

exec 9>"$LOG_DIR/.${NAME}.lock"
if ! flock -n 9; then
    echo "$(date -Is) $NAME: the previous run is still going; this one was skipped" \
        >> "$LOG_DIR/feed_sync_skipped.log"
    exit 0
fi

{
    echo "== $NAME started $(date -Is), limit ${MINUTES} min"
    cd "$BACKEND" && timeout "${MINUTES}m" "$PYTHON" "scripts/vuln/${NAME}.py"
    rc=$?
    [ "$rc" -eq 124 ] && echo "== $NAME stopped at its ${MINUTES}-minute limit"
    echo "== $NAME finished $(date -Is), exit $rc"
    exit "$rc"
} > "$LOG" 2>&1
