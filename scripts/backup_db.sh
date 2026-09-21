#!/usr/bin/env bash
# Dump the CCure application database to a timestamped file.
#
# Linux twin of backup_db.ps1, for the deployment where PostgreSQL runs in the
# `ccure-db` container. The server runs with archive_mode = off, so there is no
# point-in-time recovery: whatever is in the database right now is all there
# is. A dump taken before any destructive operation — a test run, a migration,
# a bulk delete — is the difference between a ten-minute restore and permanent
# loss.
#
# Two things about how the dump is taken, both deliberate:
#
#   * It runs the CONTAINER's pg_dump, not the host's. The host client is
#     PostgreSQL 16 and the server is 18; pg_dump refuses a server newer than
#     itself, and an archive written by 18 (format 1.16) is unreadable by an
#     older pg_restore anyway. The container's tools match the server by
#     construction, which is also why verification and restore go through
#     `docker exec`.
#
#   * It connects as the bootstrap superuser over the container's Unix socket,
#     where the image's pg_hba.conf is `trust`. So no password is needed, and
#     none is stored in a crontab — the Windows scheduled task had to embed one
#     in its command line.
#
# Reference data (the CVE catalogue, the compliance catalogue) makes the full
# dump large and slow. --skip-reference-data excludes those tables for a fast
# dump of just the operational data: users, orgs, scans, assets, services,
# audit logs. `vuln_intel` (7 GB, rebuilt from public feeds by
# Backend/scripts/vuln/) is never dumped unless named with --database.
#
# --remote copies the finished dump to another machine with scp. The VM's own
# disk is the only place the data lives otherwise, and a dump beside its
# database survives a bad migration but not a failed disk.
#
# Usage:
#   scripts/backup_db.sh
#       Full dump → backups/ccure_db_<stamp>_full.dump
#   scripts/backup_db.sh --skip-reference-data
#       Operational data only (fast).
#   scripts/backup_db.sh --skip-reference-data \
#       --remote cdac@10.180.6.14:D:/ccure-backups --ssh-key ~/.ssh/ccure_backup_ed25519
#       …and push the result to the Windows machine.
#
# Restore (the container's pg_restore, for the same version reason):
#   docker exec -i ccure-db pg_restore -U postgres -d ccure_db --clean --if-exists \
#       < backups/ccure_db_<stamp>_ops.dump
#
# Exit codes: 0 ok · 1 dump failed (nothing kept) · 2 dump ok but remote copy
# failed (local file kept; look at the log line).

set -euo pipefail

DATABASE="ccure_db"
CONTAINER="ccure-db"
DB_USER="postgres"
OUT_DIR=""
KEEP_DAYS=30
SKIP_REFERENCE_DATA=0
REMOTE=""
SSH_KEY=""
REMOTE_KEEP_DAYS=30

usage() { sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --database)            DATABASE="$2"; shift 2 ;;
        --container)           CONTAINER="$2"; shift 2 ;;
        --user)                DB_USER="$2"; shift 2 ;;
        --out-dir)             OUT_DIR="$2"; shift 2 ;;
        --keep-days)           KEEP_DAYS="$2"; shift 2 ;;
        --skip-reference-data) SKIP_REFERENCE_DATA=1; shift ;;
        --remote)              REMOTE="$2"; shift 2 ;;
        --ssh-key)             SSH_KEY="$2"; shift 2 ;;
        --remote-keep-days)    REMOTE_KEEP_DAYS="$2"; shift 2 ;;
        -h|--help)             usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -n "$OUT_DIR" ] || OUT_DIR="$REPO_ROOT/backups"
mkdir -p "$OUT_DIR"

# Dumps carry every user's password hash and every credential the compliance
# store encrypts. Owner-only, whatever the directory's default is.
umask 077

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

# One dump at a time. The Windows task used MultipleInstances=IgnoreNew; a
# second cron firing while a slow full dump is still running would otherwise
# double the load and race on the prune below.
LOCK="$OUT_DIR/.backup_db.lock"
exec 9>"$LOCK"
if ! flock -n 9; then
    log "another backup_db.sh is still running (lock: $LOCK); skipping"
    exit 0
fi

if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]; then
    log "ERROR: container '$CONTAINER' is not running; nothing to dump"
    exit 1
fi

STAMP="$(date '+%Y%m%d_%H%M%S')"
if [ "$SKIP_REFERENCE_DATA" -eq 1 ]; then SUFFIX="_ops"; else SUFFIX="_full"; fi
OUT_FILE="$OUT_DIR/${DATABASE}_${STAMP}${SUFFIX}.dump"

# Custom format (-Fc): compressed, and pg_restore can pick individual tables out
# of it, which matters when you only want the scans back.
DUMP_ARGS=(-U "$DB_USER" -d "$DATABASE" -Fc)
if [ "$SKIP_REFERENCE_DATA" -eq 1 ]; then
    for t in vulnerability_definitions compliance_controls compliance_rules \
             compliance_rule_controls compliance_policy_rules; do
        DUMP_ARGS+=(--exclude-table-data "public.$t")
    done
fi

log "dumping '$DATABASE' from $CONTAINER -> $OUT_FILE"
# Written to a .part first so a dump that dies half-way — container restart,
# disk full — never leaves a truncated file with a name the prune and the
# remote copy would treat as a good backup.
if ! docker exec "$CONTAINER" pg_dump "${DUMP_ARGS[@]}" > "$OUT_FILE.part"; then
    log "ERROR: pg_dump failed"
    rm -f "$OUT_FILE.part"
    exit 1
fi

# A zero-exit pg_dump that wrote nothing usable is still possible (a stdout
# pipe that broke late, for one). Ask the matching pg_restore to read the
# archive's table of contents before the file is allowed to keep its name.
# The listing is captured whole and tested afterwards: piped straight into
# `grep -q`, grep exits on its first match, pg_restore takes SIGPIPE, and
# under pipefail a good archive fails verification — intermittently.
if ! TOC="$(docker exec -i "$CONTAINER" pg_restore -l < "$OUT_FILE.part")" \
   || ! grep -q 'TABLE DATA' <<< "$TOC"; then
    log "ERROR: archive verification failed — pg_restore -l lists no table data"
    rm -f "$OUT_FILE.part"
    exit 1
fi
mv "$OUT_FILE.part" "$OUT_FILE"

SIZE_MB=$(awk -v b="$(stat -c %s "$OUT_FILE")" 'BEGIN { printf "%.1f", b / 1048576 }')
log "done: $(basename "$OUT_FILE") ($SIZE_MB MB)"

# Prune old dumps so the directory does not grow without bound.
if [ "$KEEP_DAYS" -gt 0 ]; then
    mapfile -t OLD < <(find "$OUT_DIR" -maxdepth 1 -type f -name "${DATABASE}_*.dump" -mtime +"$KEEP_DAYS")
    if [ "${#OLD[@]}" -gt 0 ]; then
        log "removing ${#OLD[@]} local dump(s) older than $KEEP_DAYS days"
        rm -f "${OLD[@]}"
    fi
fi

[ -n "$REMOTE" ] || exit 0

# ── Off-VM copy ──────────────────────────────────────────────────────────────
# REMOTE is user@host:path. A Windows OpenSSH target takes a drive path with
# forward slashes (D:/ccure-backups); scp's SFTP mode hands it to the Windows
# sftp-server unchanged.
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
[ -n "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")
REMOTE_HOST="${REMOTE%%:*}"
REMOTE_PATH="${REMOTE#*:}"

log "copying to $REMOTE"
if ! scp -q "${SSH_OPTS[@]}" "$OUT_FILE" "$REMOTE_HOST:${REMOTE_PATH%/}/$(basename "$OUT_FILE")"; then
    log "ERROR: remote copy to $REMOTE failed — the local dump is intact"
    exit 2
fi
log "remote copy ok"

# Prune on the far side too, or the Windows directory grows until the disk is
# full. A failure here is logged and is not a backup failure.
#
# The script is sent as -EncodedCommand (base64 of UTF-16LE), never as a
# quoted -Command string. OpenSSH for Windows hands the command line to
# whatever the account's login shell is, and on this workstation that is
# PowerShell, which expanded the `$_` inside a double-quoted -Command to
# nothing — and then exited 0 with the pipeline broken, so the log said
# "prune ok" while nothing was ever deleted. Base64 has no character either
# shell interprets. The remote side prints how many files it removed and
# fails loudly, so "ok" carries a number rather than an exit status.
if [ "$REMOTE_KEEP_DAYS" -gt 0 ]; then
    WIN_PATH="${REMOTE_PATH//\//\\}"
    PRUNE_PS="\$ErrorActionPreference = 'Stop'
\$old = @(Get-ChildItem -LiteralPath '$WIN_PATH' -Filter '${DATABASE}_*.dump' | Where-Object { \$_.LastWriteTime -lt (Get-Date).AddDays(-$REMOTE_KEEP_DAYS) })
\$old | Remove-Item -Force
Write-Output \$old.Count"
    PRUNE_B64="$(printf '%s' "$PRUNE_PS" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
    if REMOVED="$(ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" "powershell -NoProfile -NonInteractive -EncodedCommand $PRUNE_B64" 2>/dev/null | tr -d '\r' | tail -1)" \
       && [[ "$REMOVED" =~ ^[0-9]+$ ]]; then
        log "remote prune ok: removed $REMOVED dump(s) older than $REMOTE_KEEP_DAYS days"
    else
        log "WARNING: remote prune failed; dumps on $REMOTE_HOST are not being expired"
    fi
fi
