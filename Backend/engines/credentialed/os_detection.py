"""
Operating-system detection over an already-authenticated shell session.

Moved here from ``routers/credentialed.py`` (Phase 3 of the modular-platform
programme). It only ever drove an SSH session and never belonged to the HTTP
layer: its one caller is the credentialed scan task, which had to import a
private helper from a router to reach it — the edge that put ``core.tasks`` and
``routers.credentialed`` in an import cycle.

Behaviour is unchanged, including the logger: records still go to
``ccure.api``, where they were written before the move.
"""

from __future__ import annotations

import logging

log = logging.getLogger("ccure.api")


def detect_os(ssh) -> str:
    """
    Robust OS auto-detection via SSH.

    Runs up to 5 lightweight probes in priority order — each designed for a
    different SSH default shell (cmd.exe, PowerShell, bash/sh).  Stops as
    soon as a confident match is found.

    Returns 'windows' or 'linux'.
    """

    # ── Probe 1: cmd.exe native — ver always prints "Microsoft Windows" ──────
    r = ssh.run("ver", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] ver → %s", out[:80])
    if r.success and "microsoft windows" in out.lower():
        return "windows"

    # ── Probe 2: cmd /c ver — same as above but explicit cmd ─────────────────
    r = ssh.run("cmd /c ver", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] cmd /c ver → %s", out[:80])
    if r.success and "microsoft windows" in out.lower():
        return "windows"

    # ── Probe 3: PowerShell $env:OS — Windows_NT on all Windows machines ─────
    r = ssh.run("$env:OS", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] $env:OS → %s", out[:80])
    if r.success and "windows" in out.lower():
        return "windows"

    # ── Probe 4: uname exact match — only real Linux/macOS returns this ───────
    r = ssh.run("uname -s", timeout=4)
    out = r.stdout.strip().upper()
    log.debug("[OS-detect] uname -s → %s", out[:80])
    if r.success and out in {"LINUX", "DARWIN", "FREEBSD", "OPENBSD", "NETBSD"}:
        return "linux"
    if r.success and "NT" in out and "LINUX" not in out:
        return "windows"

    # ── Probe 5: PowerShell [Environment]::OSVersion — works on PS 5+ ────────
    r = ssh.run("[Environment]::OSVersion.Platform", timeout=4)
    out = r.stdout.strip()
    log.debug("[OS-detect] OSVersion.Platform → %s", out[:80])
    if r.success and "win" in out.lower():
        return "windows"

    # ── Safe fallback ─────────────────────────────────────────────────────────
    log.warning("[OS-detect] All probes inconclusive — defaulting to 'linux'")
    return "linux"
