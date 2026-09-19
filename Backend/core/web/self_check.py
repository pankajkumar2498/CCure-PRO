"""
core/web/self_check.py
────────────────────────────────────────────────────────────────────────────
Web-scanner runtime readiness self-check (Phase 15).

Phase 14 misclassified SQLi as broken because a probe used a login shell whose
/etc/profile reset PATH and hid the tool — the scanner itself could run it. The
lesson is that "is this scanner actually able to do its job right now?" must be
answered by the scanner, in its own runtime, and reported loudly — not inferred
from an ad-hoc shell probe, and never left to a silent per-engine skip.

This runs each detection engine's dependency the way the engine will, in the
worker's own process/environment, and returns a structured verdict:

  READY      — every required component is present.
  DEGRADED   — all required present, but a recommended one is missing (some
               coverage is reduced; the scan still runs and says so).
  NOT_READY  — a required component is missing; the worker cannot perform its
               primary checks and must say so rather than silently skip them.

No secret is ever emitted: database/redis checks report only a sanitized host
and OK/FAIL, never a URL, user or password.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Dict

log = logging.getLogger("ccure.web.self_check")

READY = "READY"
DEGRADED = "DEGRADED"
NOT_READY = "NOT_READY"

_OK = "ok"
_MISSING = "missing"
_ERROR = "error"

#: Components without which a web scan cannot do its primary job.
REQUIRED = {"nuclei", "sqlmap", "playwright_chromium", "postgres", "redis"}
#: Components whose absence reduces coverage but does not stop a scan.
RECOMMENDED = {"nuclei_templates", "ffuf", "sslyze", "subfinder"}


def _result(status: str, detail: str, required: bool) -> dict:
    return {"status": status, "detail": detail, "required": required}


def _which(name: str) -> str | None:
    return shutil.which(name)


def _binary_version(name: str, version_args) -> dict:
    path = _which(name)
    if not path:
        return _result(_MISSING, f"{name} not found on PATH", name in REQUIRED)
    try:
        out = subprocess.run(
            [path, *version_args],
            capture_output=True,
            text=True,
            timeout=20,
        )
        ver = (out.stdout or out.stderr or "").strip().splitlines()
        ver = ver[0][:80] if ver else "(version unknown)"
        return _result(_OK, f"{path} — {ver}", name in REQUIRED)
    except Exception as exc:  # noqa: BLE001
        return _result(
            _ERROR, f"{path} present but not runnable: {exc}", name in REQUIRED
        )


def _check_sqlmap() -> dict:
    # Use the wrapper's own resolution, so the check matches how the engine
    # actually finds sqlmap (PATH incl. the pip user-bin), not a login shell.
    try:
        from core.web.sqlmap.wrapper import SqlmapWrapper

        w = SqlmapWrapper()
        if not w.is_available():
            return _result(_MISSING, "sqlmap not resolvable by the wrapper", True)
        try:
            out = subprocess.run(
                [w.binary, "--version"], capture_output=True, text=True, timeout=30
            )
            ver = (out.stdout or out.stderr or "").strip().splitlines()
            ver = ver[0][:60] if ver else "(unknown)"
        except Exception:
            ver = "(version check skipped)"
        return _result(_OK, f"{w.binary} — {ver}", True)
    except Exception as exc:  # noqa: BLE001
        return _result(_ERROR, f"sqlmap wrapper error: {exc}", True)


def _check_nuclei_templates() -> dict:
    from config import WebScanConfig

    d = getattr(WebScanConfig, "NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
    if not os.path.isdir(d):
        return _result(_MISSING, f"templates dir absent: {d}", False)
    try:
        # Count actual template files, not just top-level entries (the README
        # files at the root once made a full tree look like ~29 entries).
        n = 0
        for _root, _dirs, files in os.walk(d):
            n += sum(1 for f in files if f.endswith((".yaml", ".yml")))
            if n > 500:
                break
        if n == 0:
            return _result(_MISSING, f"{d} has no template files", False)
        return _result(_OK, f"{d} — {'500+' if n > 500 else n} templates", False)
    except Exception as exc:  # noqa: BLE001
        return _result(_ERROR, f"templates dir unreadable: {exc}", False)


def _check_playwright() -> dict:
    try:
        import importlib.util

        if importlib.util.find_spec("playwright") is None:
            return _result(_MISSING, "playwright python package absent", True)
    except Exception as exc:  # noqa: BLE001
        return _result(_ERROR, f"playwright import error: {exc}", True)
    base = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/playwright")
    try:
        import glob

        if glob.glob(os.path.join(base, "chromium-*")) or glob.glob(
            os.path.join(base, "chromium_*")
        ):
            return _result(_OK, f"chromium under {base}", True)
        # Fall back to the default cache location.
        if glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*")):
            return _result(_OK, "chromium under ~/.cache/ms-playwright", True)
        return _result(_MISSING, f"no chromium browser under {base}", True)
    except Exception as exc:  # noqa: BLE001
        return _result(_ERROR, f"browser probe error: {exc}", True)


def _check_sslyze() -> dict:
    try:
        import importlib.util

        if importlib.util.find_spec("sslyze") is None:
            return _result(_MISSING, "sslyze package absent", False)
        return _result(_OK, "sslyze importable", False)
    except Exception as exc:  # noqa: BLE001
        return _result(_ERROR, f"sslyze import error: {exc}", False)


def _check_redis() -> dict:
    try:
        from core.redis_client import get_redis_client

        get_redis_client().ping()
        return _result(_OK, "redis reachable", True)
    except Exception as exc:  # noqa: BLE001
        # Never echo the URL/credentials — only the exception class.
        return _result(_ERROR, f"redis unreachable ({type(exc).__name__})", True)


def _check_postgres() -> dict:
    try:
        from sqlalchemy import text

        from db.base import SessionLocal

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            return _result(_OK, "postgres reachable", True)
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001
        return _result(_ERROR, f"postgres unreachable ({type(exc).__name__})", True)


def run_self_check() -> Dict[str, object]:
    """Run every readiness probe and return a structured verdict (no secrets)."""
    checks: Dict[str, dict] = {
        "nuclei": _binary_version("nuclei", ["-version"]),
        "nuclei_templates": _check_nuclei_templates(),
        "ffuf": _binary_version("ffuf", ["-V"]),
        "subfinder": _binary_version("subfinder", ["-version"]),
        "sqlmap": _check_sqlmap(),
        "playwright_chromium": _check_playwright(),
        "sslyze": _check_sslyze(),
        "redis": _check_redis(),
        "postgres": _check_postgres(),
    }

    required_missing = [
        n for n, r in checks.items() if r["required"] and r["status"] != _OK
    ]
    recommended_missing = [
        n for n, r in checks.items() if not r["required"] and r["status"] != _OK
    ]

    if required_missing:
        status = NOT_READY
    elif recommended_missing:
        status = DEGRADED
    else:
        status = READY

    return {
        "status": status,
        "checks": checks,
        "required_missing": required_missing,
        "recommended_missing": recommended_missing,
    }


def log_self_check(report: Dict[str, object] | None = None) -> Dict[str, object]:
    """Run (or accept) a self-check and log it at a level matching the verdict."""
    report = report or run_self_check()
    status = report["status"]
    lines = [
        f"  {'OK ' if r['status']=='ok' else r['status'].upper():8} {n}: {r['detail']}"
        for n, r in report["checks"].items()
    ]  # type: ignore[index]
    body = "Web scanner self-check: %s\n%s" % (status, "\n".join(lines))
    if status == NOT_READY:
        log.error(
            "%s\nSCANNER NOT READY — required component(s) missing: %s. "
            "The affected security engine(s) will not run; scans must not be "
            "read as clean.",
            body,
            ", ".join(report["required_missing"]),  # type: ignore[arg-type]
        )
    elif status == DEGRADED:
        log.warning(
            "%s\nSCANNER DEGRADED — recommended component(s) missing: %s.",
            body,
            ", ".join(report["recommended_missing"]),  # type: ignore[arg-type]
        )
    else:
        log.info(body)
    return report


if __name__ == "__main__":
    import json
    import sys

    rep = log_self_check()
    print(json.dumps(rep, indent=2))
    sys.exit(0 if rep["status"] != NOT_READY else 1)
