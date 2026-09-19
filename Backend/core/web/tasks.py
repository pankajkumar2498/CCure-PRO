"""
core/web/tasks.py
─────────────────
Celery background tasks for web application scanning.

Each task corresponds to one pipeline phase:
  run_web_recon_task   →  Phase 1: RECON   (web_recon queue)
  run_web_crawl_task   →  Phase 2: CRAWL   (web_crawl queue)
  run_web_detect_task  →  Phase 3: DETECT  (web_dast queue)
  run_web_audit_task   →  Phase 4: AUDIT   (web_audit queue)

Tasks are chained: each phase dispatches the next on success.
Phase results are persisted to PostgreSQL after each phase completes.
"""

import asyncio
import logging

from core.celery_app import celery_app
from db.base import (
    SessionLocal,
    gen_web_asset_id,
    gen_web_finding_id,
    utcnow,
)
from core.web.correlation import _finding_identity
from core.web.timeout import enforce_global_timeout
from db.models.web_scans import WebAsset, WebFinding, WebScan

log = logging.getLogger("ccure.web.tasks")


def _run_async(coro):
    """Run async code safely from Celery worker threads or eager contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import threading
        from concurrent.futures import Future

        future = Future()

        def run_in_thread():
            try:
                result = asyncio.run(coro)
                future.set_result(result)
            except BaseException as e:
                future.set_exception(e)

        thread = threading.Thread(target=run_in_thread)
        thread.start()
        return future.result()
    else:
        return asyncio.run(coro)


def _check_cancelled(db, web_scan_id: str) -> bool:
    """Check if the web scan has been cancelled."""
    scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
    return scan and scan.status == "cancelled"


def _settle_web_scan_failed(db, web_scan_id: str, phase: str, reason: str) -> None:
    """
    Settle a web scan terminal after a phase-task error (Phase 18).

    Robust to an ORM that is itself the failure — the exact shape of the network
    incident CLAUDE.md records, where the except handler shared its broken query
    with the thing it was recovering from. It first tries the ORM (which also
    stamps the phase sub-status), and if that raises it falls back to
    force_terminal_web_scan_status, which is plain SQL against `web_scans` with
    no mapper, so the scan still reaches a terminal state and records a reason
    even when the ORM is what broke. force_terminal no-ops on an already-terminal
    scan, so a real completed/cancelled result is never overwritten. A best-
    effort terminal progress frame is published so the UI settles immediately
    rather than waiting for the next poll.
    """
    reason = (reason or "")[:1000]
    from core.scan_control import WEB_TERMINAL_STATUSES

    settled = False
    changed = False
    try:
        # Guard atomically on non-terminal status: only a scan that has not
        # already reached a terminal state is settled, so a completion (or a
        # cancellation) that won the race is never overwritten — the
        # failure-vs-completion / cancellation-vs-completion races. The scan
        # status is settled first, and the phase sub-status is stamped only when
        # that settle actually took effect, so a completed scan is never made to
        # show a failed phase.
        changed = (
            db.query(WebScan)
            .filter(
                WebScan.id == web_scan_id,
                ~WebScan.status.in_(list(WEB_TERMINAL_STATUSES)),
            )
            .update(
                {"status": "failed", "failure_reason": reason},
                synchronize_session=False,
            )
            > 0
        )
        if changed:
            _update_scan_phase_status(db, web_scan_id, phase, "failed")
        db.commit()
        settled = True
    except Exception:
        log.debug("ORM settle failed after %s error; using force_terminal", phase)
        try:
            db.rollback()
        except Exception:
            pass
        try:
            from core.scan_control import force_terminal_web_scan_status

            # force_terminal is itself a no-op on an already-terminal scan, so
            # the no-overwrite guarantee holds on the fallback path too.
            changed = force_terminal_web_scan_status(web_scan_id, "failed", reason)
            settled = True
        except Exception:
            log.debug("force_terminal fallback failed for %s", web_scan_id)
    # Only announce a terminal frame when this call actually settled the scan;
    # emitting one for a scan that completed elsewhere would tell the UI a real
    # result failed.
    if settled and changed:
        try:
            _emit_progress(
                web_scan_id,
                "failed",
                {"status": "failed", "message": reason, "error": reason},
            )
        except Exception:
            pass


def _emit_progress(web_scan_id: str, phase: str, data: dict) -> None:
    """Publish progress update via Redis pub/sub for web scans."""
    try:
        import json

        from core.redis_client import get_redis_client

        client = get_redis_client()
        message = json.dumps(
            {
                "scan_id": web_scan_id,
                "scan_type": "web",
                "phase": phase,
                "progress": data,
            }
        )
        client.publish(f"scan_progress:{web_scan_id}", message)
    except Exception as exc:
        log.debug("Progress publish failed: %s", exc)


def _record_tool_coverage(db, web_scan_id: str, phase: str, coverage: dict) -> None:
    """
    Persist which tools ran in a phase, and which did not.

    Stored alongside the scan for the same reason the network pipeline keeps
    its coverage: findings are only interpretable against what was actually
    attempted, and a phase that skipped its primary detector must not reach
    the reader as a phase that found nothing.

    Kept in ``options`` under a reserved key, following the existing precedent
    for scan-scoped result metadata, so this needs no schema change.
    """
    if not coverage:
        return
    scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
    if not scan:
        return
    options = dict(scan.options or {})
    tool_coverage = dict(options.get("tool_coverage") or {})
    tool_coverage[phase] = coverage
    options["tool_coverage"] = tool_coverage
    db.query(WebScan).filter(WebScan.id == web_scan_id).update({"options": options})
    db.commit()


def _update_scan_phase_status(
    db,
    web_scan_id: str,
    phase: str,
    status: str,
    started_at=None,
    completed_at=None,
    **extra_fields,
) -> None:
    """Update the phase-specific status fields on WebScan."""
    updates = {
        f"{phase}_status": status,
        "pipeline_phase": phase,
        "updated_at": utcnow(),
    }
    if started_at:
        updates[f"{phase}_started_at"] = started_at
    if completed_at:
        updates[f"{phase}_completed_at"] = completed_at
    if extra_fields:
        updates.update(extra_fields)

    db.query(WebScan).filter(WebScan.id == web_scan_id).update(updates)
    db.commit()


def _persist_web_assets(db, web_scan_id: str, endpoints: list[dict]) -> None:
    """Persist discovered endpoints as WebAsset records."""
    for ep in endpoints:
        url = ep.get("url", "")
        if not url:
            continue

        asset_id = gen_web_asset_id(web_scan_id, url + ep.get("method", "GET"))

        # Check if asset already exists (idempotent)
        existing = db.query(WebAsset).filter(WebAsset.id == asset_id).first()
        if existing:
            continue

        asset = WebAsset(
            id=asset_id,
            web_scan_id=web_scan_id,
            url=url,
            method=ep.get("method", "GET"),
            content_type=ep.get("content_type", ""),
            response_code=ep.get("response_code"),
            parameters=ep.get("parameters", {}),
            auth_required=ep.get("auth_required", False),
            is_api=ep.get("is_api", False) or _is_api_url(url),
            is_form=ep.get("is_form", False),
            has_file_upload=ep.get("has_file_upload", False),
            technology=ep.get("technology", []),
            source=ep.get("source", "crawler"),
            response_size=ep.get("response_size"),
            response_time=ep.get("response_time"),
            response_headers=ep.get("response_headers", {}),
        )
        db.add(asset)

    try:
        db.flush()
    except Exception as exc:
        log.warning("WebAsset persist partial failure: %s", exc)
        db.rollback()


def _persist_web_findings(
    db,
    web_scan_id: str,
    org_id: str,
    findings: list[dict],
) -> None:
    """Persist vulnerability findings as WebFinding records."""
    from core.web.standards_mapping import map_compliance, resolve_cwe

    for f in findings:
        finding_type = f.get("finding_type", "unknown")
        matched_at = f.get("matched_at", f.get("request_url", ""))

        # Resolve the CWE at the one point every finding passes through, so the
        # weakness class is uniform however the row was produced. resolve_cwe
        # keeps a well-formed CWE the engine already supplied (nuclei's own
        # classification, NVD enrichment, the per-verb HTTP-method CWEs),
        # normalises it, falls back to the centralized finding_type default,
        # and drops a fabricated identifier rather than storing it. Unmapped
        # types (nuclei "misconfig", raw "cve") stay None — a missing CWE is
        # represented honestly, never guessed.
        f["cwe_id"] = resolve_cwe(f)

        # Map compliance here, at the one point every finding passes through,
        # rather than only in AUDIT. AUDIT maps the findings handed to it, but
        # findings the CRAWL phase persists directly — sensitive files, the open
        # redirect — never reach that list, so they landed with an empty OWASP
        # category and no compliance tags. Mapping is a pure function of the
        # finding type and idempotent, so doing it here is safe and makes the
        # mapping uniform regardless of which phase wrote the row.
        if not f.get("owasp_category"):
            compliance = map_compliance(finding_type)
            f["owasp_category"] = compliance.get("owasp", "")
            if not f.get("compliance_tags"):
                f["compliance_tags"] = compliance.get("tags", [])

        # Find matching web asset
        web_asset_id = None
        if matched_at:
            asset = (
                db.query(WebAsset)
                .filter(
                    WebAsset.web_scan_id == web_scan_id,
                    WebAsset.url == matched_at.split("?")[0],
                )
                .first()
            )
            if asset:
                web_asset_id = asset.id

        # The same identity the deduplicator uses, so a finding keeps one row
        # across phases and re-runs while distinct checks keep their own.
        finding_id = gen_web_finding_id(
            web_asset_id or web_scan_id,
            finding_type,
            _finding_identity(f),
        )

        # Idempotent check.
        #
        # A row already exists whenever a later phase revisits a finding the
        # DETECT phase wrote — which is every finding, because AUDIT maps
        # compliance and merges duplicates and then re-persists the result.
        # Bumping only the timestamp discarded all of that: OWASP category and
        # compliance tags were computed on every run and never stored, so the
        # report and the compliance scorecard read them back empty, and a
        # finding whose severity was raised by corroboration from a second tool
        # kept the lower one.
        #
        # Analyst-owned state (status, assignment, notes) is deliberately not
        # touched here — a re-scan must not silently reopen a triaged finding.
        existing = db.query(WebFinding).filter(WebFinding.id == finding_id).first()
        if existing:
            existing.last_found_at = utcnow()
            if f.get("owasp_category"):
                existing.owasp_category = f["owasp_category"]
            if f.get("compliance_tags"):
                existing.compliance_tags = f["compliance_tags"]
            if f.get("cvss_score") is not None:
                existing.cvss_score = f["cvss_score"]
            if f.get("is_verified"):
                existing.is_verified = True
            if f.get("cwe_id") and not existing.cwe_id:
                existing.cwe_id = f["cwe_id"]
            # Severity only ever moves up: corroboration adds confidence, and a
            # second phase reporting the same issue at a lower rating is not
            # evidence the first was wrong.
            if _severity_rank(f.get("severity")) > _severity_rank(existing.severity):
                existing.severity = f["severity"]
            if f.get("detected_by") and f["detected_by"] != existing.detected_by:
                tools = sorted(
                    set(str(existing.detected_by or "").split(","))
                    | set(str(f["detected_by"]).split(","))
                )
                existing.detected_by = ",".join(t for t in tools if t)
            continue

        finding = WebFinding(
            id=finding_id,
            web_scan_id=web_scan_id,
            web_asset_id=web_asset_id,
            org_id=org_id,
            finding_type=finding_type,
            title=f.get("title", "Unknown Finding"),
            description=f.get("description", ""),
            severity=f.get("severity", "info"),
            cvss_score=f.get("cvss_score"),
            cvss_vector=f.get("cvss_vector"),
            detected_by=f.get("detected_by", "unknown"),
            template_id=f.get("template_id"),
            matched_at=matched_at,
            request_method=f.get("request_method"),
            request_url=f.get("request_url"),
            request_headers=f.get("request_evidence"),
            request_body=f.get("request_body"),
            response_code=f.get("response_code"),
            response_headers=f.get("response_headers_text"),
            response_body=f.get("response_evidence"),
            payload_used=f.get("payload_used"),
            owasp_category=f.get("owasp_category", ""),
            compliance_tags=f.get("compliance_tags", []),
            cve_id=f.get("cve_id"),
            cwe_id=f.get("cwe_id"),
            status="open",
            is_verified=f.get("is_verified", False),
        )
        db.add(finding)

    try:
        db.flush()
    except Exception as exc:
        log.warning("WebFinding persist partial failure: %s", exc)
        db.rollback()


def _update_scan_stats(db, web_scan_id: str) -> None:
    """Recalculate aggregate stats on the WebScan record."""

    scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
    if not scan:
        return

    total_endpoints = (
        db.query(WebAsset).filter(WebAsset.web_scan_id == web_scan_id).count()
    )

    findings = db.query(WebFinding).filter(WebFinding.web_scan_id == web_scan_id).all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan.total_endpoints = total_endpoints
    scan.total_findings = len(findings)
    scan.critical_count = severity_counts["critical"]
    scan.high_count = severity_counts["high"]
    scan.medium_count = severity_counts["medium"]
    scan.low_count = severity_counts["low"]
    scan.info_count = severity_counts["info"]
    scan.updated_at = utcnow()

    db.commit()


_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _severity_rank(severity) -> int:
    return _SEVERITY_RANK.get(str(severity or "info").lower(), 0)


def _is_api_url(url: str) -> bool:
    """Heuristic: does this URL look like an API endpoint?"""
    indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]
    return any(ind in url.lower() for ind in indicators)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: RECON
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(
    name="ccure.web.run_recon",
    queue="web_recon",
    bind=True,
    soft_time_limit=1800,
    time_limit=2400,
)
def run_web_recon_task(
    self,
    user_id: str,
    web_scan_id: str,
    target_url: str,
    scan_scope: dict,
    options: dict,
):
    """Phase 1: Reconnaissance — subdomain enum, WAF detect, tech fingerprint."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}
        # Global wall-clock timeout (Phase 12): stop the phase chain
        # at this boundary if the scan has exceeded WEB_SCAN_TIMEOUT.
        _to = enforce_global_timeout(web_scan_id, phase="recon")
        if _to:
            return {"success": False, "error": _to["reason"], "timed_out": True}

        now = utcnow()
        _update_scan_phase_status(
            db,
            web_scan_id,
            "recon",
            "running",
            started_at=now,
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update(
            {"status": "running", "started_at": now}
        )
        db.commit()
        _emit_progress(
            web_scan_id,
            "recon",
            {"status": "running", "message": "Starting reconnaissance..."},
        )

        from orchestrator.web_orchestrator import WebScanOrchestrator

        orch = WebScanOrchestrator(silent=False)
        result = _run_async(
            orch.run_recon(
                web_scan_id=web_scan_id,
                target_url=target_url,
                scan_scope=scan_scope,
                options=options,
            )
        )

        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db,
                web_scan_id,
                "recon",
                "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update(
                {
                    "status": "failed",
                    "failure_reason": result.get("error", "RECON phase failed"),
                    "completed_at": fail_time,
                }
            )
            db.commit()
            _emit_progress(
                web_scan_id,
                "recon",
                {"status": "failed", "message": result.get("error", "")},
            )
            return result

        # Persist RECON results to scan record
        db.query(WebScan).filter(WebScan.id == web_scan_id).update(
            {
                "waf_detected": result.get("waf_detected"),
                "tech_stack": result.get("tech_stack", []),
                "subdomains": result.get("subdomains", []),
                "recon_status": "complete",
                "recon_completed_at": utcnow(),
                "updated_at": utcnow(),
            }
        )
        db.commit()

        _record_tool_coverage(db, web_scan_id, "recon", result.get("tool_coverage"))
        _emit_progress(
            web_scan_id,
            "recon",
            {"status": "complete", "message": "Reconnaissance complete"},
        )

        # Chain to CRAWL phase
        next_task = run_web_crawl_task.delay(
            user_id=user_id,
            web_scan_id=web_scan_id,
            target_url=target_url,
            scan_scope=scan_scope,
            options=options,
            auth_config=db.query(WebScan)
            .filter(WebScan.id == web_scan_id)
            .first()
            .auth_config
            or {},
            sitemap_urls=result.get("sitemap_urls", []),
            waf_detected=result.get("waf_detected"),
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update(
            {
                "current_task_id": next_task.id,
            }
        )
        db.commit()

        return {
            "success": True,
            "web_scan_id": web_scan_id,
            "chained_task": next_task.id,
        }

    except Exception as exc:
        log.exception("Web RECON task failed for %s", web_scan_id)
        _settle_web_scan_failed(db, web_scan_id, "recon", str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: CRAWL
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(
    name="ccure.web.run_crawl",
    queue="web_crawl",
    bind=True,
    soft_time_limit=3600,
    time_limit=4200,
)
def run_web_crawl_task(
    self,
    user_id: str,
    web_scan_id: str,
    target_url: str,
    scan_scope: dict,
    options: dict,
    auth_config: dict,
    sitemap_urls: list[str] | None = None,
    waf_detected: str | None = None,
):
    """Phase 2: Crawling — Playwright spidering, ffuf brute, API discovery."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}
        # Global wall-clock timeout (Phase 12): stop the phase chain
        # at this boundary if the scan has exceeded WEB_SCAN_TIMEOUT.
        _to = enforce_global_timeout(web_scan_id, phase="crawl")
        if _to:
            return {"success": False, "error": _to["reason"], "timed_out": True}

        _update_scan_phase_status(
            db, web_scan_id, "crawl", "running", started_at=utcnow()
        )
        _emit_progress(
            web_scan_id,
            "crawl",
            {"status": "running", "message": "Crawling web application..."},
        )

        from orchestrator.web_orchestrator import WebScanOrchestrator

        orch = WebScanOrchestrator(silent=False)
        result = _run_async(
            orch.run_crawl(
                web_scan_id=web_scan_id,
                target_url=target_url,
                scan_scope=scan_scope,
                options=options,
                auth_config=auth_config,
                sitemap_urls=sitemap_urls,
                waf_detected=waf_detected,
            )
        )

        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db,
                web_scan_id,
                "crawl",
                "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update(
                {
                    "status": "failed",
                    "failure_reason": result.get("error", "CRAWL phase failed"),
                    "completed_at": fail_time,
                }
            )
            db.commit()
            return result

        # Persist discovered endpoints
        _persist_web_assets(db, web_scan_id, result.get("endpoints", []))

        # Persist sensitive file findings as WebFindings
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        if scan and result.get("sensitive_findings"):
            _persist_web_findings(
                db,
                web_scan_id,
                scan.org_id,
                result["sensitive_findings"],
            )

        _update_scan_phase_status(
            db, web_scan_id, "crawl", "complete", completed_at=utcnow()
        )
        _update_scan_stats(db, web_scan_id)
        db.commit()

        _emit_progress(
            web_scan_id,
            "crawl",
            {
                "status": "complete",
                "message": f"Found {len(result.get('endpoints', []))} endpoints",
            },
        )

        # Chain to DETECT phase
        next_task = run_web_detect_task.delay(
            user_id=user_id,
            web_scan_id=web_scan_id,
            target_url=target_url,
            endpoints=result.get("endpoints", []),
            forms=result.get("forms", []),
            options=options,
            auth_config=auth_config,
            waf_detected=waf_detected,
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update(
            {
                "current_task_id": next_task.id,
            }
        )
        db.commit()

        return {
            "success": True,
            "web_scan_id": web_scan_id,
            "chained_task": next_task.id,
        }

    except Exception as exc:
        log.exception("Web CRAWL task failed for %s", web_scan_id)
        _settle_web_scan_failed(db, web_scan_id, "crawl", str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: DETECT
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(
    name="ccure.web.run_detect",
    queue="web_dast",
    bind=True,
    soft_time_limit=7200,
    time_limit=8400,
)
def run_web_detect_task(
    self,
    user_id: str,
    web_scan_id: str,
    target_url: str,
    endpoints: list[dict],
    forms: list[dict],
    options: dict,
    auth_config: dict,
    waf_detected: str | None = None,
):
    """Phase 3: Detection — Nuclei templates, SQLMap, custom checks."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}
        # Global wall-clock timeout (Phase 12): stop the phase chain
        # at this boundary if the scan has exceeded WEB_SCAN_TIMEOUT.
        _to = enforce_global_timeout(web_scan_id, phase="detect")
        if _to:
            return {"success": False, "error": _to["reason"], "timed_out": True}

        _update_scan_phase_status(
            db, web_scan_id, "detect", "running", started_at=utcnow()
        )
        _emit_progress(
            web_scan_id,
            "detect",
            {"status": "running", "message": "Scanning for vulnerabilities..."},
        )

        from orchestrator.web_orchestrator import WebScanOrchestrator

        # RECON's fingerprint is carried into DETECT so the quick profile has
        # something to select templates on. Standard depth ignores it — the
        # fingerprint informs the scan, it never silently narrows it.
        scan_row = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        detect_options = {
            **(options or {}),
            "tech_stack": (scan_row.tech_stack if scan_row else []) or [],
        }

        orch = WebScanOrchestrator(silent=False)
        result = _run_async(
            orch.run_detect(
                web_scan_id=web_scan_id,
                target_url=target_url,
                endpoints=endpoints,
                forms=forms,
                options=detect_options,
                auth_config=auth_config,
                waf_detected=waf_detected,
            )
        )

        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db,
                web_scan_id,
                "detect",
                "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update(
                {
                    "status": "failed",
                    "failure_reason": result.get("error", "DETECT phase failed"),
                    "completed_at": fail_time,
                }
            )
            db.commit()
            return result

        # Persist findings
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        if scan:
            _persist_web_findings(
                db, web_scan_id, scan.org_id, result.get("findings", [])
            )

        _record_tool_coverage(db, web_scan_id, "detect", result.get("tool_coverage"))
        _update_scan_phase_status(
            db, web_scan_id, "detect", "complete", completed_at=utcnow()
        )
        _update_scan_stats(db, web_scan_id)
        db.commit()

        _emit_progress(
            web_scan_id,
            "detect",
            {
                "status": "complete",
                "message": f"Found {len(result.get('findings', []))} vulnerabilities",
            },
        )

        # Chain to AUDIT phase
        next_task = run_web_audit_task.delay(
            user_id=user_id,
            web_scan_id=web_scan_id,
            target_url=target_url,
            findings=result.get("findings", []),
            endpoints=endpoints,
            options=options,
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update(
            {
                "current_task_id": next_task.id,
            }
        )
        db.commit()

        return {
            "success": True,
            "web_scan_id": web_scan_id,
            "chained_task": next_task.id,
        }

    except Exception as exc:
        log.exception("Web DETECT task failed for %s", web_scan_id)
        _settle_web_scan_failed(db, web_scan_id, "detect", str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: AUDIT
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(
    name="ccure.web.run_audit",
    queue="web_audit",
    bind=True,
    soft_time_limit=1800,
    time_limit=2400,
)
def run_web_audit_task(
    self,
    user_id: str,
    web_scan_id: str,
    target_url: str,
    findings: list[dict],
    endpoints: list[dict],
    options: dict,
):
    """Phase 4: Audit — TLS audit, compliance mapping, risk scoring."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}
        # Global wall-clock timeout (Phase 12): stop the phase chain
        # at this boundary if the scan has exceeded WEB_SCAN_TIMEOUT.
        _to = enforce_global_timeout(web_scan_id, phase="audit")
        if _to:
            return {"success": False, "error": _to["reason"], "timed_out": True}

        _update_scan_phase_status(
            db, web_scan_id, "audit", "running", started_at=utcnow()
        )
        _emit_progress(
            web_scan_id,
            "audit",
            {"status": "running", "message": "Running security audit..."},
        )

        from orchestrator.web_orchestrator import WebScanOrchestrator

        orch = WebScanOrchestrator(silent=False)
        result = _run_async(
            orch.run_audit(
                web_scan_id=web_scan_id,
                target_url=target_url,
                findings=findings,
                endpoints=endpoints,
                options=options,
            )
        )

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db,
                web_scan_id,
                "audit",
                "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update(
                {
                    "status": "failed",
                    "failure_reason": result.get("error", "AUDIT phase failed"),
                    "completed_at": fail_time,
                }
            )
            db.commit()
            return result

        # Persist additional TLS findings
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        if scan and result.get("findings"):
            # Every finding is re-persisted, not just the ones this phase
            # produced. Findings already written in DETECT resolve to the same
            # deterministic id, so this updates them in place rather than
            # inserting a second copy — and updating them is the point: the
            # compliance mapping and the deduplication merge that AUDIT just
            # computed apply to the nuclei and sqlmap findings above all, and
            # filtering by tool excluded exactly those from ever receiving it.
            _persist_web_findings(db, web_scan_id, scan.org_id, result["findings"])

        _record_tool_coverage(db, web_scan_id, "audit", result.get("tool_coverage"))

        # Mark scan as complete
        now = utcnow()
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        duration = None
        if scan and scan.started_at:
            duration = (now - scan.started_at).total_seconds()

        db.query(WebScan).filter(WebScan.id == web_scan_id).update(
            {
                "audit_status": "complete",
                "audit_completed_at": now,
                "status": "complete",
                "pipeline_phase": "complete",
                "completed_at": now,
                "duration_seconds": duration,
                "updated_at": now,
            }
        )

        _update_scan_stats(db, web_scan_id)
        db.commit()

        _emit_progress(
            web_scan_id,
            "audit",
            {
                "status": "complete",
                "message": "Web application scan complete",
                "risk_score": result.get("risk_score", 0),
            },
        )

        log.info("Web scan %s completed successfully", web_scan_id)
        return {"success": True, "web_scan_id": web_scan_id}

    except Exception as exc:
        log.exception("Web AUDIT task failed for %s", web_scan_id)
        _settle_web_scan_failed(db, web_scan_id, "audit", str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
