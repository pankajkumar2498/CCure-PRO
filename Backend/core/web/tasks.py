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
import time
from typing import Dict, List, Optional

from core.celery_app import celery_app
from db.base import (
    SessionLocal, utcnow,
    gen_web_asset_id, gen_web_finding_id,
)
from db.models.web_scans import WebScan, WebAsset, WebFinding

log = logging.getLogger("ccure.web.tasks")


def _run_async(coro):
    """Run async code safely from Celery worker threads."""
    return asyncio.run(coro)


def _check_cancelled(db, web_scan_id: str) -> bool:
    """Check if the web scan has been cancelled."""
    scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
    return scan and scan.status == "cancelled"


def _emit_progress(web_scan_id: str, phase: str, data: Dict) -> None:
    """Publish progress update via Redis pub/sub for web scans."""
    try:
        from core.redis_client import get_redis_client
        import json
        client = get_redis_client()
        message = json.dumps({
            "scan_id": web_scan_id,
            "scan_type": "web",
            "phase": phase,
            "progress": data,
        })
        client.publish(f"scan_progress:{web_scan_id}", message)
    except Exception as exc:
        log.debug("Progress publish failed: %s", exc)


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


def _persist_web_assets(db, web_scan_id: str, endpoints: List[Dict]) -> None:
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
    findings: List[Dict],
) -> None:
    """Persist vulnerability findings as WebFinding records."""
    for f in findings:
        finding_type = f.get("finding_type", "unknown")
        matched_at = f.get("matched_at", f.get("request_url", ""))

        # Find matching web asset
        web_asset_id = None
        if matched_at:
            asset = db.query(WebAsset).filter(
                WebAsset.web_scan_id == web_scan_id,
                WebAsset.url == matched_at.split("?")[0],
            ).first()
            if asset:
                web_asset_id = asset.id

        finding_id = gen_web_finding_id(
            web_asset_id or web_scan_id,
            finding_type,
        )

        # Idempotent check
        existing = db.query(WebFinding).filter(WebFinding.id == finding_id).first()
        if existing:
            existing.last_found_at = utcnow()
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
    from sqlalchemy import func

    scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
    if not scan:
        return

    total_endpoints = db.query(WebAsset).filter(
        WebAsset.web_scan_id == web_scan_id
    ).count()

    findings = db.query(WebFinding).filter(
        WebFinding.web_scan_id == web_scan_id
    ).all()

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
    scan_scope: Dict,
    options: Dict,
):
    """Phase 1: Reconnaissance — subdomain enum, WAF detect, tech fingerprint."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        now = utcnow()
        _update_scan_phase_status(
            db, web_scan_id, "recon", "running",
            started_at=now,
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update({"status": "running", "started_at": now})
        db.commit()
        _emit_progress(web_scan_id, "recon", {"status": "running", "message": "Starting reconnaissance..."})

        from orchestrator.web_orchestrator import WebScanOrchestrator
        orch = WebScanOrchestrator(silent=False)
        result = _run_async(orch.run_recon(
            web_scan_id=web_scan_id,
            target_url=target_url,
            scan_scope=scan_scope,
            options=options,
        ))

        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db, web_scan_id, "recon", "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed",
                "failure_reason": result.get("error", "RECON phase failed"),
                "completed_at": fail_time,
            })
            db.commit()
            _emit_progress(web_scan_id, "recon", {"status": "failed", "message": result.get("error", "")})
            return result

        # Persist RECON results to scan record
        db.query(WebScan).filter(WebScan.id == web_scan_id).update({
            "waf_detected": result.get("waf_detected"),
            "tech_stack": result.get("tech_stack", []),
            "subdomains": result.get("subdomains", []),
            "recon_status": "complete",
            "recon_completed_at": utcnow(),
            "updated_at": utcnow(),
        })
        db.commit()

        _emit_progress(web_scan_id, "recon", {"status": "complete", "message": "Reconnaissance complete"})

        # Chain to CRAWL phase
        next_task = run_web_crawl_task.delay(
            user_id=user_id,
            web_scan_id=web_scan_id,
            target_url=target_url,
            scan_scope=scan_scope,
            options=options,
            auth_config=db.query(WebScan).filter(WebScan.id == web_scan_id).first().auth_config or {},
            sitemap_urls=result.get("sitemap_urls", []),
            waf_detected=result.get("waf_detected"),
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update({
            "current_task_id": next_task.id,
        })
        db.commit()

        return {"success": True, "web_scan_id": web_scan_id, "chained_task": next_task.id}

    except Exception as exc:
        log.exception("Web RECON task failed for %s", web_scan_id)
        try:
            _update_scan_phase_status(
                db, web_scan_id, "recon", "failed",
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed", "failure_reason": str(exc)[:1000],
            })
            db.commit()
        except Exception:
            log.debug("Failed to update scan status after error")
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
    scan_scope: Dict,
    options: Dict,
    auth_config: Dict,
    sitemap_urls: Optional[List[str]] = None,
    waf_detected: Optional[str] = None,
):
    """Phase 2: Crawling — Playwright spidering, ffuf brute, API discovery."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        _update_scan_phase_status(db, web_scan_id, "crawl", "running", started_at=utcnow())
        _emit_progress(web_scan_id, "crawl", {"status": "running", "message": "Crawling web application..."})

        from orchestrator.web_orchestrator import WebScanOrchestrator
        orch = WebScanOrchestrator(silent=False)
        result = _run_async(orch.run_crawl(
            web_scan_id=web_scan_id,
            target_url=target_url,
            scan_scope=scan_scope,
            options=options,
            auth_config=auth_config,
            sitemap_urls=sitemap_urls,
            waf_detected=waf_detected,
        ))

        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db, web_scan_id, "crawl", "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed",
                "failure_reason": result.get("error", "CRAWL phase failed"),
                "completed_at": fail_time,
            })
            db.commit()
            return result

        # Persist discovered endpoints
        _persist_web_assets(db, web_scan_id, result.get("endpoints", []))

        # Persist sensitive file findings as WebFindings
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        if scan and result.get("sensitive_findings"):
            _persist_web_findings(
                db, web_scan_id, scan.org_id,
                result["sensitive_findings"],
            )

        _update_scan_phase_status(db, web_scan_id, "crawl", "complete", completed_at=utcnow())
        _update_scan_stats(db, web_scan_id)
        db.commit()

        _emit_progress(web_scan_id, "crawl", {
            "status": "complete",
            "message": f"Found {len(result.get('endpoints', []))} endpoints",
        })

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
        db.query(WebScan).filter(WebScan.id == web_scan_id).update({
            "current_task_id": next_task.id,
        })
        db.commit()

        return {"success": True, "web_scan_id": web_scan_id, "chained_task": next_task.id}

    except Exception as exc:
        log.exception("Web CRAWL task failed for %s", web_scan_id)
        try:
            _update_scan_phase_status(db, web_scan_id, "crawl", "failed")
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed", "failure_reason": str(exc)[:1000],
            })
            db.commit()
        except Exception:
            log.debug("Failed to update scan status after error")
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
    endpoints: List[Dict],
    forms: List[Dict],
    options: Dict,
    auth_config: Dict,
    waf_detected: Optional[str] = None,
):
    """Phase 3: Detection — Nuclei templates, SQLMap, custom checks."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        _update_scan_phase_status(db, web_scan_id, "detect", "running", started_at=utcnow())
        _emit_progress(web_scan_id, "detect", {"status": "running", "message": "Scanning for vulnerabilities..."})

        from orchestrator.web_orchestrator import WebScanOrchestrator
        orch = WebScanOrchestrator(silent=False)
        result = _run_async(orch.run_detect(
            web_scan_id=web_scan_id,
            target_url=target_url,
            endpoints=endpoints,
            forms=forms,
            options=options,
            auth_config=auth_config,
            waf_detected=waf_detected,
        ))

        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db, web_scan_id, "detect", "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed",
                "failure_reason": result.get("error", "DETECT phase failed"),
                "completed_at": fail_time,
            })
            db.commit()
            return result

        # Persist findings
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        if scan:
            _persist_web_findings(db, web_scan_id, scan.org_id, result.get("findings", []))

        _update_scan_phase_status(db, web_scan_id, "detect", "complete", completed_at=utcnow())
        _update_scan_stats(db, web_scan_id)
        db.commit()

        _emit_progress(web_scan_id, "detect", {
            "status": "complete",
            "message": f"Found {len(result.get('findings', []))} vulnerabilities",
        })

        # Chain to AUDIT phase
        next_task = run_web_audit_task.delay(
            user_id=user_id,
            web_scan_id=web_scan_id,
            target_url=target_url,
            findings=result.get("findings", []),
            endpoints=endpoints,
            options=options,
        )
        db.query(WebScan).filter(WebScan.id == web_scan_id).update({
            "current_task_id": next_task.id,
        })
        db.commit()

        return {"success": True, "web_scan_id": web_scan_id, "chained_task": next_task.id}

    except Exception as exc:
        log.exception("Web DETECT task failed for %s", web_scan_id)
        try:
            _update_scan_phase_status(db, web_scan_id, "detect", "failed")
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed", "failure_reason": str(exc)[:1000],
            })
            db.commit()
        except Exception:
            log.debug("Failed to update scan status after error")
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
    findings: List[Dict],
    endpoints: List[Dict],
    options: Dict,
):
    """Phase 4: Audit — TLS audit, compliance mapping, risk scoring."""
    db = SessionLocal()
    try:
        if _check_cancelled(db, web_scan_id):
            return {"success": False, "error": "Scan cancelled"}

        _update_scan_phase_status(db, web_scan_id, "audit", "running", started_at=utcnow())
        _emit_progress(web_scan_id, "audit", {"status": "running", "message": "Running security audit..."})

        from orchestrator.web_orchestrator import WebScanOrchestrator
        orch = WebScanOrchestrator(silent=False)
        result = _run_async(orch.run_audit(
            web_scan_id=web_scan_id,
            target_url=target_url,
            findings=findings,
            endpoints=endpoints,
            options=options,
        ))

        if not result.get("success"):
            fail_time = utcnow()
            _update_scan_phase_status(
                db, web_scan_id, "audit", "failed",
                completed_at=fail_time,
            )
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed",
                "failure_reason": result.get("error", "AUDIT phase failed"),
                "completed_at": fail_time,
            })
            db.commit()
            return result

        # Persist additional TLS findings
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        if scan and result.get("findings"):
            # Only persist new TLS findings not already in DB
            existing_ids = {
                f.id for f in db.query(WebFinding.id).filter(
                    WebFinding.web_scan_id == web_scan_id
                ).all()
            }
            new_findings = [
                f for f in result["findings"]
                if f.get("detected_by") in ("sslyze", "custom")
            ]
            _persist_web_findings(db, web_scan_id, scan.org_id, new_findings)

        # Mark scan as complete
        now = utcnow()
        scan = db.query(WebScan).filter(WebScan.id == web_scan_id).first()
        duration = None
        if scan and scan.started_at:
            duration = (now - scan.started_at).total_seconds()

        db.query(WebScan).filter(WebScan.id == web_scan_id).update({
            "audit_status": "complete",
            "audit_completed_at": now,
            "status": "complete",
            "pipeline_phase": "complete",
            "completed_at": now,
            "duration_seconds": duration,
            "updated_at": now,
        })

        _update_scan_stats(db, web_scan_id)
        db.commit()

        _emit_progress(web_scan_id, "audit", {
            "status": "complete",
            "message": "Web application scan complete",
            "risk_score": result.get("risk_score", 0),
        })

        log.info("Web scan %s completed successfully", web_scan_id)
        return {"success": True, "web_scan_id": web_scan_id}

    except Exception as exc:
        log.exception("Web AUDIT task failed for %s", web_scan_id)
        try:
            _update_scan_phase_status(db, web_scan_id, "audit", "failed")
            db.query(WebScan).filter(WebScan.id == web_scan_id).update({
                "status": "failed", "failure_reason": str(exc)[:1000],
            })
            db.commit()
        except Exception:
            log.debug("Failed to update scan status after error")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
