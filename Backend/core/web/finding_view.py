"""
core/web/finding_view.py — a web finding as the API and the PDF show it.

Moved out of ``routers/web_scans.py`` so ``routers/dashboard.py`` can use it
without importing another router. The code is unchanged; ``routers.web_scans``
keeps ``_finding_detail`` and ``_finding_curl`` as imports of these.
"""

from __future__ import annotations

from db.models.web_scans import WebFinding


def finding_detail(f: WebFinding) -> dict:
    return {
        "id": f.id,
        "finding_type": f.finding_type,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "detected_by": f.detected_by,
        "template_id": f.template_id,
        "matched_at": f.matched_at,
        "request_method": f.request_method,
        "request_url": f.request_url,
        "payload_used": f.payload_used,
        "response_code": f.response_code,
        # Proof-based evidence (Phase 22, Item 10): the full HTTP request and
        # response are persisted but were dropped here — a reader could not
        # answer "which exact request caused this?". They are now exposed, plus
        # a curl that reproduces the request.
        "request_headers": f.request_headers,
        "request_body": f.request_body,
        "response_headers": f.response_headers,
        "response_body": f.response_body,
        "curl_command": f.curl_command or finding_curl(f),
        # Proof-based evidence completeness (Codex item 10).
        "confidence": f.confidence,
        "auth_context": f.auth_context,
        "screenshot_path": f.screenshot_path,
        "owasp_category": f.owasp_category,
        "compliance_tags": f.compliance_tags,
        "cve_id": f.cve_id,
        "cwe_id": f.cwe_id,
        "remediation": f.remediation,
        "status": f.status,
        "is_verified": f.is_verified,
        "created_at": (f.created_at.isoformat() if f.created_at else None),
    }


def finding_curl(f: WebFinding) -> str | None:
    """A curl command reproducing the finding's request (proof-based evidence).

    Built from the persisted request fields; returns None when there is no
    request URL to reproduce."""
    url = f.request_url or f.matched_at
    if not url:
        return None

    def _q(s: str) -> str:
        return "'" + str(s).replace("'", "'\\''") + "'"

    parts = ["curl", "-i", "-X", (f.request_method or "GET").upper()]
    # request_headers is stored as text; emit it as a single -H when present and
    # header-shaped, so the reproduction carries auth/content-type the scan used.
    rh = (f.request_headers or "").strip()
    if rh and ":" in rh and "\n" not in rh and len(rh) <= 300:
        parts += ["-H", _q(rh)]
    if f.request_body and (f.request_method or "").upper() in (
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ):
        parts += ["--data-raw", _q(str(f.request_body)[:2000])]
    parts.append(_q(url))
    return " ".join(parts)
