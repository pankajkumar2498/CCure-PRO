"""
Phase 23c — proof-based finding evidence (Codex item 10).

A finding lost its confidence, a reproducible curl, the identity it was tested
under, and any screenshot. These prove those are now resolved at persistence and
that the XSS engine captures a screenshot of a confirmed payload.
"""

import pytest

from core.web.tasks import _auth_context_label, _resolve_proof_evidence


# ── proof-evidence resolution ───────────────────────────────────────────────────
def test_confidence_high_for_verified_and_authoritative_tools():
    assert _resolve_proof_evidence({"is_verified": True}, None)["confidence"] == "high"
    assert (
        _resolve_proof_evidence({"detected_by": "sqlmap"}, None)["confidence"] == "high"
    )
    # an inferred/version-based finding is medium, not high
    assert (
        _resolve_proof_evidence({"detected_by": "custom"}, None)["confidence"]
        == "medium"
    )
    # an explicit engine confidence wins
    assert (
        _resolve_proof_evidence({"confidence": "low", "is_verified": True}, None)[
            "confidence"
        ]
        == "low"
    )


def test_curl_reconstructed_from_request_evidence():
    ev = _resolve_proof_evidence(
        {
            "request_method": "POST",
            "request_url": "https://a.test/api?x=1",
            "request_headers": {"Authorization": "Bearer t"},
            "request_body": '{"q":"v"}',
            "request_content_type": "application/json",
        },
        None,
    )
    curl = ev["curl_command"]
    assert curl and curl.startswith("curl") and "https://a.test/api?x=1" in curl
    assert "-X POST" in curl


def test_auth_context_prefers_finding_then_scan_label():
    assert (
        _resolve_proof_evidence({"auth_context": "userB"}, "form_login")["auth_context"]
        == "userB"
    )
    assert _resolve_proof_evidence({}, "form_login")["auth_context"] == "form_login"


def test_auth_context_label():
    assert _auth_context_label(None) == "anonymous"
    assert _auth_context_label({"type": "none"}) == "anonymous"
    assert _auth_context_label({"type": "oidc"}) == "oidc"


def test_screenshot_path_passed_through():
    ev = _resolve_proof_evidence({"screenshot_path": "/e/x.png"}, None)
    assert ev["screenshot_path"] == "/e/x.png"
    ev2 = _resolve_proof_evidence({"screenshot": "/e/y.png"}, None)
    assert ev2["screenshot_path"] == "/e/y.png"


# ── XSS screenshot capture ──────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_xss_capture_screenshot_writes_file(tmp_path):
    from core.web.xss.engine import XssEngine

    captured = {}

    class _Page:
        async def screenshot(self, path, **k):
            captured["path"] = path
            with open(path, "wb") as fh:
                fh.write(b"\x89PNG")

    eng = XssEngine(evidence_dir=str(tmp_path))
    finding = {"finding_type": "xss"}
    await eng._capture_screenshot(_Page(), finding, "abc123")
    assert finding["screenshot_path"] == captured["path"]
    import os

    assert os.path.exists(finding["screenshot_path"])


@pytest.mark.asyncio
async def test_xss_capture_noop_without_evidence_dir():
    from core.web.xss.engine import XssEngine

    eng = XssEngine(evidence_dir=None)
    finding = {"finding_type": "xss"}
    await eng._capture_screenshot(object(), finding, "abc")  # would raise if it tried
    assert "screenshot_path" not in finding
