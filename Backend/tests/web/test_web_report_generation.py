"""
Web-scan PDF report generation.

Two defects made the web report download 500 on real scans, and neither had a
test:

* the generator's default output directory resolved to ``Backend/reporting/
  reports`` — inside the code tree, not the writable bind-mounted ``reports/``
  volume — so ``os.makedirs`` failed for the API container's user;
* the summary table joined ``tech_stack`` (a list of dicts as RECON stores it)
  as if it were a list of strings, raising ``TypeError`` on every scan whose
  technology fingerprint found anything.

Both are exercised here against the shape a real scan produces.
"""

import os

from reporting.web_pdf_generator import WebScanReportGenerator


def _scan():
    return {
        "id": "wsc_report_test",
        "scan_name": "Report generation test",
        "target_url": "http://target.invalid/",
        "target_domain": "target.invalid",
        "status": "complete",
        "waf_detected": None,
        # The real shape: a list of dicts, not strings.
        "tech_stack": [
            {"name": "nginx", "category": "web-server", "version": "1.27"},
            {"name": "PHP", "category": "language", "version": "8.2"},
        ],
        "subdomains": [],
        "scan_scope": {"max_depth": 2},
        "started_at": "2026-09-18T10:00:00+00:00",
        "completed_at": "2026-09-18T10:12:00+00:00",
        "duration_seconds": 720,
    }


def _findings():
    return [
        {
            "severity": "medium",
            "finding_type": "misconfig",
            "title": "Missing Content-Security-Policy Header",
            "description": "No CSP header was returned.",
            "matched_at": "http://target.invalid/",
            "owasp_category": "A05:2021 – Security Misconfiguration",
        }
    ]


def test_report_generates_with_dict_tech_stack(tmp_path):
    # tmp_path proves the join fix independently of the directory fix.
    gen = WebScanReportGenerator(output_dir=str(tmp_path))
    path = gen.generate(_scan(), _findings(), [])
    assert os.path.exists(path)
    assert os.path.getsize(path) > 1000


def test_default_output_dir_is_the_runtime_reports_volume():
    # Backend/reports, never Backend/reporting/reports (which is not writable
    # by the API container and is inside the code tree).
    gen = WebScanReportGenerator()
    parent = os.path.basename(os.path.dirname(gen.output_dir))
    assert os.path.basename(gen.output_dir) == "reports"
    assert parent != "reporting"


def test_report_renders_sitemap_policy_and_proof_evidence(tmp_path):
    """Codex item 15: the report surfaces the site map, scan policy, scheduler
    plan and per-finding proof evidence (confidence / tested-as / status)."""
    import reportlab.rl_config

    reportlab.rl_config.pageCompression = 0  # so text is greppable in the PDF
    try:
        scan = _scan()
        scan.update(
            {
                "site_map": {
                    "endpoints": 12,
                    "forms": 3,
                    "api_operations": {"rest": 5, "graphql": 1},
                },
                "scan_policy": {
                    "name": "deep",
                    "attack_cookies": True,
                    "attack_headers": True,
                    "attack_file_uploads": False,
                    "max_params_per_page": 25,
                    "sqlmap_level": 3,
                },
                "schedule": {
                    "total_tasks": 40,
                    "passive_tasks": 16,
                    "active_tasks": 24,
                },
                "auth_status": "form_login",
            }
        )
        findings = [
            {
                "severity": "high",
                "finding_type": "sqli",
                "title": "SQL Injection",
                "description": "boom",
                "matched_at": "http://target.invalid/x",
                "confidence": "high",
                "auth_context": "form_login",
                "status": "confirmed",
                "screenshot_path": "/e/xss_abc.png",
            }
        ]
        gen = WebScanReportGenerator(output_dir=str(tmp_path))
        path = gen.generate(scan, findings, [])
        raw = open(path, "rb").read()
        for token in (b"Site Map", b"Scan Policy", b"deep", b"form_login"):
            assert token in raw, token
    finally:
        reportlab.rl_config.pageCompression = 1
