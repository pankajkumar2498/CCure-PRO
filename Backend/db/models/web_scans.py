"""
db/models/web_scans.py
──────────────────────────────────────────────────────────────────────────────
Web Application Scanning models — DAST pipeline.

Tables
──────
  web_scans      — One row per web scan session (URL-based, not IP-based)
  web_assets     — Discovered web endpoints, API routes, forms
  web_findings   — Web-specific vulnerability findings with HTTP evidence

ID Convention (Stripe-Style)
─────────────────────────────
  WebScan    →  wsc_{org_token}_{ddmonyy}_{4rand}
                e.g.  wsc_defa_1a2b3c4d_24may26_x9v1

  WebAsset   →  was_{scan_short}_{url_hash_8}
                e.g.  was_wsc_defa_24may26_a1b2c3d4

  WebFinding →  wfn_{asset_short}_{type}_{4rand}
                e.g.  wfn_was_wsc_defa_xss_k8m2

Design Notes
────────────
  - WebScan is intentionally separate from the network Scan model.
    Web scans target URLs (not CIDRs), have different phase lifecycles,
    and require HTTP-specific evidence storage.
  - WebAsset represents a discovered endpoint (URL + method + params),
    NOT a network host. One domain may have hundreds of web assets.
  - WebFinding stores full HTTP request/response evidence for
    reproducibility — critical for DAST credibility.
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, Float, ForeignKey,
    Integer, SmallInteger, String, Text, UniqueConstraint, Index,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Web Scan  (scan session targeting a URL/domain)
# ─────────────────────────────────────────────────────────────────────────────

class WebScan(Base):
    """
    One web application scan session.

    ID: wsc_{org_token}_{ddmonyy}_{4rand}
        e.g. wsc_defa_1a2b3c4d_24may26_x9v1

    Pipeline phases:  recon → crawl → detect → audit
    Status lifecycle: queued → running → complete | failed | cancelled
    """
    __tablename__ = "web_scans"
    __table_args__ = (
        Index("ix_web_scans_org_status",    "org_id", "status"),
        Index("ix_web_scans_org_created",   "org_id", "created_at"),
        Index("ix_web_scans_domain",        "target_domain"),
        Index("ix_web_scans_is_deleted",    "is_deleted"),
        Index("idx_web_scans_options_gin",  "options", postgresql_using="gin"),
        Index("idx_web_scans_tech_gin",     "tech_stack", postgresql_using="gin"),
    )

    # Stripe-style readable ID
    id              = Column(String(100), primary_key=True)

    org_id          = Column(String(100), ForeignKey("organizations.id",
                             ondelete="CASCADE", onupdate="CASCADE"),
                             nullable=False, index=True)
    created_by      = Column(String(150), ForeignKey("users.id",
                             ondelete="SET NULL", onupdate="CASCADE"),
                             nullable=True, index=True)

    # ── Target Definition ─────────────────────────────────────────────────────
    scan_name       = Column(String(255), nullable=True)
    target_url      = Column(Text,        nullable=False)
    target_domain   = Column(String(512), nullable=False)

    # Scan scope: include/exclude URL patterns, max depth, etc.
    scan_scope      = Column(JSONB, nullable=False, default=dict)

    # Authentication configuration (references, NOT raw credentials)
    # Example: {"type": "form_login", "login_url": "...", "credential_ref": "vault:xxx"}
    auth_config     = Column(JSONB, nullable=False, default=dict)

    # ── Scan Configuration ────────────────────────────────────────────────────
    options         = Column(JSONB, nullable=False, default=dict)
    rate_limit      = Column(Integer, nullable=False, default=10)

    # ── Discovery Results ─────────────────────────────────────────────────────
    waf_detected    = Column(String(100), nullable=True)   # Cloudflare, Imperva, etc.
    tech_stack      = Column(JSONB, nullable=False, default=list)  # [{name, version, category}]
    subdomains      = Column(JSONB, nullable=False, default=list)  # ["sub1.example.com", ...]

    # ── Pipeline State ────────────────────────────────────────────────────────
    status          = Column(String(50), nullable=False, default="queued", index=True)
    pipeline_phase  = Column(String(50), nullable=False, default="queued")
    failure_reason  = Column(Text, nullable=True)
    current_task_id = Column(String(100), nullable=True)

    # Authorization confirmation — REQUIRED before scan starts
    authorization_confirmed = Column(Boolean, nullable=False, default=False)

    # ── Phase Status Tracking ─────────────────────────────────────────────────
    recon_status    = Column(String(50), nullable=False, default="pending")
    crawl_status    = Column(String(50), nullable=False, default="pending")
    detect_status   = Column(String(50), nullable=False, default="pending")
    audit_status    = Column(String(50), nullable=False, default="pending")

    # ── Timing ────────────────────────────────────────────────────────────────
    queued_at        = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    started_at       = Column(TIMESTAMPTZ, nullable=True)
    completed_at     = Column(TIMESTAMPTZ, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Phase timing
    recon_started_at    = Column(TIMESTAMPTZ, nullable=True)
    recon_completed_at  = Column(TIMESTAMPTZ, nullable=True)
    crawl_started_at    = Column(TIMESTAMPTZ, nullable=True)
    crawl_completed_at  = Column(TIMESTAMPTZ, nullable=True)
    detect_started_at   = Column(TIMESTAMPTZ, nullable=True)
    detect_completed_at = Column(TIMESTAMPTZ, nullable=True)
    audit_started_at    = Column(TIMESTAMPTZ, nullable=True)
    audit_completed_at  = Column(TIMESTAMPTZ, nullable=True)

    # ── Aggregate Stats ───────────────────────────────────────────────────────
    total_endpoints  = Column(Integer, nullable=False, default=0)
    total_findings   = Column(Integer, nullable=False, default=0)
    critical_count   = Column(Integer, nullable=False, default=0)
    high_count       = Column(Integer, nullable=False, default=0)
    medium_count     = Column(Integer, nullable=False, default=0)
    low_count        = Column(Integer, nullable=False, default=0)
    info_count       = Column(Integer, nullable=False, default=0)

    # ── Report Artifacts ──────────────────────────────────────────────────────
    report_pdf_path  = Column(String(512), nullable=True)
    report_json_path = Column(String(512), nullable=True)

    # ── Soft Delete / Archive ─────────────────────────────────────────────────
    is_archived  = Column(Boolean, nullable=False, default=False)
    archived_at  = Column(TIMESTAMPTZ, nullable=True)
    is_deleted   = Column(Boolean, nullable=False, default=False)
    deleted_at   = Column(TIMESTAMPTZ, nullable=True)

    created_at   = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at   = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization    = relationship("Organization", backref="web_scans")
    created_by_user = relationship("User",         backref="web_scans",
                                   foreign_keys=[created_by])
    web_assets      = relationship("WebAsset",     back_populates="web_scan",
                                   cascade="all, delete-orphan",
                                   order_by="WebAsset.created_at.asc()")
    web_findings    = relationship("WebFinding",   back_populates="web_scan",
                                   cascade="all, delete-orphan")

    def __repr__(self):
        return f"<WebScan {self.id!r} domain={self.target_domain!r} status={self.status!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Web Asset  (discovered endpoint / URL)
# ─────────────────────────────────────────────────────────────────────────────

class WebAsset(Base):
    """
    A discovered web endpoint — URL + HTTP method + parameters.

    ID: was_{scan_short}_{url_hash_8}
        e.g. was_wsc_defa_24may26_a1b2c3d4

    One WebScan may discover hundreds or thousands of WebAssets.
    """
    __tablename__ = "web_assets"
    __table_args__ = (
        UniqueConstraint("web_scan_id", "url", "method",
                         name="uq_web_assets_scan_url_method"),
        Index("ix_web_assets_scan_id",   "web_scan_id"),
        Index("ix_web_assets_source",    "source"),
        Index("ix_web_assets_auth_req",  "auth_required"),
        Index("idx_web_assets_params_gin", "parameters", postgresql_using="gin"),
        Index("idx_web_assets_tech_gin",   "technology", postgresql_using="gin"),
    )

    id            = Column(String(250), primary_key=True)
    web_scan_id   = Column(String(100), ForeignKey("web_scans.id",
                           ondelete="CASCADE", onupdate="CASCADE"),
                           nullable=False, index=True)

    # ── Endpoint Identity ─────────────────────────────────────────────────────
    url           = Column(Text,        nullable=False)
    method        = Column(String(10),  nullable=False, default="GET")
    content_type  = Column(String(255), nullable=True)
    response_code = Column(SmallInteger, nullable=True)

    # ── Parameters (query params, body params, path params) ───────────────────
    # Example: {"query": ["id", "page"], "body": ["username", "password"],
    #           "headers": ["Authorization"]}
    parameters    = Column(JSONB, nullable=False, default=dict)

    # ── Classification ────────────────────────────────────────────────────────
    auth_required = Column(Boolean,    nullable=False, default=False)
    is_api        = Column(Boolean,    nullable=False, default=False)
    is_form       = Column(Boolean,    nullable=False, default=False)
    has_file_upload = Column(Boolean,  nullable=False, default=False)

    # Technology detected on this endpoint
    # Example: [{"name": "React", "version": "18.2", "category": "framework"}]
    technology    = Column(JSONB, nullable=False, default=list)

    # How was this endpoint discovered?
    source        = Column(String(50), nullable=False, default="crawler")
    # Values: crawler, js_parse, ffuf, swagger, sitemap, robots_txt, manual

    # ── Response Metadata ─────────────────────────────────────────────────────
    response_size   = Column(Integer, nullable=True)   # bytes
    response_time   = Column(Float,   nullable=True)   # seconds
    response_headers = Column(JSONB,  nullable=False, default=dict)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    web_scan     = relationship("WebScan",    back_populates="web_assets")
    web_findings = relationship("WebFinding", back_populates="web_asset",
                                cascade="all, delete-orphan")

    def __repr__(self):
        return f"<WebAsset {self.id!r} {self.method} {self.url[:60]}>"


# ─────────────────────────────────────────────────────────────────────────────
# Web Finding  (vulnerability with HTTP evidence)
# ─────────────────────────────────────────────────────────────────────────────

class WebFinding(Base):
    """
    A web application vulnerability found during DAST scanning.

    ID: wfn_{asset_short}_{type}_{4rand}
        e.g. wfn_was_wsc_defa_xss_k8m2

    Stores full HTTP request/response evidence for reproducibility.
    Maps to OWASP Top 10 and compliance frameworks.
    """
    __tablename__ = "web_findings"
    __table_args__ = (
        Index("ix_web_findings_scan_id",     "web_scan_id"),
        Index("ix_web_findings_asset_id",    "web_asset_id"),
        Index("ix_web_findings_severity",    "severity"),
        Index("ix_web_findings_type",        "finding_type"),
        Index("ix_web_findings_status",      "status"),
        Index("ix_web_findings_owasp",       "owasp_category"),
        Index("ix_web_findings_template",    "template_id"),
        Index("ix_web_findings_tool",        "detected_by"),
        Index("idx_web_findings_tags_gin",   "compliance_tags", postgresql_using="gin"),
        CheckConstraint(
            "cvss_score >= 0.0 AND cvss_score <= 10.0",
            name="ck_web_finding_cvss_score",
        ),
    )

    id             = Column(String(350), primary_key=True)
    web_scan_id    = Column(String(100), ForeignKey("web_scans.id",
                            ondelete="CASCADE", onupdate="CASCADE"),
                            nullable=False)
    web_asset_id   = Column(String(250), ForeignKey("web_assets.id",
                            ondelete="CASCADE", onupdate="CASCADE"),
                            nullable=True)
    org_id         = Column(String(100), ForeignKey("organizations.id",
                            ondelete="CASCADE", onupdate="CASCADE"),
                            nullable=False, index=True)

    # ── Vulnerability Classification ──────────────────────────────────────────
    finding_type   = Column(String(50), nullable=False)
    # Values: xss, sqli, ssrf, misconfig, exposed_panel, default_creds,
    #         tls_issue, cors, cve, open_redirect, file_inclusion, xxe,
    #         information_disclosure, csrf, idor, command_injection,
    #         path_traversal, header_injection, technology_detected

    title          = Column(String(512), nullable=False)
    description    = Column(Text,        nullable=True)

    severity       = Column(String(20),    nullable=False, default="info")
    cvss_score     = Column(Float,         nullable=True)
    cvss_vector    = Column(String(255),   nullable=True)

    # ── Detection Metadata ────────────────────────────────────────────────────
    detected_by    = Column(String(50), nullable=False, default="nuclei")
    # Values: nuclei, sqlmap, playwright, sslyze, ffuf, custom, crawler

    template_id    = Column(String(255), nullable=True)   # Nuclei template ID
    matched_at     = Column(Text,        nullable=True)   # URL where matched

    # ── HTTP Evidence (critical for DAST credibility) ─────────────────────────
    request_method   = Column(String(10),  nullable=True)
    request_url      = Column(Text,        nullable=True)
    request_headers  = Column(Text,        nullable=True)
    request_body     = Column(Text,        nullable=True)
    response_code    = Column(SmallInteger, nullable=True)
    response_headers = Column(Text,        nullable=True)
    response_body    = Column(Text,        nullable=True)  # truncated to 10KB
    payload_used     = Column(Text,        nullable=True)  # injection payload

    # ── Compliance Mapping ────────────────────────────────────────────────────
    owasp_category  = Column(String(100), nullable=True)
    # Example: "A03:2021 – Injection"

    compliance_tags = Column(JSONB, nullable=False, default=list)
    # Example: ["PCI-DSS-6.5.1", "SOC2-CC6.1", "OWASP-A03"]

    cve_id          = Column(String(30), nullable=True, index=True)

    # ── Status & Triage ───────────────────────────────────────────────────────
    status          = Column(String(50), nullable=False, default="open")
    # Values: open, confirmed, false_positive, accepted_risk, fixed, reopened

    is_verified     = Column(Boolean, nullable=False, default=False)
    # True if the tool confirmed exploitability (not just pattern match)

    false_positive_reason = Column(Text, nullable=True)
    accepted_risk_reason  = Column(Text, nullable=True)
    accepted_by           = Column(String(150), ForeignKey("users.id",
                                   ondelete="SET NULL", onupdate="CASCADE"),
                                   nullable=True)

    remediation_notes     = Column(Text, nullable=True)
    fixed_at              = Column(TIMESTAMPTZ, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    first_found_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_found_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    created_at     = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at     = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    web_scan     = relationship("WebScan",     back_populates="web_findings")
    web_asset    = relationship("WebAsset",    back_populates="web_findings")
    organization = relationship("Organization", backref="web_findings")

    def __repr__(self):
        return (
            f"<WebFinding {self.id!r} type={self.finding_type!r} "
            f"severity={self.severity!r} status={self.status!r}>"
        )
