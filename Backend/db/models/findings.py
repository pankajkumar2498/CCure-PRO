"""
db/models/findings.py
──────────────────────────────────────────────────────────────────────────────
Normalized vulnerability and service findings.

Tables
──────
  services               — One row per (scan × asset × port × protocol)
  tls_details            — One row per TLS-enabled service (1:1 with services)
  http_security_details  — One row per HTTP service (1:1 with services)
  vulnerability_definitions — The CVE / vulnerability catalog
  asset_vulnerabilities  — One row per (scan × asset × cve) — the "finding"

ID Convention (Stripe-Style)
─────────────────────────────
  Service         →  svc_{asset_id}_{port}_{proto}
                     e.g.  svc_ast_defa_1a2b3c4d_192_168_1_5_22_tcp
                     Reading it: "TCP port 22 on the asset with id ast_defa_1a2b3c4d_192_168_1_5"

  TLSDetail /
  HttpDetail      →  BigInteger (1:1 with service, no need for its own readable ID)

  VulnDefinition  →  CVE-2024-4577  (already readable — kept as-is)

  AssetVuln       →  fnd_{asset_id}_{vuln_id}
                     e.g.  fnd_ast_def_192.168.1.5_CVE-2024-4577
                     Reading it: "Finding: CVE-2024-4577 on host 192.168.1.5"
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

# ─────────────────────────────────────────────────────────────────────────────
# Service  (open port + service fingerprint)
# ─────────────────────────────────────────────────────────────────────────────


class Service(Base):
    """
    A single open port/service found on an asset during a scan.

    ID: svc_{ip}_{port}_{protocol}
        e.g. svc_192.168.1.5_22_tcp
        Reading: "TCP/22 on host 192.168.1.5"
    """

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "asset_id",
            "port",
            "protocol",
            name="uq_services_scan_asset_port_proto",
        ),
        Index("ix_services_asset_port", "asset_id", "port"),
        Index("ix_services_scan_asset", "scan_id", "asset_id"),
        Index("ix_services_service_name", "service_name"),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_service_port"),
    )

    # Stripe-style readable ID: "svc_192.168.1.5_22_tcp"
    id = Column(String(200), primary_key=True)
    scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Port Details ──────────────────────────────────────────────────────────
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, default="tcp")
    state = Column(String(20), nullable=False, default="open")

    # ── Service Identification (from nmap -sV) ────────────────────────────────
    service_name = Column(String(100), nullable=True)
    service_product = Column(String(255), nullable=True)
    service_version = Column(String(255), nullable=True)
    service_extra = Column(String(512), nullable=True)
    banner = Column(Text, nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    scan = relationship("Scan", back_populates="services")
    asset = relationship("Asset", back_populates="services")
    tls_detail = relationship(
        "TLSDetail",
        back_populates="service",
        uselist=False,
        cascade="all, delete-orphan",
    )
    http_detail = relationship(
        "HttpSecurityDetail",
        back_populates="service",
        uselist=False,
        cascade="all, delete-orphan",
    )
    vulnerabilities = relationship("AssetVulnerability", back_populates="service")

    def __repr__(self):
        return f"<Service {self.id!r} state={self.state!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# TLS Details (1:1 with Service)
# ─────────────────────────────────────────────────────────────────────────────


class TLSDetail(Base):
    """Full TLS/SSL assessment for a specific service port."""

    __tablename__ = "tls_details"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    service_id = Column(
        String(200),
        ForeignKey("services.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        unique=True,
    )

    is_enabled = Column(Boolean, nullable=False, default=False)
    protocol_version = Column(String(20), nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    key_bits = Column(Integer, nullable=True)

    cert_subject = Column(JSONB, nullable=True)
    cert_issuer = Column(JSONB, nullable=True)
    cert_serial = Column(String(128), nullable=True)
    cert_not_before = Column(TIMESTAMPTZ, nullable=True)
    cert_not_after = Column(TIMESTAMPTZ, nullable=True)
    cert_is_expired = Column(Boolean, nullable=True)
    cert_is_self_signed = Column(Boolean, nullable=True)
    cert_san_domains = Column(JSONB, nullable=False, default=list)
    cert_fingerprint_sha256 = Column(String(95), nullable=True)

    grade = Column(String(5), nullable=True)
    is_weak_cipher = Column(Boolean, nullable=False, default=False)
    issues = Column(JSONB, nullable=False, default=list)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    service = relationship("Service", back_populates="tls_detail")

    def __repr__(self):
        return f"<TLSDetail service={self.service_id!r} grade={self.grade!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Security Details (1:1 with Service)
# ─────────────────────────────────────────────────────────────────────────────


class HttpSecurityDetail(Base):
    """HTTP security header assessment for a web-facing service port."""

    __tablename__ = "http_security_details"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    service_id = Column(
        String(200),
        ForeignKey("services.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        unique=True,
    )

    status_code = Column(Integer, nullable=True)
    server_header = Column(String(255), nullable=True)
    content_type = Column(String(255), nullable=True)

    has_hsts = Column(Boolean, nullable=False, default=False)
    hsts_max_age = Column(Integer, nullable=True)
    has_csp = Column(Boolean, nullable=False, default=False)
    csp_value = Column(Text, nullable=True)
    x_frame_options = Column(String(100), nullable=True)
    x_content_type = Column(Boolean, nullable=False, default=False)
    x_xss_protection = Column(String(100), nullable=True)
    referrer_policy = Column(String(100), nullable=True)
    permissions_policy = Column(Text, nullable=True)

    redirects_to_https = Column(Boolean, nullable=False, default=False)
    missing_headers = Column(JSONB, nullable=False, default=list)
    security_score = Column(SmallInteger, nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    service = relationship("Service", back_populates="http_detail")

    def __repr__(self):
        return f"<HttpSecurityDetail service={self.service_id!r} score={self.security_score}>"


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Definitions  (CVE Catalog)
# ─────────────────────────────────────────────────────────────────────────────


class VulnerabilityDefinition(Base):
    """
    The canonical vulnerability catalog — one row per unique CVE/vulnerability ID.
    ID is already human-readable: "CVE-2024-4577" or "CCURE-CUSTOM-001".
    No change needed here.
    """

    __tablename__ = "vulnerability_definitions"
    __table_args__ = (
        Index("ix_vuln_def_severity", "severity"),
        Index("ix_vuln_def_cvss_v3", "cvss_v3_score"),
        Index("ix_vuln_def_published", "published_at"),
        Index("ix_vuln_def_source", "source"),
        # Trigram index for fast partial vulnerability title search
        Index(
            "idx_vuln_def_title_trgm",
            "title",
            postgresql_using="gin",
            postgresql_ops={"title": "gin_trgm_ops"},
        ),
        # Integrity constraint for CVSS scores
        CheckConstraint(
            "cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0", name="ck_vuln_cvss_score"
        ),
    )

    id = Column(String(30), primary_key=True)  # "CVE-2024-4577" — already readable!
    cve_id = Column(String(30), unique=True, nullable=True, index=True)
    cwe_ids = Column(JSONB, nullable=False, default=list)

    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)

    cvss_v2_score = Column(Numeric(3, 1), nullable=True)
    cvss_v3_score = Column(Numeric(3, 1), nullable=True)
    cvss_v4_score = Column(Numeric(3, 1), nullable=True)
    cvss_vector = Column(String(255), nullable=True)

    severity = Column(String(20), nullable=False, default="info", index=True)

    published_at = Column(Date, nullable=True)
    last_modified_at = Column(Date, nullable=True)

    references = Column(JSONB, nullable=False, default=list)
    affected_software = Column(JSONB, nullable=False, default=list)

    source = Column(String(50), nullable=False, default="nvd")
    is_custom = Column(Boolean, nullable=False, default=False)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    asset_findings = relationship("AssetVulnerability", back_populates="vulnerability")

    def __repr__(self):
        return f"<VulnDef {self.id!r} severity={self.severity!r} cvss={self.cvss_v3_score}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Vulnerability  (the "Finding")
# ─────────────────────────────────────────────────────────────────────────────


class AssetVulnerability(Base):
    """
    A specific vulnerability found on a specific asset during a specific scan.

    ID: fnd_{asset_id}_{vuln_id}
        e.g. fnd_ast_def_192.168.1.5_CVE-2024-4577
        Reading: "Finding: CVE-2024-4577 detected on host 192.168.1.5 (default org)"
    """

    __tablename__ = "asset_vulnerabilities"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "scan_id",
            "asset_id",
            "vuln_id",
            name="uq_asset_vuln_scan_asset_cve",
        ),
        Index("ix_asset_vuln_asset_id", "asset_id"),
        Index("ix_asset_vuln_vuln_id", "vuln_id"),
        Index("ix_asset_vuln_severity", "severity"),
        Index("ix_asset_vuln_status", "status"),
        Index("ix_asset_vuln_source_family", "source_family"),
        Index("ix_asset_vuln_evidence_source", "evidence_source"),
        Index("ix_asset_vuln_first_found", "first_found_at"),
        # {"postgresql_partition_by": "HASH (org_id)"}
    )

    # Stripe-style readable ID: "fnd_ast_def_192.168.1.5_CVE-2024-4577"
    id = Column(String(350), primary_key=True)
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
        index=True,
    )

    scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    vuln_id = Column(
        String(30),
        ForeignKey("vulnerability_definitions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    service_id = Column(
        String(200),
        ForeignKey("services.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    severity = Column(String(20), nullable=True)
    cvss_score = Column(Numeric(3, 1), nullable=True)

    status = Column(String(50), nullable=False, default="open", index=True)

    source_family = Column(String(50), nullable=False, default="unknown")
    evidence_source = Column(String(50), nullable=False, default="unknown")

    proof = Column(Text, nullable=True)
    plugin_output = Column(Text, nullable=True)

    remediation_notes = Column(Text, nullable=True)
    fixed_at = Column(TIMESTAMPTZ, nullable=True)
    accepted_risk_reason = Column(Text, nullable=True)
    accepted_by = Column(
        String(150),
        ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    first_found_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_found_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")
    asset = relationship("Asset", back_populates="vulnerabilities")
    vulnerability = relationship(
        "VulnerabilityDefinition", back_populates="asset_findings"
    )
    service = relationship("Service", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<AssetVuln {self.id!r} status={self.status!r}>"
