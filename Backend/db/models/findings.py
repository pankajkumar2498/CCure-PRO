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

Why normalize findings?
────────────────────────
  With the old JSON-blob approach you CANNOT do:
    SELECT * FROM findings WHERE cve_id = 'CVE-2024-4577'
    SELECT count(*) FROM findings WHERE severity = 'critical' AND status = 'open'

  With this normalized schema you CAN do all of the above instantly,
  even across millions of rows, because PostgreSQL can use indexes.

  This is how Nessus, Qualys, and Rapid7 work internally.
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, Date, Numeric, ForeignKey,
    Integer, SmallInteger, String, Text, UniqueConstraint, Index, CheckConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Service  (open port + service fingerprint)
# ─────────────────────────────────────────────────────────────────────────────

class Service(Base):
    """
    A single open port/service found on an asset during a scan.

    One row per (scan_id × asset_id × port × protocol).
    For the same physical port observed in multiple scans, there will be
    multiple rows — this is intentional, as it allows change-over-time tracking.

    Relationship to TLS / HTTP:
      If the service supports TLS → one TLSDetail row links back here.
      If the service is HTTP/HTTPS → one HttpSecurityDetail row links back here.

    state  — 'open' | 'closed' | 'filtered'
    protocol — 'tcp' | 'udp' | 'sctp'
    """
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", "port", "protocol",
                         name="uq_services_scan_asset_port_proto"),
        Index("ix_services_asset_port",  "asset_id", "port"),
        Index("ix_services_scan_asset",  "scan_id",  "asset_id"),
        Index("ix_services_service_name","service_name"),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_service_port"),
    )

    id              = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id         = Column(UUID(as_uuid=True), ForeignKey("scans.id",   ondelete="CASCADE"),
                             nullable=False, index=True)
    asset_id        = Column(UUID(as_uuid=True), ForeignKey("assets.id",  ondelete="CASCADE"),
                             nullable=False, index=True)

    # ── Port Details ──────────────────────────────────────────────────────────
    port            = Column(Integer,     nullable=False)
    protocol        = Column(String(10),  nullable=False, default="tcp")   # tcp | udp | sctp
    state           = Column(String(20),  nullable=False, default="open")  # open|closed|filtered

    # ── Service Identification (from nmap -sV) ────────────────────────────────
    service_name    = Column(String(100), nullable=True)   # "http", "ssh", "smb"
    service_product = Column(String(255), nullable=True)   # "Apache httpd"
    service_version = Column(String(255), nullable=True)   # "2.4.55"
    service_extra   = Column(String(512), nullable=True)   # Extra nmap banner info
    banner          = Column(Text,        nullable=True)   # Raw banner grab

    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    scan            = relationship("Scan",  back_populates="services")
    asset           = relationship("Asset", back_populates="services")
    tls_detail      = relationship("TLSDetail",         back_populates="service",
                                   uselist=False, cascade="all, delete-orphan")
    http_detail     = relationship("HttpSecurityDetail", back_populates="service",
                                   uselist=False, cascade="all, delete-orphan")
    vulnerabilities = relationship("AssetVulnerability", back_populates="service")

    def __repr__(self):
        return f"<Service {self.protocol}/{self.port} {self.service_name!r} asset={self.asset_id}>"


# ─────────────────────────────────────────────────────────────────────────────
# TLS Details (1:1 with Service)
# ─────────────────────────────────────────────────────────────────────────────

class TLSDetail(Base):
    """
    Full TLS/SSL assessment for a specific service port.

    grade follows Qualys SSL Labs convention:
      A+ (perfect) | A | B | C | D | T (cert trust issue) | F (fatal) | N (no TLS)

    issues JSONB examples:
      ["BEAST", "POODLE", "weak_cipher:RC4", "expired_cert", "self_signed"]

    cert_san_domains — Subject Alternative Names:
      ["example.com", "*.example.com", "mail.example.com"]
    """
    __tablename__ = "tls_details"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    service_id      = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="CASCADE"),
                             nullable=False, unique=True)

    is_enabled      = Column(Boolean, nullable=False, default=False)
    protocol_version = Column(String(20), nullable=True)   # "TLSv1.3", "TLSv1.2"
    cipher_suite    = Column(String(255), nullable=True)   # "ECDHE-RSA-AES256-GCM-SHA384"
    key_bits        = Column(Integer,     nullable=True)   # 2048, 4096

    # ── Certificate ───────────────────────────────────────────────────────────
    cert_subject    = Column(JSONB,  nullable=True)   # {"CN": "example.com", "O": "ACME Corp"}
    cert_issuer     = Column(JSONB,  nullable=True)   # {"CN": "Let's Encrypt", "O": "ISRG"}
    cert_serial     = Column(String(128), nullable=True)
    cert_not_before = Column(TIMESTAMPTZ, nullable=True)
    cert_not_after  = Column(TIMESTAMPTZ, nullable=True)
    cert_is_expired      = Column(Boolean, nullable=True)
    cert_is_self_signed  = Column(Boolean, nullable=True)
    cert_san_domains     = Column(JSONB,   nullable=False, default=list)
    cert_fingerprint_sha256 = Column(String(95), nullable=True)  # "AA:BB:CC:..."

    # ── Assessment ────────────────────────────────────────────────────────────
    grade           = Column(String(5),  nullable=True)    # A+ | A | B | C | D | T | F
    is_weak_cipher  = Column(Boolean,    nullable=False, default=False)
    issues          = Column(JSONB,      nullable=False, default=list)  # list of issue strings

    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    service = relationship("Service", back_populates="tls_detail")

    def __repr__(self):
        return f"<TLSDetail service={self.service_id} grade={self.grade!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Security Details (1:1 with Service)
# ─────────────────────────────────────────────────────────────────────────────

class HttpSecurityDetail(Base):
    """
    HTTP security header assessment for a web-facing service port.

    Captures what Tenable / OWASP ZAP call "passive web checks" —
    validating that security headers are present and correctly configured.

    missing_headers JSONB examples:
      ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]

    security_score — 0-100 composite score based on how many best-practice
                     headers are correctly configured.
    """
    __tablename__ = "http_security_details"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    service_id      = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="CASCADE"),
                             nullable=False, unique=True)

    status_code     = Column(Integer,     nullable=True)
    server_header   = Column(String(255), nullable=True)
    content_type    = Column(String(255), nullable=True)

    # ── Security Headers ─────────────────────────────────────────────────────
    has_hsts        = Column(Boolean,  nullable=False, default=False)
    hsts_max_age    = Column(Integer,  nullable=True)
    has_csp         = Column(Boolean,  nullable=False, default=False)
    csp_value       = Column(Text,     nullable=True)
    x_frame_options = Column(String(100), nullable=True)    # "DENY" | "SAMEORIGIN"
    x_content_type  = Column(Boolean,  nullable=False, default=False)
    x_xss_protection = Column(String(100), nullable=True)
    referrer_policy = Column(String(100), nullable=True)
    permissions_policy = Column(Text,  nullable=True)

    redirects_to_https = Column(Boolean, nullable=False, default=False)

    missing_headers = Column(JSONB,        nullable=False, default=list)
    security_score  = Column(SmallInteger, nullable=True)   # 0-100

    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    service = relationship("Service", back_populates="http_detail")

    def __repr__(self):
        return f"<HttpSecurityDetail service={self.service_id} score={self.security_score}>"


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Definitions  (CVE Catalog)
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityDefinition(Base):
    """
    The canonical vulnerability catalog — one row per unique CVE/vulnerability ID.

    This table is the "dictionary" of known vulnerabilities.
    Think of it as a local mirror of NVD (National Vulnerability Database).

    Populated by:
      a) The existing cves.db SQLite side-database (migrate-in)
      b) Live NVD API sync (future)
      c) Custom vulnerability rules defined by the user

    cvss_v3_score — Use this as the primary severity indicator.
    cvss_v2_score — Kept for legacy compatibility.
    cvss_v4_score — Populated when available (NVD newer data).

    references JSONB:
      [{"url": "https://nvd.nist.gov/...", "source": "NVD"},
       {"url": "https://github.com/...", "source": "GitHub"}]

    affected_software JSONB (CPE list):
      [{"cpe": "cpe:2.3:a:php:php:8.1.0:*:...", "version_range": "<8.1.25"}]
    """
    __tablename__ = "vulnerability_definitions"
    __table_args__ = (
        Index("ix_vuln_def_severity",      "severity"),
        Index("ix_vuln_def_cvss_v3",       "cvss_v3_score"),
        Index("ix_vuln_def_published",     "published_at"),
        Index("ix_vuln_def_source",        "source"),
        
        # Trigram index for fast partial vulnerability title search
        Index("idx_vuln_def_title_trgm", "title", postgresql_using="gin",
              postgresql_ops={"title": "gin_trgm_ops"}),
        
        # Integrity constraint for CVSS scores
        CheckConstraint("cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0", 
                        name="ck_vuln_cvss_score"),
    )

    id           = Column(String(30), primary_key=True)   # "CVE-2024-4577" or "CCURE-CUSTOM-001"
    cve_id       = Column(String(30), unique=True, nullable=True, index=True)  # official CVE ID
    cwe_ids      = Column(JSONB, nullable=False, default=list)  # ["CWE-78", "CWE-94"]

    title       = Column(String(512), nullable=False)
    description = Column(Text,        nullable=True)

    # ── CVSS Scores ───────────────────────────────────────────────────────────
    cvss_v2_score = Column(Numeric(3, 1), nullable=True)
    cvss_v3_score = Column(Numeric(3, 1), nullable=True)
    cvss_v4_score = Column(Numeric(3, 1), nullable=True)
    cvss_vector   = Column(String(255),   nullable=True)

    severity      = Column(String(20), nullable=False, default="info", index=True)
    # critical | high | medium | low | info

    published_at     = Column(Date, nullable=True)
    last_modified_at = Column(Date, nullable=True)

    references        = Column(JSONB, nullable=False, default=list)
    affected_software = Column(JSONB, nullable=False, default=list)

    source  = Column(String(50), nullable=False, default="nvd")   # nvd | mitre | custom
    is_custom = Column(Boolean,  nullable=False, default=False)   # User-added definition

    created_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    asset_findings = relationship("AssetVulnerability", back_populates="vulnerability")

    def __repr__(self):
        return f"<VulnDef {self.id!r} severity={self.severity!r} cvss={self.cvss_v3_score}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Vulnerability  (the "Finding")
# ─────────────────────────────────────────────────────────────────────────────

class AssetVulnerability(Base):
    """
    A specific vulnerability found on a specific asset during a specific scan.

    This is the core "finding" record — equivalent to a Nessus plugin result
    or a Qualys QID detection.

    One row per (scan_id × asset_id × vuln_id):
      - Each new scan that finds the same CVE creates a NEW row
      - This allows tracking "how long has this been open?" via first_found_at
      - And "was it fixed and then re-introduced?" via status history

    status lifecycle
    ────────────────
      open       — Currently detected, not yet remediated
      fixed      — Present in a previous scan, absent in the latest scan
      accepted   — Risk formally accepted by authorized user (with reason)
      suppressed — Filtered from reports (known false positive)

    severity / cvss_score
    ──────────────────────
      These OVERRIDE the definition-level scores when context matters.
      Example: CVE-2024-4577 is "Critical" in general, but if this host has
      a WAF rule blocking exploitation, the analyst may downgrade it to "Medium".

    proof / plugin_output
    ──────────────────────
      Evidence collected during the scan:
        proof:         "Port 9200 responded to unauthenticated API call"
        plugin_output: Full raw nmap/banner output
    """
    __tablename__ = "asset_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", "vuln_id",
                         name="uq_asset_vuln_scan_asset_cve"),
        Index("ix_asset_vuln_asset_id",  "asset_id"),
        Index("ix_asset_vuln_vuln_id",   "vuln_id"),
        Index("ix_asset_vuln_severity",  "severity"),
        Index("ix_asset_vuln_status",    "status"),
        Index("ix_asset_vuln_first_found","first_found_at"),
        # Enable Hash Partitioning by org_id
        {"postgresql_partition_by": "HASH (org_id)"}
    )

    # Primary key must include the partition key in PostgreSQL partitioned tables
    id          = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    org_id      = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
                         primary_key=True, index=True)
    
    scan_id     = Column(UUID(as_uuid=True), ForeignKey("scans.id",   ondelete="CASCADE"),
                         nullable=False, index=True)
    asset_id    = Column(UUID(as_uuid=True), ForeignKey("assets.id",  ondelete="CASCADE"),
                         nullable=False, index=True)
    vuln_id     = Column(String(30),         ForeignKey("vulnerability_definitions.id", ondelete="RESTRICT"),
                         nullable=False, index=True)
    service_id  = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"),
                         nullable=True)   # Which specific port is vulnerable

    # ── Override severity (per-finding context) ───────────────────────────────
    severity    = Column(String(20),    nullable=True)     # Overrides definition severity
    cvss_score  = Column(Numeric(3, 1), nullable=True)     # Overrides definition score

    # ── Status & Lifecycle ────────────────────────────────────────────────────
    status      = Column(String(50), nullable=False, default="open", index=True)
    # open | fixed | accepted | suppressed

    # ── Evidence ─────────────────────────────────────────────────────────────
    proof           = Column(Text, nullable=True)      # Human-readable proof
    plugin_output   = Column(Text, nullable=True)      # Raw scanner output

    # ── Remediation Tracking ─────────────────────────────────────────────────
    remediation_notes    = Column(Text,        nullable=True)
    fixed_at             = Column(TIMESTAMPTZ, nullable=True)
    accepted_risk_reason = Column(Text,        nullable=True)
    accepted_by          = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                                  nullable=True)

    # ── Lifecycle Timestamps ──────────────────────────────────────────────────
    first_found_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_found_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    created_at     = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    scan           = relationship("Scan",                  back_populates="vulnerabilities")
    asset          = relationship("Asset",                 back_populates="vulnerabilities")
    vulnerability  = relationship("VulnerabilityDefinition", back_populates="asset_findings")
    service        = relationship("Service",               back_populates="vulnerabilities")

    def __repr__(self):
        return f"<AssetVuln vuln={self.vuln_id!r} asset={self.asset_id} status={self.status!r}>"
