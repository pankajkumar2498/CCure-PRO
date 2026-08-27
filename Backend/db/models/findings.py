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
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import relationship

# ─────────────────────────────────────────────────────────────────────────────
# Service  (open port + service fingerprint)
# ─────────────────────────────────────────────────────────────────────────────

#: How a service came to be recorded. The two sources answer different
#: questions and are not interchangeable: a port scan establishes that
#: something answered on the network, a credentialed audit establishes what the
#: host is actually running. Storing them without distinction made a
#: loopback-only listener indistinguishable from a network-confirmed open port.
SOURCE_NETWORK_SCAN = "network_scan"
SOURCE_CREDENTIALED = "credentialed"

#: Confirmed reachable from the scanner.
STATE_OPEN = "open"
#: Observed listening on the host; network reachability not established.
STATE_LISTENING = "listening"
#: Listening, but bound to loopback — provably not reachable off-box.
STATE_HOST_ONLY = "host_only"

#: A service that is running and may be reachable. Used wherever the question
#: is "what is this asset serving". Excludes host_only, because a loopback bind
#: is positive evidence of non-exposure rather than missing information.
OBSERVED_SERVICE_STATES = (STATE_OPEN, STATE_LISTENING)

#: A service confirmed reachable across the network. Used where the question is
#: specifically about exposure.
NETWORK_EXPOSED_STATES = (STATE_OPEN,)

#: The only severity ratings either severity column may hold, lowercase.
#:
#: ``scans.cvss.severity_from_score`` returns these title-cased and every write
#: path lowers them (``scans/asset_syncer.py`` is the sole writer of both
#: columns, at the catalog upsert and the finding upsert). "unscored" is
#: deliberately distinct from "none": the first means no score was published,
#: the second means a published score of 0.0.
SEVERITY_VALUES = ("critical", "high", "medium", "low", "none", "unscored")

#: Rendered exactly as migration z9e0f1g2h3i4 renders it, so the model and the
#: migration produce byte-identical CHECK constraints and autogenerate sees no
#: difference between a bootstrapped and an upgraded database.
SEVERITY_CANONICAL_SQL = "severity IN %s" % str(SEVERITY_VALUES)


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
    state = Column(String(20), nullable=False, default=STATE_OPEN)

    # ── Provenance ────────────────────────────────────────────────────────────
    # Which observation produced this row, and what each side could establish.
    # network_reachable is deliberately tri-state: NULL means nothing looked,
    # which is a different fact from False ("looked, not reachable") and must
    # never be collapsed into it.
    discovery_source = Column(
        String(30), nullable=False, default=SOURCE_NETWORK_SCAN, index=True
    )
    network_reachable = Column(Boolean, nullable=True)
    bind_scope = Column(String(24), nullable=True)
    credentialed_confirmed = Column(Boolean, nullable=False, default=False)

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
        return (
            f"<Service {self.id!r} state={self.state!r} "
            f"source={self.discovery_source!r}>"
        )


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


#: ``vulnerability_definitions.definition_type``. The catalogue holds two
#: kinds of row and conflating them is what forced every capability that finds
#: something without a CVE — a CIS control, a STIG rule, a weak service ACL, a
#: database account with no password policy — to grow its own findings table.
#:
#: Vocabulary and identifier minting live in ``core/checks/definitions.py``;
#: these constants are re-exported from there so the model and the CHECK
#: constraint cannot drift from the code that produces the values.
DEFINITION_TYPE_VALUES = (
    "cve",
    "config_check",
    "plugin_check",
    "privilege_check",
)

#: Rendered exactly as migration e1f2a3b4c5d6 renders it, so a bootstrapped and
#: an upgraded database produce byte-identical CHECK constraints and
#: autogenerate sees no difference between them. Same reasoning as
#: SEVERITY_CANONICAL_SQL above.
DEFINITION_TYPE_SQL = "definition_type IN %s" % str(DEFINITION_TYPE_VALUES)


class VulnerabilityDefinition(Base):
    """
    The canonical catalogue — one row per unique vulnerability or check.

    Two kinds of row, distinguished by ``definition_type``:

      * ``cve`` — a published vulnerability, keyed on its real CVE identifier
        and written by the vulnerability feeds. ``cve_id`` is set.
      * everything else — a check this product defines, keyed on a
        ``CCURE-``-prefixed identifier minted by
        ``core.checks.definitions.definition_id_for_check``. ``cve_id`` is
        NULL, because there is no CVE and inventing one would put a
        CVE-shaped string that NVD has never heard of in front of a customer.

    The distinction is enforced by ``ck_vuln_def_cve_id_matches_type`` rather
    than left to convention: a config check filed as a ``cve`` inherits CVE
    semantics — KEV lookups, EPSS scores, CVSS bands, "search this in NVD" —
    every one of which is meaningless for it.
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
        # Severity must be one of the six canonical lowercase ratings. Declared
        # here as well as in migration z9e0f1g2h3i4 — see SEVERITY_CANONICAL_SQL.
        CheckConstraint(SEVERITY_CANONICAL_SQL, name="ck_vuln_def_severity_canonical"),
        Index("ix_vuln_def_definition_type", "definition_type"),
        CheckConstraint(DEFINITION_TYPE_SQL, name="ck_vuln_def_definition_type"),
        # A CVE row carries a CVE id; a check row does not. Without this, a
        # check written with definition_type='cve' would be indistinguishable
        # from a real advisory everywhere downstream, and a real CVE written
        # with cve_id NULL would silently drop out of every join that reaches
        # the feeds through that column.
        CheckConstraint(
            "(definition_type = 'cve' AND cve_id IS NOT NULL) OR "
            "(definition_type <> 'cve' AND cve_id IS NULL)",
            name="ck_vuln_def_cve_id_matches_type",
        ),
        # Integrity constraint for CVSS scores
        CheckConstraint(
            "cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0", name="ck_vuln_cvss_score"
        ),
    )

    #: "CVE-2024-4577", or "CCURE-CFG-CIS-WIN2022-2-3-1-1" for a check.
    #: Widened from 30 by migration e1f2a3b4c5d6: a CVE never exceeds 20-odd
    #: characters, but a benchmark control identifier carries a framework, a
    #: platform and a dotted control number and does not fit.
    id = Column(String(120), primary_key=True)
    #: Deliberately left at 30 while ``id`` widened. Only a real CVE goes here,
    #: and a column too narrow to hold anything else is a structural reminder
    #: of that rather than a comment somebody has to read.
    cve_id = Column(String(30), unique=True, nullable=True, index=True)
    #: Deliberately carries no ``index=True``. The index is declared once, by
    #: name, in ``__table_args__`` above, matching migration e1f2a3b4c5d6. With
    #: both, a fresh install (which builds from ``Base.metadata``) would get two
    #: indexes on this column — SQLAlchemy's auto-named one and the migration's
    #: — while an upgraded install got only the migration's. Same trap the
    #: ``in_kev`` note in CLAUDE.md describes, approached from the other side.
    definition_type = Column(
        String(20), nullable=False, default="cve", server_default="cve"
    )
    cwe_ids = Column(JSONB, nullable=False, default=list)

    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)

    cvss_v2_score = Column(Numeric(3, 1), nullable=True)
    cvss_v3_score = Column(Numeric(3, 1), nullable=True)
    cvss_v4_score = Column(Numeric(3, 1), nullable=True)
    cvss_vector = Column(String(255), nullable=True)

    #: Which CVSS revision ``cvss_vector`` and the populated score column were
    #: published in. Without it a v2 score filed under ``cvss_v3_score`` is
    #: indistinguishable from a real v3 one, and the two revisions' band tables
    #: disagree above 9.0 — v2 has no Critical tier.
    cvss_version = Column(String(8), nullable=True)

    #: Always one of ``scans.cvss.CANONICAL_SEVERITIES`` (lower case). Enforced
    #: by ck_vuln_def_severity_canonical — two spellings of one severity split
    #: every GROUP BY in the product and silently dropped rows from the totals.
    severity = Column(String(20), nullable=False, default="unscored", index=True)

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
        # Triage sorts on these two, and both are highly selective — a few dozen
        # rows out of a few thousand — so they are partial indexes covering only
        # the true case.
        #
        # They are declared here as well as in migration c3h4i5j6k7l8 because
        # this project builds a schema two ways: a fresh install runs
        # Base.metadata.create_all() and stamps head, while an existing install
        # runs alembic upgrade head. An index that only the migration knows
        # about therefore exists on upgraded databases and not on fresh ones —
        # and c3h4i5j6k7l8.downgrade() then failed on a fresh database because
        # it dropped an index create_all() had never made.
        Index(
            "idx_asset_vuln_verified_exploit",
            "verified_exploit",
            postgresql_where=text("verified_exploit"),
        ),
        Index(
            "idx_asset_vuln_canary",
            "canary_confirmed",
            postgresql_where=text("canary_confirmed"),
        ),
        # Composite indexes the migrations below create, for the same reason as
        # the two above: a fresh install builds from Base.metadata and never
        # runs their upgrade(), so an index declared only in a migration exists
        # on upgraded databases and not on fresh ones.
        #   ix_asset_vuln_severity_status  — z9e0f1g2h3i4 (every dashboard load)
        #   ix_asset_vuln_component        — a1f2g3h4i5j6 (per-asset component roll-up)
        #   idx_asset_vuln_component_fix   — b2g3h4i5j6k7 (the grouped findings view)
        # z9e0f1g2h3i4 also creates a single-column ix_asset_vuln_in_kev, which
        # is deliberately not repeated here: `in_kev` already carries
        # index=True, so the models produce an equivalent index under
        # SQLAlchemy's own name and a second one would only cost writes.
        Index("ix_asset_vuln_severity_status", "severity", "status"),
        Index("ix_asset_vuln_component", "asset_id", "component"),
        Index("idx_asset_vuln_component_fix", "component", "component_fixed_version"),
        # Severity must be one of the six canonical lowercase ratings, matching
        # migration z9e0f1g2h3i4. The column is nullable and a CHECK passes on
        # NULL, so a finding whose severity was never determined is unaffected.
        CheckConstraint(
            SEVERITY_CANONICAL_SQL, name="ck_asset_vuln_severity_canonical"
        ),
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
    #: Widened from 30 alongside ``vulnerability_definitions.id``. This column
    #: is what makes the finding model one model: a CIS control failure and a
    #: CVE match are the same row shape, carry the same severity, feed the same
    #: risk score and appear in the same report — they differ only in which
    #: kind of catalogue row they point at.
    vuln_id = Column(
        String(120),
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

    # ── What the scan actually observed ──────────────────────────────────────
    # The vulnerability engine derives all of this while the scan is running and
    # the reports print it, but until now none of it was stored. The API had to
    # answer with hardcoded zeros, so the UI could not distinguish a version-
    # confirmed finding from an unverified guess, and the dashboard reported no
    # known-exploited vulnerabilities while the PDF named three.
    confidence = Column(String(16), nullable=True)  # confirmed | potential
    qod = Column(Integer, nullable=True)  # quality of detection, 0-100
    detection_method = Column(String(40), nullable=True)
    detected_version = Column(String(160), nullable=True)
    cvss_vector = Column(String(200), nullable=True)
    cvss_version = Column(String(8), nullable=True)
    attack_surface = Column(String(16), nullable=True)  # remote | local | client
    in_kev = Column(Boolean, nullable=False, default=False, index=True)
    kev_due_date = Column(Date, nullable=True)
    epss_score = Column(Numeric(7, 5), nullable=True)
    epss_percentile = Column(Numeric(7, 5), nullable=True)
    has_exploit = Column(Boolean, nullable=False, default=False)

    #: Which corpora reported an exploit — ExploitDB, Metasploit, Nuclei,
    #: CISA KEV, VulnCheck KEV. `has_exploit` alone cannot tell a weaponised
    #: Metasploit module from an unreproduced proof of concept, and those
    #: warrant very different urgency.
    exploit_sources = Column(ARRAY(Text), nullable=True)
    #: Someone reproduced the exploit rather than merely publishing it.
    verified_exploit = Column(Boolean, nullable=False, default=False)
    #: Observed being exploited against VulnCheck's honeypots — direct
    #: observation, the strongest exploitation evidence available here.
    canary_confirmed = Column(Boolean, nullable=False, default=False)
    ransomware_linked = Column(Boolean, nullable=False, default=False)

    #: The vendor's own advisory for this CVE, and its remediation wording.
    #: For OT products this is often the only actionable instruction that
    #: exists: NVD supplies a CPE range, Siemens supplies "Update to V2606 or
    #: later version".
    vendor_advisory_id = Column(String(100), nullable=True)
    vendor_advisory_url = Column(Text, nullable=True)
    vendor_remediation = Column(Text, nullable=True)

    #: The probe output the finding was raised on, captured at detection time.
    #: Distinct from ``plugin_output`` (a rendering) and from the catalogue
    #: description (which is not evidence at all).
    evidence = Column(Text, nullable=True)

    #: ``scan_id`` is re-pointed to the latest scan on every re-scan, so it
    #: cannot answer "what did scan N report?". This one is written once.
    first_scan_id = Column(String(64), nullable=True)

    #: The service or package this finding is about, and the version observed
    #: for it. The grouping key that lets "one outdated Chrome" be presented as
    #: one row resolving 1,736 CVEs rather than 1,736 rows.
    component = Column(String(200), nullable=True)
    component_version = Column(String(160), nullable=True)

    #: The version that resolves this finding. Without it the grouped view can
    #: state the problem but not the action — "Chrome 138.0.7204.184, 1,736
    #: findings" with no answer to "upgrade to what?". NULL means no fix is
    #: published, which is a real state and not the same as unrecorded.
    component_fixed_version = Column(String(160), nullable=True)

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
