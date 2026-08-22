"""
main.py
─────────────────────────────────────────────────────────────────────────────
FastAPI entry point for Ccure Audit Pro Edition v1.

This file is ONLY responsible for:
  - App instantiation and lifespan
  - Middleware (CORS, rate limiting, request-ID correlation, validation error scrubbing)
  - Router registration via app.include_router()

All endpoint logic lives in focused router modules under routers/.
All shared helpers and pipeline constants live in scan_helpers.py.
"""

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager

from orchestrator.host_discovery_api import HostDiscoveryAPI

# ── Router imports ────────────────────────────────────────────────────────────
from auth.router import router as auth_router
from db.models.users import ensure_user_schema
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from routers.admin_email_domains import router as admin_email_domains_router
from routers.admin_nvd import router as admin_nvd_router
from routers.admin_orgs import router as admin_orgs_router
from routers.admin_rbac import router as admin_rbac_router
from routers.admin_users import router as admin_users_router
from routers.assets import router as assets_router
from routers.audit import router as audit_router
from routers.compliance import router as compliance_router
from routers.credentialed import router as credentialed_router
from routers.dashboard import router as dashboard_router
from routers.findings import router as findings_router
from routers.health import router as health_router
from routers.notifications import router as notifications_router
from routers.phase_scans import router as phase_scans_router
from routers.reports import router as reports_router
from routers.topology import router as topology_router
from routers.traditional_scans import router as traditional_scans_router
from routers.user_profile import router as user_profile_router
from routers.web_scans import router as web_scans_router
from scan_helpers import set_api
from scans.schema_bootstrap import ensure_scan_schema
from routers.scan_history import router as scans_router

# ── Structured JSON Logging ──────────────────────────────────────────────────


class _JsonFormatter(logging.Formatter):
    """Emit every log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload: dict = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach request_id if injected by the correlation middleware
        if hasattr(record, "request_id"):
            payload["request_id"] = record.request_id  # type: ignore[attr-defined]
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


_use_json_logs = os.getenv("LOG_FORMAT", "text").lower() == "json"
_log_level = os.getenv("LOG_LEVEL", "INFO").upper()

_handler = logging.StreamHandler()
if _use_json_logs:
    _handler.setFormatter(_JsonFormatter())
else:
    _handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s - %(message)s",
            datefmt="%H:%M:%S",
        )
    )

logging.basicConfig(level=_log_level, handlers=[_handler])
logging.getLogger("uvicorn.access").setLevel(
    os.getenv("ACCESS_LOG_LEVEL", "WARNING").upper()
)
log = logging.getLogger("ccure.api")


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    from config import AppConfig
    from db.base import engine
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError

    # 0. Health check: Test database connectivity
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info("Database connection verified")

        # Run additive migrations
        try:
            ensure_user_schema()
            ensure_scan_schema()

            from db.models.assets import ensure_mac_vendor_schema
            from db.models.email_security import ensure_email_security_schema
            from db.models.topology import ensure_topology_schema

            ensure_topology_schema()
            ensure_mac_vendor_schema()
            # Creates the domain rule tables and seeds the never-block floor.
            # Idempotent, and it must run before the first registration is
            # served — a guard with no allowlist rows would refuse Gmail.
            ensure_email_security_schema()

            log.info(
                "User, scan, topology, mac vendor and email security schemas "
                "verified and migrated"
            )
        except Exception as e:
            log.error(f"Failed to execute additive schema updates: {e}")
    except OperationalError as e:
        log.error(f"Database connection failed. Is the database running? Error: {e}")
        # We no longer raise RuntimeError to allow the container to start.
        # The app will likely fail on requests, but the container stays alive for debugging/migration.

    # 1. Ensure basic roles and default organization exist (Data Seeding)
    # This assumes Alembic migrations have already run.
    from db.migrate_production_schema import seed_default_org, seed_rbac

    try:
        with engine.begin() as conn:
            seed_rbac(conn)
            seed_default_org(conn)
    except Exception as e:
        log.warning(
            f"Skipping RBAC seeding (schema may not be fully migrated yet): {e}"
        )

    # 1.6. Ensure first admin exists
    from auth.email_utils import email_matches, normalize_email
    from auth.jwt_handler import hash_password
    from db.base import SessionLocal, gen_user_id
    from db.models.rbac import Organization, Role
    from db.models.users import User

    with SessionLocal() as db:
        if AppConfig.DEFAULT_ADMIN_EMAIL and AppConfig.DEFAULT_ADMIN_PASSWORD:
            admin_email = normalize_email(AppConfig.DEFAULT_ADMIN_EMAIL)
            if (
                not db.query(User)
                .filter(email_matches(User.email, admin_email))
                .first()
            ):
                log.info(f"Seeding default admin user: {admin_email}")
                org = (
                    db.query(Organization)
                    .filter(Organization.slug == "default")
                    .first()
                )
                role = db.query(Role).filter(Role.name == "superadmin").first()
                if org and role:
                    admin = User(
                        id=gen_user_id(org.slug, "admin"),  # e.g. usr_def_admin_x9v1
                        username="admin",
                        email=admin_email,
                        password_hash=hash_password(AppConfig.DEFAULT_ADMIN_PASSWORD),
                        org_id=org.id,
                        role_id=role.id,
                        is_active=True,
                        is_verified=True,
                    )
                    db.add(admin)
                    try:
                        db.commit()
                        log.info(f"Successfully seeded admin user: {admin_email}")
                    except Exception as e:
                        db.rollback()
                        log.error(f"Failed to seed admin: {e}")
            else:
                log.warning(
                    "Could not seed admin: default org or superadmin role missing."
                )
        else:
            if db.query(User).count() == 0:
                log.warning(
                    "Database has no users and DEFAULT_ADMIN_EMAIL/PASSWORD are not set. No admin seeded."
                )

    # 1.7. Ensure compliance catalog (ISO 27001 framework, controls, & rules) is seeded
    try:
        from db.models.compliance import (
            ComplianceControl,
            ComplianceFramework,
            ComplianceRule,
        )

        with SessionLocal() as db:
            fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_iso27001_2022")
                .first()
            )
            nist_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_nist_csf_v2")
                .first()
            )
            soc2_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_soc2_type2")
                .first()
            )
            certin_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_cert_in_2022")
                .first()
            )
            dpdp_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_dpdp_2023")
                .first()
            )
            gdpr_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_gdpr")
                .first()
            )
            pci_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_pci_dss_v4")
                .first()
            )
            nist53_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_nist_800_53_r5")
                .first()
            )
            iec_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_iec_62443")
                .first()
            )
            nist82_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_nist_800_82_r3")
                .first()
            )
            nerc_cip_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_nerc_cip")
                .first()
            )
            nis2_fw = (
                db.query(ComplianceFramework)
                .filter(ComplianceFramework.id == "cfw_nis2")
                .first()
            )
            nist_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_nist_csf_v2")
                .count()
            )
            soc2_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_soc2_type2")
                .count()
            )
            certin_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_cert_in_2022")
                .count()
            )
            dpdp_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_dpdp_2023")
                .count()
            )
            gdpr_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_gdpr")
                .count()
            )
            pci_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_pci_dss_v4")
                .count()
            )
            nist53_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_nist_800_53_r5")
                .count()
            )
            iec_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_iec_62443")
                .count()
            )
            nist82_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_nist_800_82_r3")
                .count()
            )
            nerc_cip_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_nerc_cip")
                .count()
            )
            nis2_ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_nis2")
                .count()
            )
            ctrl_count = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.framework_id == "cfw_iso27001_2022")
                .count()
            )
            rule_count = db.query(ComplianceRule).count()
            if (
                not fw
                or not nist_fw
                or not soc2_fw
                or not certin_fw
                or not dpdp_fw
                or not gdpr_fw
                or not pci_fw
                or not nist53_fw
                or not iec_fw
                or not nist82_fw
                or not nerc_cip_fw
                or not nis2_fw
                or ctrl_count < 93
                # NIST CSF 2.0 defines exactly 106 Subcategories. The threshold
                # here was 20 — every other framework's is its real control
                # count — so a NIST catalogue truncated to any size above 20
                # satisfied the self-heal check and was never re-seeded.
                or nist_ctrl_count < 106
                # 61 against a catalogue of 55: this condition was true on every
                # start, so the whole seeder ran on every container start. That
                # is what turned the NIST rule-wiring bug below into a
                # progressive one — each restart handed another set of
                # Subcategories an attestation placeholder that suppressed their
                # automated verdicts.
                or soc2_ctrl_count < 55
                or certin_ctrl_count < 10
                or dpdp_ctrl_count < 16
                or gdpr_ctrl_count < 18
                or pci_ctrl_count < 12
                or nist53_ctrl_count < 100
                or iec_ctrl_count < 50
                or nist82_ctrl_count < 30
                or nerc_cip_ctrl_count < 52
                or nis2_ctrl_count < 42
                or rule_count < 20
            ):
                log.info(
                    f"Auto-seeding compliance catalog (Found ISO={bool(fw)}, NIST={bool(nist_fw)}, SOC2={bool(soc2_fw)}, CERT-In={bool(certin_fw)}, DPDP={bool(dpdp_fw)}, GDPR={bool(gdpr_fw)}, PCI={bool(pci_fw)}, NIST80053={bool(nist53_fw)}, IEC62443={bool(iec_fw)}, NIST80082={bool(nist82_fw)}, NERCCIP={bool(nerc_cip_fw)})..."
                )
                from scripts.seed_compliance import seed_framework_and_controls
                from scripts.seed_real_rules import seed_and_evaluate

                from core.compliance_seeds import SEEDS_DIR

                base_scripts_dir = str(SEEDS_DIR)
                iso_seed = os.path.join(
                    base_scripts_dir, "iso27001_2022_controls_seed.json"
                )
                nist_seed = os.path.join(
                    base_scripts_dir, "nist_csf_v2_controls_seed.json"
                )
                soc2_seed = os.path.join(
                    base_scripts_dir, "soc2_type2_controls_seed.json"
                )
                certin_seed = os.path.join(
                    base_scripts_dir, "cert_in_2022_controls_seed.json"
                )
                pci_seed = os.path.join(
                    base_scripts_dir, "pci_dss_v4_controls_seed.json"
                )
                dpdp_seed = os.path.join(
                    base_scripts_dir, "dpdp_2023_controls_seed.json"
                )
                gdpr_seed = os.path.join(base_scripts_dir, "gdpr_controls_seed.json")
                nist53_seed = os.path.join(
                    base_scripts_dir, "nist_800_53_r5_controls_seed.json"
                )
                iec_seed = os.path.join(
                    base_scripts_dir, "iec_62443_controls_seed.json"
                )

                try:
                    if os.path.exists(iso_seed):
                        seed_framework_and_controls(db, iso_seed)
                    if os.path.exists(nist_seed):
                        seed_framework_and_controls(db, nist_seed)
                    if os.path.exists(soc2_seed):
                        seed_framework_and_controls(db, soc2_seed)
                    if os.path.exists(certin_seed):
                        seed_framework_and_controls(db, certin_seed)
                    if os.path.exists(pci_seed):
                        seed_framework_and_controls(db, pci_seed)
                    if os.path.exists(dpdp_seed):
                        seed_framework_and_controls(db, dpdp_seed)
                    if os.path.exists(gdpr_seed):
                        seed_framework_and_controls(db, gdpr_seed)
                    if os.path.exists(nist53_seed):
                        seed_framework_and_controls(db, nist53_seed)
                    if os.path.exists(iec_seed):
                        seed_framework_and_controls(db, iec_seed)
                    nist82_seed = os.path.join(
                        base_scripts_dir, "nist_800_82_r3_controls_seed.json"
                    )
                    if os.path.exists(nist82_seed):
                        seed_framework_and_controls(db, nist82_seed)
                    nerc_cip_seed = os.path.join(
                        base_scripts_dir, "nerc_cip_controls_seed.json"
                    )
                    if os.path.exists(nerc_cip_seed):
                        seed_framework_and_controls(db, nerc_cip_seed)
                    nis2_seed = os.path.join(
                        base_scripts_dir, "nis2_controls_seed.json"
                    )
                    if os.path.exists(nis2_seed):
                        seed_framework_and_controls(db, nis2_seed)

                    seed_and_evaluate()
                    log.info("Compliance catalog auto-seeding completed successfully!")
                except Exception as seed_err:
                    db.rollback()
                    log.warning(
                        f"Compliance catalog seeding handled concurrently or deferred: {seed_err}"
                    )
            else:
                log.info(
                    "Compliance catalog (ISO 27001, NIST CSF v2.0, SOC 2 Type II, CERT-In 2022, PCI-DSS v4.0, DPDP Act 2023, GDPR, NIST SP 800-53 Rev. 5, IEC 62443, NIST SP 800-82 Rev. 3 frameworks, controls & rules) fully present and synchronized."
                )
    except Exception as e:
        log.warning(f"Compliance catalog auto-seeding skipped or deferred: {e}")

    # 3. Initialize scan engines
    api = HostDiscoveryAPI(silent=False)
    set_api(api)
    log.info("HostDiscoveryAPI initialised")

    # 4. Start background report cleanup
    import asyncio

    from routers.reports import cleanup_old_reports

    #: How long cleanup_loop waits between passes.
    #
    #: This loop had no delay at all. `while True:` ran a filesystem walk over
    #: the reports directory and two DELETE statements back-to-back for the life
    #: of the process — measured at ~3,300 iterations/second with the work
    #: stubbed out, and an idle container sitting at 35-46% CPU with no traffic.
    #:
    #: It also made two tests intermittently fail, which is how it was found:
    #:
    #:   * test_oui_lookup patches db.base.SessionLocal globally. This loop runs
    #:     on its own thread, picked up that mock, and called commit() on it, so
    #:     a test asserting commit was called once saw two calls.
    #:   * test_email_verification sets a token's expires_at into the past and
    #:     then reads the row back. This loop deletes exactly those rows, and
    #:     landing in that window raised ObjectDeletedError.
    #:
    #: Hourly is far more frequent than either job needs: reports are retained
    #: for 7 days and verification tokens live 24 hours, so nothing here is
    #: time-critical. Do not remove the sleep to make pruning more responsive —
    #: neither deletion has a deadline, and the previous behaviour is what a
    #: busy-wait costs.
    CLEANUP_INTERVAL_SECONDS = 3600

    async def cleanup_loop():
        while True:
            try:
                await asyncio.to_thread(cleanup_old_reports, 7)
            except Exception as e:
                log.error("Report cleanup failed: %s", e)

            try:
                from datetime import datetime, timezone

                from db.base import SessionLocal
                from db.models import EmailVerificationToken, PasswordResetToken

                db = SessionLocal()
                try:
                    now = datetime.now(timezone.utc)
                    deleted_count = (
                        db.query(PasswordResetToken)
                        .filter(PasswordResetToken.expires_at <= now)
                        .delete()
                    )
                    # Expired verification tokens are dead weight for the same
                    # reason: they cannot be redeemed, and an expired-token row
                    # is a record of an email address kept past its purpose.
                    verification_count = (
                        db.query(EmailVerificationToken)
                        .filter(EmailVerificationToken.expires_at <= now)
                        .delete()
                    )
                    if deleted_count or verification_count:
                        db.commit()
                        log.info(
                            "Purged %d expired password reset tokens and %d "
                            "expired email verification tokens.",
                            deleted_count,
                            verification_count,
                        )
                except Exception as db_exc:
                    db.rollback()
                    log.error("Failed to prune expired auth tokens: %s", db_exc)
                finally:
                    db.close()
            except Exception as e:
                log.error("Auth token cleanup failed: %s", e)

            # Outside both try blocks on purpose: a failure in either job above
            # must not turn this back into a busy-wait.
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)

    async def nvd_auto_sync_loop():
        """Option A: Background 24-hour automatic NVD live catalog sync into vuln_intel DB."""
        from scans.nvd_sync import get_nvd_sync_status, sync_nvd_to_vuln_intel

        # Initial delay on startup to allow DB migrations to finish
        await asyncio.sleep(5)
        while True:
            try:
                status = get_nvd_sync_status()
                if status.get("status") != "SYNCING":
                    log.info(
                        "Starting automatic 24-hour live NVD catalog sync into vuln_intel DB..."
                    )
                    await sync_nvd_to_vuln_intel(days_back=90)
            except Exception as e:
                log.error("Automatic NVD sync background loop error: %s", e)

            await asyncio.sleep(86400)  # 24 hours

    cleanup_task = asyncio.create_task(cleanup_loop())
    nvd_sync_task = asyncio.create_task(nvd_auto_sync_loop())

    yield
    cleanup_task.cancel()
    nvd_sync_task.cancel()
    log.info("Shutting down")


# ── App ───────────────────────────────────────────────────────────────────────

is_prod = os.getenv("ENV", "development").lower() == "production"

app = FastAPI(
    title="CCure Pro Audit",
    description="CDAC RTSG Vulnerability Scanner.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
)


# ── CORS ──────────────────────────────────────────────────────────────────────

_default_origins = [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:5173",
]
_configured_origins = os.getenv("CORS_ALLOW_ORIGINS", "")
allow_origins = [
    origin.strip()
    for origin in (
        _configured_origins.split(",") if _configured_origins else _default_origins
    )
    if origin.strip()
]

# `allow_origin_regex="https?://.*"` used to sit here alongside the allow-list.
#
# It matches every origin on the web, so the allow-list above was decoration:
# an OPTIONS preflight carrying `Origin: https://evil.example.com` came back
# with `Access-Control-Allow-Origin: https://evil.example.com` and
# `Access-Control-Allow-Credentials: true`. That combination tells the browser
# it may send the victim's cookies to this API from any site they visit *and*
# let that site read the response.
#
# Two things kept it from being immediately exploitable: the refresh cookie is
# SameSite=lax, so it is not attached to cross-site fetches, and access tokens
# live in page memory rather than storage. Neither is a property this line was
# relying on. Setting REFRESH_COOKIE_SAMESITE=none — which any genuinely
# cross-origin deployment needs — would have turned it into silent
# account takeover for every logged-in user who visited a hostile page.
#
# CORS_ALLOW_ORIGINS already names every origin this deployment is served from,
# so the explicit list is sufficient. Add new origins there.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


# ── Rate limiting ─────────────────────────────────────────────────────────────

from scan_helpers import limiter
from slowapi.errors import RateLimitExceeded

app.state.limiter = limiter


def _make_rate_limit_response(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return a machine-readable 429 in the standard error envelope."""
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "error_code": "RATE_LIMIT_EXCEEDED",
            "message": str(exc.detail),
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id or ""},
    )


app.add_exception_handler(RateLimitExceeded, _make_rate_limit_response)


# ── Security headers on API responses ────────────────────────────────────────
#
# The frontend's nginx sets a full header set for the SPA, but nothing set any
# on the API, and the API is reached directly by the browser (VITE_API_BASE_URL
# points at :8000, not through the SPA's server). Two of these matter here in
# particular:
#
#   * nosniff — /reports/download/{scan_id} returns files. A response the
#     browser is allowed to re-interpret as HTML is a stored-XSS vector on the
#     API's own origin, which is where the session lives.
#   * A restrictive CSP on API responses. An API returns JSON and files and
#     never needs to load anything, so 'none' costs nothing and neutralises any
#     response that does get rendered as a document.
#
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "Cross-Origin-Resource-Policy": "same-site",
}

# Strict-Transport-Security is sent only on requests that actually arrived over
# TLS, decided from the X-Forwarded-Proto that host Nginx sets.
#
# Two reasons not to send it unconditionally. A browser ignores the header on a
# plain-HTTP response, so an unconditional one would be decoration that makes
# the deployment look protected in a header dump when it is not. And the API is
# still directly reachable on 127.0.0.1:8000 without TLS for local tooling —
# claiming HTTPS-only there would be a lie about a listener that has no
# certificate.
#
# max-age is 300 for the rollout, matching Nginx. HSTS is a one-way door: a
# client that has cached "HTTPS-only" for a year cannot reach a broken
# deployment to be told why. Raise both to 31536000 together once every client
# is confirmed working.
#
# Note this only has any effect for the *hostname*. RFC 6797 §8.1.1 requires
# browsers to ignore HSTS when the host is an IP literal, so
# https://10.180.6.14 gets encryption but never gets pinned. That is why
# FRONTEND_URL is https://ccure.internal.
_HSTS_VALUE = "max-age=300"


def _is_secure_request(request: Request) -> bool:
    forwarded = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
    if forwarded:
        return forwarded.lower() == "https"
    return request.url.scheme == "https"


def _apply_security_headers(response: Response, request: Request) -> None:
    """Set security headers without clobbering any a handler set deliberately."""
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    if _is_secure_request(request):
        response.headers.setdefault("Strict-Transport-Security", _HSTS_VALUE)


# ── Request-ID correlation middleware ────────────────────────────────────────────


@app.middleware("http")
async def _request_id_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id

    # Handle Private Network Access (PNA) preflight requests.
    #
    # This handler runs *before* CORSMiddleware and answers the preflight
    # itself, so it has to apply the same origin policy — it previously
    # reflected `Origin` verbatim (falling back to "*"), which approved the
    # preflight for any site on the internet. Approving a preflight is not
    # nothing even without Allow-Credentials: it is what tells the browser to
    # go ahead and send the real request, and a state-changing request does its
    # damage whether or not the caller can read the reply.
    if request.method == "OPTIONS" and request.headers.get(
        "Access-Control-Request-Private-Network"
    ):
        origin = request.headers.get("Origin")
        if origin and origin not in allow_origins:
            log.warning("Rejected PNA preflight from disallowed origin: %s", origin)
            return Response(status_code=403)

        response = Response()
        response.headers["Access-Control-Allow-Private-Network"] = "true"
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        )
        response.headers["Access-Control-Allow-Headers"] = "*"
        return response

    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    _apply_security_headers(response, request)
    if response.status_code >= 500:
        log.error(
            "%s %s returned %s", request.method, request.url.path, response.status_code
        )
    elif response.status_code >= 400:
        log.warning(
            "%s %s returned %s", request.method, request.url.path, response.status_code
        )
    return response


# ── Global HTTP exception handler (unified error envelope) ───────────────────────


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException):
    """
    Wrap every HTTP error in a machine-readable envelope:

        {
          "success": false,
          "error_code": "HTTP_<STATUS>",
          "message": "<detail>",
          "request_id": "<uuid>"
        }

    This replaces FastAPI's default {"detail": ...} shape and satisfies
    the .agent expectation for structured error codes + correlation IDs.
    """
    request_id = getattr(request.state, "request_id", None)
    # Allow endpoints to pass a custom error_code via exc.headers
    error_code = (exc.headers or {}).get("X-Error-Code") or f"HTTP_{exc.status_code}"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error_code": error_code,
            "message": exc.detail,
            "detail": exc.detail,
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id or ""},
    )


# ── Validation error scrubbing ────────────────────────────────────────────────

_SENSITIVE_FIELDS = {"password", "key_path", "secret", "token", "api_key", "credential"}


@app.exception_handler(RequestValidationError)
async def _scrubbed_validation_error(request: Request, exc: RequestValidationError):
    """
    Override FastAPI's default 422 handler to mask any field whose name
    matches a known-sensitive pattern.  Without this, Pydantic may echo
    the raw user-submitted value (e.g. a password) in the error body.
    Also wraps the response in the standard error envelope with request_id.
    """
    request_id = getattr(request.state, "request_id", None)
    scrubbed = []
    for err in exc.errors():
        err_copy = dict(err)
        # Always remove the raw 'input' payload. Pydantic V2 attaches the entire
        # request body to every error, so even a missing 'ip' field error would
        # echo the raw 'password' field in its 'input' dictionary.
        err_copy.pop("input", None)

        # Pydantic attaches the original exception object under ctx["error"]
        # for anything a validator raised, and an exception is not JSON
        # serialisable — leaving it in place made the 422 itself fail to
        # render, turning a clear "which field is wrong" into a 500.
        ctx = err_copy.get("ctx")
        if isinstance(ctx, dict):
            err_copy["ctx"] = {key: str(value) for key, value in ctx.items()}

        loc = err_copy.get("loc", ())
        if any(str(segment).lower() in _SENSITIVE_FIELDS for segment in loc):
            err_copy["ctx"] = {"note": "Value redacted for security."}
        scrubbed.append(err_copy)
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error_code": "VALIDATION_ERROR",
            "message": "Request validation failed.",
            "errors": scrubbed,
            "detail": scrubbed,
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id or ""},
    )


# ── Router registration ──────────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(health_router)
app.include_router(traditional_scans_router)
app.include_router(phase_scans_router)
app.include_router(credentialed_router)
app.include_router(reports_router)
app.include_router(admin_users_router)
app.include_router(admin_email_domains_router)
app.include_router(admin_rbac_router)
app.include_router(admin_orgs_router)
app.include_router(admin_nvd_router)
app.include_router(audit_router)
app.include_router(user_profile_router)
app.include_router(notifications_router)
app.include_router(dashboard_router)
app.include_router(assets_router)
app.include_router(findings_router)
app.include_router(web_scans_router)
app.include_router(topology_router)
app.include_router(compliance_router)


# ── Dev entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
