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

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from api.host_discovery_api import HostDiscoveryAPI
from scans.models import ensure_scan_schema
from db.models.users import ensure_user_schema
from scan_helpers import set_api

# ── Router imports ────────────────────────────────────────────────────────────
from auth.router import router as auth_router
from scans.router import router as scans_router
from routers.health import router as health_router
from routers.traditional_scans import router as traditional_scans_router
from routers.phase_scans import router as phase_scans_router
from routers.credentialed import router as credentialed_router
from routers.reports import router as reports_router
from routers.admin_users import router as admin_users_router
from routers.admin_rbac import router as admin_rbac_router
from routers.admin_orgs import router as admin_orgs_router
from routers.audit import router as audit_router
from routers.user_profile import router as user_profile_router
from routers.notifications import router as notifications_router

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
log = logging.getLogger("ccure.api")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlalchemy import inspect, text
    from sqlalchemy.exc import OperationalError
    from db.base import engine, Base
    from config import AppConfig
    
    # 0. Health check: Test database connectivity
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info("Database connection verified")
    except OperationalError as e:
        log.error(f"Database connection failed. Is the database running? Error: {e}")
        # We no longer raise RuntimeError to allow the container to start.
        # The app will likely fail on requests, but the container stays alive for debugging/migration.
    
    # 1. Health check: ensure DB schema is populated
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    required_tables = {"users", "organizations", "roles", "scans", "assets"}
    
    if not required_tables.issubset(existing_tables):
        missing = required_tables - existing_tables
        if AppConfig.is_sqlite() or "sqlite" in AppConfig.DATABASE_URL:
            log.warning(f"Missing tables {missing}. Development mode: Auto-creating via Base.metadata.create_all()")
            # Import models so Base metadata is populated
            import db.models.users
            import db.models.rbac
            import db.models.scans
            import db.models.assets
            import db.models.findings
            import db.models.notifications
            Base.metadata.create_all(bind=engine)
        else:
            log.warning(
                "Database schema incomplete for PostgreSQL. Missing tables: %s. "
                "Running production schema bootstrap automatically.",
                sorted(missing),
            )
            from db.migrate_production_schema import (
                create_all_tables,
                enable_extensions,
                seed_default_org,
                seed_rbac,
            )

            with engine.begin() as conn:
                enable_extensions(conn)
            create_all_tables()
            with engine.begin() as conn:
                seed_rbac(conn)
                seed_default_org(conn)

            # Re-check after bootstrap so startup fails loudly only if the schema
            # is still incomplete after the additive migration.
            inspector = inspect(engine)
            existing_tables = set(inspector.get_table_names())
            still_missing = required_tables - existing_tables
            if still_missing:
                raise RuntimeError(
                    f"PostgreSQL schema bootstrap did not create required tables: {sorted(still_missing)}"
                )

    # 1.5. Additive backfills before any User queries run
    ensure_scan_schema()
    ensure_user_schema()

    # 1.6. Ensure first admin exists
    from db.models.users import User
    from db.models.rbac import Organization, Role
    from auth.email_utils import email_matches, normalize_email
    from auth.jwt_handler import hash_password
    from db.base import SessionLocal, gen_user_id

    with SessionLocal() as db:
        admin_email = normalize_email("admin@ccurepro.com")
        if not db.query(User).filter(email_matches(User.email, admin_email)).first():
            log.info(f"Seeding default admin user: {admin_email}")
            org = db.query(Organization).filter(Organization.slug == "default").first()
            role = db.query(Role).filter(Role.name == "superadmin").first()
            if org and role:
                admin = User(
                    id=gen_user_id(org.slug, "admin"),  # e.g. usr_def_admin_x9v1
                    username="admin",
                    email=admin_email,
                    password_hash=hash_password("AdminCdac@123"),
                    org_id=org.id,
                    role_id=role.id,
                    is_active=True,
                    is_verified=True
                )
                db.add(admin)
                try:
                    db.commit()
                    log.info(f"Successfully seeded admin user: {admin_email}")
                except Exception as e:
                    db.rollback()
                    log.error(f"Failed to seed admin: {e}")
            else:
                log.warning("Could not seed admin: default org or superadmin role missing.")
    
    # 3. Initialize scan engines
    api = HostDiscoveryAPI(silent=False)
    set_api(api)
    log.info("HostDiscoveryAPI initialised")
    
    # 4. Start background report cleanup
    from routers.reports import cleanup_old_reports
    import asyncio
    
    async def cleanup_loop():
        while True:
            try:
                await asyncio.to_thread(cleanup_old_reports, 7)
            except Exception as e:
                log.error("Report cleanup failed: %s", e)
            await asyncio.sleep(86400)  # 24 hours
            
    cleanup_task = asyncio.create_task(cleanup_loop())
    
    yield
    cleanup_task.cancel()
    log.info("Shutting down")


# ── App ───────────────────────────────────────────────────────────────────────

is_prod = os.getenv("ENV", "development").lower() == "production"

app = FastAPI(
    title       = "Ccure Audit - Pro Edition",
    description = "CDAC-style network scanner.",
    version     = "1.0.0",
    lifespan    = lifespan,
    docs_url    = None if is_prod else "/docs",
    redoc_url   = None if is_prod else "/redoc",
    openapi_url = None if is_prod else "/openapi.json",
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
    for origin in (_configured_origins.split(",") if _configured_origins else _default_origins)
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


# ── Rate limiting ─────────────────────────────────────────────────────────────

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from scan_helpers import limiter

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


# ── Request-ID correlation middleware ────────────────────────────────────────────

@app.middleware("http")
async def _request_id_middleware(request: Request, call_next):
    """
    Stamp every request with a unique X-Request-ID so that logs,
    error responses, and client retries can all be correlated.
    Honour an incoming X-Request-ID header if provided by an upstream proxy.
    """
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
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
    error_code = (
        (exc.headers or {}).get("X-Error-Code")
        or f"HTTP_{exc.status_code}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error_code": error_code,
            "message": exc.detail,
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
app.include_router(admin_rbac_router)
app.include_router(admin_orgs_router)
app.include_router(audit_router)
app.include_router(user_profile_router)
app.include_router(notifications_router)


# ── Dev entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
