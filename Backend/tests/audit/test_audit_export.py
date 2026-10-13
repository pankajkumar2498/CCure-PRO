"""
tests/audit/test_audit_export.py
─────────────────────────────────────────────────────────────────────────────
Phase 5: ``GET /admin/audit-logs/export``.

The export is the one route in this module that hands the audit trail to
somebody outside the platform, so the properties asserted here are the ones
whose absence would be a data-leak rather than a bug:

* it is reachable only with ``audit:export``, which ``analyst`` and ``viewer``
  do not hold;
* it can never emit another tenant's events, because it is scoped by the same
  ``_scoped_query`` the list endpoint uses rather than by a second
  implementation;
* it refuses rather than truncates at the row cap;
* it records — and **commits** — its own ``audit.log_exported`` event before a
  byte leaves.

Integrity labelling has its own suite next door
(``test_audit_export_integrity.py``); this one is about the endpoint.
"""

from native_rbac import grant_permissions, system_role, create_user, fixture_role


import csv
import io
from datetime import datetime, timedelta, timezone

import pytest
from auth.jwt_handler import create_access_token, hash_password
from config import AppConfig
from db.base import gen_user_id, gen_uuid, utcnow
from db.models import AuditLog, Organization, User

BASE = "/admin/audit-logs"
EXPORT = f"{BASE}/export"


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _event(db_session, org_id, **kw):
    row = AuditLog(
        id=gen_uuid(),
        org_id=org_id,
        user_id=kw.get("user_id"),
        action=kw.get("action", "user.login"),
        resource_type=kw.get("resource_type", "user"),
        resource_id=kw.get("resource_id", "res-1"),
        status=kw.get("status", "success"),
        severity=kw.get("severity", "info"),
        ip_address=kw.get("ip", "10.180.6.14"),
        request_id=kw.get("request_id"),
        changes=kw.get("changes"),
        user_agent=kw.get("user_agent", "Mozilla/5.0 Chrome/120"),
        created_at=kw.get("created_at") or datetime.now(timezone.utc),
    )
    db_session.add(row)
    db_session.commit()
    return row


def _headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def parse_csv(text: str) -> tuple[list[str], list[dict]]:
    """Split the export into its ``#`` preamble and its parsed data rows."""
    preamble = [line for line in text.splitlines() if line.startswith("#")]
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    reader = csv.DictReader(io.StringIO(body))
    return preamble, list(reader)


@pytest.fixture
def seeded(db_session, test_user):
    """A small, precisely known set of events in the caller's own tenant."""
    org = test_user.org_id
    now = datetime.now(timezone.utc)
    return {
        "login": _event(
            db_session,
            org,
            action="user.login",
            severity="info",
            status="success",
            ip="10.180.6.14",
            user_id=test_user.id,
            created_at=now - timedelta(minutes=5),
        ),
        "failed": _event(
            db_session,
            org,
            action="user.login_failed",
            severity="medium",
            status="failure",
            ip="203.0.113.9",
            created_at=now - timedelta(hours=3),
        ),
        "role": _event(
            db_session,
            org,
            action="user.role_changed",
            severity="high",
            created_at=now - timedelta(days=3),
        ),
        "old": _event(
            db_session,
            org,
            action="organization.deleted",
            severity="critical",
            created_at=now - timedelta(days=20),
        ),
    }


@pytest.fixture
def other_tenant(db_session):
    """A second organisation with its own admin and its own audit event."""
    uid = gen_uuid()[:8]
    org = Organization(
        id=f"org_xother_{uid}",
        name=f"Export Other {uid}",
        slug=f"export-other-{uid}",
        is_active=True,
    )
    db_session.add(org)
    db_session.flush()

    role = system_role(db_session, "platform.org_admin")
    admin = create_user(
        db_session,
        id=gen_user_id(org.slug, "xotheradmin"),
        username=f"xotheradmin_{uid}",
        email=f"xotheradmin_{uid}@other.test",
        full_name="Export Other Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)

    event = _event(db_session, org.id, action="organization.updated", severity="medium")
    return {"org": org, "admin": admin, "event": event}


def _role_user(db_session, org, role_name: str) -> User:
    role = system_role(db_session, role_name)
    uid = gen_uuid()[:8]
    user = create_user(
        db_session,
        id=gen_user_id(org.slug, f"{role_name}{uid}"),
        username=f"x{role_name}_{uid}",
        email=f"x{role_name}_{uid}@test.com",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ─── Route resolution ────────────────────────────────────────────────────────


def test_export_is_registered_before_the_dynamic_event_route():
    """
    `/export` must resolve to the export handler, not to `/{event_id}`.

    FastAPI matches routes in registration order, so a literal path declared
    *after* a same-prefix dynamic one is unreachable: the export request would
    be read as a lookup for an event whose id is the string "export" and would
    answer 404. The failure is total and silent — the route exists, is
    documented, carries a permission, and can never be called.
    """
    from fastapi.routing import APIRoute
    from main import app

    audit_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith(BASE)
    ]
    paths = [route.path for route in audit_routes]
    assert f"{BASE}/export" in paths
    assert f"{BASE}/{{event_id}}" in paths
    assert paths.index(f"{BASE}/export") < paths.index(f"{BASE}/{{event_id}}"), (
        "the literal /export route is registered after the dynamic "
        "/{event_id} route and is therefore unreachable"
    )

    # Resolve the way Starlette does — first route whose path matches wins.
    from starlette.routing import Match

    scope = {
        "type": "http",
        "method": "GET",
        "path": f"{BASE}/export",
        "path_params": {},
        "root_path": "",
        "headers": [],
    }
    resolved = next(
        route for route in audit_routes if route.matches(scope)[0] is Match.FULL
    )
    assert resolved.endpoint.__name__ == "export_audit_logs", (
        f"GET {BASE}/export resolves to {resolved.endpoint.__name__}, which "
        "means the export route is shadowed"
    )


# ─── Authentication and permission ───────────────────────────────────────────


def test_export_requires_authentication(client):
    assert client.get(EXPORT).status_code in (401, 403)


def test_export_refused_without_audit_export(client, db_session, test_org):
    """
    A role holding `audit:read` but not `audit:export` must be refused.

    Export is a different act from reading the trail on screen — it takes a
    copy off the platform — so it carries its own permission rather than
    inheriting the read one.
    """
    uid = gen_uuid()[:8]
    role = fixture_role(db_session, f"reader_only_{uid}")
    db_session.add(role)
    db_session.flush()

    grant_permissions(db_session, role, "platform.audit_log.read")

    user = create_user(
        db_session,
        id=gen_user_id(test_org.slug, f"readonly{uid}"),
        username=f"readonly_{uid}",
        email=f"readonly_{uid}@test.com",
        password_hash=hash_password("securepassword123"),
        org_id=test_org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert client.get(BASE + "/", headers=_headers(user)).status_code == 200
    assert client.get(EXPORT, headers=_headers(user)).status_code == 403


@pytest.mark.parametrize("role_name", ["platform.analyst", "platform.viewer"])
def test_analyst_and_viewer_cannot_export(client, db_session, test_org, role_name):
    user = _role_user(db_session, test_org, role_name)
    res = client.get(EXPORT, headers=_headers(user))
    assert res.status_code == 403, f"{role_name} exported the audit trail"


def test_org_admin_can_export(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers)
    assert res.status_code == 200, res.text


# ─── Tenant isolation ────────────────────────────────────────────────────────


def test_export_does_not_leak_another_tenants_events(
    client, auth_headers, seeded, other_tenant
):
    res = client.get(EXPORT, headers=auth_headers)
    assert res.status_code == 200
    _, rows = parse_csv(res.text)
    ids = {row["id"] for row in rows}
    assert other_tenant["event"].id not in ids
    assert seeded["login"].id in ids


def test_export_cannot_be_widened_by_naming_another_tenant(
    client, auth_headers, seeded, other_tenant
):
    """
    Filtering by another tenant's actor must return nothing, not that actor's
    events. The filter is applied *after* the tenant scope, so it can only ever
    narrow — this is the assertion that fails if the two are ever reordered.
    """
    res = client.get(
        EXPORT,
        headers=auth_headers,
        params={"user_id": other_tenant["admin"].id},
    )
    assert res.status_code == 200
    _, rows = parse_csv(res.text)
    assert rows == []
    assert "Events in this file : 0" in res.text


def test_a_tenant_exports_its_own_events(client, other_tenant):
    res = client.get(EXPORT, headers=_headers(other_tenant["admin"]))
    assert res.status_code == 200
    _, rows = parse_csv(res.text)
    assert other_tenant["event"].id in {row["id"] for row in rows}


# ─── Filters behave exactly as they do on the list endpoint ──────────────────


@pytest.mark.parametrize(
    "params,expected_key",
    [
        ({"severity": "high"}, "role"),
        ({"action": "user.login_failed"}, "failed"),
        ({"status": "failure"}, "failed"),
        ({"ip_address": "203.0.113.9"}, "failed"),
        ({"resource_type": "user"}, None),
    ],
)
def test_filters_narrow_the_export(client, auth_headers, seeded, params, expected_key):
    res = client.get(EXPORT, headers=auth_headers, params=params)
    assert res.status_code == 200, res.text
    _, rows = parse_csv(res.text)
    ids = {row["id"] for row in rows}
    if expected_key:
        assert ids == {seeded[expected_key].id}
    else:
        assert seeded["login"].id in ids


def test_export_honours_a_range_preset(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers, params={"range": "24h"})
    assert res.status_code == 200
    _, rows = parse_csv(res.text)
    actions = {row["action"] for row in rows}
    assert "organization.deleted" not in actions
    assert "user.role_changed" not in actions
    assert "user.login" in actions


def test_export_search_matches_an_event_id(client, auth_headers, seeded):
    target = seeded["role"]
    res = client.get(EXPORT, headers=auth_headers, params={"q": target.id})
    assert res.status_code == 200
    _, rows = parse_csv(res.text)
    assert [row["id"] for row in rows] == [target.id]


def test_unknown_severity_is_rejected(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers, params={"severity": "kritical"})
    assert res.status_code == 422


def test_unknown_format_is_rejected(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers, params={"format": "xlsx"})
    assert res.status_code == 422
    assert "xlsx" in res.json()["detail"]


def test_inverted_date_range_is_rejected(client, auth_headers, seeded):
    now = datetime.now(timezone.utc)
    res = client.get(
        EXPORT,
        headers=auth_headers,
        params={
            "date_from": now.isoformat(),
            "date_to": (now - timedelta(days=1)).isoformat(),
        },
    )
    assert res.status_code == 422


# ─── The row cap refuses; it never truncates ─────────────────────────────────


def test_over_the_cap_returns_413_and_no_partial_export(
    client, auth_headers, seeded, monkeypatch
):
    """
    A truncated audit extract is worse than a refused one: it looks complete,
    and "nothing happened after that point" is exactly the conclusion it
    invites. 413 names the real count so the caller can narrow the range.
    """
    monkeypatch.setattr(AppConfig, "AUDIT_EXPORT_MAX_ROWS", 2)
    res = client.get(EXPORT, headers=auth_headers)
    assert res.status_code == 413, res.text
    detail = res.json()["detail"]
    assert "exceeds" in detail
    assert "2" in detail
    assert "id," not in res.text, "a partial export was produced alongside the refusal"


def test_the_pdf_cap_is_independent_of_the_csv_cap(
    client, auth_headers, seeded, monkeypatch
):
    """
    The two numbers answer different questions — a machine-readable extract
    versus a document somebody reads — so lowering one must not move the other.
    """
    monkeypatch.setattr(AppConfig, "AUDIT_EXPORT_PDF_MAX_ROWS", 1)
    monkeypatch.setattr(AppConfig, "AUDIT_EXPORT_MAX_ROWS", 50_000)

    assert client.get(EXPORT, headers=auth_headers).status_code == 200
    over = client.get(EXPORT, headers=auth_headers, params={"format": "pdf"})
    assert over.status_code == 413
    assert "PDF" in over.json()["detail"]


def test_a_refused_export_writes_no_audit_event(
    client, auth_headers, db_session, test_user, seeded, monkeypatch
):
    """Nothing left the platform, so there is nothing to record."""
    before = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.org_id == test_user.org_id,
            AuditLog.action == "audit.log_exported",
        )
        .count()
    )
    monkeypatch.setattr(AppConfig, "AUDIT_EXPORT_MAX_ROWS", 1)
    assert client.get(EXPORT, headers=auth_headers).status_code == 413
    after = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.org_id == test_user.org_id,
            AuditLog.action == "audit.log_exported",
        )
        .count()
    )
    assert after == before


# ─── Keyset pagination ───────────────────────────────────────────────────────


def test_keyset_pagination_returns_every_row_exactly_once(
    client, auth_headers, db_session, test_user, monkeypatch
):
    """
    The export walks the set in pages. A cursor keyed on `created_at` alone
    would skip or repeat rows sharing a timestamp, and an OFFSET pager would
    re-read everything before each page. Twelve events, page size three.
    """
    now = datetime.now(timezone.utc)
    made = [
        _event(
            db_session,
            test_user.org_id,
            action="user.profile_updated",
            resource_id=f"paged-{index}",
            created_at=now - timedelta(seconds=index),
        )
        for index in range(12)
    ]
    monkeypatch.setattr(AppConfig, "AUDIT_EXPORT_PAGE_SIZE", 3)

    res = client.get(
        EXPORT, headers=auth_headers, params={"action": "user.profile_updated"}
    )
    assert res.status_code == 200
    _, rows = parse_csv(res.text)

    exported = [row["id"] for row in rows]
    assert len(exported) == len(set(exported)), "a row was emitted more than once"
    assert set(exported) == {event.id for event in made}


def test_events_sharing_a_timestamp_are_all_exported(
    client, auth_headers, db_session, test_user, monkeypatch
):
    """
    Two events written inside the same millisecond are ordinary. The cursor is
    `(created_at, id)` for exactly this case; keyed on the timestamp alone one
    of these rows would fall through the page boundary and vanish.
    """
    moment = datetime.now(timezone.utc)
    made = [
        _event(
            db_session,
            test_user.org_id,
            action="user.preferences_updated",
            resource_id=f"same-{index}",
            created_at=moment,
        )
        for index in range(6)
    ]
    monkeypatch.setattr(AppConfig, "AUDIT_EXPORT_PAGE_SIZE", 2)

    res = client.get(
        EXPORT, headers=auth_headers, params={"action": "user.preferences_updated"}
    )
    assert res.status_code == 200
    _, rows = parse_csv(res.text)
    assert {row["id"] for row in rows} == {event.id for event in made}


def test_rows_are_ordered_newest_first(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers)
    _, rows = parse_csv(res.text)
    stamps = [row["created_at"] for row in rows]
    assert stamps == sorted(stamps, reverse=True)


# ─── The export event ────────────────────────────────────────────────────────


def test_export_writes_and_commits_its_own_audit_event(
    client, auth_headers, db_session, test_user, seeded
):
    """
    The event has to be **committed**, not merely written.

    `get_db` closes the request's session without committing, and for a
    StreamingResponse it does so before the body is produced — so an event left
    uncommitted at the end of the handler is discarded in silence. This is the
    phase 4.1 failure mode, and the assertion is deliberately made from a
    second, independent session rather than from the one the endpoint used.
    """
    from db.base import SessionLocal

    res = client.get(EXPORT, headers=auth_headers, params={"range": "30d"})
    assert res.status_code == 200
    res.read()

    independent = SessionLocal()
    try:
        row = (
            independent.query(AuditLog)
            .filter(
                AuditLog.org_id == test_user.org_id,
                AuditLog.action == "audit.log_exported",
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )
    finally:
        independent.close()

    assert row is not None, "the export event was never committed"
    assert row.status == "success"
    assert row.severity == "high"
    assert row.changes["format"] == "csv"
    assert row.changes["verification_requested"] is True
    assert row.changes["row_count"] >= 1
    assert row.changes["filters"]["range"] == "30d"
    assert row.actor_username == test_user.username


def test_the_export_never_contains_its_own_event(
    client, auth_headers, db_session, test_user, seeded
):
    """
    Every pass is bounded by one instant captured before the count. Without
    that bound this request's own `audit.log_exported` row — written between
    the count and the stream, and the newest row in the tenant — would appear
    first in a newest-first export whose header had already counted without it.
    """
    res = client.get(EXPORT, headers=auth_headers)
    preamble, rows = parse_csv(res.text)

    assert "audit.log_exported" not in {row["action"] for row in rows}
    declared = next(
        line for line in preamble if line.startswith("# Events in this file")
    )
    assert int(declared.split(":")[1].strip()) == len(rows)


def test_the_export_records_no_secret(client, auth_headers, db_session, test_user):
    """
    `changes` is redacted **on the way in**, and the export must not undo that.

    Written through `log_audit_event` rather than by constructing the row, and
    that is the whole point: redaction lives in the write path, so a test that
    inserted the ORM object directly would put an unredacted secret into the
    audit table itself and then assert about an export of it. It would fail
    while the endpoint was correct — and, had the columns been ordered
    differently, could equally have passed while proving nothing.
    """
    from core.audit import log_audit_event

    log_audit_event(
        db_session,
        test_user,
        "user.password_changed",
        resource_type="user",
        resource_id=test_user.id,
        changes={"password": "hunter2", "totp_secret": "JBSWY3DP"},
    )
    db_session.commit()

    res = client.get(EXPORT, headers=auth_headers)
    assert "hunter2" not in res.text
    assert "JBSWY3DP" not in res.text
    assert "[REDACTED]" in res.text


# ─── Response shape ──────────────────────────────────────────────────────────


def test_csv_carries_every_hashed_field_plus_the_links(client, auth_headers, seeded):
    """
    The CSV is the artefact somebody verifies against, so it has to carry the
    whole canonical payload — not a display subset — plus `prev_hash` and
    `record_hash`.
    """
    from reporting.audit_export import CSV_COLUMNS

    res = client.get(EXPORT, headers=auth_headers)
    _, rows = parse_csv(res.text)
    assert rows, "nothing to inspect"
    assert set(rows[0]) == set(CSV_COLUMNS)
    for field in (
        "id",
        "org_id",
        "action",
        "resource_type",
        "resource_id",
        "status",
        "severity",
        "ip_address",
        "user_agent",
        "request_id",
        "changes",
        "actor_user_id",
        "actor_username",
        "created_at",
        "prev_hash",
        "record_hash",
    ):
        assert field in rows[0]


def test_content_disposition_is_rfc6266(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers)
    disposition = res.headers["content-disposition"]
    assert disposition.startswith("attachment; filename=")
    assert "filename*=UTF-8''" in disposition
    assert "ccure-audit-log-" in disposition
    assert "INTEGRITY-FAILURE" not in disposition


def test_pdf_export_is_a_pdf(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers, params={"format": "pdf"})
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-")
    assert ".pdf" in res.headers["content-disposition"]


def test_export_is_not_cached(client, auth_headers, seeded):
    res = client.get(EXPORT, headers=auth_headers)
    assert res.headers.get("cache-control") == "no-store"


def test_an_empty_result_is_a_valid_export_not_an_error(client, auth_headers):
    """Zero matching events is an answer, and the file must still say so."""
    res = client.get(
        EXPORT, headers=auth_headers, params={"action": "no.such.action.exists"}
    )
    assert res.status_code == 200
    preamble, rows = parse_csv(res.text)
    assert rows == []
    assert any("Events in this file : 0" in line for line in preamble)


# ─── Rate limiting ───────────────────────────────────────────────────────────
#
# `conftest` disables the limiter for the whole session, so a 429 cannot be
# provoked here. The registration is what is asserted, exactly as
# `tests/security/test_upload_validation.py` does for the two upload routes.


def test_export_carries_a_registered_rate_limit():
    from scan_helpers import limiter

    assert limiter._route_limits.get(
        "routers.audit.export_audit_logs"
    ), "the export renders documents and streams the audit trail; it needs a limit"


def test_export_can_receive_rate_limit_headers():
    """
    The limiter is built `headers_enabled=True`. A limited handler that hands
    slowapi nothing to write on answers 500 on every request once the limiter
    is enabled — and the suite disables it, so only a live server shows it.
    """
    import inspect

    from routers.audit import export_audit_logs

    parameters = inspect.signature(export_audit_logs).parameters
    assert "request" in parameters
    assert "response" in parameters
