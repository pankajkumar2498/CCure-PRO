"""
tests/audit/test_audit_api_filtering.py
─────────────────────────────────────────────────────────────────────────────
Phase 2: filtering, search, date ranges, pagination and the event-detail
endpoint on ``/admin/audit-logs``.

Before this phase the API filtered on action, resource_type and status only.
An investigation starting from "what did this person do", "what came from this
address" or "what happened between 09:00 and 10:00" had no way to ask.

Two properties are asserted throughout and are easy to lose:

  * **filters compose** — applying two must narrow, not widen. A filter added
    to the wrong query object silently ORs instead of ANDs.
  * **filters are applied in the database** — ``total`` must reflect the
    filtered set, not the table. A count taken before the filters is the shape
    of bug that only shows up as a wrong pager at scale.
"""

from datetime import datetime, timedelta, timezone

import pytest
from db.base import gen_uuid
from db.models import AuditLog

BASE = "/admin/audit-logs/"


def _event(
    db_session,
    org_id,
    *,
    action="user.login",
    user_id=None,
    resource_type="user",
    resource_id="res-1",
    status="success",
    severity="info",
    ip="10.180.6.14",
    request_id=None,
    created_at=None,
    changes=None,
):
    row = AuditLog(
        id=gen_uuid(),
        org_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        severity=severity,
        ip_address=ip,
        request_id=request_id,
        changes=changes,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        created_at=created_at or datetime.now(timezone.utc),
    )
    db_session.add(row)
    db_session.commit()
    return row


@pytest.fixture
def seeded(db_session, test_user):
    """A small, precisely known set of events in the caller's own tenant."""
    org = test_user.org_id
    now = datetime.now(timezone.utc)
    rows = {
        "login": _event(
            db_session,
            org,
            action="user.login",
            severity="info",
            status="success",
            ip="10.180.6.14",
            user_id=test_user.id,
            request_id="req-alpha-0001",
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
            status="success",
            ip="10.180.6.99",
            resource_type="user",
            resource_id="usr_target_1",
            created_at=now - timedelta(days=3),
        ),
        "old": _event(
            db_session,
            org,
            action="organization.deleted",
            severity="critical",
            status="success",
            ip="10.180.6.14",
            created_at=now - timedelta(days=20),
        ),
    }
    return rows


def _actions(payload):
    return [row["action"] for row in payload["logs"]]


# The `auth_headers` fixture performs a real login, which writes its own
# `user.login` event into this same tenant. Tests whose filter can match it
# assert on the set of distinct actions, or on specific seeded ids, rather than
# on an exact row count — an exact count would be asserting the fixture's
# behaviour rather than the endpoint's.


# ─── Severity ────────────────────────────────────────────────────────────────


def test_filter_by_severity(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"severity": "high"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert _actions(body) == ["user.role_changed"]
    assert body["total"] == 1, "total must reflect the filter, not the table"


def test_severity_filter_is_case_insensitive(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"severity": "HIGH"})
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.role_changed"]


def test_unknown_severity_is_rejected_not_silently_empty(client, auth_headers, seeded):
    """
    An empty result for a typo looks identical to "nothing matched", which in an
    audit tool reads as "this person did nothing" — the wrong conclusion.
    """
    res = client.get(BASE, headers=auth_headers, params={"severity": "kritical"})
    assert res.status_code == 422
    assert "kritical" in res.json()["detail"]


# ─── IP address ──────────────────────────────────────────────────────────────


def test_filter_by_exact_ip(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"ip_address": "203.0.113.9"})
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.login_failed"]


def test_ip_filter_matches_a_prefix(client, auth_headers, seeded):
    """ "Everything from this subnet" is the question an investigation asks."""
    res = client.get(BASE, headers=auth_headers, params={"ip_address": "10.180.6."})
    assert res.status_code == 200
    assert sorted(_actions(res.json())) == sorted(
        ["user.login", "user.role_changed", "organization.deleted"]
    )


def test_malformed_ip_filter_does_not_500(client, auth_headers, seeded):
    """
    The reason the column is matched as text rather than INET: an INET
    comparison against this raises DataError in the driver, and a typo in a
    filter box must not be a server error.
    """
    res = client.get(BASE, headers=auth_headers, params={"ip_address": "not-an-ip"})
    assert res.status_code == 200
    assert res.json()["logs"] == []


# ─── Date ranges ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "preset,expected",
    [
        ("24h", {"user.login", "user.login_failed"}),
        ("7d", {"user.login", "user.login_failed", "user.role_changed"}),
        (
            "30d",
            {
                "user.login",
                "user.login_failed",
                "user.role_changed",
                "organization.deleted",
            },
        ),
    ],
)
def test_range_presets(client, auth_headers, seeded, preset, expected):
    res = client.get(BASE, headers=auth_headers, params={"range": preset})
    assert res.status_code == 200, res.text
    assert set(_actions(res.json())) == expected


def test_unknown_range_preset_is_rejected(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"range": "last-fortnight"})
    assert res.status_code == 422


def test_custom_window_bounds_both_ends(client, auth_headers, seeded):
    now = datetime.now(timezone.utc)
    res = client.get(
        BASE,
        headers=auth_headers,
        params={
            "date_from": (now - timedelta(hours=6)).isoformat(),
            "date_to": (now - timedelta(hours=1)).isoformat(),
        },
    )
    assert res.status_code == 200
    # Only the 3-hour-old failure sits inside that window.
    assert _actions(res.json()) == ["user.login_failed"]


def test_explicit_dates_win_over_a_preset(client, auth_headers, seeded):
    """
    The UI sends both while switching from a preset to a custom range. If the
    preset won, the custom range the user just typed would be ignored.
    """
    now = datetime.now(timezone.utc)
    res = client.get(
        BASE,
        headers=auth_headers,
        params={
            "range": "24h",
            "date_from": (now - timedelta(days=25)).isoformat(),
        },
    )
    assert res.status_code == 200
    # The 20-day-old event is the one a 24h preset would have hidden.
    assert "organization.deleted" in _actions(res.json())


def test_naive_datetime_is_read_as_utc_not_rejected(client, auth_headers, seeded):
    """
    ``<input type="datetime-local">`` submits without a zone. Comparing a naive
    value against a timestamptz column raises in PostgreSQL, so this would
    otherwise be a 500 from the date picker.
    """
    naive = (datetime.now(timezone.utc) - timedelta(hours=6)).replace(tzinfo=None)
    res = client.get(
        BASE, headers=auth_headers, params={"date_from": naive.isoformat()}
    )
    assert res.status_code == 200, res.text
    assert set(_actions(res.json())) == {"user.login", "user.login_failed"}


def test_inverted_window_is_rejected(client, auth_headers, seeded):
    now = datetime.now(timezone.utc)
    res = client.get(
        BASE,
        headers=auth_headers,
        params={
            "date_from": now.isoformat(),
            "date_to": (now - timedelta(days=1)).isoformat(),
        },
    )
    assert res.status_code == 422


# ─── Search ──────────────────────────────────────────────────────────────────


def test_search_finds_an_event_by_its_id(client, auth_headers, seeded):
    """The identifier a support ticket quotes must resolve to its event."""
    target = seeded["role"]
    res = client.get(BASE, headers=auth_headers, params={"q": target.id})
    assert res.status_code == 200
    assert [row["id"] for row in res.json()["logs"]] == [target.id]


def test_search_finds_an_event_by_request_id(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"q": "req-alpha-0001"})
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.login"]


def test_search_matches_action_substring(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"q": "role_chang"})
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.role_changed"]


def test_search_matches_resource_id(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"q": "usr_target_1"})
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.role_changed"]


def test_search_matches_the_actor(client, auth_headers, seeded, test_user):
    """Search spans the joined user, which is why the join is made once."""
    res = client.get(BASE, headers=auth_headers, params={"q": test_user.email})
    assert res.status_code == 200
    assert "user.login" in _actions(res.json())


def test_search_matches_ip(client, auth_headers, seeded):
    res = client.get(BASE, headers=auth_headers, params={"q": "203.0.113"})
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.login_failed"]


def test_search_composes_with_a_filter_rather_than_widening(
    client, auth_headers, seeded
):
    """
    The failure mode this guards: applying the search to a different query
    object than the filters produces an OR, and the result set grows when the
    user expected it to shrink.
    """
    res = client.get(
        BASE, headers=auth_headers, params={"q": "user.", "severity": "high"}
    )
    assert res.status_code == 200
    assert _actions(res.json()) == ["user.role_changed"]


# ─── Filters compose ─────────────────────────────────────────────────────────


def test_filters_and_together(client, auth_headers, seeded):
    res = client.get(
        BASE,
        headers=auth_headers,
        params={"status": "success", "severity": "info"},
    )
    assert res.status_code == 200
    # Both conditions hold for every row, and nothing failing or higher-severity
    # leaked in.
    assert set(_actions(res.json())) == {"user.login"}
    assert all(r["status"] == "success" for r in res.json()["logs"])
    assert all(r["severity"] == "info" for r in res.json()["logs"])


def test_existing_filters_still_work(client, auth_headers, seeded):
    """Backward compatibility: the three original parameters are unchanged."""
    for param, value, expected in [
        ("action", "user.login", {"user.login"}),
        ("status", "failure", {"user.login_failed"}),
        ("resource_type", "user", None),
    ]:
        res = client.get(BASE, headers=auth_headers, params={param: value})
        assert res.status_code == 200, res.text
        if expected is not None:
            assert set(_actions(res.json())) == expected


# ─── Pagination ──────────────────────────────────────────────────────────────


def test_pagination_is_database_driven_and_total_is_unpaged(
    client, auth_headers, seeded
):
    unpaged = client.get(BASE, headers=auth_headers, params={"limit": 1000})
    assert unpaged.status_code == 200
    total = unpaged.json()["total"]
    assert total >= 4, "the seeded events must be visible"

    first = client.get(BASE, headers=auth_headers, params={"limit": 2, "skip": 0})
    second = client.get(BASE, headers=auth_headers, params={"limit": 2, "skip": 2})
    assert first.status_code == second.status_code == 200

    assert len(first.json()["logs"]) == 2, "limit must be applied in the database"
    # `total` describes the whole filtered set and must not shrink with the page.
    assert first.json()["total"] == second.json()["total"] == total
    assert not set(r["id"] for r in first.json()["logs"]) & set(
        r["id"] for r in second.json()["logs"]
    ), "pages must not overlap"


def test_total_is_correct_for_a_superadmin_with_no_filters(
    client, db_session, seeded, test_org
):
    """
    The unfiltered superadmin listing — the one path with neither a join nor a
    column-referencing filter to anchor the count's FROM clause.

    A bare `func.count()` there emits `SELECT count(*)` with no FROM, which
    PostgreSQL answers `1`. The page rendered fifty rows above a pager that
    said "1 event", and every other test missed it because they all
    authenticate as an org_admin, whose tenant filter joins `users` and so
    keeps the FROM alive.
    """
    from auth.jwt_handler import create_access_token
    from db.models import Role, User

    superadmin_role = db_session.query(Role).filter(Role.name == "superadmin").first()
    admin = User(
        id=f"usr_super_{gen_uuid()[:8]}",
        username=f"super_{gen_uuid()[:6]}",
        email=f"super_{gen_uuid()[:6]}@test.com",
        password_hash="x",
        org_id=test_org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token(
        admin.id, admin.username, role="superadmin", org_id=admin.org_id
    )
    res = client.get(
        BASE, headers={"Authorization": f"Bearer {token}"}, params={"limit": 50}
    )
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["total"] >= len(body["logs"]), (
        f"total ({body['total']}) is smaller than the page it returned "
        f"({len(body['logs'])} rows) — the count lost its FROM clause"
    )
    assert body["total"] >= 4, "the seeded events should be counted"


def test_results_are_newest_first(client, auth_headers, seeded):
    body = client.get(BASE, headers=auth_headers).json()
    stamps = [row["created_at"] for row in body["logs"]]
    assert stamps == sorted(stamps, reverse=True)


# ─── Detail endpoint ─────────────────────────────────────────────────────────


def test_detail_endpoint_returns_the_full_record(client, auth_headers, seeded):
    target = seeded["login"]
    res = client.get(f"{BASE}{target.id}", headers=auth_headers)
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["id"] == target.id
    assert body["action"] == "user.login"
    assert body["severity"] == "info"
    assert body["request_id"] == "req-alpha-0001"
    assert body["org_id"] == target.org_id
    # Detail-only fields the list response deliberately omits.
    assert body["timezone"] == "UTC"
    assert "session_id" in body
    assert body["user_agent"]


def test_detail_surfaces_session_id_when_the_event_carries_one(
    client, auth_headers, db_session, test_user
):
    row = _event(
        db_session,
        test_user.org_id,
        action="user.session_revoked",
        severity="low",
        changes={"session_id": 4242},
    )
    res = client.get(f"{BASE}{row.id}", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["session_id"] == 4242


def test_unknown_event_id_is_404(client, auth_headers):
    res = client.get(f"{BASE}{gen_uuid()}", headers=auth_headers)
    assert res.status_code == 404


def test_list_response_stays_lean(client, auth_headers, seeded):
    """
    §21: the list response must not carry the detail-only fields. This is a
    response-size guard — at 250 rows a page the difference is real.
    """
    row = client.get(BASE, headers=auth_headers).json()["logs"][0]
    for detail_only in ("org_id", "timezone", "session_id", "user_full_name"):
        assert detail_only not in row
