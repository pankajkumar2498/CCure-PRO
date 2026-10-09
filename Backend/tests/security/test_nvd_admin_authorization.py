"""Native authorization for shared vulnerability-feed administration.

System roles retain their frozen grants. Organization-scoped grants cannot
manage global feeds; an explicitly assigned native feed-management grant can.
Every synchronization is mocked so no test reaches a feed or the catalogue.
"""

from native_rbac import fixture_role, assign_role, system_role, create_user


import pytest
from fastapi.testclient import TestClient

from auth.jwt_handler import create_access_token
from ccure_platform.models.rbac_tables import RbacPermission, RbacRolePermission
from db.base import gen_user_id, utcnow
from db.models import Organization, User

STATUS_URL = "/api/v1/admin/nvd-sync-status"
SYNC_URL = "/api/v1/admin/sync-nvd"


def _headers(user: User) -> dict:
    """
    A bearer token built directly, not through ``POST /auth/login``.

    The login endpoint commits, and because the app shares the test session
    every uncommitted fixture row commits with it and survives the per-test
    rollback. That is a recorded trap in this suite, not a hypothetical.
    """
    token = create_access_token(
        user.id,
        user.username,
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def org(db_session) -> Organization:
    organization = Organization(
        name="NVD Authz Org",
        slug="nvd-authz",
        max_assets=10,
        max_users=10,
        is_active=True,
    )
    db_session.add(organization)
    db_session.flush()
    return organization


@pytest.fixture
def user_of_role(db_session, org):
    """Build a verified, approved, active account holding a named system role."""

    def _make(role_name: str) -> User:
        role = system_role(db_session, role_name)
        assert role is not None, f"system role {role_name!r} is not seeded"
        username = f"nvd-{role_name.split('.')[-1]}"
        user = create_user(
            db_session,
            id=gen_user_id(org.slug, username),
            username=username,
            email=f"{username}@test.com",
            full_name=f"NVD {role_name}",
            password_hash="hash",
            org_id=org.id,
            role=role,
            is_active=True,
            is_verified=True,
            approved_at=utcnow(),
            approved_by="fixture",
        )
        db_session.add(user)
        db_session.flush()
        return user

    return _make


@pytest.fixture(autouse=True)
def never_run_a_real_sync(monkeypatch):
    """
    Nothing in this module may reach the network or the catalogue.

    ``BackgroundTasks`` added by a route *do* run under ``TestClient``, after
    the response is returned — so without this the first authorised POST would
    start a genuine NVD synchronisation against the deployment's own database.
    """
    import routers.admin_nvd as module

    calls: list = []

    def _fake_sync(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "MOCKED"}

    monkeypatch.setattr(module, "sync_nvd_to_vuln_intel", _fake_sync)
    monkeypatch.setattr(
        module,
        "get_nvd_sync_status",
        lambda: {"status": "IDLE", "database_total_cves": 0},
    )
    return calls


# ─────────────────────────────────────────────────────────────────────────────
# The intended role
# ─────────────────────────────────────────────────────────────────────────────


class TestSuperadminAccess:
    def test_superadmin_can_read_the_sync_status(
        self, client: TestClient, user_of_role
    ):
        """
        The regression this whole module exists for: before the fix this was a
        403 for a superadmin, and the message said "Admin privileges required".
        """
        response = client.get(
            STATUS_URL, headers=_headers(user_of_role("platform.superadmin"))
        )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["status"] == "IDLE"

    def test_superadmin_can_trigger_a_sync(
        self, client: TestClient, user_of_role, never_run_a_real_sync
    ):
        response = client.post(
            SYNC_URL, headers=_headers(user_of_role("platform.superadmin"))
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "STARTED"
        assert body["mode"] == "incremental"
        # The route records who started it, which is the point of requiring an
        # identity for a background job nobody watches.
        assert body["triggered_by"] == "nvd-superadmin@test.com"

    def test_a_backfill_is_dispatched_as_a_backfill(
        self, client: TestClient, user_of_role, never_run_a_real_sync
    ):
        response = client.post(
            f"{SYNC_URL}?days_back=30",
            headers=_headers(user_of_role("platform.superadmin")),
        )
        assert response.status_code == 200
        assert response.json()["mode"] == "backfill"
        assert never_run_a_real_sync
        _args, kwargs = never_run_a_real_sync[-1]
        assert kwargs == {"days_back": 30, "backfill": True}


# ─────────────────────────────────────────────────────────────────────────────
# Everyone else
# ─────────────────────────────────────────────────────────────────────────────


class TestUnauthorizedRolesAreRefused:
    @pytest.mark.parametrize(
        "role_name",
        [
            "platform.org_admin",
            "platform.analyst",
            "platform.viewer",
            "platform.scanner",
        ],
    )
    @pytest.mark.parametrize("method,url", [("get", STATUS_URL), ("post", SYNC_URL)])
    def test_every_other_role_is_refused(
        self, client: TestClient, user_of_role, role_name, method, url
    ):
        response = getattr(client, method)(
            url, headers=_headers(user_of_role(role_name))
        )
        assert response.status_code == 403

    def test_org_admin_is_refused_although_it_is_an_administrator(
        self, client: TestClient, user_of_role
    ):
        """
        Stated on its own because it is the one denial that looks like a bug.

        The guard this replaced *intended* to admit org_admin. It is refused
        now because the catalogue is platform-wide: ``vulnerability_definitions``
        has no ``org_id``, so one tenant's administrator syncing it acts on
        every other tenant's findings. Widening this back is an authorisation
        decision about cross-tenant reach, not a convenience.
        """
        response = client.post(
            SYNC_URL, headers=_headers(user_of_role("platform.org_admin"))
        )
        assert response.status_code == 403

    @pytest.mark.parametrize("method,url", [("get", STATUS_URL), ("post", SYNC_URL)])
    def test_an_unauthenticated_caller_is_refused(
        self, client: TestClient, method, url
    ):
        response = getattr(client, method)(url)
        assert response.status_code in (401, 403)
        assert response.status_code != 200

    def test_a_refused_caller_never_starts_a_sync(
        self, client: TestClient, user_of_role, never_run_a_real_sync
    ):
        client.post(SYNC_URL, headers=_headers(user_of_role("platform.org_admin")))
        client.post(SYNC_URL)
        assert never_run_a_real_sync == []


# ─────────────────────────────────────────────────────────────────────────────
# The fix grants nothing else
# ─────────────────────────────────────────────────────────────────────────────


class TestBlastRadius:
    def test_holding_every_organization_permission_does_not_open_these_routes(
        self, client: TestClient, db_session, user_of_role, never_run_a_real_sync
    ):
        """
        Global feed management is a platform-scoped permission. Holding every
        organization-scoped permission cannot grant it.
        """
        org_admin = user_of_role("platform.org_admin")
        keys = [
            p.key
            for p in db_session.query(RbacPermission).filter_by(
                scope_kind="organization", delegable_to_org_roles=True
            )
        ]
        extra = fixture_role(db_session, "All organization permissions", keys=keys)
        assign_role(db_session, org_admin, extra)

        assert client.get(STATUS_URL, headers=_headers(org_admin)).status_code == 403
        assert client.post(SYNC_URL, headers=_headers(org_admin)).status_code == 403
        assert never_run_a_real_sync == []

    def test_an_explicit_native_feed_grant_allows_management_without_a_role_name_rule(
        self, client, db_session, user_of_role, never_run_a_real_sync
    ):
        user = user_of_role("platform.viewer")
        feed_manager = fixture_role(
            db_session, "Feed manager", keys=["audit.vuln_feed.manage"]
        )
        assign_role(db_session, user, feed_manager)

        assert client.get(STATUS_URL, headers=_headers(user)).status_code == 200
        assert client.post(SYNC_URL, headers=_headers(user)).status_code == 200
        assert len(never_run_a_real_sync) == 1

    def test_the_change_did_not_tighten_an_unrelated_admin_route(
        self, client: TestClient, db_session, user_of_role
    ):
        """
        An org_admin holding ``platform.user.read`` still reaches the user list. The
        NVD fix must narrow these two routes and nothing else.
        """
        org_admin = user_of_role("platform.org_admin")
        role = system_role(db_session, "platform.org_admin")
        assert (
            db_session.query(RbacRolePermission)
            .filter_by(role_id=role.id, permission_key="platform.user.read")
            .first()
            is not None
        )

        assert (
            client.get("/admin/users", headers=_headers(org_admin)).status_code != 403
        )

    def test_a_download_ticket_cannot_reach_these_routes(self):
        """
        The guard authenticates with ``get_current_user``, not
        ``get_current_user_flexible``, and the narrowing is deliberate: the
        flexible dependency also accepts a short-lived download ticket, which
        exists so a browser can fetch a report from a URL. A credential that
        can be put in a URL must not be able to start an outbound sync.
        """
        from main import app

        names = set()
        for route in app.routes:
            if getattr(route, "path", None) not in (STATUS_URL, SYNC_URL):
                continue
            stack = [route.dependant]
            while stack:
                dependant = stack.pop()
                call = getattr(dependant, "call", None)
                if call is not None:
                    names.add(getattr(call, "__name__", ""))
                stack.extend(getattr(dependant, "dependencies", []))

        assert "get_current_user" in names
        assert "get_current_user_flexible" not in names
        assert "_verify_admin" not in names
