"""
tests/security/test_nvd_admin_authorization.py
─────────────────────────────────────────────────────────────────────────────
Who may read the NVD catalogue sync status, and who may start a sync.

Both routes refused **everybody**, superadmin included, for as long as they
have existed. The local ``_verify_admin`` they used tested
``getattr(user, "is_superadmin", False)`` and
``getattr(user, "role", "") in ("superadmin", "org_admin")``; ``User`` has no
``is_superadmin`` attribute and ``User.role`` is a relationship to a ``Role``
object, so the membership test compared a ``Role`` instance against two strings
and was false for every account in the product.

It failed closed, which is the right direction to fail. What makes it worth a
test rather than a one-line fix is that nothing distinguished it from a correct
refusal: the endpoint answered 403 with "Admin privileges required", which is
exactly what it would say to a caller who genuinely lacked the privilege.

The policy asserted here is superadmin-only, and it is read off the codebase
rather than chosen:

  * ``vulnerability_definitions`` carries no ``org_id``. The catalogue is
    shared by every tenant, so one workspace's administrator triggering a sync
    acts on all of them — the same reasoning that makes ``/admin/email-domains``
    superadmin-only.
  * ``tests/security/test_endpoint_limit_inventory.py`` already records these
    two routes as "Feed synchronisation. Superadmin-only" in its rationale for
    not rate-limiting them.
  * No permission atom for feeds or the catalogue exists, so a permission guard
    would mean inventing one — and could not express this anyway, since
    superadmin holds every atom and any atom an org_admin also held would let
    them through.

**No test here starts a real synchronisation.** ``sync_nvd_to_vuln_intel`` is
replaced in the router's namespace, and one test asserts the real one was never
called. Authorisation is what is under test; the sync is not.
"""

import pytest
from fastapi.testclient import TestClient

from auth.jwt_handler import create_access_token
from db.base import gen_user_id, utcnow
from db.models import Organization, Permission, Role, RolePermission, User

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
        role=getattr(user.role, "name", None),
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
        role = db_session.query(Role).filter(Role.name == role_name).first()
        assert role is not None, f"system role {role_name!r} is not seeded"
        username = f"nvd-{role_name}"
        user = User(
            id=gen_user_id(org.slug, username),
            username=username,
            email=f"{username}@test.com",
            full_name=f"NVD {role_name}",
            password_hash="hash",
            org_id=org.id,
            role_id=role.id,
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
        response = client.get(STATUS_URL, headers=_headers(user_of_role("superadmin")))
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["status"] == "IDLE"

    def test_superadmin_can_trigger_a_sync(
        self, client: TestClient, user_of_role, never_run_a_real_sync
    ):
        response = client.post(SYNC_URL, headers=_headers(user_of_role("superadmin")))
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
            f"{SYNC_URL}?days_back=30", headers=_headers(user_of_role("superadmin"))
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
    @pytest.mark.parametrize("role_name", ["org_admin", "analyst", "viewer", "scanner"])
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
        response = client.post(SYNC_URL, headers=_headers(user_of_role("org_admin")))
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
        client.post(SYNC_URL, headers=_headers(user_of_role("org_admin")))
        client.post(SYNC_URL)
        assert never_run_a_real_sync == []


# ─────────────────────────────────────────────────────────────────────────────
# The fix grants nothing else
# ─────────────────────────────────────────────────────────────────────────────


class TestBlastRadius:
    def test_holding_every_permission_does_not_open_these_routes(
        self, client: TestClient, db_session, user_of_role, never_run_a_real_sync
    ):
        """
        The guard is by role, not by permission, and this proves the difference
        is real rather than stylistic. An org_admin granted every atom in the
        catalogue is still refused, so no future permission grant can open feed
        synchronisation to a tenant administrator by accident.
        """
        org_admin = user_of_role("org_admin")
        role = db_session.query(Role).filter(Role.name == "org_admin").first()
        for permission in db_session.query(Permission).all():
            exists = (
                db_session.query(RolePermission)
                .filter(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id,
                )
                .first()
            )
            if exists is None:
                db_session.add(
                    RolePermission(role_id=role.id, permission_id=permission.id)
                )
        db_session.flush()

        assert client.get(STATUS_URL, headers=_headers(org_admin)).status_code == 403
        assert client.post(SYNC_URL, headers=_headers(org_admin)).status_code == 403
        assert never_run_a_real_sync == []

    def test_the_change_did_not_tighten_an_unrelated_admin_route(
        self, client: TestClient, db_session, user_of_role
    ):
        """
        An org_admin holding ``users:read`` still reaches the user list. The
        NVD fix must narrow these two routes and nothing else.
        """
        org_admin = user_of_role("org_admin")
        role = db_session.query(Role).filter(Role.name == "org_admin").first()
        permission = (
            db_session.query(Permission)
            .filter(Permission.resource == "users", Permission.action == "read")
            .first()
        )
        assert permission is not None
        exists = (
            db_session.query(RolePermission)
            .filter(
                RolePermission.role_id == role.id,
                RolePermission.permission_id == permission.id,
            )
            .first()
        )
        if exists is None:
            db_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
            db_session.flush()

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
