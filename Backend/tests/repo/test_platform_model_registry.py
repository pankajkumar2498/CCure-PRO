"""
B8: the platform's models register alone, and Audit's attach nothing to them.

Two halves:

* **The registry.** ``ccure_platform.api`` used to load the whole ``db.models``
  registry, every Audit model file with it, because the platform imported its
  own models from there. The platform's models now register through their own
  registry, ``ccure_platform.models`` (notifications and email screening moved
  into it, with alias stubs), and no platform module loads ``db.models``.
* **The back-references.** Audit's web-scan and topology models declared
  ``backref=`` onto the platform's ``Organization`` (six attributes) and
  ``User`` (one), so the platform's classes changed shape with whichever Audit
  models were loaded. The relationships are one-sided now. Nothing read the
  attributes, except one thing: deleting a user made the ORM clear
  ``web_scans.created_by`` through ``User.web_scans``, and on the migrated
  schema nothing else does, because ``web_scans`` was created without the
  foreign keys its model declares. Audit's purge hook clears it now, through
  the web capability's ``core/web/offboarding.py``.
"""

import json
import subprocess
import sys
import uuid

import yaml
from sqlalchemy import inspect, text
from sqlalchemy.orm import configure_mappers
from testpaths import BACKEND_ROOT

OWNERSHIP_FILE = BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml"


def _owner_by_class():
    """Every mapped class -> the module owning its table (table_ownership.yaml)."""
    import db.models  # noqa: F401  (the whole registry)
    from db.base import Base

    configure_mappers()
    owners = yaml.safe_load(OWNERSHIP_FILE.read_text(encoding="utf-8"))["tables"]
    return {
        mapper.class_: owners[mapper.persist_selectable.name]["owner"]
        for mapper in Base.registry.mappers
        if getattr(mapper.persist_selectable, "name", None) in owners
    }


def test_platform_models_carry_no_relationship_into_a_module():
    owner = _owner_by_class()
    reaching = sorted(
        f"{cls.__name__}.{rel.key} -> {rel.mapper.class_.__name__}"
        for cls, module in owner.items()
        if module == "platform"
        for rel in inspect(cls).relationships
        if owner.get(rel.mapper.class_) != "platform"
    )
    assert reaching == []


def test_the_platform_relationships_that_remain_are_the_platforms_own():
    """Not vacuous: the classes are found and keep their own relationships."""
    from db.models import Organization, User

    assert _owner_by_class()[User] == "platform"
    assert set(inspect(Organization).relationships.keys()) == {"users"}
    assert set(inspect(User).relationships.keys()) == {
        "organization",
        "refresh_tokens",
        "audit_logs",
    }


def test_purging_a_user_clears_their_web_scans_creator_on_the_migrated_schema(
    db_session,
):
    import ccure_audit.offboarding  # noqa: F401  (registers Audit's purge hook)
    from ccure_platform.offboarding import run_user_purge_hooks
    from db.models import Organization, WebScan
    from native_rbac import create_user

    db = db_session
    suffix = uuid.uuid4().hex[:8]
    try:
        # The test schema is built from the models, which declare
        # web_scans.created_by -> users ON DELETE SET NULL. The migrations never
        # created that key, so production has none: drop it inside this
        # transaction (rolled back below) and purge against that schema.
        dropped = 0
        for (name,) in db.execute(
            text(
                "SELECT conname FROM pg_constraint WHERE contype = 'f' "
                "AND conrelid = 'web_scans'::regclass "
                "AND confrelid = 'users'::regclass"
            )
        ).all():
            db.execute(text(f'ALTER TABLE web_scans DROP CONSTRAINT "{name}"'))
            dropped += 1
        assert dropped == 1

        org = Organization(
            id=f"org_b8_{suffix}",
            name=f"B8 {suffix}",
            slug=f"b8-{suffix}",
            is_active=True,
            settings={},
        )
        db.add(org)
        db.flush()
        user = create_user(
            db,
            username=f"b8-{suffix}",
            email=f"b8-{suffix}@test.com",
            password_hash="hash",
            org_id=org.id,
            is_active=True,
            is_verified=True,
        )
        scan = WebScan(
            id=f"wsc_b8_{suffix}",
            org_id=org.id,
            created_by=user.id,
            target_url="http://target.invalid/",
            target_domain="target.invalid",
            authorization_confirmed=True,
            status="complete",
        )
        db.add(scan)
        db.flush()

        # What purge_user does: the modules' hooks, then the ORM delete.
        run_user_purge_hooks(db, user.id)
        db.delete(user)
        db.flush()

        assert (
            db.execute(
                text("SELECT created_by FROM web_scans WHERE id = :id"),
                {"id": scan.id},
            ).scalar_one()
            is None
        )
    finally:
        db.rollback()


# ── The platform registers alone ─────────────────────────────────────────────

#: Audit's model files and the registry that loads them all.
AUDIT_MODEL_MODULES = (
    "db.models",
    "db.models.amt",
    "db.models.assets",
    "db.models.compliance",
    "db.models.findings",
    "db.models.scan_policies",
    "db.models.scan_reports",
    "db.models.scan_schedules",
    "db.models.scans",
    "db.models.topology",
    "db.models.web_scans",
)

_ALONE = r"""
import importlib, json, pkgutil, sys
from sqlalchemy.orm import configure_mappers
import ccure_platform.models
from db.base import Base

configure_mappers()  # every relationship resolves with the platform's models only
registered = sorted(t.name for t in Base.metadata.sorted_tables)

import ccure_platform
for info in pkgutil.walk_packages(ccure_platform.__path__, "ccure_platform."):
    importlib.import_module(info.name)

print(json.dumps({
    "registered": registered,
    "audit_loaded": sorted(m for m in AUDIT if m in sys.modules),
}))
"""


def _alone():
    program = f"AUDIT = {AUDIT_MODEL_MODULES!r}\n" + _ALONE
    done = subprocess.run(
        [sys.executable, "-c", program],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_platform_registers_its_models_and_loads_no_audit_model():
    """
    A fresh interpreter: the platform's registry alone configures every mapper,
    and importing every module of the platform package then loads neither
    db.models nor any Audit model file.
    """
    alone = _alone()
    assert alone["audit_loaded"] == []

    owners = yaml.safe_load(OWNERSHIP_FILE.read_text(encoding="utf-8"))["tables"]
    from db.base import Base

    owner = _owner_by_class()  # the full registry, in this process
    platform_tables = sorted(
        cls.__table__.name for cls, module in owner.items() if module == "platform"
    )
    # Exactly the platform's tables register without Audit's registry, all of
    # them, and nothing else.
    assert alone["registered"] == platform_tables
    assert {owners[t]["owner"] for t in alone["registered"]} == {"platform"}
    assert set(platform_tables) <= set(Base.metadata.tables)


def test_audits_registry_still_exports_the_platforms_models():
    """Module code's ``from db.models import User`` is unchanged."""
    import ccure_platform.models as platform_models
    import db.models as registry

    for name in platform_models.__all__:
        assert getattr(registry, name) is getattr(platform_models, name), name
        assert name in registry.__all__, name
