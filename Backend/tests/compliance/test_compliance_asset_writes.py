"""
The compliance tasks read and write assets through the asset registry
(``core.asset_compliance``, 1 Nov 2026).

After a remediation that only takes effect on a restart, the task marks the
asset ``reboot_pending``. It used to load the asset row and set the key on its
``custom_attributes`` itself; ``mark_reboot_pending`` does it now, with the
same assignment, and the task's own commit still writes it. The run's asset
scope and the remediation target's lookup moved with it, unchanged.
"""

import uuid
from types import SimpleNamespace

import pytest
from db.base import utcnow
from db.models import Asset, Organization
from sqlalchemy.orm import Session

import core.compliance_tasks as compliance_tasks
from core.asset_compliance import asset_by_id, assets_for_run, mark_reboot_pending


class _Query:
    def __init__(self, row):
        self.row = row

    def filter_by(self, **_):
        return self

    def first(self):
        return self.row


class _Db:
    def __init__(self, rule):
        self.rule, self.added, self.commits = rule, [], 0

    def query(self, _model):
        return _Query(self.rule)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1


def _finalize(monkeypatch, family):
    marked = []
    monkeypatch.setattr(
        compliance_tasks,
        "mark_reboot_pending",
        lambda db, asset_id: marked.append((db, asset_id)) or True,
    )
    queued = []
    monkeypatch.setattr(
        compliance_tasks.run_reverify_evaluation, "delay", queued.append
    )
    db = _Db(SimpleNamespace(rule_family_code=family))
    finding = SimpleNamespace(id="cfnd_1", rule_id="crule_1", asset_id="ast_1")
    compliance_tasks._finalize_successful_remediation(db, finding, "usr_1", 0)
    return db, finding, marked, queued


@pytest.mark.parametrize(
    "family", ["CONFIG-SMBV1", "CONFIG-LEGACY-TLS", "CONFIG-RDP-NLA"]
)
def test_a_restart_remediation_asks_the_registry_to_mark_the_asset(monkeypatch, family):
    db, finding, marked, queued = _finalize(monkeypatch, family)
    assert marked == [(db, "ast_1")]
    assert db.commits == 1  # the task's own commit, after the mark
    assert finding.status == "remediation_applied"
    assert queued == ["cfnd_1"]


def test_any_other_remediation_marks_nothing(monkeypatch):
    db, _, marked, queued = _finalize(monkeypatch, "CONFIG-PASSWORD-POLICY")
    assert marked == []
    assert db.commits == 1
    assert queued == ["cfnd_1"]


@pytest.fixture
def org(db_session: Session) -> Organization:
    row = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name=f"Assets {uuid.uuid4().hex[:6]}",
        slug=f"assets-{uuid.uuid4().hex[:8]}",
        is_active=True,
        settings={},
    )
    db_session.add(row)
    db_session.flush()
    return row


def _asset(db: Session, org: Organization, ip: str, **attrs) -> Asset:
    row = Asset(
        id=f"ast_{uuid.uuid4().hex[:10]}",
        org_id=org.id,
        ip_address=ip,
        last_seen_at=utcnow(),
        custom_attributes=attrs or None,
    )
    db.add(row)
    db.flush()
    return row


def test_the_mark_keeps_the_other_attributes_and_leaves_the_commit_to_the_caller(
    db_session: Session, org: Organization
):
    asset = _asset(db_session, org, "192.0.2.10", tags=["cde"], cde_scope="in")

    assert mark_reboot_pending(db_session, asset.id) is True

    assert asset in db_session.dirty  # written, not yet flushed or committed
    assert asset.custom_attributes == {
        "tags": ["cde"],
        "cde_scope": "in",
        "reboot_pending": True,
    }


def test_the_mark_reports_an_unknown_asset(db_session: Session):
    assert mark_reboot_pending(db_session, "ast_gone") is False


def test_a_runs_assets_are_its_organisations_and_the_named_ones(
    db_session: Session, org: Organization
):
    a = _asset(db_session, org, "192.0.2.11")
    b = _asset(db_session, org, "192.0.2.12")

    assert {x.id for x in assets_for_run(db_session, org.id)} >= {a.id, b.id}
    assert [x.id for x in assets_for_run(db_session, org.id, [a.id])] == [a.id]
    assert assets_for_run(db_session, "org_elsewhere", [a.id]) == []
    assert asset_by_id(db_session, b.id) is b
    assert asset_by_id(db_session, "ast_gone") is None
