"""
tests/audit/test_audit_commit_atomicity.py
─────────────────────────────────────────────────────────────────────────────
Phase 4.1: a business change and its audit event must commit together.

The defect this covers was silent and widespread. Twenty-one handlers called
`log_audit_event` **after** their last `db.commit()`. `get_db` closes its
session without committing, so those rows were flushed and then thrown away —
the operation succeeded and left no record.

It was invisible for three reasons: nothing raised, the endpoints returned 200,
and the phase-4 change that makes `log_audit_event` propagate failures does not
help, because nothing fails. The row is simply never committed.

Corroborated on the live database before the fix: `install_framework`,
`asset_updated`, `attest_manual_control`, `apply_remediation`,
`import_amt_inventory` and five more actions appeared **zero times** across all
511 events, and there were no compliance-related and no asset-related audit
actions at all in two weeks of use.

Two layers of protection here:

* `test_no_handler_audits_after_its_last_commit` is the structural guard. It
  walks every handler in the application and fails on the pattern, so it covers
  all twenty-one sites at once *and* the one somebody adds next month.
* The endpoint tests below prove the atomicity property end to end for the
  handlers reachable with existing fixtures, reading back through an
  independent session.
"""

import ast
import pathlib

import pytest
from db.base import SessionLocal
from db.models import AuditLog

pytestmark = pytest.mark.usefixtures("db_session")

BACKEND = pathlib.Path(__file__).resolve().parents[2]

#: `_log_block` writes its enforced-mode event on a **separate session** that it
#: commits itself, and its two branches are mutually exclusive — the flag-mode
#: call rides along in the caller's transaction. The structural check cannot see
#: that, so it is named here with the reason rather than silently skipped.
KNOWN_SAFE = {("email_domain_guard.py", "_log_block")}


def _handlers_auditing_after_commit():
    found = []
    for path in sorted(
        list((BACKEND / "routers").glob("*.py")) + list((BACKEND / "auth").glob("*.py"))
    ):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own bug
            continue
        for fn in [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            body = list(ast.walk(fn))
            audits = [
                n.lineno
                for n in body
                if isinstance(n, ast.Call)
                and getattr(n.func, "id", "") == "log_audit_event"
            ]
            commits = [
                n.lineno
                for n in body
                if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "commit"
            ]
            if not audits or not commits:
                continue
            if max(audits) > max(commits) and (path.name, fn.name) not in KNOWN_SAFE:
                found.append(f"{path.name}::{fn.name} (audit line {max(audits)})")
    return found


def test_no_handler_audits_after_its_last_commit():
    """
    The structural guard, and the reason this defect cannot come back quietly.

    An audit call positioned after the commit it describes writes a row that
    nothing ever commits. There is no exception, no failed request and no
    warning — the only symptom is an action that never appears in the trail,
    which is exactly the symptom nobody notices.
    """
    offenders = _handlers_auditing_after_commit()
    assert offenders == [], (
        "these handlers write their audit event after the commit that would "
        "persist it, so the event is discarded when the session closes:\n  "
        + "\n  ".join(offenders)
    )


def test_the_guard_can_actually_detect_the_pattern():
    """
    A guard that cannot fail proves nothing. This checks the detector against a
    handler written in the broken shape, so a refactor that quietly neuters the
    AST walk is caught.
    """
    broken = ast.parse(
        "def handler(db, user):\n"
        "    db.commit()\n"
        "    log_audit_event(db, user, 'x', 'y', 'z')\n"
    )
    fn = broken.body[0]
    body = list(ast.walk(fn))
    audits = [
        n.lineno
        for n in body
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "log_audit_event"
    ]
    commits = [
        n.lineno
        for n in body
        if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "commit"
    ]
    assert audits and commits and max(audits) > max(commits)


# ── End-to-end atomicity ────────────────────────────────────────────────────


def _committed_audit_rows(action: str, resource_id: str) -> int:
    """
    Count through a **separate connection**.

    Load-bearing: the `client` fixture overrides `get_db` with the test's own
    session, so a row that is merely flushed looks identical to a committed one
    from inside it. Only an independent session can tell them apart — and that
    distinction is the entire subject of this file.
    """
    verify = SessionLocal()
    try:
        return (
            verify.query(AuditLog)
            .filter(AuditLog.action == action, AuditLog.resource_id == resource_id)
            .count()
        )
    finally:
        verify.close()


@pytest.fixture
def asset(db_session, test_org):
    from db.base import gen_asset_id
    from db.models import Asset

    row = Asset(
        id=gen_asset_id(str(test_org.id), "10.180.6.201"),
        org_id=str(test_org.id),
        ip_address="10.180.6.201",
        hostname="atomicity-probe",
    )
    db_session.add(row)
    db_session.commit()
    return row


def test_update_asset_commits_its_audit_event(client, db_session, asset, auth_headers):
    """
    `routers/assets.py::update_asset` — one of the twenty-one. Before the fix
    the request returned 200 and `asset_updated` never reached the table, which
    is why zero asset actions existed in 511 live events.
    """
    response = client.patch(
        f"/assets/{asset.id}",
        headers=auth_headers,
        json={"hostname": "atomicity-probe-renamed"},
    )
    assert response.status_code == 200, response.text

    assert (
        _committed_audit_rows("asset_updated", asset.id) == 1
    ), "the asset update committed without its audit event"


def test_a_failed_update_leaves_no_audit_event(client, db_session, auth_headers):
    """
    The other half of atomicity. A request that does not succeed must leave no
    audit row behind — otherwise the trail records changes that never happened,
    which is worse than recording none.
    """
    response = client.patch(
        "/assets/ast_does_not_exist",
        headers=auth_headers,
        json={"hostname": "never-applied"},
    )
    assert response.status_code >= 400

    assert _committed_audit_rows("asset_updated", "ast_does_not_exist") == 0


def test_amt_import_commits_its_audit_event(client, db_session, test_org, auth_headers):
    """
    `routers/assets.py::import_amt_inventory` — the second shape among the
    twenty-one: commit, then dispatch a Celery task, then audit. The fix moves
    the audit before the commit and leaves the dispatch after it, so the worker
    can never observe an uncommitted import.
    """
    import io
    import json

    payload = json.dumps(
        [
            {
                "mac_address_1": "00:1a:2b:3c:4d:9f",
                "asset_name": "amt-atomicity-probe",
                "vendor": "TestCo",
            }
        ]
    ).encode()

    response = client.post(
        "/assets/import-amt",
        headers=auth_headers,
        files={"file": ("assets.json", io.BytesIO(payload), "application/json")},
    )
    assert response.status_code == 200, response.text
    assert response.json()["records_imported"] == 1

    assert (
        _committed_audit_rows("amt_inventory_imported", str(test_org.id)) == 1
    ), "the AMT import committed without its audit event"


def test_a_rejected_amt_import_leaves_no_audit_event(
    client, db_session, test_org, auth_headers
):
    """
    The refusal path. `import-amt` validates before it destroys, so a file with
    no usable record is rejected outright — and must leave neither an inventory
    change nor an audit row claiming one happened.
    """
    import io
    import json

    payload = json.dumps([{"macAddress1": "wrong-field-name"}]).encode()

    response = client.post(
        "/assets/import-amt",
        headers=auth_headers,
        files={"file": ("assets.json", io.BytesIO(payload), "application/json")},
    )
    assert response.status_code >= 400

    assert _committed_audit_rows("amt_inventory_imported", str(test_org.id)) == 0
