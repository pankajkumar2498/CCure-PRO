"""
The scan-creation service (scans/scan_creation.py), which G1's C1 moved out of
the credentialed route (docs/architecture/MODULAR_REFACTORING_LOG.md §6).

What the route did, and the service must keep doing: one scan row for every
host, recorded as a credentialed scan; the policy resolved in the same session
for a credentialed scan; one commit; the policy's section list where it names
one and the request's otherwise; and the policy summary the API reports at
acceptance. Found untested by a mutation check: dropping the request-sections
fallback passed every test in the scans and credentialed groups.
"""

from scans import scan_creation


class _Scan:
    id = "scn_created"
    scan_no = 7


class _Effective:
    policy_id = "spol_1"
    policy_name = "Linux baseline"
    source = "policy"

    def __init__(self, sections):
        self.sections = sections

    def fingerprint(self):
        return "fp-1"


class _Db:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def _create(monkeypatch, policy_sections, request_sections):
    created, resolved = {}, {}

    def create_scan(**kwargs):
        created.update(kwargs)
        return _Scan()

    def resolve_scan_policy(db, **kwargs):
        resolved.update(kwargs)
        return _Effective(policy_sections), {"sections": "policy"}

    # The service imports both when called, as the route's own imports did.
    monkeypatch.setattr("scans.db_helpers.create_scan", create_scan)
    monkeypatch.setattr("scans.policy_binding.resolve_scan_policy", resolve_scan_policy)
    db = _Db()
    result = scan_creation.create_credentialed_scan(
        db,
        user_id="usr_1",
        hosts=["10.0.0.5", "10.0.0.6"],
        org_id="org_1",
        policy_id="spol_1",
        sections=request_sections,
    )
    return result, created, resolved, db


def test_the_request_sections_apply_when_the_policy_names_none(monkeypatch):
    result, _, resolved, _ = _create(monkeypatch, (), ["packages", "users"])
    assert result.sections == ["packages", "users"]
    assert resolved["request_options"] == {"sections": ["packages", "users"]}


def test_the_policy_sections_win_where_the_policy_names_them(monkeypatch):
    result, _, _, _ = _create(monkeypatch, ("services",), ["packages"])
    assert result.sections == ["services"]


def test_one_row_for_every_host_resolved_as_a_credentialed_scan_and_committed_once(
    monkeypatch,
):
    result, created, resolved, db = _create(monkeypatch, (), None)
    assert created == {
        "db": created["db"],
        "user_id": "usr_1",
        "target": "10.0.0.5, 10.0.0.6",
        "targets": ["10.0.0.5", "10.0.0.6"],
        "scan_type": "credentialed",
        "pipeline_mode": "credentialed",
        "org_id": "org_1",
    }
    assert resolved["scan_kind"] == "credentialed"
    assert resolved["has_credential"] is True
    assert resolved["policy_id"] == "spol_1" and resolved["org_id"] == "org_1"
    assert db.commits == 1
    assert (result.scan_id, result.scan_no) == ("scn_created", 7)
    assert result.policy == {
        "policy_id": "spol_1",
        "policy_name": "Linux baseline",
        "fingerprint": "fp-1",
        "source": "policy",
        "overrides": {"sections": "policy"},
    }


def test_targets_expand_as_the_network_orchestrator_expands_them():
    from orchestrator.scan_orchestrator import ScanOrchestrator

    requested = ["10.0.0.0/30", "10.0.1.5"]
    assert scan_creation.expand_targets(requested) == ScanOrchestrator._expand_targets(
        requested
    )
    assert scan_creation.MAX_CREDENTIALED_TARGETS == 256
