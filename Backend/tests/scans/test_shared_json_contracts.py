"""
Shape contracts for the JSON keys more than one capability reads or writes.

Phases and capabilities hand data to one another through JSON columns —
``scans.options``, ``assets.custom_attributes`` — rather than typed values
(docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md §6.3). Those keys are
contracts in all but name, and until now nothing checked that what one
capability writes is what another reads.

These pin **shape only**, for the keys whose contract the code itself
establishes: the writer's output, the keys the readers consume, and what a
reader does with a legacy record that lacks the key — always "not recorded" or
"not assessed", never a default that reads as a result. Nothing here changes a
stored record, renames a key or alters behaviour.

Keys whose contract is not pinned here, and why, are listed in
docs/architecture/MODULAR_REFACTORING_LOG.md (Phase A, A3).
"""

import ast
from types import SimpleNamespace

import pytest
from testpaths import BACKEND_ROOT

#: The scan tasks' source, which was core/tasks.py until G1 split it into
#: scans/tasks/ (core/tasks.py is now a facade that re-exports them). A check
#: over "the hub" reads all of these, so it sees what it saw before the split.
SCAN_TASK_MODULES = tuple(
    str(path.relative_to(BACKEND_ROOT))
    for path in sorted((BACKEND_ROOT / "scans" / "tasks").glob("*.py"))
)


def _scan(options=None):
    return SimpleNamespace(id="scn_contract", options=options)


# ─────────────────────────────────────────────────────────────────────────────
# scans.options["scan_policy"] — written at dispatch by core.scan_policy,
# read by the worker, the reports (pdf_generator, exports), the comparison and
# a JSONB query in routers/scan_policies.py.
# ─────────────────────────────────────────────────────────────────────────────

#: The stored snapshot, exactly (core.scan_policy.snapshot.snapshot_payload).
SNAPSHOT_KEYS = {
    "recorded",
    "policy_id",
    "policy_name",
    "policy_family_code",
    "version_number",
    "scan_kind",
    "source",
    "fingerprint",
    "effective",
}

#: Keys readers take straight off the stored dict rather than through
#: read_policy_snapshot: pdf_generator (recorded, policy_name, fingerprint),
#: the policy-usage query in routers/scan_policies.py (policy_id).
RAW_READER_KEYS = {"recorded", "policy_name", "fingerprint", "policy_id"}


@pytest.fixture
def request_policy():
    from core.scan_policy.resolver import effective_for_request

    return effective_for_request({"custom_ports": "22,80", "exclude_ports": "8080"})


def test_the_policy_snapshot_has_exactly_its_recorded_keys(request_policy):
    from core.scan_policy.snapshot import snapshot_payload

    payload = snapshot_payload(request_policy)
    assert set(payload) == SNAPSHOT_KEYS
    assert payload["recorded"] is True
    assert isinstance(payload["effective"], dict)
    assert isinstance(payload["fingerprint"], str) and payload["fingerprint"]


def test_every_key_a_raw_reader_takes_is_written():
    assert RAW_READER_KEYS <= SNAPSHOT_KEYS


def test_the_snapshot_round_trips_to_the_same_policy(request_policy):
    from core.scan_policy.snapshot import read_policy_snapshot, record_policy_snapshot

    scan = _scan({"origin": "schedule"})
    assert record_policy_snapshot(scan, request_policy) is True
    # Siblings in the same column survive the write.
    assert scan.options["origin"] == "schedule"
    assert read_policy_snapshot(scan).fingerprint() == request_policy.fingerprint()


@pytest.mark.parametrize(
    "options",
    [
        None,
        {},
        {"scan_policy": None},
        {"scan_policy": {}},
        {"scan_policy": {"recorded": False}},
    ],
)
def test_a_scan_without_a_snapshot_has_no_policy(options):
    """A pre-GAP-12 scan was configured by its request; inventing a policy for
    it would put a claim in a report that nothing supports."""
    from core.findings.comparison import policies_comparable, policy_context
    from core.scan_policy.snapshot import read_policy_snapshot

    scan = _scan(options)
    assert read_policy_snapshot(scan) is None
    context = policy_context(scan)
    assert context == {"recorded": False}
    # Two unknown configurations are not equivalent ones.
    assert policies_comparable(context, context) is False


# ─────────────────────────────────────────────────────────────────────────────
# scans.options["assessment_scope"] — written by scans/tasks/ and the package
# matcher through core.findings.record_assessment_scope, read by the scan
# comparison and so by remediation verification.
# ─────────────────────────────────────────────────────────────────────────────


def test_assessment_scope_has_its_recorded_shape():
    from core.findings import read_assessment_scope, record_assessment_scope

    scan = _scan({"scan_policy": {"recorded": True}})
    record_assessment_scope(
        scan,
        assets=["ast_b", "ast_a"],
        families=["credentialed_package"],
        detail={"assessed_checks": ["CCURE-CFG-X"]},
    )
    stored = scan.options["assessment_scope"]
    assert set(stored) == {"recorded", "assets", "families", "detail"}
    assert stored["recorded"] is True
    assert stored["assets"] == ["ast_a", "ast_b"]  # sorted, strings
    assert stored["families"] == ["credentialed_package"]
    assert scan.options["scan_policy"] == {"recorded": True}  # sibling kept

    scope = read_assessment_scope(scan)
    assert scope.covers("ast_a", "credentialed_package")
    assert scope.assessed_checks == frozenset({"CCURE-CFG-X"})


def test_assessment_scope_merges_rather_than_replaces():
    """One scan records scope from several paths; the second must not erase
    the first's account of what it looked at."""
    from core.findings import read_assessment_scope, record_assessment_scope

    scan = _scan()
    record_assessment_scope(
        scan, assets=["ast_a"], families=["network_service"], detail={"x": 1}
    )
    record_assessment_scope(
        scan, assets=["ast_b"], families=["credentialed_package"], detail={"y": 2}
    )
    scope = read_assessment_scope(scan)
    assert set(scope.assets) == {"ast_a", "ast_b"}
    assert set(scope.families) == {"network_service", "credentialed_package"}
    assert dict(scope.detail) == {"x": 1, "y": 2}


@pytest.mark.parametrize(
    "options",
    [
        None,
        {},
        {"assessment_scope": None},
        {"assessment_scope": {"recorded": False, "families": ["network_service"]}},
    ],
)
def test_an_unrecorded_scope_covers_nothing(options):
    """ "We do not know what this scan looked at" never becomes a fix."""
    from core.findings import read_assessment_scope

    scope = read_assessment_scope(_scan(options))
    assert scope.recorded is False
    assert scope.covers("ast_a", "network_service") is False


@pytest.mark.parametrize("raw", [None, "CCURE-CFG-X", {"a": 1}, 42])
def test_a_scope_without_a_check_list_restricts_no_check(raw):
    """A scope recorded before GAP-15, or with a malformed check list, does not
    silently reclassify every historical comparison."""
    from core.findings import read_assessment_scope

    detail = {} if raw is None else {"assessed_checks": raw}
    scope = read_assessment_scope(
        _scan(
            {
                "assessment_scope": {
                    "recorded": True,
                    "assets": ["ast_a"],
                    "families": ["credentialed_package"],
                    "detail": detail,
                }
            }
        )
    )
    assert scope.assessed_checks == frozenset()
    assert scope.covers_check("CCURE-CFG-ANYTHING") is True


# ─────────────────────────────────────────────────────────────────────────────
# scans.options["credentials"] — written by the host-discovery request (the
# only writer), read by the credentialed pass in scans/tasks/. Both sides use
# core.credential_scope, so a stored plan is one the reader accepts.
# ─────────────────────────────────────────────────────────────────────────────


def test_the_credential_plan_writer_and_reader_share_one_validator():
    def calls(path, name):
        tree = ast.parse((BACKEND_ROOT / path).read_text(encoding="utf-8"))
        return any(
            isinstance(node, ast.Name) and node.id == name for node in ast.walk(tree)
        )

    assert calls("routers/phase_scans.py", "validate_credential_options")
    assert any(calls(path, "credential_plan_entries") for path in SCAN_TASK_MODULES)


@pytest.mark.parametrize(
    "plan",
    [
        [{"credential_id": "ccrd_a"}],
        [{"credential_id": "ccrd_a", "targets": ["10.0.0.0/24", "10.0.1.5"]}],
    ],
)
def test_a_plan_the_writer_accepts_the_reader_resolves(plan):
    from core.credential_scope import (
        credential_plan_entries,
        validate_credential_options,
    )

    assert validate_credential_options({"credentials": plan})["credentials"] == plan
    entries = credential_plan_entries(plan)
    assert [credential_id for credential_id, _ in entries] == ["ccrd_a"]


def test_a_scan_without_a_plan_gets_no_credentialed_pass():
    from core.credential_scope import validate_credential_options
    from scans.tasks.credentialed import _credentialed_plan_for_scan

    assert validate_credential_options({}) == {}
    assert _credentialed_plan_for_scan(None, _scan(None)) == []
    assert _credentialed_plan_for_scan(None, _scan({})) == []


# ─────────────────────────────────────────────────────────────────────────────
# Port-scan options — written by POST /scan/asset-discovery
# (routers/phase_scans.py) and forwarded from a schedule by
# core/scheduling/dispatcher.py; read back from scans.options by the phase
# tasks in scans/tasks/ when not passed explicitly.
# ─────────────────────────────────────────────────────────────────────────────

PIPELINE_KEYS = {
    "custom_ports",
    "exclude_ports",
    "exclude_ot_from_nmap",
    "passive_first",
    "exclude_ips",
}

#: What a phase task assumes when a scan row does not carry the key — the
#: legacy and the "nobody said" case. Pinned because flipping one silently
#: changes what an old scan's continuation scans.
READER_DEFAULTS = {"exclude_ot_from_nmap": True, "passive_first": False}


def _option_subscript_writes(path: str) -> set[str]:
    tree = ast.parse((BACKEND_ROOT / path).read_text(encoding="utf-8"))
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "options"
                    and isinstance(target.slice, ast.Constant)
                ):
                    keys.add(target.slice.value)
    return keys


def _scan_row_option_reads(path: str) -> dict[str, object]:
    """``scan_row.options.get("key"[, default])`` calls: key -> default."""
    tree = ast.parse((BACKEND_ROOT / path).read_text(encoding="utf-8"))
    reads: dict[str, object] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and ast.unparse(node.func.value) == "scan_row.options"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            default = (
                node.args[1].value
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                else None
            )
            reads.setdefault(node.args[0].value, default)
    return reads


def _dispatcher_forwarded_keys() -> set[str]:
    tree = ast.parse(
        (BACKEND_ROOT / "core/scheduling/dispatcher.py").read_text(encoding="utf-8")
    )
    keys = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.keyword)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "get"
            and ast.unparse(node.value.func.value) == "options"
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and node.arg == node.value.args[0].value
        ):
            keys.add(node.arg)
    return keys


def _scan_task_option_reads() -> dict[str, object]:
    reads: dict[str, object] = {}
    for path in SCAN_TASK_MODULES:
        reads.update(_scan_row_option_reads(path))
    return reads


def test_every_port_option_a_phase_task_reads_is_written_by_the_route():
    reads = _scan_task_option_reads()
    read_pipeline_keys = set(reads) & PIPELINE_KEYS
    assert read_pipeline_keys == PIPELINE_KEYS
    assert PIPELINE_KEYS <= _option_subscript_writes("routers/phase_scans.py")


def test_a_schedule_forwards_every_port_option_under_its_own_name():
    assert PIPELINE_KEYS <= _dispatcher_forwarded_keys()


def test_a_missing_port_option_means_the_documented_default():
    reads = _scan_task_option_reads()
    for key, default in READER_DEFAULTS.items():
        assert reads[key] is default, key


# ─────────────────────────────────────────────────────────────────────────────
# assets.custom_attributes["credentialed_status"] and ["password_policy"] —
# written by the credentialed pass (scans/tasks/, scans.asset_syncer), read by
# the compliance engine (core.compliance_evidence, core.compliance_tasks).
# ─────────────────────────────────────────────────────────────────────────────


def test_credentialed_status_is_recorded_without_disturbing_other_attributes():
    from scans.asset_syncer import (
        CREDENTIALED_STATUS_FAILED,
        CREDENTIALED_STATUS_SUCCESS,
        set_credentialed_status,
    )

    assert (CREDENTIALED_STATUS_SUCCESS, CREDENTIALED_STATUS_FAILED) == (
        "success",
        "failed",
    )
    before = {"provenance": {"os_name": "nmap"}}
    asset = SimpleNamespace(custom_attributes=before)
    set_credentialed_status(asset, CREDENTIALED_STATUS_SUCCESS)
    assert asset.custom_attributes == {
        "provenance": {"os_name": "nmap"},
        "credentialed_status": "success",
    }
    # Reassigned, not mutated: an in-place edit of a JSONB dict is not flushed.
    assert asset.custom_attributes is not before


def _status_literals_written(path: str) -> set:
    """Values assigned to a ``["credentialed_status"]`` subscript in *path*."""
    tree = ast.parse((BACKEND_ROOT / path).read_text(encoding="utf-8"))
    values = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "credentialed_status"
                ):
                    values.add(ast.unparse(node.value))
    return values


def test_every_status_written_is_in_the_vocabulary():
    allowed = {
        "CREDENTIALED_STATUS_SUCCESS",
        "CREDENTIALED_STATUS_FAILED",
        "status",  # set_credentialed_status's own parameter
    }
    for path in (*SCAN_TASK_MODULES, "scans/asset_syncer.py"):
        assert _status_literals_written(path) <= allowed, path


class _OneAssetDb:
    """Just enough of a Session for an adapter that loads one asset."""

    def __init__(self, asset):
        self._asset = asset

    def query(self, *_):
        return self

    def filter(self, *_):
        return self

    def first(self):
        return self._asset


@pytest.mark.parametrize(
    "attributes, successful",
    [
        (None, False),
        ({}, False),
        ({"credentialed_status": "failed"}, False),
        ({"credentialed_status": "success"}, True),
    ],
)
def test_only_success_counts_as_authenticated_and_nothing_is_defaulted(
    attributes, successful
):
    from core.compliance_evidence import ComplianceEvidenceProvider

    asset = SimpleNamespace(custom_attributes=attributes)
    payload = ComplianceEvidenceProvider._adapt_credential_validation(
        _OneAssetDb(asset), "ast_contract"
    )
    # An uncollected password policy is absent, never False/0/8.
    assert payload == {"credentialed_scan_successful": successful}


def _dict_literal_keys_in(path: str, function: str, anchor: str) -> set[str]:
    """Keys of the dict literal in *function* that holds the *anchor* key."""
    tree = ast.parse((BACKEND_ROOT / path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            for inner in ast.walk(node):
                if isinstance(inner, ast.Dict):
                    keys = {
                        k.value
                        for k in inner.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)
                    }
                    if anchor in keys:
                        return keys
    raise AssertionError(f"no dict literal holding {anchor!r} in {path}::{function}")


def _password_policy_reads() -> set[str]:
    tree = ast.parse(
        (BACKEND_ROOT / "core/compliance_evidence.py").read_text(encoding="utf-8")
    )
    reads = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and ast.unparse(node.func.value) == "pwd_attrs"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            reads.add(node.args[0].value)
    return reads


def test_password_policy_keys_written_are_the_keys_compliance_reads():
    written = _dict_literal_keys_in(
        "scans/tasks/credentialed_sync.py",
        "_sync_credentialed_asset_identity",
        "lockout_threshold",
    )
    assert written == {
        "complexity",
        "history_length",
        "min_length",
        "max_age_days",
        "lockout_threshold",
    }
    assert _password_policy_reads() == written


def test_a_collected_password_policy_reaches_compliance_key_by_key():
    from core.compliance_evidence import ComplianceEvidenceProvider

    asset = SimpleNamespace(
        custom_attributes={
            "credentialed_status": "success",
            "password_policy": {"min_length": 14, "lockout_threshold": 5},
        }
    )
    payload = ComplianceEvidenceProvider._adapt_credential_validation(
        _OneAssetDb(asset), "ast_contract"
    )
    assert payload == {
        "credentialed_scan_successful": True,
        "minimum_password_length": 14,
        "account_lockout_threshold": 5,
    }
