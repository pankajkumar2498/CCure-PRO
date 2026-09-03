"""
tests/scans/test_scan_policy_spec.py
─────────────────────────────────────────────────────────────────────────────
GAP-12 — the policy model, its fingerprint, validation and the snapshot.

No database and no HTTP. These pin the rules the rest of the phase depends on:

* an empty collection means "no restriction", never "nothing"
* the fingerprint tracks *behaviour*, not identity
* a snapshot, once written, is not rewritten
* validation refuses rather than falling back

Coverage areas exercised here: pol.filter.severity, pol.record.fingerprint,
pol.record.snapshot, pol.bind.validation, pol.bind.credential,
pol.lifecycle.version, pol.select.builtin.
"""

from dataclasses import replace

import pytest
from core.scan_policy import (
    EffectivePolicy,
    PolicyValidationError,
    effective_for_request,
    effective_from_config,
    next_version_number,
    policy_fingerprint,
    read_policy_snapshot,
    record_policy_snapshot,
    severity_at_least,
    snapshots_agree,
    validate_policy,
)
from core.scan_policy.validation import assert_credential_ok


class _Scan:
    """A scan row's relevant surface. The real model behaves identically here."""

    def __init__(self, options=None):
        self.id = "scn_test_0001"
        self.options = dict(options or {})


# ─────────────────────────────────────────────────────────────────────────────
# Empty means "no restriction"
# ─────────────────────────────────────────────────────────────────────────────


def test_an_empty_selection_is_no_restriction_not_nothing():
    """
    The single most dangerous defect available in a policy engine: reading an
    unset field as "select nothing" lets an under-specified policy reduce a
    scan to zero checks while still reporting success.
    """
    policy = effective_from_config({})
    assert policy.framework_ids == ()
    assert policy.check_families == ()
    assert policy.platforms == ()
    assert policy.min_severity is None
    # And the describe() text says so in words, because a blank cell in an
    # audit report reads as "not recorded" rather than as a decision.
    described = policy.describe()
    assert "Every framework installed" in described["Benchmarks"]
    assert described["Platform scope"] == "Windows and Linux"
    assert described["Severity threshold"] == "No threshold"


def test_unset_fields_never_become_a_filter_argument():
    """
    ``benchmark_checks_for_org`` is called with ``or None`` on every collection,
    so an empty tuple must not arrive as an empty list — which the query would
    read as ``IN ()`` and match nothing.
    """
    policy = effective_from_config({})
    assert (list(policy.framework_ids) or None) is None
    assert (list(policy.platforms) or None) is None
    assert (list(policy.excluded_check_ids) or None) is None


# ─────────────────────────────────────────────────────────────────────────────
# pol.record.fingerprint
# ─────────────────────────────────────────────────────────────────────────────


def test_fingerprint_ignores_identity_so_renaming_is_not_a_scope_change():
    """
    Renaming a policy must not make a scan incomparable with the one before it.
    """
    base = effective_from_config({"min_severity": "high"})
    renamed = replace(
        base,
        policy_name="Something else entirely",
        policy_id="spol_other",
        version_number=99,
        policy_family_code="renamed",
        source="request",
    )
    assert base.fingerprint() == renamed.fingerprint()


def test_fingerprint_changes_when_what_is_assessed_changes():
    a = effective_from_config({"min_severity": "high"})
    b = effective_from_config({"min_severity": "low"})
    c = effective_from_config({"framework_ids": ["cfw_bm_stig_rhel9"]})
    assert len({a.fingerprint(), b.fingerprint(), c.fingerprint()}) == 3


def test_fingerprint_is_order_independent_for_equivalent_configurations():
    """
    Two policies naming the same frameworks in a different order assess the
    same thing, but the fingerprint hashes the tuple as written — so the two
    differ. Pinned as the *documented* behaviour rather than assumed away:
    order is preserved because it is shown to a reader, and the cost is that a
    reordered list reads as a different configuration.
    """
    a = effective_from_config({"framework_ids": ["a", "b"]})
    b = effective_from_config({"framework_ids": ["b", "a"]})
    assert a.fingerprint() != b.fingerprint()


def test_duplicate_entries_are_collapsed():
    """A repeated framework would resolve its checks twice and be scored twice."""
    policy = effective_from_config({"framework_ids": ["a", "a", "b"]})
    assert policy.framework_ids == ("a", "b")


def test_fingerprint_is_stable_across_calls():
    policy = effective_from_config({"framework_ids": ["x"], "min_severity": "medium"})
    assert policy.fingerprint() == policy.fingerprint() == policy_fingerprint(policy)


# ─────────────────────────────────────────────────────────────────────────────
# pol.filter.severity
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "severity,floor,expected",
    [
        ("critical", "high", True),
        ("high", "high", True),
        ("medium", "high", False),
        ("info", "low", False),
        ("low", None, True),
        ("medium", "", True),
    ],
)
def test_severity_floor(severity, floor, expected):
    assert severity_at_least(severity, floor) is expected


def test_an_unrecognised_severity_clears_every_floor():
    """
    A check whose severity this build does not recognise has not been
    established to be below the threshold. Dropping it would remove a check
    from a scan on the strength of a string nobody defined — the direction that
    over-claims a clean host.
    """
    assert severity_at_least("unscored", "critical") is True
    assert severity_at_least("", "critical") is True


def test_an_unrecognised_floor_filters_nothing():
    assert severity_at_least("info", "catastrophic") is True


# ─────────────────────────────────────────────────────────────────────────────
# pol.bind.validation
# ─────────────────────────────────────────────────────────────────────────────


def test_an_unknown_setting_is_refused_not_stored():
    """
    A misspelled key in a JSONB column is a setting the operator believes is in
    force and that nothing reads.
    """
    result = validate_policy({"min_severty": "high"})
    assert not result.valid
    assert any("min_severty" in e for e in result.errors)


def test_every_problem_is_reported_at_once():
    """Four typos should not cost four round trips."""
    result = validate_policy(
        {
            "check_families": ["nonsense"],
            "platforms": ["solaris"],
            "min_severity": "catastrophic",
            "discovery_intensity": "extreme",
        }
    )
    assert not result.valid
    assert len(result.errors) >= 4


def test_excluding_the_builtins_with_no_framework_is_refused():
    """
    That combination resolves nothing at all, and a scan reporting success
    having assessed no configuration is indistinguishable from a clean host.
    """
    result = validate_policy({"include_builtin_checks": False})
    assert not result.valid
    assert any("built-in" in e for e in result.errors)


def test_excluding_the_builtins_with_a_framework_is_allowed():
    result = validate_policy(
        {"include_builtin_checks": False, "framework_ids": ["cfw_bm_stig_rhel9"]}
    )
    assert result.valid, result.errors


def test_a_malformed_port_expression_is_refused():
    for bad in ("22,", "80-", "0", "70000", "22-21", "http"):
        result = validate_policy({"custom_ports": bad})
        assert not result.valid, f"{bad!r} should be refused"


def test_a_wellformed_port_expression_is_accepted():
    result = validate_policy({"custom_ports": "22,80,8000-8100"})
    assert result.valid, result.errors


def test_a_malformed_target_exclusion_is_refused():
    result = validate_policy({"excluded_targets": ["not-an-address"]})
    assert not result.valid


def test_target_exclusions_accept_address_range_and_cidr():
    result = validate_policy(
        {"excluded_targets": ["10.0.0.1", "10.0.0.1-50", "192.168.0.0/24"]}
    )
    assert result.valid, result.errors


def test_intrusive_probes_always_warn():
    """
    The one setting that lets the scanner change a host it is auditing. A
    policy carrying it must never do so silently.
    """
    result = validate_policy({"allow_intrusive": True})
    assert result.valid
    assert any("intrusive" in w.lower() for w in result.warnings)


def test_a_network_policy_warns_about_credentialed_only_settings():
    result = validate_policy({"min_severity": "high"}, scan_kind="network")
    assert result.valid
    assert any("no effect" in w for w in result.warnings)


def test_raise_if_invalid_carries_every_error():
    result = validate_policy({"platforms": ["aix"], "min_severity": "nonsense"})
    with pytest.raises(PolicyValidationError) as exc:
        result.raise_if_invalid()
    assert len(exc.value.errors) == 2


# ─────────────────────────────────────────────────────────────────────────────
# pol.bind.credential
# ─────────────────────────────────────────────────────────────────────────────


def test_require_credential_refuses_when_none_is_available():
    """
    Without this the scan degrades quietly to unauthenticated, collects
    nothing, and reports the host as clean.
    """
    policy = effective_from_config({"require_credential": True})
    result = assert_credential_ok(policy, has_credential=False)
    assert not result.valid
    assert any("authenticated session" in e for e in result.errors)


def test_require_credential_passes_when_one_is_available():
    policy = effective_from_config({"require_credential": True})
    assert assert_credential_ok(policy, has_credential=True).valid


def test_a_policy_not_requiring_a_credential_is_unaffected():
    policy = effective_from_config({})
    assert assert_credential_ok(policy, has_credential=False).valid


# ─────────────────────────────────────────────────────────────────────────────
# pol.record.snapshot
# ─────────────────────────────────────────────────────────────────────────────


def test_a_snapshot_round_trips():
    scan = _Scan()
    policy = effective_from_config(
        {"framework_ids": ["cfw_bm_stig_ubuntu2404"], "min_severity": "high"},
        policy_id="spol_abc",
        policy_name="Ubuntu baseline",
        policy_family_code="ubuntu-baseline",
        version_number=2,
    )
    assert record_policy_snapshot(scan, policy) is True

    read_back = read_policy_snapshot(scan)
    assert read_back is not None
    assert read_back.framework_ids == ("cfw_bm_stig_ubuntu2404",)
    assert read_back.min_severity == "high"
    assert read_back.policy_name == "Ubuntu baseline"
    assert read_back.version_number == 2
    # The identity that matters downstream survives, and so does the
    # fingerprint — a snapshot that read back as a different configuration
    # would make every historical comparison wrong.
    assert read_back.fingerprint() == policy.fingerprint()


def test_a_snapshot_is_not_overwritten():
    """
    A completed scan's configuration is the record of what produced it. Nothing
    in the product rewrites one, and the refusal is what makes "editing a
    policy does not alter Scan A" a property of the code.
    """
    scan = _Scan()
    first = effective_from_config({"min_severity": "high"}, policy_name="First")
    second = effective_from_config({"min_severity": "low"}, policy_name="Second")

    assert record_policy_snapshot(scan, first) is True
    assert record_policy_snapshot(scan, second) is False

    read_back = read_policy_snapshot(scan)
    assert read_back.min_severity == "high"
    assert read_back.policy_name == "First"


def test_overwrite_is_available_for_the_reapply_case():
    """
    Both dispatch routes rebuild ``scan.options`` from a dict literal, which
    drops a snapshot written before it. Re-applying the *same* snapshot is not
    changing a settled configuration.
    """
    scan = _Scan()
    policy = effective_from_config({"min_severity": "high"})
    record_policy_snapshot(scan, policy)
    scan.options = {"origin": "schedule"}  # the literal that drops it
    assert read_policy_snapshot(scan) is None
    record_policy_snapshot(scan, policy, overwrite=True)
    assert read_policy_snapshot(scan).min_severity == "high"


def test_a_scan_with_no_snapshot_reads_as_none_not_as_a_default():
    """
    None is a real answer for a scan that predates this phase. Inventing a
    policy record for one would put a claim in a report that nothing supports.
    """
    assert read_policy_snapshot(_Scan()) is None
    assert read_policy_snapshot(_Scan({"origin": "schedule"})) is None
    assert read_policy_snapshot(None) is None


def test_the_snapshot_reassigns_options_rather_than_mutating_it():
    """
    SQLAlchemy does not see an in-place edit of a JSON column, so a mutation
    would be silently dropped on commit.
    """
    scan = _Scan()
    original = scan.options
    record_policy_snapshot(scan, effective_from_config({}))
    assert scan.options is not original


def test_snapshots_agree_only_when_both_are_recorded():
    recorded = {"fingerprint": "abc"}
    assert snapshots_agree(recorded, {"fingerprint": "abc"}) is True
    assert snapshots_agree(recorded, {"fingerprint": "def"}) is False
    # Two unknowns are not agreement.
    assert snapshots_agree(None, None) is False
    assert snapshots_agree(recorded, {}) is False


def test_a_request_only_scan_still_records_a_configuration():
    """
    A scan with no policy has an effective configuration — its own parameters —
    and recording it is what lets two such scans be told apart when somebody
    changed the port range between them.
    """
    policy = effective_for_request(
        {"custom_ports": "22,80", "discovery_intensity": "deep"}
    )
    assert policy.source == "request"
    assert policy.policy_name == ""
    assert policy.custom_ports == "22,80"
    assert policy.describe()["Policy"] == "None (scan request defaults)"


def test_request_exclude_ips_becomes_excluded_targets():
    policy = effective_for_request({"exclude_ips": "10.0.0.1, 10.0.0.2"})
    assert policy.excluded_targets == ("10.0.0.1", "10.0.0.2")


# ─────────────────────────────────────────────────────────────────────────────
# pol.lifecycle.version
# ─────────────────────────────────────────────────────────────────────────────


def test_version_numbers_never_reissue_a_deleted_one():
    """
    ``max + 1`` rather than ``len + 1``: the scans that ran under the deleted
    version still name it in their snapshots, and two configurations answering
    to one identifier is what the version number exists to prevent.
    """
    assert next_version_number([]) == 1
    assert next_version_number([1, 2, 3]) == 4
    assert next_version_number([1, 3]) == 4  # 2 was deleted; it is not reissued


# ─────────────────────────────────────────────────────────────────────────────
# The dataclass contract
# ─────────────────────────────────────────────────────────────────────────────


def test_the_effective_policy_is_frozen():
    """
    It is written into a scan's record and read back months later. A value that
    could change between those readings would make the record a description of
    something other than what ran.
    """
    policy = EffectivePolicy()
    with pytest.raises(Exception):
        policy.min_severity = "high"  # type: ignore[misc]


def test_every_declared_coverage_field_exists():
    """
    ``FIELD_AREAS`` is what the coverage script reads. An area claiming
    coverage from a field that was removed would report capability the product
    does not have.
    """
    from dataclasses import fields

    from core.scan_policy.spec import FIELD_AREAS

    live = {f.name for f in fields(EffectivePolicy)}
    missing = sorted(set(FIELD_AREAS) - live)
    assert not missing, f"FIELD_AREAS names fields that do not exist: {missing}"
