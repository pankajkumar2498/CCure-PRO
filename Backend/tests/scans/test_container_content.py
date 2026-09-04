"""
tests/scans/test_container_content.py
─────────────────────────────────────────────────────────────────────────────
The shipped container rules, the YAML and TOML formats Phase 9 added, and the
GAP-17 denominator.

The boundary with GAP-09 is asserted here in code. GAP-09 owns the Docker
*daemon* configuration — daemon.json, the TCP socket, icc, userns-remap — and
counting those ten checks again under GAP-17 would inflate this phase by a
quarter before a line of it was written. Misattributing coverage between gaps
is a mistake this programme has had to correct twice.
"""

import pytest

from core.checks.definitions import (
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_CVE,
    definition_id_for_check,
    definition_type_for_id,
)
from core.config_audit.builtin import (
    BUILTIN_CHECKS,
    CONTAINER_CHECKS,
    MIDDLEWARE_CHECKS,
)
from core.config_audit.containers import CONTAINER_PROBES
from core.config_audit.engine import select_checks
from core.config_audit.spec import AbsencePolicy
from core.config_audit.structured import (
    ParseError,
    navigate,
    toml_pointer,
    yaml_pointer,
)
from scripts.measure_container_coverage import (
    NOT_PLANNED,
    SCOPE,
    SUPPORTED_RUNTIMES,
)

SCOPE_AREAS = {area for area, _t, _d in SCOPE}
_PROBE_CHECKS = [c for c in CONTAINER_CHECKS if c.check_type == "container"]
_FILE_CHECKS = [c for c in CONTAINER_CHECKS if c.check_type == "structured_config"]


# ── Shape ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("check", CONTAINER_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_runs_on_the_host_platform(check):
    """
    A container runtime is assessed over the *host's* credentialed session, so
    these are linux rules. The reserved ``container`` platform describes a
    container as a target in its own right, which this phase does not do.
    """
    assert check.platforms == ("linux",)
    assert check.requires_credentials is True


@pytest.mark.parametrize("check", CONTAINER_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_names_its_runtime_and_area(check):
    assert check.metadata.get("runtime") in SUPPORTED_RUNTIMES
    area = check.metadata.get("gap17_area")
    assert area, f"{check.check_id} claims no gap17_area"
    assert area in SCOPE_AREAS, (
        f"{check.check_id} claims area {area!r}, which is not in the frozen "
        f"GAP-17 denominator. The denominator is fixed; adding an area to it "
        f"to match what was built is inflating coverage."
    )


@pytest.mark.parametrize("check", _PROBE_CHECKS, ids=lambda c: c.check_id)
def test_every_probe_rule_names_a_probe_that_exists(check):
    assert check.collect["probe"] in CONTAINER_PROBES


@pytest.mark.parametrize("check", _PROBE_CHECKS, ids=lambda c: c.check_id)
def test_every_probe_rule_treats_an_empty_enumeration_as_a_pass(check):
    """
    A probe that found nothing is a real result, unlike a missing file. Any
    other policy would leave a correctly configured host with an unassessed
    control.
    """
    assert check.absent is AbsencePolicy.PASS


@pytest.mark.parametrize("check", _FILE_CHECKS, ids=lambda c: c.check_id)
def test_every_file_rule_uses_a_format_this_phase_added_and_a_pointer(check):
    assert check.collect["format"] in ("yaml", "toml")
    assert check.collect.get("pointer")
    paths = check.collect["path"]
    assert isinstance(paths, list) and len(paths) > 1


@pytest.mark.parametrize("check", CONTAINER_CHECKS, ids=lambda c: c.check_id)
def test_no_container_rule_is_filed_as_a_cve(check):
    assert check.finding_type == DEFINITION_TYPE_CONFIG_CHECK
    assert check.finding_type != DEFINITION_TYPE_CVE


@pytest.mark.parametrize("check", CONTAINER_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_mints_a_usable_identifier(check):
    minted = definition_id_for_check(check.check_id, check.finding_type)
    assert minted.startswith("CCURE-CFG-")
    assert len(minted) <= 120
    assert definition_type_for_id(minted) == DEFINITION_TYPE_CONFIG_CHECK


@pytest.mark.parametrize("check", CONTAINER_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_is_actionable(check):
    assert check.remediation.strip(), f"{check.check_id} has no remediation"
    assert check.rationale.strip(), f"{check.check_id} has no rationale"
    assert check.description.strip(), f"{check.check_id} has no description"


def test_ids_and_minted_identifiers_stay_unique_across_every_builtin():
    ids = [c.check_id for c in BUILTIN_CHECKS]
    assert len(ids) == len(set(ids))
    minted = [
        definition_id_for_check(c.check_id, c.finding_type) for c in BUILTIN_CHECKS
    ]
    assert len(minted) == len(set(minted))


# ── The GAP-09 boundary ──────────────────────────────────────────────────────


def test_the_docker_daemon_checks_stay_with_gap09():
    """
    daemon.json, the TCP socket, icc, userns-remap, insecure registries and the
    log driver were built and validated in GAP-09. This phase assesses what the
    daemon is *running*, not how the daemon is set up.
    """
    daemon = [c for c in MIDDLEWARE_CHECKS if c.metadata.get("middleware") == "docker"]
    assert len(daemon) == 10
    assert all(c.metadata.get("gap09_area") for c in daemon)
    assert not any(c.metadata.get("gap17_area") for c in daemon)


def test_no_container_rule_claims_a_gap09_area():
    for check in CONTAINER_CHECKS:
        assert not check.metadata.get("gap09_area"), check.check_id


def test_no_container_rule_reads_daemon_json():
    """The file GAP-09 owns must not be read by a rule counted here."""
    for check in _FILE_CHECKS:
        for path in check.collect["path"]:
            assert "daemon.json" not in path, check.check_id


# ── Coverage claims ──────────────────────────────────────────────────────────


def test_areas_recorded_as_not_planned_have_no_implementation():
    implemented = {c.metadata.get("gap17_area") for c in CONTAINER_CHECKS}
    overlap = implemented & set(NOT_PLANNED)
    assert not overlap, (
        f"areas {sorted(overlap)} are implemented but still listed in "
        f"NOT_PLANNED with a reason for not implementing them"
    )


def test_every_supported_runtime_ships_rules():
    covered = {c.metadata.get("runtime") for c in CONTAINER_CHECKS}
    assert covered == set(SUPPORTED_RUNTIMES)


def test_the_control_plane_areas_are_declared_and_mostly_unimplemented():
    """
    k3s runs the API server from process flags rather than a static manifest,
    and it is the only cluster that can be stood up disposably here. Writing
    those checks blind is what this records as refused.
    """
    control_plane = {a for a, theme, _d in SCOPE if theme == "controlplane"}
    unimplemented = control_plane & set(NOT_PLANNED)
    assert len(unimplemented) == 5
    # The sixth is answerable without a manifest, and is implemented.
    assert control_plane - unimplemented == {"k8s.apiserver.authorization_mode"}


# ── Selection ────────────────────────────────────────────────────────────────


def test_container_rules_are_selected_for_a_linux_host_audit():
    selected = {c.check_id for c in select_checks(BUILTIN_CHECKS, platform="linux")}
    assert {c.check_id for c in CONTAINER_CHECKS} <= selected


def test_container_rules_are_never_selected_for_windows_or_database():
    for platform in ("windows", "database"):
        selected = select_checks(BUILTIN_CHECKS, platform=platform)
        assert not [c for c in selected if c.check_type == "container"]


def test_the_check_type_matches_the_migration():
    """
    Migration b0c1d2e3f4a5 renders the vocabulary by hand, and this asserts it
    is still coherent with the model.

    **It deliberately does not assert equality.** It did, and Phase 10 broke it
    by adding ``scap_rule`` — the same way Phase 9 broke Phase 8's. A migration
    renders the vocabulary *as of that migration*, so pinning a historical one
    to the current model makes every later check type a failing test in a phase
    it has nothing to do with.

    What must hold forever is that this migration's list is a subset of the
    model's — a value here the model has since dropped would produce a
    constraint admitting something no rule can be — and that it adds exactly
    the value it exists to add. The stronger "equals the model" assertion
    belongs to the *newest* migration, and lives with it in
    ``test_scap_content.py``.
    """
    import importlib.util
    from pathlib import Path

    from db.models.compliance import RULE_CHECK_TYPES

    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "b0c1d2e3f4a5_container_check_type.py"
    )
    spec = importlib.util.spec_from_file_location("_gap17_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert set(module.CHECK_TYPES) <= set(RULE_CHECK_TYPES)
    assert "container" in module.CHECK_TYPES
    assert "container" not in module.OLD_CHECK_TYPES


# ── The YAML and TOML formats ────────────────────────────────────────────────

KUBELET_YAML = """
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  x509:
    clientCAFile: /var/lib/rancher/k3s/server/tls/client-ca.crt
authorization:
  mode: Webhook
readOnlyPort: 0
rotateCertificates: true
"""

CONTAINERD_TOML = """
version = 2
[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "rancher/mirrored-pause:3.6"
  [plugins."io.containerd.grpc.v1.cri".registry.configs."reg.internal:5000".tls]
    insecure_skip_verify = true
"""


def test_yaml_reads_a_kubelet_configuration():
    assert yaml_pointer(KUBELET_YAML, "authentication.anonymous.enabled") is False
    assert yaml_pointer(KUBELET_YAML, "authorization.mode") == "Webhook"
    assert yaml_pointer(KUBELET_YAML, "readOnlyPort") == 0
    assert yaml_pointer(KUBELET_YAML, "nothing.here") is None


def test_yaml_refuses_a_python_object_tag():
    """
    Only ``safe_load`` is ever called. The full loader constructs arbitrary
    Python objects from tags like ``!!python/object/apply``, which would be
    remote code execution in the scanner reading a file off a host it audits.
    """
    with pytest.raises(ParseError):
        yaml_pointer('!!python/object/apply:os.system ["echo pwned"]', "x")


def test_yaml_refuses_an_empty_document():
    """
    An empty file parses to None, which would navigate to None and be
    indistinguishable from a genuinely absent key.
    """
    with pytest.raises(ParseError):
        yaml_pointer("", "anything")


def test_toml_reads_a_containerd_configuration():
    assert toml_pointer(CONTAINERD_TOML, "version") == 2


def test_a_dotted_path_cannot_reach_containerds_quoted_keys():
    """
    The reason list pointers exist. ``[plugins."io.containerd.grpc.v1.cri"]``
    parses to a key literally named ``io.containerd.grpc.v1.cri``; a dotted
    path splits it into five segments that resolve to nothing — and "resolves
    to nothing" is ABSENT, which for most rules means "at the product default".
    So containerd would have reported clean however it was configured.
    """
    dotted = "plugins.io.containerd.grpc.v1.cri.sandbox_image"
    assert toml_pointer(CONTAINERD_TOML, dotted) is None

    as_list = ["plugins", "io.containerd.grpc.v1.cri", "sandbox_image"]
    assert toml_pointer(CONTAINERD_TOML, as_list) == "rancher/mirrored-pause:3.6"


def test_the_containerd_rule_uses_a_list_pointer():
    """The rule must actually use the form that works."""
    rule = next(
        c for c in _FILE_CHECKS if c.check_id.endswith("containerd.insecure_mirrors")
    )
    assert isinstance(rule.collect["pointer"], list)


def test_navigate_indexes_lists_and_returns_none_for_a_missing_path():
    document = {"a": [{"b": 1}, {"b": 2}]}
    assert navigate(document, "a.1.b") == 2
    assert navigate(document, ["a", "1", "b"]) == 2
    assert navigate(document, "a.9.b") is None
    assert navigate(document, "a.b") is None


def test_malformed_documents_raise_rather_than_resolving_to_nothing():
    with pytest.raises(ParseError):
        toml_pointer("this is not toml = = =", "x")
    with pytest.raises(ParseError):
        yaml_pointer("a:\n  - [unclosed\n", "a")
