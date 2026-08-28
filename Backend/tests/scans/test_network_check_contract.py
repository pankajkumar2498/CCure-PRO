"""
The network check contract — identifiers, typing, and the invariants.

GAP-06. These tests exist because of two production defects, and each one is
asserted from the direction that would have caught it:

  * six plugins detected real conditions and emitted no finding, because
    ``VulnerabilityEngine._merge`` promotes only a top-level ``cves`` key;
  * every network finding was filed in the catalogue as a fabricated CVE.
"""

import pytest

from core.checks.definitions import (
    DEFINITION_TYPE_CVE,
    DEFINITION_TYPE_PLUGIN_CHECK,
    definition_type_for_id,
    is_cve_id,
)
from engines.vulnerability.network_checks import (
    NETWORK_CHECKS,
    NetworkCheck,
    check_for_area,
    definition_ids,
    legacy_identifier_map,
    network_finding,
)
from scans.cvss import CANONICAL_SEVERITIES


# ─────────────────────────────────────────────────────────────────────────────
# The catalogue itself
# ─────────────────────────────────────────────────────────────────────────────
class TestCatalogueIntegrity:
    def test_every_area_is_unique(self):
        areas = [c.area for c in NETWORK_CHECKS]
        assert len(areas) == len(set(areas))

    def test_every_check_id_is_unique(self):
        ids = [c.check_id for c in NETWORK_CHECKS]
        assert len(ids) == len(set(ids))

    def test_every_definition_identifier_is_unique(self):
        ids = definition_ids()
        assert len(ids) == len(set(ids)), (
            "Two checks minting one identifier split that condition's finding "
            "history across two catalogue rows."
        )

    def test_every_severity_is_canonical(self):
        for check in NETWORK_CHECKS:
            assert check.severity in CANONICAL_SEVERITIES, check.area

    def test_every_non_dynamic_check_has_remediation(self):
        for check in NETWORK_CHECKS:
            if check.dynamic:
                continue
            assert check.remediation.strip(), (
                f"{check.area} has no remediation. A finding nobody can act on "
                "is a line in a report, not a finding."
            )

    def test_every_check_declares_the_plugin_that_produces_it(self):
        for check in NETWORK_CHECKS:
            assert check.plugin.strip(), check.area


# ─────────────────────────────────────────────────────────────────────────────
# Identifier typing — the defect this phase repairs
# ─────────────────────────────────────────────────────────────────────────────
class TestIdentifiersAreCorrectlyTyped:
    def test_no_check_mints_a_fabricated_cve(self):
        """
        The central assertion of this phase.

        A network check must never produce a CVE-shaped identifier for
        something that is not a published CVE. ``MISC-FTP-ANON`` was one, and
        because ``asset_syncer`` copied the identifier into ``cve_id`` and left
        ``definition_type`` at its ``'cve'`` default, it inherited KEV
        membership, EPSS scoring, CVSS bands and an NVD link.
        """
        for check in NETWORK_CHECKS:
            if check.dynamic:
                continue
            identifier = check.definition_id
            assert not identifier.upper().startswith("MISC-"), check.area
            if identifier.upper().startswith("CVE-"):
                assert is_cve_id(identifier), (
                    f"{check.area} produces {identifier!r}, which looks like a "
                    "CVE and is not one."
                )
                assert check.cve_id == identifier

    def test_a_real_cve_stays_a_real_cve(self):
        real = [c for c in NETWORK_CHECKS if c.cve_id]
        assert real, "The catalogue should still carry the genuine CVE checks."
        for check in real:
            assert is_cve_id(check.cve_id)
            assert check.definition_type == DEFINITION_TYPE_CVE
            assert check.definition_id == check.cve_id
            assert definition_type_for_id(check.definition_id) == DEFINITION_TYPE_CVE

    def test_every_other_check_is_a_plugin_check_with_no_cve(self):
        for check in NETWORK_CHECKS:
            if check.dynamic or check.cve_id:
                continue
            assert check.definition_type == DEFINITION_TYPE_PLUGIN_CHECK
            assert check.definition_id.startswith("CCURE-CHK-")
            assert (
                definition_type_for_id(check.definition_id)
                == DEFINITION_TYPE_PLUGIN_CHECK
            )

    def test_a_cve_shaped_cve_id_is_refused_at_construction(self):
        with pytest.raises(ValueError, match="well-formed CVE"):
            NetworkCheck(
                area="x.y",
                check_id="X-Y",
                title="t",
                severity="low",
                plugin="p",
                description="d",
                remediation="r",
                cve_id="MISC-NOT-A-CVE",
            )

    def test_a_dynamic_area_refuses_to_declare_a_type(self):
        """
        Nuclei files a CVE-tagged template as ``cve`` and an untagged one as
        ``plugin_check``. Reading either off the declaration would let a real
        CVE be filed as a check or a template id be filed as a CVE.
        """
        dynamic = [c for c in NETWORK_CHECKS if c.dynamic]
        assert dynamic
        for check in dynamic:
            with pytest.raises(ValueError):
                _ = check.definition_id
            with pytest.raises(ValueError):
                _ = check.definition_type


class TestLegacyIdentifiersHaveARoute:
    def test_every_legacy_identifier_maps_to_a_declared_check(self):
        mapping = legacy_identifier_map()
        assert mapping, "The fabricated identifiers must have somewhere to go."
        declared = set(definition_ids())
        for old, new in mapping.items():
            assert old.upper().startswith("MISC-"), old
            assert new in declared, f"{old} maps to {new}, which nothing declares."

    def test_the_migration_and_the_catalogue_agree(self):
        """
        ``e7f8a9b0c1d2`` carries the map as a literal rather than importing it,
        so that replaying the migration years from now does the same thing it
        does today. That duplication is only safe while this test holds.
        """
        import importlib.util
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[2]
            / "alembic"
            / "versions"
            / "e7f8a9b0c1d2_network_check_identifiers.py"
        )
        spec = importlib.util.spec_from_file_location("_gap06_migration", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert module.LEGACY_IDENTIFIERS == legacy_identifier_map(), (
            "The migration's identifier map has drifted from the catalogue. A "
            "stored finding would be repointed at a row nothing produces."
        )

    def test_two_identifiers_may_share_one_destination(self):
        """
        MISC-SMB-SIGNING and MISC-NUCLEI-SMB-SIGNING are two names for one
        condition. Merging them is intended; the migration resolves the
        resulting collision by keeping the longer history.
        """
        mapping = legacy_identifier_map()
        assert mapping["MISC-SMB-SIGNING"] == mapping["MISC-NUCLEI-SMB-SIGNING"]


# ─────────────────────────────────────────────────────────────────────────────
# Building a finding
# ─────────────────────────────────────────────────────────────────────────────
class TestNetworkFinding:
    def test_a_finding_carries_the_catalogue_identifier(self):
        record = network_finding(
            "ftp.anonymous_login", "230 Login successful", target="10.0.0.1:21", port=21
        )
        assert record["cve_id"] == "CCURE-CHK-FTP-ANONYMOUS-LOGIN"
        assert record["definition_type"] == DEFINITION_TYPE_PLUGIN_CHECK
        assert record["port"] == 21

    def test_a_finding_without_evidence_is_refused(self):
        """
        The Phase 0 invariant, reaching network checks. A FAIL asserted with
        nothing observed behind it is the direction that reaches a customer as
        a false positive.
        """
        with pytest.raises(ValueError, match="requires evidence"):
            network_finding("ftp.anonymous_login", "")
        with pytest.raises(ValueError, match="requires evidence"):
            network_finding("ftp.anonymous_login", "   \n  ")

    def test_evidence_is_carried_through_verbatim(self):
        record = network_finding(
            "ssh.weak_algorithms", "Weak KEX: diffie-hellman-group1-sha1"
        )
        assert "diffie-hellman-group1-sha1" in record["evidence"]

    def test_detection_method_is_active_check(self):
        """
        ``active_check`` maps to DetectionMethod.CONFIG_CHECK — QoD 99,
        Confirmed — and is in the normalizer's AUTHORITATIVE set, which lets
        the finding bypass the CPE version-range test. Without it, a check that
        observed a condition directly would be withheld as unverified because
        it has no version to range-check.
        """
        record = network_finding("smb.v1_enabled", "SMBv1 magic in negotiate reply")
        assert record["detection_method"] == "active_check"

    def test_severity_may_be_overridden_with_a_canonical_value(self):
        default = network_finding("snmp.default_community", "public accepted")
        raised = network_finding(
            "snmp.default_community", "private accepted", severity="critical"
        )
        assert default["severity"] == "high"
        assert raised["severity"] == "critical"

    def test_an_unknown_area_names_what_is_available(self):
        with pytest.raises(KeyError, match="Declared areas"):
            network_finding("nonsense.area", "evidence")

    def test_a_dynamic_area_cannot_be_built_from_the_catalogue(self):
        with pytest.raises(ValueError, match="per finding"):
            network_finding("nuclei.template_verification", "evidence")

    def test_check_for_area_round_trips(self):
        for check in NETWORK_CHECKS:
            assert check_for_area(check.area) is check
