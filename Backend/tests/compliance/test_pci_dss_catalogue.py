"""
The PCI DSS catalogue — corrected on 28 Sep 2026, switched on, and parked again
the same day when the work was narrowed to ISO.

Three things were put right before it could be offered, and each is pinned
here:

* **Its requirement numbers.** Checked against PCI DSS v4.0.1: 16 of the 62
  entries described one requirement under another's number — every "Roles and
  responsibilities" entry sat at X.1.1, which is the policies-and-procedures
  requirement; the standard puts roles at X.1.2 — and the stored number was an
  internal key (``pci_10_1_1``) rather than the standard's (``10.1.1``).
* **What its controls inherit.** Only rules that evaluate something cross a
  crosswalk; ISO's attestation placeholders no longer land on PCI controls.
* **Unrecorded facts.** Five evidence keys read only by PCI rules defaulted to
  False, so every host nobody had checked failed the requirement.

It is a selection of the standard's requirements, and its name says so: a
score over 62 requirements must not read as a score over all of PCI DSS.
"""

from __future__ import annotations

import json
import re
import uuid

from core import compliance_frameworks
from core.compliance_seeds import seed_path

FRAMEWORK_ID = "cfw_pci_dss_v4"
SEED = seed_path("pci_dss_v4_controls_seed.json")
REQUIREMENT = re.compile(r"^(?:[1-9]|1[0-2])(?:\.\d{1,2}){1,3}$")


def _seed() -> dict:
    with open(SEED, encoding="utf-8") as fh:
        return json.load(fh)


def test_the_catalogue_is_v4_0_1_and_says_it_is_a_selection():
    fw = _seed()["framework"]
    n = len(_seed()["controls"])
    assert fw["version"] == "4.0.1"
    assert fw["name"] == f"PCI DSS v4.0.1 ({n} selected requirements)"
    assert "not the whole standard" in fw["description"]


def test_each_entry_is_published_under_the_standards_number():
    controls = _seed()["controls"]
    numbers = [c["control_number"] for c in controls]
    assert len(numbers) == len(set(numbers))
    assert all(REQUIREMENT.match(n) for n in numbers), numbers


def test_roles_and_responsibilities_are_x_1_2():
    """X.1.1 is "policies and procedures are documented and in use"; X.1.2 is
    "roles and responsibilities are documented, assigned and understood"."""
    roles = [
        c
        for c in _seed()["controls"]
        if c["title"].startswith("Roles and responsibilities")
    ]
    assert len(roles) == 11
    assert sorted(c["control_number"] for c in roles) == sorted(
        f"{n}.1.2" for n in range(1, 12)
    )


def test_the_other_verified_corrections_hold():
    by_number = {c["control_number"]: c["title"] for c in _seed()["controls"]}
    assert "unnecessary functionality" in by_number["2.2.4"]
    assert "previous four" in by_number["8.3.7"]
    assert "destroyed" in by_number["9.4.7"]
    assert "protected from unauthorized modifications" in by_number["10.3.2"]
    assert "File integrity monitoring" in by_number["11.5.2"]


def test_pci_is_parked_and_published_under_its_numbers():
    """Parked again on 28 Sep 2026 (work narrowed to ISO); the fixes stay."""
    from scripts.seed_compliance import _control_number

    assert not compliance_frameworks.is_active(FRAMEWORK_ID)
    assert FRAMEWORK_ID in compliance_frameworks.parked_framework_ids()
    ctrl = {"id": "pci_1_1_1", "control_number": "1.1.2"}
    assert _control_number(FRAMEWORK_ID, ctrl) == "1.1.2"


def test_placeholder_rule_ids_follow_the_control_id_not_its_number():
    """Renumbering must not mint a second set of placeholder rules."""
    import inspect

    import scripts.seed_real_rules as seeder

    source = inspect.getsource(seeder.seed_and_evaluate)
    block = source[source.index("# Map rules and controls for PCI DSS v4.0.1") :]
    block = block[: block.index("Successfully mapped rules and controls for PCI DSS")]
    assert 'suffix = pci_ctrl.id.replace("cct_pci_dss_v4_", "")' in block
    assert "pci_ctrl.control_number.lower()" not in block
    assert 'evidence_source="manual"' in block


def test_unrecorded_pci_facts_are_not_failures(db_session):
    from core.asset_evidence import offline_configuration
    from db.models import Organization
    from db.models.assets import Asset

    keys = (
        "pam_mfa_enforced",
        "asv_scan_fresh",
        "pci_log_daily_reviewed",
        "ir_test_fresh_365d",
        "fim_active",
    )
    org_id = f"org_pci_{uuid.uuid4().hex[:8]}"
    db_session.add(Organization(id=org_id, name=org_id, slug=org_id.replace("_", "-")))
    db_session.flush()
    try:
        blank = Asset(
            id=f"ast_{org_id}_a",
            org_id=org_id,
            ip_address="192.0.2.10",
            custom_attributes={},
        )
        known = Asset(
            id=f"ast_{org_id}_b",
            org_id=org_id,
            ip_address="192.0.2.11",
            custom_attributes={
                "pam_mfa_modules": [],
                "asv_last_passing_scan_date": "not a date",
                "pci_log_daily_reviewed": True,
                "ir_last_test_date": "2020-01-01T00:00:00Z",
                "fim_active": False,
            },
        )
        db_session.add_all([blank, known])
        db_session.flush()

        adapt = offline_configuration
        nothing = adapt(db_session, blank.id)
        # Not collected is absent — the engine renders manual_review — never False.
        assert not any(k in nothing for k in keys), {k: nothing.get(k) for k in keys}

        recorded = adapt(db_session, known.id)
        assert recorded["pam_mfa_enforced"] is False  # collected: no MFA module
        assert "asv_scan_fresh" not in recorded  # unreadable date: nothing established
        assert recorded["pci_log_daily_reviewed"] is True
        assert recorded["ir_test_fresh_365d"] is False  # recorded, and stale
        assert recorded["fim_active"] is False  # recorded as off
    finally:
        db_session.rollback()
