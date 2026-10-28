"""
An evidence value that was never collected is absent, never False.

`_adapt_offline_configuration` defaulted six keys to False until 28 Sep 2026 —
the pattern CLAUDE.md forbids on the registry-hardening path, because False
asserts the insecure state. Four of them are read by active ISO/IEC 27001, NIST
CSF, CIS and PCI DSS rules, so a host whose registry hardening had never been
read FAILED those controls: 3 of this installation's 4 assets on that date. An
absent key is what the engine renders as not assessed.
"""

from __future__ import annotations

import uuid

import pytest

KEYS = (
    "uac_enabled",
    "firewall_profile_active",
    "remote_desktop_disabled",
    "audit_policy_configured",
    "ids_ips_active",
    "waf_active",
)


@pytest.fixture()
def assets(db_session):
    from db.models import Organization
    from db.models.assets import Asset

    org_id = f"org_ev_{uuid.uuid4().hex[:8]}"
    db_session.add(Organization(id=org_id, name=org_id, slug=org_id.replace("_", "-")))
    db_session.flush()
    blank = Asset(
        id=f"ast_{org_id}_blank",
        org_id=org_id,
        ip_address="192.0.2.20",
        custom_attributes={},
    )
    read = Asset(
        id=f"ast_{org_id}_read",
        org_id=org_id,
        ip_address="192.0.2.21",
        custom_attributes={
            "registry_hardening": {
                "uac_enabled": False,
                "firewall_active": True,
                "rdp_disabled": True,
                "audit_configured": False,
            },
            "ids_ips_active": True,
            "waf_active": False,
        },
    )
    db_session.add_all([blank, read])
    db_session.flush()
    try:
        yield blank, read
    finally:
        db_session.rollback()


def test_uncollected_values_are_absent(db_session, assets):
    from core.asset_evidence import offline_configuration

    blank, _ = assets
    payload = offline_configuration(db_session, blank.id)
    present = {k: payload[k] for k in KEYS if k in payload}
    assert not present, f"asserted without being collected: {present}"


def test_collected_values_are_reported_as_collected(db_session, assets):
    from core.asset_evidence import offline_configuration

    _, read = assets
    payload = offline_configuration(db_session, read.id)
    assert payload["uac_enabled"] is False  # collected and off: a real finding
    assert payload["firewall_profile_active"] is True
    assert payload["remote_desktop_disabled"] is True
    assert payload["audit_policy_configured"] is False
    assert payload["ids_ips_active"] is True
    assert payload["waf_active"] is False
