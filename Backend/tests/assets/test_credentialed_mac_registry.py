"""
The Vulnerability Audit's credentialed pass records the MAC it read.

The defect these exist for: a host behind a router yields no MAC to discovery.
ARP stops at the scanner's own segment, and the NetBIOS reply that carries a
MAC across a router comes only from Windows or Samba. The credentialed pass
reads the MAC off the host itself and stores it in
``credentialed_report.system_info``, but ``sync_vulnerability_audit`` wrote
hostname, FQDN and OS from that record and never the MAC. 10.180.6.45 (Ubuntu,
another subnet) kept no MAC in the asset registry through three authenticated
audits that had each read ``2c:58:b9:87:0b:b3`` (28 Oct 2026).

``uq_assets_org_mac`` makes a MAC unique within an organisation and the sync
commits once for every host, so a MAC already held elsewhere must be skipped,
not written: a refused write would lose the whole scan's findings.
"""

import logging
import uuid

import pytest

MAC = "2c:58:b9:87:0b:b3"
OTHER_MAC = "2c:58:b9:15:74:70"


def _host(ip, mac=None, **kw):
    """A host record in the shape the pipeline stores for phase 3."""
    host = {
        "ip_address": ip,
        "is_active": True,
        "credentialed": True,
        "open_ports": [],
        "cves": [],
        "credentialed_report": {
            "system_info": {"hostname": "superusr-HP3", "mac_address": mac}
        },
    }
    host.update(kw)
    return host


@pytest.fixture()
def registry(monkeypatch, db_session):
    """
    An organisation with a scan, assets made on request, and a runner for
    ``sync_vulnerability_audit``. Only the intel lookup is stubbed; asset
    resolution, the field writes and the commit run for real.
    """
    from db.base import gen_asset_id
    from db.models import Asset, Organization
    from db.models.scans import Scan
    from scans import asset_syncer

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)

    def _org():
        suffix = uuid.uuid4().hex[:8]
        org = Organization(
            id=f"org_mac_{suffix}",
            name=f"credentialed-mac-{suffix}",
            slug=f"credmac{suffix}",
        )
        db_session.add(org)
        db_session.flush()
        return org

    class Registry:
        org = _org()
        scan_id = f"scn_mac_{uuid.uuid4().hex[:8]}"

        @staticmethod
        def other_org():
            return _org()

        @staticmethod
        def asset(ip, mac=None, org=None, mac_source=None):
            org = org or Registry.org
            attrs = {}
            if mac_source:
                attrs["provenance"] = {"mac_address": {"source": mac_source}}
            asset = Asset(
                id=gen_asset_id(org.slug, ip),
                org_id=org.id,
                ip_address=ip,
                mac_address=mac,
                custom_attributes=attrs,
            )
            db_session.add(asset)
            db_session.commit()
            return asset

        @staticmethod
        def sync(*hosts):
            asset_syncer.sync_vulnerability_audit(
                db_session, Registry.scan_id, Registry.org.id, None, list(hosts)
            )
            db_session.expire_all()

    db_session.add(
        Scan(id=Registry.scan_id, org_id=Registry.org.id, target_str="10.180.6.45")
    )
    db_session.commit()
    return Registry


@pytest.fixture()
def live_mac_index(db_session):
    """
    The unique index the live database enforces.

    No model or migration in this repository declares ``uq_assets_org_mac``
    (it came with the early schema and outlived its declaration), so a schema
    built from the models lacks it and an unguarded write would pass these
    tests. Created only if absent, and dropped only if created here.
    """
    from sqlalchemy import text

    exists = db_session.execute(
        text("SELECT 1 FROM pg_indexes WHERE indexname = 'uq_assets_org_mac'")
    ).first()
    if not exists:
        db_session.execute(
            text(
                "CREATE UNIQUE INDEX uq_assets_org_mac ON assets "
                "(org_id, mac_address) WHERE mac_address IS NOT NULL"
            )
        )
        db_session.commit()
    yield
    db_session.rollback()
    if not exists:
        db_session.execute(text("DROP INDEX IF EXISTS uq_assets_org_mac"))
        db_session.commit()


def _mac_changes(db_session, asset_id):
    from db.models import AssetChangeLog

    return (
        db_session.query(AssetChangeLog)
        .filter(
            AssetChangeLog.asset_id == asset_id,
            AssetChangeLog.field_name == "mac_address",
        )
        .all()
    )


def test_the_mac_the_session_read_reaches_the_asset(registry, db_session):
    """The regression: the MAC was in the report and never in the registry."""
    asset = registry.asset("10.180.6.45")
    registry.sync(_host("10.180.6.45", MAC))

    assert asset.mac_address == MAC
    provenance = asset.custom_attributes["provenance"]["mac_address"]
    assert provenance["source"] == "credentialed"
    assert provenance["scan_id"] == registry.scan_id
    [change] = _mac_changes(db_session, asset.id)
    assert change.old_value == {"val": None}
    assert change.new_value == {"val": MAC}


def test_the_mac_is_stored_in_canonical_form(registry):
    """``macaddr`` stores lower-case; anything else logs a change every scan."""
    asset = registry.asset("10.180.6.45")
    registry.sync(_host("10.180.6.45", "2C-58-B9-87-0B-B3"))
    assert asset.mac_address == MAC


def test_it_replaces_a_mac_inferred_on_the_wire(registry):
    """A NetBIOS reply can name another adapter; the host's own answer wins."""
    asset = registry.asset("10.180.6.45", mac=OTHER_MAC, mac_source="discovery")
    registry.sync(_host("10.180.6.45", MAC))
    assert asset.mac_address == MAC


@pytest.mark.parametrize("placeholder", [None, "", "N/A", "00:00:00:00:00:00"])
def test_a_placeholder_writes_nothing(registry, placeholder):
    asset = registry.asset("10.180.6.45", mac=OTHER_MAC, mac_source="discovery")
    registry.sync(_host("10.180.6.45", placeholder))
    assert asset.mac_address == OTHER_MAC
    assert asset.custom_attributes["provenance"]["mac_address"]["source"] == (
        "discovery"
    )


def test_a_host_with_no_credentialed_report_leaves_the_mac_alone(registry):
    asset = registry.asset("10.180.6.45", mac=OTHER_MAC, mac_source="discovery")
    host = _host("10.180.6.45")
    del host["credentialed_report"]
    registry.sync(host)
    assert asset.mac_address == OTHER_MAC


def test_a_mac_another_asset_holds_is_skipped_and_the_sync_still_commits(
    registry, live_mac_index, caplog
):
    """
    Written, it would break ``uq_assets_org_mac`` at the sync's one commit
    and lose every finding the scan wrote, not just this field.
    """
    holder = registry.asset("10.180.5.10", mac=MAC)
    asset = registry.asset("10.180.6.45")

    with caplog.at_level(logging.WARNING, logger="scans.asset_syncer"):
        registry.sync(_host("10.180.6.45", MAC))

    assert asset.mac_address is None
    assert holder.mac_address == MAC
    assert asset.last_scan_id == registry.scan_id
    assert asset.custom_attributes["credentialed_status"] == "success"
    assert any(
        MAC in r.getMessage() and holder.id in r.getMessage() for r in caplog.records
    )


def test_two_hosts_reporting_one_mac_in_a_sync_do_not_collide(registry, live_mac_index):
    """
    The session does not autoflush, so the first host's write is invisible to
    a query when the second host is reached.
    """
    first = registry.asset("10.180.6.45")
    second = registry.asset("10.180.6.46")
    registry.sync(_host("10.180.6.45", MAC), _host("10.180.6.46", MAC))

    assert first.mac_address == MAC
    assert second.mac_address is None
    assert second.last_scan_id == registry.scan_id


def test_the_same_mac_in_another_organisation_is_not_a_conflict(
    registry, live_mac_index
):
    """Uniqueness is per organisation; another tenant's asset is irrelevant."""
    registry.asset("10.180.6.45", mac=MAC, org=registry.other_org())
    asset = registry.asset("10.180.6.45")
    registry.sync(_host("10.180.6.45", MAC))
    assert asset.mac_address == MAC


def test_rescanning_the_same_mac_logs_no_change(registry, db_session):
    asset = registry.asset("10.180.6.45")
    registry.sync(_host("10.180.6.45", MAC))
    registry.sync(_host("10.180.6.45", MAC))
    assert asset.mac_address == MAC
    assert len(_mac_changes(db_session, asset.id)) == 1
