"""
What the asset registry's API reads from the findings tables (G6, C7;
``core/findings/reads.py``).

The estate listings scope by organisation and label each row with its host,
joining hosts through the findings side's port rather than the asset model.
These run them against a database: each organisation sees its own services and
certificates, with its own host's address and name, and nothing of the other's.
The certificate listing is the one whose first version failed to build its
query once the host's columns were added (the API golden found it), so it is
run with every sort the route offers.
"""

import uuid

import pytest

from core.findings import reads
from db.base import utcnow
from db.models.assets import Asset
from db.models.findings import Service, TLSDetail
from db.models.rbac import Organization


def _org(db, label):
    org_id = f"org_reads_{label}_{uuid.uuid4().hex[:6]}"
    db.add(
        Organization(
            id=org_id,
            name=f"Reads {label} {org_id}",
            slug=org_id.replace("_", "-"),
            is_active=True,
            settings={},
        )
    )
    return org_id


def _host(db, org_id, ip, hostname, *, port=443, name="https"):
    asset_id = f"ast_{org_id}_{ip.replace('.', '_')}"
    db.add(
        Asset(
            id=asset_id,
            org_id=org_id,
            ip_address=ip,
            hostname=hostname,
            device_category="server",
            subnet="10.99.0.0/24",
            last_seen_at=utcnow(),
        )
    )
    service_id = f"svc_{asset_id}_{port}_tcp"
    db.add(
        Service(
            id=service_id,
            asset_id=asset_id,
            port=port,
            protocol="tcp",
            state="open",
            service_name=name,
        )
    )
    db.flush()
    db.add(
        TLSDetail(
            service_id=service_id,
            is_enabled=True,
            protocol_version="TLSv1.2",
            grade="B",
            is_weak_cipher=False,
            cert_san_domains=[],
            issues=[],
            created_at=utcnow(),
        )
    )
    db.flush()
    return asset_id


@pytest.fixture
def estate(db_session):
    mine = _org(db_session, "mine")
    theirs = _org(db_session, "theirs")
    db_session.flush()
    my_host = _host(db_session, mine, "10.99.0.1", "mine-1")
    their_host = _host(db_session, theirs, "10.99.0.2", "theirs-1")
    return mine, theirs, my_host, their_host


@pytest.mark.parametrize(
    "sort_by", ["grade", "expiration", "port", "ip_address", "hostname", "other"]
)
@pytest.mark.parametrize("sort_dir", ["asc", "desc"])
def test_certificates_are_the_organisations_own_with_their_host(
    db_session, estate, sort_by, sort_dir
):
    mine, theirs, my_host, _ = estate
    total, rows = reads.certificate_inventory(
        db_session,
        mine,
        search=None,
        sort_by=sort_by,
        sort_dir=sort_dir,
        skip=0,
        limit=50,
    )
    assert total == 1
    assert [(r["asset_id"], r["asset_ip"], r["asset_hostname"]) for r in rows] == [
        (my_host, "10.99.0.1", "mine-1")
    ]


def test_certificates_are_searched_by_host(db_session, estate):
    mine, _, my_host, _ = estate
    for term, found in (("mine-1", 1), ("10.99.0.1", 1), ("theirs-1", 0)):
        total, rows = reads.certificate_inventory(
            db_session,
            mine,
            search=term,
            sort_by="expiration",
            sort_dir="asc",
            skip=0,
            limit=50,
        )
        assert (total, len(rows)) == (found, found), term


def test_services_are_the_organisations_own(db_session, estate):
    mine, theirs, my_host, their_host = estate
    total, rows = reads.service_inventory(
        db_session,
        mine,
        search=None,
        port=None,
        protocol=None,
        asset_type="server",
        subnet="10.99",
        sort_by="port",
        sort_dir="asc",
        skip=0,
        limit=50,
    )
    assert total == 1
    assert rows[0]["service_name"] == "https" and rows[0]["asset_count"] == 1

    total, rows = reads.service_hosts(
        db_session,
        theirs,
        service_name="https",
        port=443,
        protocol="tcp",
        search=None,
        skip=0,
        limit=50,
    )
    assert total == 1
    assert (rows[0]["asset_id"], rows[0]["asset_ip"], rows[0]["asset_hostname"]) == (
        their_host,
        "10.99.0.2",
        "theirs-1",
    )
    assert rows[0]["asset_type"] == "server"


def test_an_assets_services_and_open_service_count(db_session, estate):
    _, _, my_host, their_host = estate
    assert reads.open_service_counts(db_session, [my_host, their_host]) == {
        my_host: 1,
        their_host: 1,
    }
    services = reads.asset_services(db_session, my_host)
    assert [(s["port"], s["tls"]["grade"]) for s in services] == [(443, "B")]
