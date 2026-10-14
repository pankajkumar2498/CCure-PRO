"""
A base finding id never contains the product marker ``__``.

Migration a7c9e1b3d5f8 lets one CVE have a row per product on a host; the
product-qualified row's id is the base id plus ``__`` and a digest. Two things
rest on ``__`` appearing nowhere else: ``_base_id_owners`` tells a qualified
row from a base one by it, and the migration's downgrade deletes exactly the
rows whose id contains it. A base id with ``__`` in it would be read as a
product row and, on downgrade, deleted outright.

No generator produces one today — IPs never reach ``_safe_id_part``'s length
limit, so it never truncates onto a trailing ``_`` — and this pins it.
"""

from __future__ import annotations

import pytest
from db.base import gen_asset_id
from scans.asset_syncer import (
    _COMPONENT_ID_MARK,
    FINDING_SOURCE_FAMILY,
    _component_finding_id,
    _source_specific_finding_id,
)
from sqlalchemy import text

ORGS = ["org_development", "a", "-x-", "a_b-c", "ÄÖ", "development org!"]
IPS = [
    "10.180.6.45",
    "192.168.100.200",
    "::ffff:192.168.100.200",
    "fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
    "2001:db8::1",
]
IDENTIFIERS = [
    "CVE-2024-3094",
    "CCURE-CFG-CCURE-LINUX-SHADOW-PERMISSIONS",
    "CCURE-CHK-NUCLEI-GIT-CONFIG",
    "MISC-CREDENTIALED-PACKAGES-NOT-ASSESSED",
]


def _base_ids():
    for org in ORGS:
        for ip in IPS:
            asset = gen_asset_id(org, ip)
            for identifier in IDENTIFIERS:
                yield f"fnd_{asset}_{identifier}"  # the legacy form
                for family in set(FINDING_SOURCE_FAMILY.values()):
                    yield _source_specific_finding_id(asset, identifier, family)


def test_no_base_finding_id_contains_the_product_marker():
    offenders = [i for i in _base_ids() if _COMPONENT_ID_MARK in i]
    assert offenders == []


def test_a_product_row_carries_the_marker_exactly_once():
    for base in list(_base_ids())[:20]:
        qualified = _component_finding_id(base, "xserver-common")
        assert qualified.count(_COMPONENT_ID_MARK) == 1
        assert qualified.startswith(base + _COMPONENT_ID_MARK)


@pytest.mark.parametrize(
    "finding_id,deleted",
    [
        ("fnd_ast_deve_1a2b3c4d_10_180_6_45_credentialed_package_CVE-2024-1", False),
        ("fnd_ast_deve_1a2b3c4d_10_180_6_45_CVE-2024-1", False),
        ("fnd_ast_deve_1a2b3c4d_10_180_6_45_CVE-2024-1__0a1b2c3d4e", True),
    ],
)
def test_the_downgrade_pattern_matches_product_rows_only(
    db_session, finding_id, deleted
):
    # The literal the migration executes, evaluated by PostgreSQL: `_` is a
    # LIKE wildcard, so an unescaped pattern would match every id with two
    # characters anywhere — every row in the table.
    import ast

    from testpaths import BACKEND_ROOT

    source = (
        BACKEND_ROOT / "alembic/versions/a7c9e1b3d5f8_finding_key_per_component.py"
    ).read_text(encoding="utf-8")
    downgrade = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "downgrade"
    )
    (statement,) = [
        node.value
        for node in ast.walk(downgrade)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("DELETE FROM asset_vulnerabilities")
    ]
    predicate = statement.split("WHERE id ", 1)[1]
    matched = db_session.execute(
        text(f"SELECT CAST(:id AS text) {predicate}"), {"id": finding_id}
    ).scalar_one()
    assert matched is deleted
