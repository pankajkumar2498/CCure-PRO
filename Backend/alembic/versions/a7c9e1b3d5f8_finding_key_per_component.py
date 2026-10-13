"""One finding row per CVE *per product* on a host in a scan.

``uq_asset_vuln_scan_asset_cve`` kept one row per (org, scan, asset, CVE). A CVE
that affects several installed products — CVE-2025-30033 on six Siemens
products of one engineering workstation, 13 Oct 2026 — was reported as six
findings and stored as one, naming whichever product was written last, so the
findings page, the export and remediation lost the other five.

The key gains ``component``, NULLS NOT DISTINCT: a finding with no component
(a network or configuration check) still has exactly one row per CVE, and a
CVE on two named products can have two. Every existing row satisfies the wider
key, so the upgrade cannot fail on data.

Downgrade restores the narrower key. It cannot hold per-product rows, so it
first deletes the product-qualified ones (ids carrying ``__``, the qualifier
``scans.asset_syncer`` appends); the base row for each CVE remains.
"""

from alembic import op

revision = "a7c9e1b3d5f8"
down_revision = "f6a8c0e2b4d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_asset_vuln_scan_asset_cve", "asset_vulnerabilities", type_="unique"
    )
    op.execute(
        "ALTER TABLE asset_vulnerabilities "
        "ADD CONSTRAINT uq_asset_vuln_scan_asset_cve "
        "UNIQUE NULLS NOT DISTINCT (org_id, scan_id, asset_id, vuln_id, component)"
    )


def downgrade() -> None:
    op.execute("DELETE FROM asset_vulnerabilities WHERE id LIKE '%\\_\\_%'")
    op.drop_constraint(
        "uq_asset_vuln_scan_asset_cve", "asset_vulnerabilities", type_="unique"
    )
    op.create_unique_constraint(
        "uq_asset_vuln_scan_asset_cve",
        "asset_vulnerabilities",
        ["org_id", "scan_id", "asset_id", "vuln_id"],
    )
