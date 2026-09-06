"""
Clear reverse-lookup strings that were stored as machine identities.

`_mdns_query` read the mDNS answer's *owner name* rather than its data, so it
recorded the "<reversed-ip>.in-addr.arpa" string it had just asked about as if
the host had answered with it. That value reached `assets.hostname` (the UI
falls back to `mdns_name` when PTR and NetBIOS are both empty) and
`assets.fqdn` / `assets.dns_name` (it was in `_extract_dns_identity`'s fqdn
chain, and `_looks_like_fqdn` accepts anything dotted).

The parse is fixed, but these rows cannot heal themselves. `_can_update_field`
refuses an incoming FQDN with fewer labels than the stored one, and
"14.6.180.10.in-addr.arpa" has six labels against a real name's three — so
every future scan's correct answer is rejected in favour of the garbage.

The fields are set to NULL rather than to a name derived here. NULL means "not
known", which is true, and it is the one state `_can_update_field` always
allows a scan to replace; writing a value by hand would be asserting an
identity no scan established.

Dry run by default. Pass --apply to write.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

SUFFIX = "in-addr.arpa"
FIELDS = ("hostname", "fqdn", "dns_name")

SELECT_SQL = text(
    """
    SELECT id, ip_address, hostname, fqdn, dns_name, discovery_method
      FROM assets
     WHERE hostname LIKE :pat OR fqdn LIKE :pat OR dns_name LIKE :pat
     ORDER BY ip_address
    """
)

UPDATE_SQL = text(
    """
    UPDATE assets SET
        hostname = CASE WHEN hostname LIKE :pat THEN NULL ELSE hostname END,
        fqdn     = CASE WHEN fqdn     LIKE :pat THEN NULL ELSE fqdn     END,
        dns_name = CASE WHEN dns_name LIKE :pat THEN NULL ELSE dns_name END
     WHERE hostname LIKE :pat OR fqdn LIKE :pat OR dns_name LIKE :pat
    """
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true", help="write the change (default: dry run)"
    )
    args = parser.parse_args()

    load_dotenv(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
        )
    )
    engine = create_engine(os.environ["DATABASE_URL"])
    pattern = f"%{SUFFIX}"

    with engine.connect() as conn:
        rows = conn.execute(SELECT_SQL, {"pat": pattern}).fetchall()

    if not rows:
        print("No reverse-lookup identities found. Nothing to do.")
        return 0

    print(f"{len(rows)} asset(s) carry a reverse-lookup string as an identity:\n")
    values = 0
    for row in rows:
        data = dict(row._mapping)
        print(f"  {data['ip_address']}  (discovery_method={data['discovery_method']})")
        for field in FIELDS:
            value = data.get(field)
            if value and value.endswith(SUFFIX):
                print(f"      {field:9s}: {value!r}  ->  NULL")
                values += 1
    print(f"\n{values} value(s) across {len(rows)} row(s).")

    if not args.apply:
        print("\nDry run. Re-run with --apply to write.")
        return 0

    with engine.begin() as conn:
        result = conn.execute(UPDATE_SQL, {"pat": pattern})
        print(f"\nUpdated {result.rowcount} row(s).")

    with engine.connect() as conn:
        remaining = conn.execute(
            text(
                "SELECT count(*) FROM assets "
                "WHERE hostname LIKE :pat OR fqdn LIKE :pat OR dns_name LIKE :pat"
            ),
            {"pat": pattern},
        ).scalar()
    print(f"Remaining reverse-lookup identities: {remaining}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
