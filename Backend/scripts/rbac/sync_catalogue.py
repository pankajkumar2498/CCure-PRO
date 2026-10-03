"""
Apply the RBAC permission catalogue and the legacy mapping to a database.

    python -m scripts.rbac.sync_catalogue            # dry run: reports, writes nothing
    python -m scripts.rbac.sync_catalogue --apply    # commits

Run from ``Backend/`` (in the API container: ``docker exec ccure-api python -m
scripts.rbac.sync_catalogue``).

What it does, in one transaction:

1. ensures the five system roles and the self-registration default exist;
2. loads every permission declaration through the composition root (the platform's
   and each enabled module's) and syncs the catalogue — new permissions inserted,
   changed ones updated, undeclared ones deprecated, system roles reconciled to
   their ``default_grants``, the superadmin role materialised with every active
   permission;
3. writes the golden legacy mapping into ``rbac_legacy_map`` — every legacy atom
   accounted for, including the ones nothing enforces;
4. reports the continuity invariants.

It validates **before** it writes: a declaration or mapping problem stops it with
every problem listed and nothing applied; a legacy atom the live ``permissions``
table holds that the mapping does not account for is such a problem.

**RBAC-2 is dark.** Running this populates the ``rbac_*`` tables only; nothing
reads them on a request, the legacy tables are untouched, and no user is assigned
to a new role. It is not run at start-up. Take ``scripts/backup_db.sh
--skip-reference-data`` before ``--apply`` on a real database, as with any write.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--apply", action="store_true", help="commit (default: dry run)"
    )
    args = parser.parse_args(argv)

    from ccure_platform import composition
    from ccure_platform.rbac import governance, legacy_map
    from ccure_platform.rbac.catalogue import (
        CatalogueError,
        ensure_default_roles,
        ensure_system_roles,
    )
    from db.base import SessionLocal

    db = SessionLocal()
    try:
        sources = composition.load_permission_sources()
        declarations = [d for s in sources for d in s.permissions]
        golden = legacy_map.load_golden()
        atoms = {
            f"{r}:{a}"
            for r, a in db.execute(text("SELECT resource, action FROM permissions"))
        }
        problems = legacy_map.validate_golden(
            golden, declarations=declarations, legacy_atoms=atoms
        )
        if problems:
            print("The golden mapping does not hold:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1

        created = ensure_system_roles(db)
        configured = ensure_default_roles(db)
        catalogue = composition.sync_permission_catalogue(db)
        mapped = legacy_map.sync_legacy_map(db, golden)
        continuity = governance.continuity_report(db)

        print(f"system roles created:      {len(created)}")
        print(f"default roles configured:  {len(configured)}")
        print(
            f"permissions:               +{len(catalogue.registered)} registered, "
            f"{len(catalogue.updated)} updated, {len(catalogue.deprecated)} deprecated"
        )
        print(
            "role grants:               "
            f"+{sum(len(v) for v in catalogue.grants_added.values())} added, "
            f"-{sum(len(v) for v in catalogue.grants_removed.values())} removed"
        )
        print(
            f"legacy map:                +{len(mapped.roles_added)} roles, "
            f"+{len(mapped.atoms_added)} atoms, {len(mapped.atoms_updated)} updated, "
            f"{len(mapped.stale)} stale"
        )
        print(f"legacy atoms accounted for: {len(atoms)} of {len(atoms)}")
        print(f"continuity:                {continuity.status}")
        if args.apply:
            db.commit()
            print("applied.")
        else:
            db.rollback()
            print("dry run: nothing written. Re-run with --apply to commit.")
        return 0
    except CatalogueError as exc:
        db.rollback()
        print(exc, file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
