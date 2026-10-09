"""Synchronize the native permission catalogue and frozen system grants.

Dry run by default; pass --apply to commit the audited synchronization.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--apply", action="store_true", help="commit (default: dry run)"
    )
    args = parser.parse_args(argv)

    from ccure_platform import composition
    from ccure_platform.rbac import contract as c
    from ccure_platform.rbac import governance
    from ccure_platform.rbac.catalogue import (
        CatalogueError,
        ensure_default_roles,
        ensure_system_roles,
        sync,
        validate_declarations,
    )
    from db.base import SessionLocal

    db = SessionLocal()
    try:
        sources = composition.load_permission_sources()
        problems = validate_declarations(
            sources,
            known_roles={s.key: s.assignable_scope for s in c.SYSTEM_ROLE_SEEDS},
        )
        if problems:
            raise CatalogueError(problems)
        created = ensure_system_roles(db)
        configured = ensure_default_roles(db)
        catalogue = sync(db, sources)
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
