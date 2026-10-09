"""Read-only native catalogue, administrator and continuity readiness."""

import json


def main():
    from ccure_platform import composition
    from ccure_platform.rbac.readiness import assess
    from db.base import SessionLocal

    with SessionLocal() as db:
        result = assess(db, composition.load_permission_sources())
        print(json.dumps(result.as_dict(), indent=2))
        return 0 if result.ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
