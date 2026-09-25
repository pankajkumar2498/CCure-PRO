"""
Generate the committed JSON Schemas for the CCure integration contracts.

    python -m scripts.contracts.generate_schemas          # write
    python -m scripts.contracts.generate_schemas --check  # exit 1 on drift
    python -m scripts.contracts.generate_schemas --bundle # print {path: schema} as JSON

``--bundle`` exists for this deployment's API container, whose user cannot
write into the host-owned bind mount: render inside the container, write on the
host (``scripts/contracts/write_bundle.py``).

The schemas are generated, never hand-edited: the Pydantic models in
``ccure_contracts`` are the source, and the JSON files are what a team working
outside this repository (plan Phase 18) or in another language validates
against. ``tests/repo/test_integration_contracts.py`` fails when the two drift.
"""

from __future__ import annotations

import argparse
import json
import sys

from ccure_contracts.registry import CONTRACTS, SCHEMA_VERSION

_ID_BASE = "https://ccurepro.cdac.in/contracts"


def render(spec) -> str:
    schema = spec.model.model_json_schema(by_alias=True, mode="validation")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{_ID_BASE}/{spec.area}/v1/{spec.name}.schema.json",
        "x-ccure-schema-version": SCHEMA_VERSION,
        "x-ccure-status": spec.status,
        **schema,
    }
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--check", action="store_true", help="report drift, write nothing"
    )
    parser.add_argument(
        "--bundle", action="store_true", help="print every schema as one JSON object"
    )
    args = parser.parse_args(argv)

    if args.bundle:
        root = CONTRACTS[0].schema_path.parents[4]
        bundle = {str(s.schema_path.relative_to(root)): render(s) for s in CONTRACTS}
        print(json.dumps(bundle))
        return 0

    drift = []
    for spec in CONTRACTS:
        text = render(spec)
        path = spec.schema_path
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        drift.append(path)
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    for path in drift:
        print(("DRIFT " if args.check else "wrote ") + str(path))
    if args.check and drift:
        print("Regenerate with: python -m scripts.contracts.generate_schemas")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
