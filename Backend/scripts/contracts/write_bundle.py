"""
Write a schema bundle produced by ``generate_schemas --bundle`` to disk.

    docker exec -w /app ccure-api python -m scripts.contracts.generate_schemas --bundle \
        | python3 scripts/contracts/write_bundle.py

Standard library only, so it runs on a host without the application's packages.
Paths in the bundle are relative to Backend/ and must stay inside it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]


def main() -> int:
    bundle = json.load(sys.stdin)
    for rel, text in bundle.items():
        target = (BACKEND / rel).resolve()
        if BACKEND not in target.parents:
            print(f"refusing path outside Backend/: {rel}", file=sys.stderr)
            return 1
        if target.exists() and target.read_text(encoding="utf-8") == text:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"wrote {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
