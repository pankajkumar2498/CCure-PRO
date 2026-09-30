"""
Run a command against a rehearsal database (Phase 11.3).

    python -m scripts.db.rehearsal_env DATABASE_URL ccure_rehearsal_11_3 -- <command…>

Rewrites the named environment variable's database name — keeping the host,
credentials and query string the container already has — and ``exec``s the
command. The URL is never printed. Only a database whose name starts
``ccure_rehearsal_`` is accepted, so a slip cannot point a rehearsal step at the
live database.
"""

from __future__ import annotations

import os
import sys
import urllib.parse

PREFIX = "ccure_rehearsal_"


def main(argv: list[str]) -> int:
    if len(argv) < 4 or argv[2] != "--":
        print(__doc__, file=sys.stderr)
        return 2
    var, database, command = argv[0], argv[1], argv[3:]
    if not database.startswith(PREFIX) or not database.replace("_", "").isalnum():
        print(f"refusing database {database!r}: not a {PREFIX}* name", file=sys.stderr)
        return 2
    base = os.environ.get(var) or os.environ["DATABASE_URL"]
    parts = urllib.parse.urlsplit(base)
    os.environ[var] = urllib.parse.urlunsplit(parts._replace(path=f"/{database}"))
    os.execvp(command[0], command)
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
