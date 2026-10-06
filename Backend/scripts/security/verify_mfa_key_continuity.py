#!/usr/bin/env python3
"""Prove that an explicit MFA_ENCRYPTION_KEY derives the same Fernet key as the
JWT secret it replaces, so no stored ``users.totp_secret`` becomes unreadable.

    python3 -m scripts.security.verify_mfa_key_continuity \\
        --from-env-file .env --to-env-file .env [--check-database]

``--from-env-file`` names the file holding the JWT secret being retired
(JWT_SECRET_KEY), ``--to-env-file`` the one holding MFA_ENCRYPTION_KEY. Exit 0 only
if both exist and derive the same key and, with ``--check-database``, every stored
secret decrypts under it. Values are never printed — only booleans and counts.

``--check-database`` reads ciphertexts through ``docker exec ccure-db psql`` (read
only, ``SELECT``) and decrypts them here; nothing is written anywhere.
"""

from __future__ import annotations

import argparse
import hmac
import os
import re
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("SKIP_DOTENV_LOAD", "1")  # read nothing from Backend/.env

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

from config import derive_mfa_fernet_key  # noqa: E402


def read_value(path: Path, name: str) -> str | None:
    """``name``'s value in a dotenv-style file, or None. Never logged."""
    pattern = re.compile(rf"^{re.escape(name)}=(.*)$")
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if match:
            return match.group(1).strip().strip("\"'") or None
    return None


def same_key(old_secret: str, new_secret: str) -> bool:
    """Whether both secrets derive the identical Fernet key (constant-time)."""
    return hmac.compare_digest(
        derive_mfa_fernet_key(old_secret), derive_mfa_fernet_key(new_secret)
    )


def stored_ciphertexts(container: str) -> list[str]:
    out = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "psql",
            "-U",
            "postgres",
            "-d",
            "ccure_db",
            "-At",
            "-c",
            "SELECT totp_secret FROM users WHERE totp_secret IS NOT NULL",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def undecryptable(ciphertexts: list[str], secret: str) -> int:
    fernet = Fernet(derive_mfa_fernet_key(secret))
    bad = 0
    for token in ciphertexts:
        try:
            fernet.decrypt(token.encode())
        except InvalidToken:
            bad += 1
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from-env-file", type=Path, required=True)
    ap.add_argument("--to-env-file", type=Path, required=True)
    ap.add_argument("--check-database", action="store_true")
    ap.add_argument("--container", default="ccure-db")
    args = ap.parse_args()

    old = read_value(args.from_env_file, "JWT_SECRET_KEY")
    new = read_value(args.to_env_file, "MFA_ENCRYPTION_KEY")
    print(f"JWT_SECRET_KEY present:      {old is not None}")
    print(f"MFA_ENCRYPTION_KEY present:  {new is not None}")
    if old is None or new is None:
        return 1
    same = same_key(old, new)
    print(f"derive the same Fernet key:  {same}")
    ok = same
    if args.check_database:
        cts = stored_ciphertexts(args.container)
        bad = undecryptable(cts, new)
        print(
            f"stored MFA secrets:          {len(cts)} (undecryptable under the new key: {bad})"
        )
        ok = ok and bad == 0
    print("CONTINUITY PROVEN" if ok else "CONTINUITY NOT PROVEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
