"""
Manage the platform's token signing keyset (Phase 9.3).

The keyset directory holds ``keyset.json`` and one PEM file per private key
(``ccure_platform/identity/keys.py`` defines the format and the states). It lives
**outside the repository** and is mounted read-only into the api container only.

Run it in the backend image as root, so key files can be owned by the api
container's user (uid 1000) with mode 600 — the host account cannot read them,
which is the point:

    docker run --rm -u 0 -v <host keys dir>:/keys -v "$PWD/Backend":/app -w /app \\
        ccure-audit-pro-backend:latest \\
        python -m scripts.security.manage_token_keys --keys-dir /keys <command>

Commands:

    list                         kids, states, files (no key material)
    generate --state next        a new P-256 key; `next` pre-distributes it
    set-state KID STATE          next -> active -> retired (rotation)
    remove KID                   drop a key: tokens it signed stop verifying

Rotation (design §3.6), every 180 days by the owner's decision:
generate a `next` key, restart the api (it is published), wait at least the
JWKS cache time; set the old active key `retired` and the new one `active`,
restart; after the longest token lifetime (7 days) plus a margin, `remove` the
retired key and restart. Every change is validated by loading the whole keyset
before the manifest is replaced, so a broken keyset is never written.

Escrow: the project owner keeps an offline copy of each private key file.
Printing key material is deliberately not a feature of this tool.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ccure_platform.identity import keys


def _write_manifest(directory: str, manifest: dict) -> None:
    """Validate the resulting keyset, then atomically replace the manifest."""
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".keyset-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp, 0o644)  # public: kids and states only
    staged = os.path.join(directory, keys.MANIFEST)
    backup = staged + ".previous"
    had_manifest = os.path.exists(staged)
    if had_manifest:
        os.replace(staged, backup)
    os.replace(tmp, staged)
    try:
        keys.load_keyset(directory)
    except keys.KeySetError:
        if had_manifest:
            os.replace(backup, staged)
        else:
            os.remove(staged)
        raise
    if had_manifest:
        os.remove(backup)


def _manifest(directory: str) -> dict:
    if os.path.exists(os.path.join(directory, keys.MANIFEST)):
        return keys.read_manifest(directory)
    return {"version": keys.MANIFEST_VERSION, "keys": []}


def _chown(path: str, owner: str | None) -> None:
    if owner:
        uid, gid = (int(x) for x in owner.split(":"))
        os.chown(path, uid, gid)


def generate(directory: str, state: str, owner: str | None) -> str:
    manifest = _manifest(directory)
    private_key = ec.generate_private_key(ec.SECP256R1())
    kid = keys.jwk_thumbprint(private_key.public_key())
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"es256-{created}-{kid[:8]}.pem"
    path = os.path.join(directory, filename)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    _chown(path, owner)
    manifest["keys"].append(
        {
            "kid": kid,
            "alg": keys.ALGORITHM,
            "state": state,
            "file": filename,
            "created": created,
        }
    )
    try:
        _write_manifest(directory, manifest)
    except keys.KeySetError:
        os.remove(path)
        raise
    return kid


def set_state(directory: str, kid: str, state: str) -> None:
    manifest = _manifest(directory)
    entries = [e for e in manifest["keys"] if e.get("kid") == kid]
    if not entries:
        raise keys.KeySetError(f"no key {kid}")
    entries[0]["state"] = state
    _write_manifest(directory, manifest)


def remove(directory: str, kid: str) -> str:
    manifest = _manifest(directory)
    entries = [e for e in manifest["keys"] if e.get("kid") == kid]
    if not entries:
        raise keys.KeySetError(f"no key {kid}")
    if entries[0]["state"] == "active":
        raise keys.KeySetError("refusing to remove the active key; retire it first")
    manifest["keys"] = [e for e in manifest["keys"] if e.get("kid") != kid]
    _write_manifest(directory, manifest)
    # The private key file is left in place for escrow and forensics; it is
    # no longer trusted because the manifest no longer names it.
    return entries[0]["file"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--keys-dir", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    gen = sub.add_parser("generate")
    gen.add_argument("--state", choices=keys.STATES, default="next")
    gen.add_argument(
        "--owner", help="uid:gid to own the private key file, e.g. 1000:1000"
    )
    st = sub.add_parser("set-state")
    st.add_argument("kid")
    st.add_argument("state", choices=keys.STATES)
    rm = sub.add_parser("remove")
    rm.add_argument("kid")
    args = parser.parse_args(argv)

    try:
        if args.command == "list":
            for entry in _manifest(args.keys_dir)["keys"]:
                print(
                    f"{entry['kid']}  {entry['state']:8s}  {entry['alg']}  {entry['file']}"
                )
            keys.load_keyset(args.keys_dir)
            print("keyset valid")
        elif args.command == "generate":
            print(generate(args.keys_dir, args.state, args.owner))
        elif args.command == "set-state":
            set_state(args.keys_dir, args.kid, args.state)
            print(f"{args.kid} -> {args.state}")
        elif args.command == "remove":
            print(
                f"removed {args.kid}; key file {remove(args.keys_dir, args.kid)} left for escrow"
            )
    except keys.KeySetError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
