"""
Manage the service-identity registry (Phase 9.5).

The registry directory holds ``services.json`` and each service's **public**
keys (``ccure_platform/service_identity/registry.py`` defines the format). It
lives outside the repository and is mounted read-only into the api only.
Changes take effect when the api restarts.

    python -m scripts.security.register_service_identity --registry-dir DIR <command>

Commands:

    list
    register ID --name NAME --module MODULE --audience AUD --scope S... --tenant T...
    add-key ID --public-key FILE        import a public key the service generated
    generate-key ID --private-out DIR   make a key pair: the private key goes to
                                        DIR, for the service's own deployment,
                                        and never into the registry
    remove-key ID KID
    set-status ID active|disabled
    set-scopes ID S...
    set-tenants ID T...

A service should generate its own key pair and hand over only the public key
(``add-key``). ``generate-key`` exists for a service deployed on the same host;
it refuses to write a private key into the registry or the platform keyset.

Every change is validated by loading the whole resulting registry before the
manifest is replaced; a change that would not load is rolled back. With
``--platform-keys-dir``, a kid that is also a platform signing key is refused
here too, as the api refuses it at load time. No key material is printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from ccure_platform.identity import keys as keyset_mod
from ccure_platform.identity import tokens
from ccure_platform.service_identity import registry as reg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _manifest(directory: str) -> dict:
    if os.path.exists(os.path.join(directory, reg.MANIFEST)):
        return reg.read_manifest(directory)
    return {"version": reg.MANIFEST_VERSION, "services": []}


def _platform_kids(platform_keys_dir: str | None) -> set[str]:
    if not platform_keys_dir:
        return set()
    return {k.kid for k in keyset_mod.load_keyset(platform_keys_dir).keys}


def _write_manifest(directory: str, manifest: dict, platform_kids: set[str]) -> None:
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".services-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp, 0o644)
    target = os.path.join(directory, reg.MANIFEST)
    backup = target + ".previous"
    had = os.path.exists(target)
    if had:
        os.replace(target, backup)
    os.replace(tmp, target)
    try:
        reg.load_registry(directory, forbidden_kids=platform_kids)
    except reg.RegistryError:
        if had:
            os.replace(backup, target)
        else:
            os.remove(target)
        raise
    if had:
        os.remove(backup)


def _entry(manifest: dict, service_id: str) -> dict:
    for entry in manifest["services"]:
        if entry.get("id") == service_id:
            return entry
    raise reg.RegistryError(f"no service {service_id}")


def register(
    directory,
    service_id,
    *,
    name,
    module,
    audience,
    scopes,
    tenants,
    platform_kids=frozenset(),
):
    manifest = _manifest(directory)
    if any(e.get("id") == service_id for e in manifest["services"]):
        raise reg.RegistryError(f"service {service_id} is already registered")
    manifest["services"].append(
        {
            "id": service_id,
            "name": name,
            "module": module,
            "status": "active",
            "audience": audience,
            "scopes": sorted(set(scopes)),
            "tenants": list(dict.fromkeys(tenants)),
            "keys": [],
        }
    )
    _write_manifest(directory, manifest, set(platform_kids))


def _store_public_key(directory, service_id, public_key, platform_kids) -> str:
    manifest = _manifest(directory)
    entry = _entry(manifest, service_id)
    kid = keyset_mod.jwk_thumbprint(public_key)
    filename = f"{service_id}-es256-{kid[:8]}.pem"
    path = os.path.join(directory, filename)
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    entry["keys"].append({"kid": kid, "file": filename})
    try:
        _write_manifest(directory, manifest, set(platform_kids))
    except reg.RegistryError:
        os.remove(path)
        raise
    return kid


def add_key(directory, service_id, public_key_file, platform_kids=frozenset()) -> str:
    with open(public_key_file, "rb") as fh:
        data = fh.read()
    if b"PRIVATE KEY" in data:
        raise reg.RegistryError("refusing a private key: pass the public key only")
    try:
        public_key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise reg.RegistryError("not a PEM public key") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise reg.RegistryError("only P-256 (ES256) keys are accepted")
    return _store_public_key(directory, service_id, public_key, platform_kids)


def generate_key(directory, service_id, private_out, platform_kids=frozenset()) -> str:
    private_out = os.path.abspath(private_out)
    if os.path.abspath(directory) == private_out or os.path.exists(
        os.path.join(private_out, reg.MANIFEST)
    ):
        raise reg.RegistryError("the private key must not be written into the registry")
    if os.path.exists(os.path.join(private_out, keyset_mod.MANIFEST)):
        raise reg.RegistryError(
            "the private key must not be written into the platform keyset"
        )
    private_key = ec.generate_private_key(ec.SECP256R1())
    kid = keyset_mod.jwk_thumbprint(private_key.public_key())
    os.makedirs(private_out, mode=0o700, exist_ok=True)
    private_path = os.path.join(private_out, f"{service_id}-es256-{kid[:8]}.key.pem")
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    try:
        return _store_public_key(
            directory, service_id, private_key.public_key(), platform_kids
        )
    except reg.RegistryError:
        os.remove(private_path)
        raise


def remove_key(directory, service_id, kid, platform_kids=frozenset()) -> None:
    manifest = _manifest(directory)
    entry = _entry(manifest, service_id)
    before = len(entry["keys"])
    entry["keys"] = [k for k in entry["keys"] if k.get("kid") != kid]
    if len(entry["keys"]) == before:
        raise reg.RegistryError(f"service {service_id} has no key {kid}")
    _write_manifest(directory, manifest, set(platform_kids))


def _update(directory, service_id, field, value, platform_kids=frozenset()) -> None:
    manifest = _manifest(directory)
    _entry(manifest, service_id)[field] = value
    _write_manifest(directory, manifest, set(platform_kids))


def set_status(directory, service_id, status, platform_kids=frozenset()) -> None:
    _update(directory, service_id, "status", status, platform_kids)


def set_scopes(directory, service_id, scopes, platform_kids=frozenset()) -> None:
    _update(directory, service_id, "scopes", sorted(set(scopes)), platform_kids)


def set_tenants(directory, service_id, tenants, platform_kids=frozenset()) -> None:
    _update(
        directory, service_id, "tenants", list(dict.fromkeys(tenants)), platform_kids
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--registry-dir", required=True)
    parser.add_argument("--platform-keys-dir")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    r = sub.add_parser("register")
    r.add_argument("id")
    r.add_argument("--name", required=True)
    r.add_argument("--module", required=True)
    r.add_argument(
        "--audience", required=True, choices=sorted(tokens.SERVICE_AUDIENCES)
    )
    r.add_argument("--scope", action="append", default=[])
    r.add_argument("--tenant", action="append", required=True)
    a = sub.add_parser("add-key")
    a.add_argument("id")
    a.add_argument("--public-key", required=True)
    g = sub.add_parser("generate-key")
    g.add_argument("id")
    g.add_argument("--private-out", required=True)
    rk = sub.add_parser("remove-key")
    rk.add_argument("id")
    rk.add_argument("kid")
    st = sub.add_parser("set-status")
    st.add_argument("id")
    st.add_argument("status", choices=reg.STATUSES)
    ss = sub.add_parser("set-scopes")
    ss.add_argument("id")
    ss.add_argument("scopes", nargs="+")
    stn = sub.add_parser("set-tenants")
    stn.add_argument("id")
    stn.add_argument("tenants", nargs="+")
    args = parser.parse_args(argv)
    d = args.registry_dir

    try:
        kids = _platform_kids(args.platform_keys_dir)
        if args.command == "list":
            for e in _manifest(d)["services"]:
                print(
                    f"{e['id']}  {e['status']:8s}  {e['audience']}  "
                    f"scopes={','.join(e['scopes'])}  tenants={','.join(e['tenants'])}  "
                    f"keys={','.join(k['kid'][:8] for k in e['keys']) or '-'}"
                )
            reg.load_registry(d, forbidden_kids=kids)
            print("registry valid")
        elif args.command == "register":
            register(
                d,
                args.id,
                name=args.name,
                module=args.module,
                audience=args.audience,
                scopes=args.scope,
                tenants=args.tenant,
                platform_kids=kids,
            )
            print(f"registered {args.id}")
        elif args.command == "add-key":
            print(add_key(d, args.id, args.public_key, kids))
        elif args.command == "generate-key":
            print(generate_key(d, args.id, args.private_out, kids))
        elif args.command == "remove-key":
            remove_key(d, args.id, args.kid, kids)
            print(f"removed {args.kid} from {args.id}")
        elif args.command == "set-status":
            set_status(d, args.id, args.status, kids)
            print(f"{args.id} -> {args.status}")
        elif args.command == "set-scopes":
            set_scopes(d, args.id, args.scopes, kids)
            print(f"{args.id} scopes updated")
        elif args.command == "set-tenants":
            set_tenants(d, args.id, args.tenants, kids)
            print(f"{args.id} tenants updated")
    except (reg.RegistryError, keyset_mod.KeySetError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
