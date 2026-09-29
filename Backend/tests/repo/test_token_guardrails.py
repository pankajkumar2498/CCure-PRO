"""
Token guardrails — Phase 9.1.

Signing and verification live in ``ccure_platform.identity.tokens`` and nowhere
else (docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md §6):

* **no other module imports a JWT library**, so no module can quietly verify
  tokens its own way;
* **verification takes the expected kind as a required argument**, so an
  access-token endpoint cannot accept a refresh, ticket or challenge token;
* **the legacy any-kind decode has a fixed set of callers** — the two WebSocket
  ticket logins (reserved for Phase 10) and the rate-limit audit's wiring in
  ``main.py`` — and the set can only shrink;
* **no private key material is committed**.
"""

from __future__ import annotations

import ast
import inspect
import re

from scripts.architecture.import_graph import discover_modules
from testpaths import BACKEND_ROOT

JWT_LIBRARIES = ("jose", "jwt", "joserfc", "authlib", "jwcrypto")
TOKEN_MODULE = "ccure_platform.identity.tokens"

#: Who may still call the any-kind ``decode_token``, and why. Shrinks only.
LEGACY_DECODE_CALLERS = {
    "routers.scan_history": "WebSocket ticket login — Phase 10",
    "routers.web_scans": "WebSocket ticket login — Phase 10",
    "main": "hands the decoder to core.rate_limit_audit, which checks the kind",
}


def _modules():
    return sorted(discover_modules().items())


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name, None
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                yield node.module, a.name


def test_only_the_token_module_imports_a_jwt_library():
    offenders = []
    for module, path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name, _ in _imports(tree):
            if name.split(".")[0] in JWT_LIBRARIES and module != TOKEN_MODULE:
                offenders.append(f"{module}: {name}")
    assert not offenders, (
        "a module other than ccure_platform.identity.tokens imports a JWT "
        "library — sign and verify through the token module:\n  "
        + "\n  ".join(offenders)
    )


def test_the_token_module_does_import_one():
    """The check above is only meaningful if the token module is found."""
    path = dict(_modules())[TOKEN_MODULE]
    names = {n.split(".")[0] for n, _ in _imports(ast.parse(path.read_text()))}
    assert names & set(JWT_LIBRARIES)


def test_verify_requires_the_expected_kind_issuer_and_audience():
    from ccure_platform.identity import tokens

    params = inspect.signature(tokens.verify).parameters
    for name in ("expected_kind", "issuer", "audience"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
        assert params[name].default is inspect.Parameter.empty, name
    import pytest

    with pytest.raises(ValueError):
        tokens.verify(
            "x",
            expected_kind="accesss",
            issuer=tokens.ISSUER,
            audience=tokens.USER_AUDIENCE,
        )


def test_the_legacy_any_kind_decode_has_a_fixed_set_of_callers():
    callers = set()
    for module, path in _modules():
        if module.startswith("ccure_platform.identity."):
            continue  # the token module and jwt_handler's own wrapper
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for _, name in _imports(tree):
            if name in ("decode_token", "decode_any_kind"):
                callers.add(module)
    assert callers <= set(LEGACY_DECODE_CALLERS), (
        "new caller(s) of the any-kind decode — use "
        "tokens.verify(token, expected_kind=…):\n  "
        + "\n  ".join(sorted(callers - set(LEGACY_DECODE_CALLERS)))
    )
    assert callers == set(LEGACY_DECODE_CALLERS), (
        "these no longer call decode_token — remove them from "
        f"LEGACY_DECODE_CALLERS: {sorted(set(LEGACY_DECODE_CALLERS) - callers)}"
    )


def test_the_platform_checks_no_token_type_by_hand():
    """
    ``payload.get("type")`` was how every caller checked the kind (finding
    F9-3). Inside the platform only the token module may do it now.
    """
    pattern = re.compile(r"""payload\.get\(\s*["']type["']\s*\)""")
    offenders = []
    for module, path in _modules():
        in_platform = module.startswith("ccure_platform.") or module in (
            "routers.user_profile",
        )
        if not in_platform or module == TOKEN_MODULE:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{module}:{number}")
    assert not offenders, offenders


# ── no key material in the repository ───────────────────────────────────────

_PEM_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/=\r\n]{40,}", re.MULTILINE
)
_JWK_PRIVATE = re.compile(r'"d"\s*:\s*"[A-Za-z0-9_\-]{20,}"')
_SKIP = {".venv", "node_modules", "__pycache__", "reports", "logs", ".git"}


def test_no_private_key_material_is_committed():
    """
    A PEM private-key block with a body, or a JWK private member. A form
    placeholder showing the header alone does not match: it carries no key.
    """
    found = []
    for path in BACKEND_ROOT.rglob("*"):
        if not path.is_file() or any(part in _SKIP for part in path.parts):
            continue
        if path.suffix not in {
            ".py",
            ".json",
            ".pem",
            ".key",
            ".txt",
            ".yaml",
            ".yml",
            ".env",
            ".cfg",
            ".ini",
            "",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if _PEM_KEY.search(text) or (
            path.suffix == ".json" and _JWK_PRIVATE.search(text)
        ):
            found.append(str(path.relative_to(BACKEND_ROOT)))
    assert not found, f"private key material in the repository: {found}"


def test_the_key_scan_recognises_a_key():
    # Assembled at run time so the repository never contains a literal PEM
    # block — gitleaks (pre-commit) rightly refuses one, even a fake.
    begin, end = (
        "-----BEGIN EC " + "PRIVATE KEY-----",
        "-----END EC " + "PRIVATE KEY-----",
    )
    sample = f"{begin}\n{'A' * 64}\n{end}"
    assert _PEM_KEY.search(sample)
    placeholder = 'placeholder="-----BEGIN OPENSSH ' + 'PRIVATE KEY-----"'
    assert not _PEM_KEY.search(placeholder)


def test_only_the_api_service_can_reach_the_signing_keys():
    """
    Owner's decision (Phase 9 review): worker, web-worker and beat receive no
    private key. The keyset reaches a container only through the compose mount,
    so the compose file is where that is enforced. Skipped where the file is not
    reachable (the API container mounts Backend/ only); runs on the host and CI.
    """
    import pytest
    import yaml

    from testpaths import REPO_ROOT

    compose = REPO_ROOT / "docker-compose.yml"
    if not compose.is_file():
        pytest.skip(f"docker-compose.yml is not reachable from {REPO_ROOT}")
    services = yaml.safe_load(compose.read_text())["services"]

    def keys_mounts(service):
        return [
            v
            for v in service.get("volumes") or []
            if isinstance(v, str) and "CCURE_TOKEN_KEYS_HOST_DIR" in v
        ]

    def keys_env(service):
        env = service.get("environment") or []
        items = env if isinstance(env, list) else [f"{k}={v}" for k, v in env.items()]
        return [e for e in items if str(e).startswith("CCURE_TOKEN_KEYS_DIR")]

    holders = sorted(n for n, s in services.items() if keys_mounts(s) or keys_env(s))
    assert holders == [
        "api"
    ], f"the token keyset reaches {holders}; only api may hold it"
    (mount,) = keys_mounts(services["api"])
    assert mount.endswith(":ro"), f"the keyset mount must be read-only: {mount}"


def test_only_the_api_service_carries_the_token_settings():
    """
    Step 9.6a: the issuance algorithm and the legacy HS256 switch are api
    settings. A worker given either would suggest it issues or verifies user
    tokens, which none does. Skipped where docker-compose.yml is not reachable.
    """
    import pytest
    import yaml

    from testpaths import REPO_ROOT

    compose = REPO_ROOT / "docker-compose.yml"
    if not compose.is_file():
        pytest.skip(f"docker-compose.yml is not reachable from {REPO_ROOT}")
    services = yaml.safe_load(compose.read_text())["services"]

    def names(service):
        env = service.get("environment") or []
        items = env if isinstance(env, list) else [f"{k}={v}" for k, v in env.items()]
        return {str(e).split("=", 1)[0] for e in items}

    api_only = (
        "CCURE_ACCEPT_LEGACY_HS256",
        "CCURE_TOKEN_SIGNING_ALG",
    )
    for setting in api_only:
        holders = sorted(n for n, s in services.items() if setting in names(s))
        assert holders == ["api"], f"{setting} reaches {holders}; only api may hold it"
