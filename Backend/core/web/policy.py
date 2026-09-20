"""
core/web/policy.py
────────────────────────────────────────────────────────────────────────────
Web scan policy resolver (Codex P2 item 11).

A named policy is a set of assessment knobs the operator does not want to set one
by one: how aggressively to test, whether to attack cookies / headers / file
uploads, how many parameters per page, and per-engine time budgets. This resolves
a policy *name* to concrete settings, and lets any explicit option override the
preset — so "deep, but don't attack cookies" is expressible.

Every knob here is honoured by the orchestrator (a knob nothing reads is worse
than a missing one): the attack toggles decide the sqlmap testing level and which
parameter locations become injection targets, ``max_params_per_page`` bounds the
XSS/injection candidate set, and the per-engine timeouts override the defaults.
"""

from __future__ import annotations

from typing import Any, Dict

#: The named presets. "custom" is what an operator gets when they set knobs
#: without naming a policy. Each names only the assessment-shaping fields.
POLICIES = ("safe", "standard", "deep", "api", "authenticated", "custom")

_PRESETS: Dict[str, Dict[str, Any]] = {
    # Least intrusive: never touch cookies/headers/uploads, small surface budget.
    "safe": {
        "scan_depth": "quick",
        "attack_cookies": False,
        "attack_headers": False,
        "attack_file_uploads": False,
        "max_params_per_page": 5,
    },
    # The default posture: test query/form/JSON/path; leave session-bearing
    # cookies and transport headers alone (attacking them risks breaking the
    # session and is high-noise), no upload attacks.
    "standard": {
        "scan_depth": "standard",
        "attack_cookies": False,
        "attack_headers": False,
        "attack_file_uploads": False,
        "max_params_per_page": 10,
    },
    # Thorough: attack cookies, headers and uploads, wider budget.
    "deep": {
        "scan_depth": "deep",
        "attack_cookies": True,
        "attack_headers": True,
        "attack_file_uploads": True,
        "max_params_per_page": 25,
    },
    # API-focused: attack headers (API keys/versions live there) but not the
    # session cookie; uploads off.
    "api": {
        "scan_depth": "standard",
        "attack_cookies": False,
        "attack_headers": True,
        "attack_file_uploads": False,
        "max_params_per_page": 15,
    },
    # Authenticated app: same shape as standard; the difference is that auth is
    # configured, which the pipeline handles separately.
    "authenticated": {
        "scan_depth": "standard",
        "attack_cookies": False,
        "attack_headers": False,
        "attack_file_uploads": False,
        "max_params_per_page": 12,
    },
}

_DEFAULTS = _PRESETS["standard"]


def sqlmap_level_for(attack_cookies: bool, attack_headers: bool) -> int:
    """
    The sqlmap ``--level`` implied by the attack toggles. sqlmap tests GET/POST
    parameters at level 1, adds Cookie testing at level 2, and HTTP headers
    (User-Agent/Referer/Host) at level 3. So the toggles map directly onto the
    level rather than being a separate mechanism.
    """
    if attack_headers:
        return 3
    if attack_cookies:
        return 2
    return 1


def resolve_policy(options: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Resolve the effective web scan policy from the scan options.

    A named ``scan_policy`` supplies the baseline; any explicit key in
    ``options`` overrides it, so the preset is a convenience, never a ceiling.
    Returns a dict with every knob set to a concrete value plus the derived
    ``sqlmap_level`` and the resolved policy ``name``.
    """
    options = options or {}
    name = str(options.get("scan_policy") or "").lower()
    base = dict(_PRESETS.get(name, _DEFAULTS))
    if name not in _PRESETS:
        name = "custom" if _has_explicit_knobs(options) else "standard"

    def _pick(key, default):
        val = options.get(key)
        return val if val is not None else base.get(key, default)

    attack_cookies = bool(_pick("attack_cookies", False))
    attack_headers = bool(_pick("attack_headers", False))
    resolved = {
        "name": name,
        "scan_depth": _pick("scan_depth", "standard"),
        "attack_cookies": attack_cookies,
        "attack_headers": attack_headers,
        "attack_file_uploads": bool(_pick("attack_file_uploads", False)),
        "max_params_per_page": int(_pick("max_params_per_page", 10) or 10),
        "sqlmap_level": sqlmap_level_for(attack_cookies, attack_headers),
        # Per-engine time budgets — None means "use the pipeline default".
        "nuclei_timeout": options.get("nuclei_timeout"),
        "sqlmap_timeout": options.get("sqlmap_timeout"),
    }
    return resolved


#: The parameter locations gated by the attack toggles. query/form/json/path are
#: always in scope; cookie/header/multipart are opt-in via the policy.
def allowed_locations(policy: Dict[str, Any]) -> set:
    """The parameter locations a scan under this policy may test."""
    locs = {"query", "form", "json", "path", "soap"}
    if policy.get("attack_cookies"):
        locs.add("cookie")
    if policy.get("attack_headers"):
        locs.add("header")
    if policy.get("attack_file_uploads"):
        locs.add("multipart")
    return locs


def _has_explicit_knobs(options: Dict[str, Any]) -> bool:
    return any(
        options.get(k) is not None
        for k in (
            "attack_cookies",
            "attack_headers",
            "attack_file_uploads",
            "max_params_per_page",
            "nuclei_timeout",
            "sqlmap_timeout",
        )
    )
