"""
Phase 23c — web scan policy engine (Codex P2 item 11).

A named policy resolves to concrete assessment knobs, and explicit options
override the preset. These pin the presets, the override behaviour, and the
mapping from the attack toggles to sqlmap's testing level and the allowed
parameter locations — every knob the orchestrator actually reads.
"""

from core.web.policy import (
    allowed_locations,
    resolve_policy,
    sqlmap_level_for,
)


def test_presets_shape():
    safe = resolve_policy({"scan_policy": "safe"})
    assert safe["name"] == "safe"
    assert not safe["attack_cookies"] and not safe["attack_headers"]
    assert safe["max_params_per_page"] == 5
    deep = resolve_policy({"scan_policy": "deep"})
    assert deep["attack_cookies"] and deep["attack_headers"]
    assert deep["attack_file_uploads"] and deep["max_params_per_page"] == 25
    assert deep["sqlmap_level"] == 3  # headers on → level 3


def test_explicit_option_overrides_preset():
    # deep, but don't attack cookies — the override wins over the preset.
    p = resolve_policy({"scan_policy": "deep", "attack_cookies": False})
    assert p["attack_cookies"] is False
    assert p["attack_headers"] is True  # still from the deep preset
    assert p["sqlmap_level"] == 3


def test_custom_when_knobs_set_without_a_named_policy():
    p = resolve_policy({"max_params_per_page": 7})
    assert p["name"] == "custom"
    assert p["max_params_per_page"] == 7


def test_default_is_standard():
    p = resolve_policy({})
    assert p["name"] == "standard"
    assert p["sqlmap_level"] == 1  # cookies/headers off → level 1


def test_sqlmap_level_mapping():
    assert sqlmap_level_for(False, False) == 1
    assert sqlmap_level_for(True, False) == 2
    assert sqlmap_level_for(False, True) == 3
    assert sqlmap_level_for(True, True) == 3


def test_allowed_locations_gated_by_toggles():
    base = allowed_locations(resolve_policy({"scan_policy": "safe"}))
    assert "cookie" not in base and "header" not in base and "multipart" not in base
    assert {"query", "form", "json", "path"} <= base
    deep = allowed_locations(resolve_policy({"scan_policy": "deep"}))
    assert {"cookie", "header", "multipart"} <= deep


def test_per_engine_timeouts_pass_through():
    p = resolve_policy({"nuclei_timeout": 600, "sqlmap_timeout": 120})
    assert p["nuclei_timeout"] == 600 and p["sqlmap_timeout"] == 120
    assert resolve_policy({})["nuclei_timeout"] is None
