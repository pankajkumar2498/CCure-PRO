"""
Structural guards on the compliance rule catalogue.

These are not behavioural tests. They assert that every seeded rule is capable
of producing a verdict at all, which is the failure mode that hid the worst
defects in this module: 49 of 79 rules named an evidence source with no adapter
(`auto_scan`) or read a key no adapter emits, so they reported `manual_review`
forever while the dashboard showed them as coverage. Nothing caught it because
every test asserted on endpoints rather than on the catalogue.

Each check here is mechanical and would have failed on the pre-fix catalogue.
"""

from testpaths import BACKEND_ROOT

import ast
import importlib
import inspect
import textwrap

import pytest
from core import compliance_evidence
from core.compliance_evidence import VALID_RULE_EVIDENCE_SOURCES

SEED_RULES = BACKEND_ROOT / "scripts" / "seed_real_rules.py"

# Evidence source -> the function that builds its payload. Since G4 these live
# with the tables they read, and Audit's composition root registers them
# (ccure_audit/evidence_providers.py); two sources are composed there from two
# producers, so the function named here is the one holding the dict literal.
_ADAPTERS = {
    "vulnerability_audit": "core.findings.evidence:vulnerability_audit",
    "malware_scan": "core.asset_evidence:malware_scan",
    "services_ports": "core.findings.evidence:services_ports",
    "tls_certificates": "core.findings.evidence:tls_certificates",
    "network_topology": "core.topology.evidence:network_topology",
    "credential_validation": "core.asset_evidence:credential_validation",
    "offline_configuration": "core.asset_evidence:offline_configuration",
    "web_vulnerability_audit": "core.web.evidence:web_vulnerability_audit",
}


def _adapter(source: str):
    module, name = _ADAPTERS[source].split(":")
    return getattr(importlib.import_module(module), name)


def _seeded_rules() -> list:
    """Every rule literal in seed_real_rules.py, without importing it.

    The module connects to a database at import time, so it is parsed rather
    than imported.
    """
    tree = ast.parse(SEED_RULES.read_text(encoding="utf-8"))
    rules: list = []
    for node in ast.walk(tree):
        # rules_data = [ ... ]
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "rules_data":
                    rules.extend(ast.literal_eval(node.value))
        # rules_data.extend([ ... ])
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "extend"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "rules_data"
        ):
            rules.extend(ast.literal_eval(node.args[0]))
    return rules


def _adapter_keys(source: str) -> set:
    """Keys the adapter for `source` can return, read from its return literals."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(_adapter(source))))
    keys: set = set()
    for node in ast.walk(tree):
        # Both `return {...}` and `payload = {...}; return {k: v ...}` shapes.
        if isinstance(node, ast.Dict):
            keys.update(
                k.value
                for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            )
    return keys


def test_seed_file_is_parseable():
    rules = _seeded_rules()
    assert len(rules) > 50, "rule catalogue looks truncated"


def test_every_rule_declares_a_real_evidence_source():
    """No rule may name an evidence source the provider cannot serve.

    `auto_scan` was such a source: 35 rules declared it, `_fetch_and_translate`
    had no branch for it, and every one of them returned
    `_evidence_available: False` on every asset forever.
    """
    offenders = [
        (r["id"], r.get("evidence_source"))
        for r in _seeded_rules()
        if r.get("evidence_source") not in VALID_RULE_EVIDENCE_SOURCES
    ]
    assert not offenders, (
        "rules declare an evidence source with no adapter: "
        f"{offenders}. Valid sources: {sorted(VALID_RULE_EVIDENCE_SOURCES)}"
    )


def test_every_automated_rule_reads_a_key_its_adapter_emits():
    """A rule whose key the adapter never returns can only report unassessed.

    Fourteen rules read `offline_configuration` keys that were not in the
    adapter's return dict — five of which the adapter computed and then dropped
    on the floor.
    """
    offenders = []
    for rule in _seeded_rules():
        source = rule.get("evidence_source")
        if source not in _ADAPTERS:
            continue  # manual rules have nothing to read
        key = (rule.get("check_definition") or {}).get("key")
        if not key:
            offenders.append((rule["id"], source, "<no key>"))
            continue
        if key not in _adapter_keys(source):
            offenders.append((rule["id"], source, key))

    assert not offenders, (
        "rules read evidence keys their adapter never emits "
        f"(rule_id, source, key): {offenders}"
    )


def test_manual_rules_are_not_given_evaluable_criteria():
    """A manual rule must not look automated.

    The scan loop skips manual rules and raises an org-level attestation
    placeholder instead. A manual rule carrying a key/operator/expected triple
    would suggest to a reader that it gets evaluated, and it never does.
    """
    offenders = [
        r["id"]
        for r in _seeded_rules()
        if r.get("evidence_source") == "manual"
        and {"key", "operator", "expected"} <= set((r.get("check_definition") or {}))
    ]
    assert (
        not offenders
    ), f"manual rules carry evaluable criteria that will never run: {offenders}"


def test_evidence_sources_constant_matches_the_registered_providers():
    """EVIDENCE_SOURCES must list exactly the sources that have a provider.

    Cache invalidation iterates this constant to build its keys. It used to
    carry three names that were not evidence sources at all
    (`active_services`, `tls_ssl_configuration`, `network_link_topology`), so
    the flush deleted keys that never existed and left the real cached evidence
    in place. Since G4 the providers are registered (the dispatcher this test
    used to read is the registry), so the comparison is with what is
    registered, and with this file's table of who builds each payload.
    """
    from ccure_audit import evidence_providers

    sources = set(compliance_evidence.EVIDENCE_SOURCES)
    assert set(evidence_providers.PROVIDERS) == sources
    assert compliance_evidence.registered_evidence_sources() == (
        compliance_evidence.EVIDENCE_SOURCES
    )
    assert set(_ADAPTERS) == sources


@pytest.mark.parametrize("source", sorted(_ADAPTERS))
def test_every_declared_source_has_an_adapter_function(source):
    assert callable(_adapter(source))


@pytest.mark.parametrize(
    "source", sorted(set(_ADAPTERS) - {"malware_scan", "web_vulnerability_audit"})
)
def test_a_registered_provider_is_the_function_named_here(source):
    """The two composed sources aside, what compliance calls is the function
    whose keys this file reads, not a copy of it."""
    assert compliance_evidence.evidence_provider(source) is _adapter(source)
