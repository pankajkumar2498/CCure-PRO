"""
Compliance consumes evidence providers (G4, C4;
docs/architecture/MODULAR_REFACTORING_LOG.md §6).

``core/compliance_evidence.py`` declares the evidence sources, keeps the
registry of who answers each and caches the answers. The answers live with the
tables they read — the findings store, the asset registry, the network topology
and web application scanning — and Audit's composition root,
``ccure_audit/evidence_providers.py``, registers them. These pin:

* the evidence module imports no other capability's code or model, and names
  no table;
* the providers import nothing of compliance (registration is the composition
  root's);
* every process that evaluates compliance registers every source: the worker
  through Celery's ``imports``, the API through the same loader call;
* the registry's rules: a source it does not declare is refused, a second
  provider for one source is refused, and a declared source with no provider
  raises rather than reading as not assessed.
"""

import ast

import pytest

from core import compliance_evidence
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

PROVIDER_MODULES = (
    "core.findings.evidence",
    "core.asset_evidence",
    "core.topology.evidence",
    "core.web.evidence",
)


def _edges():
    _, edges = collect_edges()
    return edges


def test_the_evidence_module_imports_no_other_capability():
    beyond = sorted(
        (e.src, e.dst)
        for e in _edges()
        if e.src == "core.compliance_evidence"
        and capability_map.capability_of(e.dst) not in ("compliance", "infra")
    )
    assert beyond == []


def test_the_evidence_module_names_no_table():
    measurement = capability_map.measure()
    owners = capability_map.table_owners()
    # Compliance's remaining references are the scan task's and the router's
    # reads of assets and services, outside the evidence path (log §7).
    evidence_tables = {
        "asset_vulnerabilities",
        "network_links",
        "tls_details",
        "vulnerability_definitions",
        "web_findings",
        "web_scans",
    }
    still = sorted(
        table
        for capability, table in measurement["foreign_table_references"]
        if capability == "compliance" and table in evidence_tables
    )
    assert still == []
    assert all(owners.get(t) != "compliance" for t in evidence_tables)


@pytest.mark.parametrize("module", PROVIDER_MODULES)
def test_a_provider_imports_nothing_of_compliance(module):
    into_compliance = sorted(
        (e.src, e.dst)
        for e in _edges()
        if e.src == module and capability_map.capability_of(e.dst) == "compliance"
    )
    assert into_compliance == []
    assert capability_map.capability_of(module) != "compliance"


def test_the_worker_and_the_api_load_the_registrations():
    from core.celery_app import celery_app

    assert "ccure_audit.evidence_providers" in celery_app.conf.imports
    assert "ccure_audit.evidence_providers" in celery_app.loader.default_modules
    main = ast.parse((BACKEND_ROOT / "main.py").read_text(encoding="utf-8"))
    calls = [
        node.func.attr
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert "import_default_modules" in calls


def test_every_declared_source_is_registered_once_the_registrations_load():
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    assert compliance_evidence.registered_evidence_sources() == (
        compliance_evidence.EVIDENCE_SOURCES
    )


def test_a_source_the_registry_does_not_declare_is_refused():
    with pytest.raises(ValueError):
        compliance_evidence.register_evidence_provider("auto_scan", lambda db, a: {})


def test_a_second_provider_for_one_source_is_refused(monkeypatch):
    monkeypatch.setattr(compliance_evidence, "_PROVIDERS", {})

    def first(db, asset_id):
        return {}

    compliance_evidence.register_evidence_provider("services_ports", first)
    compliance_evidence.register_evidence_provider("services_ports", first)  # no-op
    with pytest.raises(ValueError):
        compliance_evidence.register_evidence_provider(
            "services_ports", lambda db, a: {}
        )


def test_a_declared_source_without_a_provider_raises(monkeypatch):
    monkeypatch.setattr(compliance_evidence, "_PROVIDERS", {})
    with pytest.raises(compliance_evidence.EvidenceProviderMissing):
        compliance_evidence.ComplianceEvidenceProvider._fetch_and_translate(
            None, "ast_any", "services_ports"
        )


def test_an_undeclared_source_still_reads_as_not_assessed(monkeypatch):
    monkeypatch.setattr(compliance_evidence, "_PROVIDERS", {})
    payload = compliance_evidence.ComplianceEvidenceProvider._fetch_and_translate(
        None, "ast_any", "auto_scan"
    )
    assert payload["_evidence_available"] is False
