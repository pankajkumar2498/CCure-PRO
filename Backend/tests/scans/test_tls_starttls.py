"""
tests/scans/test_tls_starttls.py
─────────────────────────────────────────────────────────────────────────────
Reaching services that negotiate TLS inside a plaintext protocol. Phase 11,
GAP-07.

What was missing
────────────────
Before this phase the TLS assessment only looked at ports that speak TLS from
the first byte — 443, 8443, 993, 995 and a few more. A mail server with an
expired certificate on port 25, a directory server with a 1024-bit key on 389,
a database with TLS 1.0 on 5432: none of them were assessed at all, on a host
whose web port was assessed thoroughly. Measured against five real listeners,
this phase found **19 findings on services the previous scanner could not see**.

Three properties, and the third is the one that would break something
─────────────────────────────────────────────────────────────────────
1. The table and the selector agree — a service listed here that the selector
   does not route to ``tls_scanner`` is never reached on a host exposing only
   that port.
2. A service that does not offer STARTTLS produces **no finding**, and
   certainly no evidence that its TLS is fine.
3. A STARTTLS endpoint **never becomes ``tls_info``**. That key means "the
   first *implicit*-TLS endpoint that answered"; ``asset_syncer`` writes the
   asset's TLS record from it and ``core/risk.py`` scores from it. Promoting a
   mail server there would rewrite an asset's TLS identity with a certificate
   no browser ever negotiates.
"""

import pytest

from engines.vulnerability.plugin_selector import plugin_names, select_plugins
from engines.vulnerability.plugins import tls_scanner
from engines.vulnerability.plugins.tls_scanner import STARTTLS_SERVICES
from scripts.measure_tls_coverage import NOT_PLANNED, SCOPE

STARTTLS_AREAS = {
    area for area, theme, _d in SCOPE if theme == "starttls" and area not in NOT_PLANNED
}


# ── The table itself ─────────────────────────────────────────────────────────


def test_every_planned_transport_is_in_the_table():
    """
    ``STARTTLS_SERVICES`` is the capability claim the coverage harness reads.
    starttls.smtp, starttls.imap, starttls.pop3, starttls.ldap,
    starttls.postgres and starttls.ftp are the six this phase set out to reach.
    """
    assert {f"starttls.{name}" for name in STARTTLS_SERVICES} == STARTTLS_AREAS


def test_the_transports_not_planned_are_absent_from_the_table():
    """starttls.xmpp, starttls.rdp and starttls.mysql, each with a reason."""
    for area in ("starttls.xmpp", "starttls.rdp", "starttls.mysql"):
        assert area in NOT_PLANNED
        assert area.split(".", 1)[1] not in STARTTLS_SERVICES


def test_every_service_name_resolves_against_sslyzes_own_enum():
    """
    The names are not free-form: they are looked up on sslyze's opportunistic
    TLS enum. A service this build of sslyze cannot negotiate must be
    impossible to add here by mistake — mysql is exactly that case, and the
    lookup returning None is why it is declared unimplemented rather than
    silently producing connection errors.
    """
    from engines.tls.wrapper import SSLyzeWrapper

    for name in STARTTLS_SERVICES:
        assert SSLyzeWrapper._opportunistic_protocol(name) is not None, name
    assert SSLyzeWrapper._opportunistic_protocol("mysql") is None
    assert SSLyzeWrapper._opportunistic_protocol("nonsense") is None


@pytest.mark.parametrize(
    "service,port",
    [(s, p) for s, ports in STARTTLS_SERVICES.items() for p in ports],
)
def test_the_selector_routes_every_starttls_port_to_the_plugin(service, port):
    """
    The failure this prevents is silent: a port in the table but not in
    ``_PORT_MAP`` means a host exposing only that port never runs the plugin,
    and the transport looks supported while reaching nothing. PostgreSQL hit
    exactly this during the phase — 5432 already had an entry for
    ``default_creds``, and a second dict key for it was dead.
    """
    parallel, serial = select_plugins({"open_ports": [{"port": port}]})
    assert "tls_scanner" in plugin_names(
        parallel + serial
    ), f"{service} on port {port} does not select tls_scanner"


def test_the_port_map_has_no_duplicate_keys():
    """
    A repeated key in a dict literal keeps only the last value, silently. That
    is how the PostgreSQL entry above came to be dead.
    """
    import ast
    import pathlib

    source = pathlib.Path(tls_scanner.__file__).parent.parent / "plugin_selector.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "_PORT_MAP" not in targets or not isinstance(node.value, ast.Dict):
            continue
        keys = [k.value for k in node.value.keys if isinstance(k, ast.Constant)]
        duplicates = {k for k in keys if keys.count(k) > 1}
        assert not duplicates, f"_PORT_MAP repeats {sorted(duplicates)}"


# ── Reaching them ────────────────────────────────────────────────────────────


class FakeAudit:
    """Records every deep audit the plugin asks for, and answers from a script."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, ip, port, starttls=""):
        self.calls.append((port, starttls))
        return self.answers.get((port, starttls), {})


def certificate_answer(subject="CN=svc", **extra):
    payload = {
        "certificate": {
            "subject": subject,
            "issuer": subject,
            "self_signed": True,
            "not_after": "2030-01-01T00:00:00+00:00",
            "chain_trusted": False,
            "trust_failures": [{"store": "Mozilla", "error": "self signed"}],
            "ocsp_stapled": True,
        },
        "protocols": {"tls_1_2": {"supported": True}},
    }
    payload.update(extra)
    return payload


@pytest.fixture()
def no_implicit_tls(monkeypatch):
    """Remove the implicit-TLS ports so a test isolates the STARTTLS path."""
    monkeypatch.setattr(tls_scanner, "_TLS_PORTS", [])
    monkeypatch.setattr(tls_scanner, "_STARTTLS_ENABLED", True)
    monkeypatch.setattr(tls_scanner, "_DEEP_ENABLED", True)


def test_a_starttls_service_is_assessed(monkeypatch, no_implicit_tls):
    audit = FakeAudit({(25, "smtp"): certificate_answer()})
    monkeypatch.setattr(tls_scanner, "_deep_audit", audit)

    result = tls_scanner.run("192.0.2.10", [25])
    assert audit.calls == [(25, "smtp")]
    endpoints = result["tls_endpoints"]
    assert endpoints[0]["port"] == 25
    assert endpoints[0]["starttls"] == "smtp"
    assert endpoints[0]["deep_assessed"] is True


def test_a_starttls_endpoint_never_becomes_tls_info(monkeypatch, no_implicit_tls):
    """
    ``asset_syncer`` and ``core/risk.py`` read ``tls_info``. A mail server's
    certificate appearing there would change the asset's TLS identity to
    something no browser negotiates.
    """
    monkeypatch.setattr(
        tls_scanner, "_deep_audit", FakeAudit({(25, "smtp"): certificate_answer()})
    )
    result = tls_scanner.run("192.0.2.10", [25])
    assert "tls_info" not in result
    assert result["tls_endpoints"]


def test_an_implicit_endpoint_still_becomes_tls_info(monkeypatch):
    """The behaviour Phase 6 established is unchanged by this phase."""
    from core.models import TLSInfo

    info = TLSInfo(enabled=True)
    info.version = "TLSv1.3"
    monkeypatch.setattr(tls_scanner, "_TLS_PORTS", [443])
    monkeypatch.setattr(tls_scanner, "_probe", lambda ip, port, **k: info)
    monkeypatch.setattr(tls_scanner, "_deep_audit", FakeAudit({}))

    result = tls_scanner.run("192.0.2.10", [443])
    assert result["tls_info"]["version"] == "TLSv1.3"


def test_a_service_that_does_not_offer_starttls_produces_nothing(
    monkeypatch, no_implicit_tls
):
    """
    The normal outcome for a probe of a port that speaks something else. It
    must not be a finding, and must not be evidence that the endpoint is fine.
    """
    audit = FakeAudit(
        {(25, "smtp"): {"error": "no TLS handshake with 192.0.2.10:25 via smtp"}}
    )
    monkeypatch.setattr(tls_scanner, "_deep_audit", audit)

    assert tls_scanner.run("192.0.2.10", [25]) == {}


def test_an_audit_returning_no_certificate_is_not_an_endpoint(
    monkeypatch, no_implicit_tls
):
    monkeypatch.setattr(
        tls_scanner, "_deep_audit", FakeAudit({(25, "smtp"): {"protocols": {}}})
    )
    assert tls_scanner.run("192.0.2.10", [25]) == {}


def test_every_exposed_starttls_service_is_reached(monkeypatch, no_implicit_tls):
    monkeypatch.setattr(tls_scanner, "_DEEP_MAX_ENDPOINTS", 10)
    ports = [25, 143, 110, 389, 5432, 21]
    audit = FakeAudit(
        {
            (25, "smtp"): certificate_answer(),
            (143, "imap"): certificate_answer(),
            (110, "pop3"): certificate_answer(),
            (389, "ldap"): certificate_answer(),
            (5432, "postgres"): certificate_answer(),
            (21, "ftp"): certificate_answer(),
        }
    )
    monkeypatch.setattr(tls_scanner, "_deep_audit", audit)

    result = tls_scanner.run("192.0.2.10", ports)
    assert sorted(c[1] for c in audit.calls) == [
        "ftp",
        "imap",
        "ldap",
        "pop3",
        "postgres",
        "smtp",
    ]
    assert len(result["tls_endpoints"]) == 6


def test_the_endpoint_budget_bounds_the_work(monkeypatch, no_implicit_tls):
    """
    This product scans OT segments. A host exposing six opportunistic services
    must not silently cost six full cipher-suite enumerations beyond the
    budget an operator set.
    """
    monkeypatch.setattr(tls_scanner, "_DEEP_MAX_ENDPOINTS", 2)
    audit = FakeAudit(
        {
            (25, "smtp"): certificate_answer(),
            (143, "imap"): certificate_answer(),
            (110, "pop3"): certificate_answer(),
        }
    )
    monkeypatch.setattr(tls_scanner, "_deep_audit", audit)

    tls_scanner.run("192.0.2.10", [25, 143, 110])
    assert len(audit.calls) == 2


def test_implicit_ports_consume_the_budget_before_starttls(monkeypatch):
    """
    One budget covers both kinds of endpoint. A web port assessed deeply is
    work the operator already paid for, and STARTTLS must not exceed the
    ceiling by running on top of it.
    """
    from core.models import TLSInfo

    info = TLSInfo(enabled=True)
    monkeypatch.setattr(tls_scanner, "_TLS_PORTS", [443])
    monkeypatch.setattr(tls_scanner, "_DEEP_MAX_ENDPOINTS", 1)
    monkeypatch.setattr(tls_scanner, "_probe", lambda ip, port, **k: info)
    audit = FakeAudit(
        {(443, ""): certificate_answer(), (25, "smtp"): certificate_answer()}
    )
    monkeypatch.setattr(tls_scanner, "_deep_audit", audit)

    tls_scanner.run("192.0.2.10", [443, 25])
    assert audit.calls == [(443, "")]


def test_starttls_can_be_disabled(monkeypatch, no_implicit_tls):
    monkeypatch.setattr(tls_scanner, "_STARTTLS_ENABLED", False)
    audit = FakeAudit({(25, "smtp"): certificate_answer()})
    monkeypatch.setattr(tls_scanner, "_deep_audit", audit)

    assert tls_scanner.run("192.0.2.10", [25]) == {}
    assert audit.calls == []


def test_findings_on_a_starttls_endpoint_carry_its_port(monkeypatch, no_implicit_tls):
    monkeypatch.setattr(
        tls_scanner, "_deep_audit", FakeAudit({(389, "ldap"): certificate_answer()})
    )
    result = tls_scanner.run("192.0.2.10", [389])
    findings = result.get("cves") or []
    assert findings
    assert {f["port"] for f in findings} == {389}
    assert "tls.certificate_untrusted_chain" in {f["check_area"] for f in findings}


def test_a_host_with_no_tls_of_either_kind_returns_nothing(monkeypatch):
    monkeypatch.setattr(tls_scanner, "_TLS_PORTS", [443])
    monkeypatch.setattr(tls_scanner, "_deep_audit", FakeAudit({}))
    assert tls_scanner.run("192.0.2.10", [80, 22]) == {}
