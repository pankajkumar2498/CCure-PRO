"""
core/config_audit/builtin/middleware_tomcat.py
─────────────────────────────────────────────────────────────────────────────
Apache Tomcat configuration checks. Phase 8 (GAP-09).

Read out of a live Tomcat 10.1 container through the real collector before the
rules were written, and the container settled two things worth recording.

The stock image is already hardened on two of these
───────────────────────────────────────────────────
``webapps/`` is **empty** — the official image moves the bundled applications
to ``webapps.dist/`` — and ``tomcat-users.xml`` defines no users at all. So a
stock container passes the default-application and default-account checks, and
proving those checks *fire* needed the applications copied back deliberately.
A check that has only ever been seen passing is indistinguishable from one that
cannot fail.

``shutdown="SHUTDOWN"`` is a real finding on a stock install
────────────────────────────────────────────────────────────
``<Server port="8005" shutdown="SHUTDOWN">`` is what the image ships, it is
what Tomcat's own documentation tells you to change, and anyone who can reach
port 8005 and send that word stops the server. It is not a theoretical default.

Tomcat is XML, so there are no directives at all — the settings are attributes
on elements, addressed by XPath. That is the whole reason ``config_file`` could
not have been extended to cover this.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["TOMCAT_CHECKS", "tomcat_checks"]

#: The official image, a tarball install, and the Debian packaging.
_SERVER_XML = (
    "/usr/local/tomcat/conf/server.xml",
    "/opt/tomcat/conf/server.xml",
    "/etc/tomcat10/server.xml",
    "/etc/tomcat9/server.xml",
    "/var/lib/tomcat9/conf/server.xml",
)
_USERS_XML = (
    "/usr/local/tomcat/conf/tomcat-users.xml",
    "/opt/tomcat/conf/tomcat-users.xml",
    "/etc/tomcat10/tomcat-users.xml",
    "/etc/tomcat9/tomcat-users.xml",
    "/var/lib/tomcat9/conf/tomcat-users.xml",
)

_DOC = "https://tomcat.apache.org/tomcat-10.1-doc/config/index.html"


def _xml(paths, xpath: str, attribute: str = "", result: str = "value") -> dict:
    params = {
        "path": list(paths),
        "format": "xml",
        "xpath": xpath,
        "result": result,
    }
    if attribute:
        params["attribute"] = attribute
    return params


def _check(
    *,
    suffix: str,
    title: str,
    severity: str,
    collect: dict,
    expect: Expectation,
    absent: AbsencePolicy,
    description: str,
    rationale: str,
    remediation: str,
    area: str,
    references=(_DOC,),
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.mw.tomcat.{suffix}",
        title=title,
        check_type="structured_config",
        platforms=("linux", "windows"),
        severity=severity,
        collect=collect,
        expect=expect,
        absent=absent,
        description=description,
        rationale=rationale,
        remediation=remediation,
        references=tuple(references),
        tags=("middleware", "tomcat"),
        metadata={"gap09_area": area, "middleware": "tomcat"},
    )


TOMCAT_CHECKS: List[ConfigCheck] = [
    _check(
        suffix="shutdown_command",
        title="Tomcat does not use the default shutdown command",
        severity="high",
        collect=_xml(_SERVER_XML, ".", attribute="shutdown"),
        expect=Expectation(
            "not_equals", "SHUTDOWN", description="anything but the default word"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The word that stops the server when sent to the shutdown port. "
            "Tomcat ships the literal string 'SHUTDOWN'. Unset, the "
            "attribute is required by the schema, so its absence means the "
            "file could not be read as expected rather than a default."
        ),
        rationale=(
            "Anyone who can reach the shutdown port and send this word stops "
            "the server. No authentication is involved and none is possible — "
            "the word is the only secret, and by default it is published in "
            "every copy of Tomcat's documentation."
        ),
        remediation=(
            "Set a long random 'shutdown' value on <Server>, or disable the "
            'port entirely with port="-1".'
        ),
        references=("https://tomcat.apache.org/tomcat-10.1-doc/config/server.html",),
        area="mw.exposure.management_port",
    ),
    _check(
        suffix="shutdown_port",
        title="Tomcat's shutdown port is disabled",
        severity="medium",
        collect=_xml(_SERVER_XML, ".", attribute="port"),
        expect=Expectation("equals", "-1", description="-1 (disabled)"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The <Server> shutdown port. '-1' disables the listener entirely; "
            "Tomcat ships 8005. Unset, the attribute is required by the "
            "schema, so its absence means the file could not be read as "
            "expected rather than a default."
        ),
        rationale=(
            "The listener accepts a plain-text word on a local socket and "
            "stops the server. Where the shutdown command has been changed the "
            "risk is lower, but a listener that cannot be reached at all is "
            "the only state with no residual risk."
        ),
        remediation=(
            'Set port="-1" on <Server> and stop Tomcat through the service '
            "manager instead."
        ),
        references=("https://tomcat.apache.org/tomcat-10.1-doc/config/server.html",),
        area="mw.exposure.management_port",
    ),
    _check(
        suffix="default_accounts",
        title="Tomcat defines no accounts in tomcat-users.xml",
        severity="high",
        collect=_xml(_USERS_XML, ".//user", attribute="username", result="values"),
        expect=Expectation("is_empty", description="no user defined"),
        # An enumeration: no users found is a real result, not a missing
        # reading, so a clean server passes rather than deferring.
        absent=AbsencePolicy.PASS,
        description=(
            "Accounts defined in the file-based realm. The official image "
            "ships this file with every user commented out."
        ),
        rationale=(
            "The file realm stores passwords in cleartext by default and is "
            "what the manager application authenticates against. Accounts here "
            "are frequently left from a tutorial, with the credentials that "
            "tutorial published."
        ),
        remediation=(
            "Remove the <user> entries and authenticate the manager "
            "application against the organisation's directory, or delete the "
            "manager application if it is not used."
        ),
        references=("https://tomcat.apache.org/tomcat-10.1-doc/realm-howto.html",),
        area="mw.access.default_accounts",
    ),
    _check(
        suffix="access_log_valve",
        title="Tomcat records access to deployed applications",
        severity="medium",
        collect=_xml(
            _SERVER_XML,
            ".//Valve[@className='org.apache.catalina.valves.AccessLogValve']",
            result="count",
        ),
        expect=Expectation("gte", 1, description="an AccessLogValve is configured"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "AccessLogValve entries anywhere in server.xml. This counts "
            "matches, so it never reports an absent reading and the absence "
            "policy below is unreachable; it is declared because ConfigCheck "
            "requires a choice."
        ),
        rationale=(
            "Tomcat writes no request log at all without this valve. The "
            "catalina log records the server's own lifecycle, not what was "
            "requested, so an investigation into an application compromise has "
            "nothing to read."
        ),
        remediation=(
            "Add an AccessLogValve to the <Host>, with a pattern that includes "
            "the client address and the request line."
        ),
        references=("https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html",),
        area="mw.log.access_log",
    ),
    _check(
        suffix="connector_server_header",
        title="Tomcat connectors do not advertise the product",
        severity="low",
        # `result: value`, not `values`, and the difference is not cosmetic.
        # For a list actual the shared operators test *membership* rather than
        # substring, so `not_contains ["apache-coyote"]` against
        # ['Apache-Coyote/1.1'] compares two unequal strings and passes — a
        # server advertising itself, reported clean. The scalar path applies
        # the regex properly. The cost is that a server with several
        # <Connector> elements is judged on the last one; that is recorded as a
        # limitation rather than papered over.
        collect=_xml(_SERVER_XML, ".//Connector", attribute="server"),
        expect=Expectation(
            "not_matches",
            r"(apache-?coyote|tomcat)",
            description="a neutral Server header, or none",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The 'server' attribute on each <Connector>. Unset, Tomcat sends "
            "'Apache-Coyote/1.1'."
        ),
        rationale=(
            "Naming the product and its connector tells an attacker which "
            "published vulnerabilities to try before probing for any of them."
        ),
        remediation=(
            'Set server="" or a neutral value on each <Connector>. Note this '
            "is obscurity, not a control, and does not replace patching."
        ),
        references=("https://tomcat.apache.org/tomcat-10.1-doc/config/http.html",),
        area="mw.disclosure.version_tokens",
    ),
]


#: The bundled applications, and the directories they deploy into.
#:
#: These use the Phase 3 ``directory`` check type rather than
#: ``structured_config``: "is this application deployed" is the existence of a
#: directory, and there is nothing structured to read. Reaching for the new
#: collector because the phase added one would have been the wrong instinct —
#: the check types exist to be reused.
_WEBAPP_ROOTS = (
    "/usr/local/tomcat/webapps",
    "/opt/tomcat/webapps",
    "/var/lib/tomcat10/webapps",
    "/var/lib/tomcat9/webapps",
)


def _webapp_check(
    *, suffix: str, app: str, title: str, severity: str, rationale: str, area: str
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.mw.tomcat.{suffix}",
        title=title,
        check_type="directory",
        platforms=("linux", "windows"),
        severity=severity,
        # The directory collector takes one path, so the most common location
        # is used. A Tomcat installed elsewhere reports ABSENT, which for these
        # rules is a pass — and that is the safe direction: a missed deployed
        # application is a false negative, while guessing at paths and reading
        # an unrelated directory would be a false positive.
        collect={"path": f"{_WEBAPP_ROOTS[0]}/{app}", "attribute": "exists"},
        expect=Expectation("is_empty", description=f"{app} is not deployed"),
        absent=AbsencePolicy.PASS,
        description=(
            f"Whether Tomcat's bundled '{app}' application is deployed. The "
            f"official image moves the bundled applications to webapps.dist/, "
            f"so a stock container has none of them deployed."
        ),
        rationale=rationale,
        remediation=(
            f"Delete {_WEBAPP_ROOTS[0]}/{app} if the application is not "
            f"required. Where it is, restrict it by address and authenticate "
            f"it against the organisation's directory."
        ),
        references=(_DOC,),
        tags=("middleware", "tomcat"),
        metadata={"gap09_area": area, "middleware": "tomcat"},
    )


TOMCAT_CHECKS.extend(
    [
        _webapp_check(
            suffix="manager_app",
            app="manager",
            title="Tomcat does not deploy the manager application",
            severity="high",
            rationale=(
                "The manager application deploys and undeploys web "
                "applications. An authenticated session with it is remote code "
                "execution by design, which is why it is the first thing every "
                "Tomcat credential-guessing tool tries."
            ),
            area="mw.access.admin_interface",
        ),
        _webapp_check(
            suffix="host_manager_app",
            app="host-manager",
            title="Tomcat does not deploy the host-manager application",
            severity="high",
            rationale=(
                "host-manager creates and removes virtual hosts, so it "
                "controls which applications the server will serve at all. "
                "Like manager, an authenticated session with it is equivalent "
                "to control of the server."
            ),
            area="mw.access.admin_interface",
        ),
        _webapp_check(
            suffix="examples_app",
            app="examples",
            title="Tomcat does not deploy the examples application",
            severity="medium",
            rationale=(
                "The examples application has historically shipped servlets "
                "that echo request data and expose session contents, and it "
                "exists only to demonstrate the product. On a production "
                "server it is attack surface with no purpose."
            ),
            area="mw.disclosure.default_content",
        ),
        _webapp_check(
            suffix="docs_app",
            app="docs",
            title="Tomcat does not deploy the documentation application",
            severity="low",
            rationale=(
                "The bundled documentation states the exact Tomcat version it "
                "was shipped with, which identifies the build to anyone who "
                "can reach it without any probing."
            ),
            area="mw.disclosure.default_content",
        ),
    ]
)


def tomcat_checks() -> List[ConfigCheck]:
    return list(TOMCAT_CHECKS)
