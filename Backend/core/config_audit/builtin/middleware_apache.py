"""
core/config_audit/builtin/middleware_apache.py
─────────────────────────────────────────────────────────────────────────────
Apache httpd configuration checks. Phase 8 (GAP-09).

Every directive here was read out of a live httpd 2.4 container through the
real collector before its rule was written, and two of the rules are shaped by
what that showed.

``User`` is not a top-level directive on a stock install
────────────────────────────────────────────────────────
The official image puts ``User`` and ``Group`` inside
``<IfModule unixd_module>``. A rule asserting them at ``scope: []`` reports
ABSENT on an entirely normal server — a false "not configured" — so these use
``scope: None``, which matches at any depth. That is the distinction the
structured collector exists to make, and the first version of this file got it
wrong until a real container said so.

``Include`` is relative to ServerRoot
─────────────────────────────────────
Not to the directory holding the file. Resolving it the other way turned
``Include conf/extra/proxy-html.conf`` into ``…/conf/conf/extra/…``, which does
not exist, which left the include unexpanded, which downgraded every absent
directive in the file from a verdict to "could not assess". The collector reads
``ServerRoot`` out of the configuration itself.

What these deliberately do *not* check
──────────────────────────────────────
``Options Indexes`` (directory listing), ``TraceEnable`` (dangerous methods)
and header configuration are all observed over the wire by **GAP-06** and are
not repeated here.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["APACHE_CHECKS", "apache_checks"]

#: Debian/Ubuntu, RHEL/Fedora, and a from-source or official-image install.
_PATHS = (
    "/etc/apache2/apache2.conf",
    "/etc/httpd/conf/httpd.conf",
    "/usr/local/apache2/conf/httpd.conf",
)

_DOC = "https://httpd.apache.org/docs/2.4/mod/core.html"


def _read(directive: str, scope=None, result: str = "value") -> dict:
    params = {
        "path": list(_PATHS),
        "format": "apache",
        "directive": directive,
        "result": result,
    }
    if scope is not None:
        params["scope"] = list(scope)
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
        check_id=f"ccure.mw.apache.{suffix}",
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
        tags=("middleware", "apache"),
        metadata={"gap09_area": area, "middleware": "apache"},
    )


APACHE_CHECKS: List[ConfigCheck] = [
    _check(
        suffix="server_tokens",
        title="Apache does not advertise its version and modules",
        severity="low",
        collect=_read("ServerTokens"),
        expect=Expectation("in", ["prod", "productonly"], description="Prod"),
        # Absent means the compiled default, which for 2.4 is Full — the most
        # verbose setting there is. Named in the description so MANUAL_REVIEW
        # is a one-step decision rather than a research task.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "What Apache puts in the Server header. Unset, httpd 2.4 defaults "
            "to 'Full', which names the version and every loaded module."
        ),
        rationale=(
            "The module list is more useful to an attacker than the version: "
            "it says which attack surface is actually compiled in and loaded, "
            "before a single request has been sent to test for it."
        ),
        remediation="Set 'ServerTokens Prod' at the top level and restart.",
        references=("https://httpd.apache.org/docs/2.4/mod/core.html#servertokens",),
        area="mw.disclosure.version_tokens",
    ),
    _check(
        suffix="server_status",
        title="Apache does not expose server-status or server-info",
        severity="medium",
        collect=_read("SetHandler", result="values"),
        expect=Expectation(
            "not_contains",
            ["server-status", "server-info"],
            description="no server-status or server-info handler",
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "Locations configured with the server-status or server-info " "handlers."
        ),
        rationale=(
            "server-status lists every in-flight request with its client "
            "address and URL, and server-info dumps the full configuration "
            "including paths and module settings. Both are routinely left "
            "reachable after a debugging session."
        ),
        remediation=(
            "Remove the SetHandler block, or confine it with "
            "'Require ip <management network>'."
        ),
        references=("https://httpd.apache.org/docs/2.4/mod/mod_status.html",),
        area="mw.disclosure.status_endpoint",
    ),
    _check(
        suffix="run_as_user",
        title="Apache does not run its workers as root",
        severity="high",
        # scope=None on purpose — the stock layout puts this inside
        # <IfModule unixd_module>, and pinning it to the top level reports a
        # correctly configured server as unconfigured.
        collect=_read("User"),
        expect=Expectation("not_in", ["root", "#0"], description="a non-root account"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The account child processes drop to. On Windows this directive "
            "does not apply, which is why the check defers rather than failing "
            "when it is absent."
        ),
        rationale=(
            "Child processes parse untrusted request data. One running as root "
            "turns a parsing flaw into host compromise rather than into "
            "compromise of the served content."
        ),
        remediation=(
            "Set 'User www-data' (or the distribution's service account) and "
            "restart. The parent still starts as root to bind port 80."
        ),
        area="mw.process.run_as_user",
    ),
    _check(
        suffix="allow_override",
        title="Apache does not honour .htaccess overrides",
        severity="medium",
        collect=_read("AllowOverride", scope=["Directory"], result="values"),
        expect=Expectation(
            "not_contains",
            ["all"],
            description="None or a named directive group, never All",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether per-directory .htaccess files may override the server "
            "configuration, read across every <Directory> container. Unset, "
            "httpd 2.4 defaults to None."
        ),
        rationale=(
            "'AllowOverride All' lets anyone who can write a file into the "
            "document root change the server's authentication, rewriting and "
            "handler configuration. An upload flaw becomes a configuration "
            "change, and Apache re-reads it on the next request."
        ),
        remediation=(
            "Set 'AllowOverride None' and move the needed directives into the "
            "server configuration, where they are version-controlled."
        ),
        references=("https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride",),
        area="mw.access.override_files",
    ),
    _check(
        suffix="log_level",
        title="Apache logs at a level that records rejected requests",
        severity="low",
        collect=_read("LogLevel"),
        expect=Expectation(
            "not_in",
            ["emerg", "alert", "crit", "error"],
            description="warn, info or debug",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=("The error log verbosity. Unset, httpd defaults to 'warn'."),
        rationale=(
            "At 'error' and above the log records failures of the server, not "
            "refusals by it. Authorisation denials and rejected requests — the "
            "entries that show an attack in progress — are logged at 'warn'."
        ),
        remediation="Set 'LogLevel warn' and restart.",
        references=("https://httpd.apache.org/docs/2.4/mod/core.html#loglevel",),
        area="mw.log.log_level",
    ),
    _check(
        suffix="custom_log",
        title="Apache records access to served content",
        severity="medium",
        collect=_read("CustomLog", result="count"),
        expect=Expectation("gte", 1, description="at least one access log"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Access log destinations configured anywhere in the tree. This "
            "counts matches, so it never reports an absent reading and the "
            "absence policy below is unreachable; it is declared because "
            "ConfigCheck requires a choice."
        ),
        rationale=(
            "Without an access log there is no record of what was requested or "
            "from where, so neither an investigation nor an abuse report has "
            "anything to work from."
        ),
        remediation=(
            "Add 'CustomLog logs/access_log combined' at the server level or "
            "in each virtual host."
        ),
        references=("https://httpd.apache.org/docs/2.4/mod/mod_log_config.html",),
        area="mw.log.access_log",
    ),
    _check(
        suffix="error_log",
        title="Apache records errors to a defined destination",
        severity="low",
        collect=_read("ErrorLog", result="count"),
        expect=Expectation("gte", 1, description="an error log destination"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The error log destination. This counts matches, so it never "
            "reports an absent reading and the absence policy below is "
            "unreachable; it is declared because ConfigCheck requires a "
            "choice."
        ),
        rationale=(
            "The error log is where a failed authorisation, a module failure "
            "and a malformed request all surface. Unset, output goes wherever "
            "the service manager sends stderr, which may be nowhere."
        ),
        remediation="Set 'ErrorLog logs/error_log' or a destination you collect.",
        area="mw.log.error_log",
    ),
    _check(
        suffix="timeout",
        title="Apache bounds how long a request may take",
        severity="low",
        collect=_read("Timeout"),
        expect=Expectation("lte", 120, description="120 seconds or less"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Seconds Apache waits for a request to complete. Unset, httpd 2.4 "
            "defaults to 60."
        ),
        rationale=(
            "A long timeout is what makes a slow-request attack cheap: each "
            "connection occupies a worker for the whole interval while costing "
            "the client nothing but a socket."
        ),
        remediation="Set 'Timeout 60' and consider mod_reqtimeout as well.",
        references=("https://httpd.apache.org/docs/2.4/mod/core.html#timeout",),
        area="mw.limits.timeouts",
    ),
]


def apache_checks() -> List[ConfigCheck]:
    return list(APACHE_CHECKS)
