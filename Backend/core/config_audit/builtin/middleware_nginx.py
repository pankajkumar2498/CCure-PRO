"""
core/config_audit/builtin/middleware_nginx.py
─────────────────────────────────────────────────────────────────────────────
nginx configuration checks. Phase 8 (GAP-09).

Every directive here was read out of a live nginx 1.27 container through the
real collector before its rule was written.

What these deliberately do *not* check
──────────────────────────────────────
Directory listing, dangerous HTTP methods, missing security headers, server
version in a live response and TLS endpoint assessment are all already
implemented and validated in **GAP-06**, which observes them over the wire.
Adding configuration-side twins would report one condition twice and make every
remediation look twice as large — the mistake Phase 7 caught in its own
PostgreSQL rules when three of them read ``pg_hba_file_rules`` with overlapping
predicates.

What is here is the half the network cannot see: the TLS policy the server
*would* negotiate, the account it runs as, whether it logs at all, and the
request limits that decide whether a slow-request flood costs it anything.

Absence, and why most of these defer
────────────────────────────────────
A directive missing from nginx.conf means the daemon is on its compiled-in
default, and those defaults differ between builds and distributions —
``server_tokens`` defaults to ``on`` in mainline but distributions patch it.
Phase 3 settled this for ``sshd_config`` and the same answer applies:
MANUAL_REVIEW, with the vendor default named in the description so a reviewer
can settle it in one step rather than going and looking it up.

The exception is the *file* being missing entirely, which the collector reports
as UNSUPPORTED — a host that does not run nginx is not failing nginx's rules.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["NGINX_CHECKS", "nginx_checks"]

#: Where distributions put the main configuration. The collector takes the
#: first that exists; a rule pinned to one path reports "not configured" on
#: every host that packages nginx differently.
_PATHS = (
    "/etc/nginx/nginx.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/opt/nginx/conf/nginx.conf",
)

_DOC = "https://nginx.org/en/docs/http/ngx_http_core_module.html"
_SSL_DOC = "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"


def _read(directive: str, scope=None, result: str = "value") -> dict:
    params = {
        "path": list(_PATHS),
        "format": "nginx",
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
    tags=("middleware", "nginx"),
) -> ConfigCheck:
    return ConfigCheck(
        check_id=f"ccure.mw.nginx.{suffix}",
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
        tags=tuple(tags),
        metadata={"gap09_area": area, "middleware": "nginx"},
    )


NGINX_CHECKS: List[ConfigCheck] = [
    _check(
        suffix="server_tokens",
        title="nginx does not advertise its version",
        severity="low",
        collect=_read("server_tokens"),
        expect=Expectation("is_false", description="off"),
        # Mainline defaults to `on`; several distributions patch it. Naming the
        # default in the description is what makes MANUAL_REVIEW actionable
        # rather than merely honest.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether nginx includes its version in error pages and the Server "
            "header. Unset, nginx defaults to 'on'."
        ),
        rationale=(
            "The exact patch version tells an attacker which published "
            "vulnerabilities apply before they probe for any of them, turning "
            "a scan of the estate into a target list."
        ),
        remediation="Set 'server_tokens off;' in the http block and reload.",
        area="mw.disclosure.version_tokens",
    ),
    _check(
        suffix="stub_status",
        title="nginx does not expose the stub_status endpoint",
        severity="medium",
        collect=_read("stub_status", result="count"),
        expect=Expectation("lte", 0, description="no stub_status location"),
        absent=AbsencePolicy.PASS,
        description=(
            "Locations serving the stub_status module, which reports active "
            "connections and request counters."
        ),
        rationale=(
            "stub_status is unauthenticated by default and discloses live "
            "traffic volumes and connection state — useful for timing an "
            "attack and for confirming that one is working."
        ),
        remediation=(
            "Remove the stub_status location, or restrict it with 'allow'/"
            "'deny' to the monitoring host only."
        ),
        references=("https://nginx.org/en/docs/http/ngx_http_stub_status_module.html",),
        area="mw.disclosure.status_endpoint",
    ),
    _check(
        suffix="run_as_user",
        title="nginx worker processes do not run as root",
        severity="high",
        collect=_read("user", scope=[]),
        expect=Expectation(
            "not_in", ["root", "root root"], description="a non-root account"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The account nginx drops to for its worker processes. Unset, nginx "
            "uses the user its build specifies, commonly 'nobody'."
        ),
        rationale=(
            "Workers handle untrusted input. A memory-safety flaw in a worker "
            "running as root is a full host compromise rather than a "
            "compromise of the web content."
        ),
        remediation="Set 'user nginx;' (or another unprivileged account) and reload.",
        area="mw.process.run_as_user",
    ),
    _check(
        suffix="ssl_protocols",
        title="nginx offers no TLS version below 1.2",
        severity="high",
        collect=_read("ssl_protocols"),
        expect=Expectation(
            "not_matches",
            r"(^|\s)(SSLv[23]|TLSv1(\.1)?)(\s|$)",
            description="no SSLv2/3, TLSv1.0 or TLSv1.1",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The TLS versions nginx will negotiate. Unset, nginx uses its "
            "build default, which for 1.27 is TLSv1 TLSv1.1 TLSv1.2 TLSv1.3."
        ),
        rationale=(
            "TLS 1.0 and 1.1 are deprecated by RFC 8996 and permit cipher "
            "suites with known weaknesses. While they remain in the list the "
            "server negotiates down for any client that asks."
        ),
        remediation="Set 'ssl_protocols TLSv1.2 TLSv1.3;' and reload.",
        references=(_SSL_DOC, "https://www.rfc-editor.org/rfc/rfc8996"),
        area="mw.tls.protocols_configured",
    ),
    _check(
        suffix="ssl_ciphers",
        title="nginx excludes null, export and anonymous cipher suites",
        severity="high",
        collect=_read("ssl_ciphers"),
        expect=Expectation(
            "not_matches",
            r"(^|:)(NULL|aNULL|eNULL|EXP(ORT)?|LOW|RC4|DES|MD5)(:|$)",
            description="no NULL, EXPORT, LOW, RC4, DES or MD5 suites",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The cipher suite list offered to clients. Unset, nginx uses "
            "OpenSSL's HIGH:!aNULL:!MD5 default."
        ),
        rationale=(
            "An anonymous or NULL suite provides no authentication or no "
            "encryption at all while still completing a handshake, so the "
            "connection looks protected in the client and is not."
        ),
        remediation=(
            "Set an explicit modern list, for example "
            "'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-"
            "SHA256:...;' with '!aNULL:!MD5:!EXPORT' appended."
        ),
        references=(_SSL_DOC,),
        area="mw.tls.ciphers_configured",
    ),
    _check(
        suffix="ssl_prefer_server_ciphers",
        title="nginx enforces its own cipher preference order",
        severity="low",
        collect=_read("ssl_prefer_server_ciphers"),
        expect=Expectation("is_true", description="on"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the server's cipher order wins over the client's. Unset, "
            "nginx defaults to 'off' and the client chooses."
        ),
        rationale=(
            "With the client choosing, a downgrade-inclined or simply outdated "
            "client selects the weakest suite both sides share, and the "
            "server's carefully ordered list has no effect. Note this applies "
            "to TLS 1.2 and below; TLS 1.3 removes the negotiation entirely."
        ),
        remediation="Set 'ssl_prefer_server_ciphers on;' and reload.",
        references=(_SSL_DOC,),
        area="mw.tls.server_preference",
    ),
    _check(
        suffix="access_log",
        title="nginx records access to served content",
        severity="medium",
        collect=_read("access_log", scope=["http"]),
        expect=Expectation("not_equals", "off", description="a log destination"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The http-level access log. 'off' disables it; unset, nginx logs "
            "to its compiled-in default path."
        ),
        rationale=(
            "Without an access log there is no record of what was requested or "
            "by whom, so neither an investigation nor an abuse report has "
            "anything to work from."
        ),
        remediation=(
            "Set 'access_log /var/log/nginx/access.log main;' in the http "
            "block, or a destination your log pipeline collects."
        ),
        references=("https://nginx.org/en/docs/http/ngx_http_log_module.html",),
        area="mw.log.access_log",
    ),
    _check(
        suffix="error_log",
        title="nginx records errors at a usable level",
        severity="low",
        collect=_read("error_log", scope=[]),
        expect=Expectation(
            "not_contains",
            ["emerg", "alert", "crit"],
            description="notice, info, warn or error — not only the fatal levels",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The main error log and its level. Unset, nginx logs to its "
            "compiled-in default at 'error'."
        ),
        rationale=(
            "At 'crit' and above the log records only what has already broken. "
            "Rejected requests, failed TLS handshakes and permission problems "
            "— the entries an investigation actually reads — are all below "
            "that threshold."
        ),
        remediation="Set 'error_log /var/log/nginx/error.log warn;' and reload.",
        area="mw.log.error_log",
    ),
    _check(
        suffix="client_max_body_size",
        title="nginx bounds the size of a request body",
        severity="medium",
        collect=_read("client_max_body_size"),
        expect=Expectation(
            "not_equals", "0", description="a non-zero limit (0 means unlimited)"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The largest request body nginx accepts. '0' disables the limit "
            "entirely; unset, nginx defaults to 1m."
        ),
        rationale=(
            "An unbounded body lets one client consume disk in the temp "
            "directory and memory in the worker, so a single request becomes a "
            "denial-of-service primitive that needs no volume behind it."
        ),
        remediation=(
            "Set 'client_max_body_size' to the largest upload the application "
            "genuinely needs."
        ),
        area="mw.limits.request_body",
    ),
    _check(
        suffix="keepalive_timeout",
        title="nginx closes idle keep-alive connections",
        severity="low",
        collect=_read("keepalive_timeout", scope=["http"]),
        expect=Expectation(
            "not_equals", "0", description="a non-zero timeout (0 disables keep-alive)"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "How long an idle keep-alive connection is held open. Unset, nginx "
            "defaults to 75s."
        ),
        rationale=(
            "Idle connections occupy worker slots. Without a timeout a client "
            "that opens connections and never uses them exhausts the "
            "connection pool at negligible cost to itself — the slowloris "
            "shape."
        ),
        remediation="Set 'keepalive_timeout 65;' or lower in the http block.",
        area="mw.limits.timeouts",
    ),
]


def nginx_checks() -> List[ConfigCheck]:
    return list(NGINX_CHECKS)
