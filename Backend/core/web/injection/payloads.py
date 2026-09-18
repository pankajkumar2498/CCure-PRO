"""
core/web/injection/payloads.py
────────────────────────────────────────────────────────────────────────────
Payloads, parser-error signatures, CWE/OWASP mapping and remediation for the
Phase 2 active-injection engine (OS command, SSTI, XXE, LDAP, XPath).

Every payload here is **non-destructive**: timing uses `sleep`/`ping` only,
SSTI uses arithmetic only, XXE uses an *internal* canary entity (never an
external or file entity), and LDAP/XPath use read-only filter syntax that
provokes a parser error or a boolean difference. Nothing modifies or deletes
target data and nothing calls out to an external host.

Detection is evidence-based, never reflection-based:
* command injection — a controlled *timing* side-channel that tracks two
  different requested delays;
* SSTI — the *computed* value of an arithmetic expression appears while the
  literal expression does not;
* XXE — an internal entity is *expanded* (its value replaces the reference);
* LDAP / XPath — a specific parser *error signature*, or a boolean differential.
"""

from __future__ import annotations

# ── OS Command Injection (CWE-78) ────────────────────────────────────────────
# Separator/terminator templates. {d} is the sleep seconds. Both *nix (sleep)
# and Windows (ping -n adds ~1s/echo) are covered. The trailing comment forms
# swallow the rest of the original command.
CMDI_TEMPLATES: list[str] = [
    ";sleep {d}",
    "|sleep {d}",
    "||sleep {d}",
    "&&sleep {d}",
    "`sleep {d}`",
    "$(sleep {d})",
    "%0asleep {d}",
    "; sleep {d} #",
    "' ;sleep {d} ; '",
    '" ;sleep {d} ; "',
    "&ping -n {dn} 127.0.0.1",  # Windows: ~1s per count
]
CMDI_CWE = "CWE-78"

# ── SSTI (CWE-1336) ──────────────────────────────────────────────────────────
# (engine_hint, template). {a}/{b} are unique factors; {p} their product. The
# finding requires {p} present and the literal "{a}*{b}" absent.
SSTI_TEMPLATES: list[tuple[str, str]] = [
    ("Jinja2/Twig/Nunjucks", "{{{{{a}*{b}}}}}"),  # {{a*b}}
    ("Freemarker/JSP-EL/Angular", "${{{a}*{b}}}"),  # ${a*b}
    ("Ruby ERB", "<%= {a}*{b} %>"),
    ("Razor", "@({a}*{b})"),
    ("Smarty/Twig-alt", "{{{a}*{b}}}"),  # {a*b}
    ("Thymeleaf", "[[${{{a}*{b}}}]]"),
    ("Velocity", "#set($x={a}*{b})$x"),
]
SSTI_CWE = "CWE-1336"

# ── XXE (CWE-611) ────────────────────────────────────────────────────────────
# In-band internal-entity canary. {c} is a unique canary; if it appears
# expanded in the response, the parser resolved the entity. No external/system
# entity, so no file access is ever attempted.
XXE_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE ccure [<!ENTITY {name} "{c}">]>'
    "<ccure><probe>&{name};</probe></ccure>"
)
XXE_CONTENT_TYPES = ["application/xml", "text/xml"]
XXE_CWE = "CWE-611"

# ── LDAP Injection (CWE-90) ──────────────────────────────────────────────────
LDAP_ERROR_TEMPLATES: list[str] = [
    "*)(&",
    ")(cn=*",
    "*))%00",
    "*()|&'",
]
# Boolean pair for a differential (always-true vs always-false filter).
LDAP_TRUE = "*"
LDAP_FALSE = ")(!(objectClass=*)"
LDAP_ERROR_SIGNATURES: list[str] = [
    "javax.naming",
    "LDAPException",
    "com.sun.jndi.ldap",
    "invalid dn",
    "bad search filter",
    "invalid search filter",
    "protocol error",
    "ldap_search",
    "supplied argument is not a valid ldap",
    "InvalidSearchFilterException",
    "AcceptSecurityContext error",
]
LDAP_CWE = "CWE-90"

# ── XPath Injection (CWE-643) ────────────────────────────────────────────────
XPATH_ERROR_TEMPLATES: list[str] = [
    "'",
    '"',
    "']",
    "'))",
    "' or ",
]
# Boolean pair (always-true vs always-false).
XPATH_TRUE = "' or '1'='1"
XPATH_FALSE = "' or '1'='2"
XPATH_ERROR_SIGNATURES: list[str] = [
    "XPathException",
    "XPathEvalError",
    "xmlXPathEval",
    "Invalid expression",
    "Invalid predicate",
    "SyntaxError: unterminated",
    "unterminated string",
    "XPST0003",
    "javax.xml.xpath",
    "System.Xml.XPath",
    "MS.Internal.Xml",
    "Expression must evaluate to a node-set",
    "unclosed token",
]
XPATH_CWE = "CWE-643"

# ── shared ───────────────────────────────────────────────────────────────────
REMEDIATION = {
    "command_injection": (
        "Never pass user input to a shell or OS command. Use parameterised APIs "
        "that avoid a shell (e.g. execve with an argument vector, subprocess "
        "without shell=True), allow-list expected values, and drop shell "
        "metacharacters. Run the component with least privilege."
    ),
    "ssti": (
        "Do not build templates from user input. Pass user data as template "
        "*variables/context*, never concatenate it into the template source. "
        "Use a sandboxed engine configuration and allow-list any expressions. "
        "Server-side template injection frequently leads to remote code "
        "execution, so treat it as critical."
    ),
    "xxe": (
        "Disable DTD processing and external entity resolution in the XML "
        "parser (e.g. FEATURE_SECURE_PROCESSING, disallow-doctype-decl, "
        "resolve_entities=False, XMLConstants.ACCESS_EXTERNAL_DTD=''). Prefer a "
        "hardened parser and reject documents containing a DOCTYPE."
    ),
    "ldap_injection": (
        "Escape LDAP special characters in user input per RFC 4515 before "
        "building a search filter, or use a parameterised LDAP API. Validate "
        "and allow-list expected input and apply least-privilege bind accounts."
    ),
    "xpath_injection": (
        "Do not concatenate user input into XPath expressions. Use "
        "parameterised/precompiled XPath with variable binding, escape or "
        "allow-list input, and validate against an expected schema."
    ),
}

# Confirmed side-channel evidence → these are strong, so severity is not
# discounted. SSTI is critical (routine path to RCE); command injection is
# critical; the rest are high.
SEVERITY = {
    "command_injection": "critical",
    "ssti": "critical",
    "xxe": "high",
    "ldap_injection": "high",
    "xpath_injection": "high",
}
CWE = {
    "command_injection": CMDI_CWE,
    "ssti": SSTI_CWE,
    "xxe": XXE_CWE,
    "ldap_injection": LDAP_CWE,
    "xpath_injection": XPATH_CWE,
}
TITLE = {
    "command_injection": "OS Command Injection",
    "ssti": "Server-Side Template Injection (SSTI)",
    "xxe": "XML External Entity (XXE) — entity processing",
    "ldap_injection": "LDAP Injection",
    "xpath_injection": "XPath Injection",
}
