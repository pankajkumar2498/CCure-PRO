"""
core/config_audit/structured.py
─────────────────────────────────────────────────────────────────────────────
Parsers for configuration formats that have *structure*. Phase 8 of the
gap-closure programme, closing GAP-09.

Why the Phase 3 ``config_file`` collector is not enough
───────────────────────────────────────────────────────
It reads one directive out of a flat ``key<separator>value`` file, which is
exactly right for ``sshd_config`` and ``login.defs`` and useless for every
product this phase assesses:

* **nginx** nests directives in ``{ }`` blocks and terminates them with ``;``.
  ``ssl_protocols`` inside ``http`` and inside one ``server`` are different
  settings, and a flat reader returns whichever it saw last with no idea which
  server it belonged to.
* **Apache** nests them in ``<Directory>`` / ``<VirtualHost>`` containers.
  ``AllowOverride None`` under ``<Directory />`` and under a document root are
  different statements about different parts of the filesystem.
* **Tomcat** is XML. There is no directive at all — the settings are attributes
  on elements.
* **The Docker daemon** is JSON.

So a flat reader does not merely miss these, it answers them *wrongly and
confidently*, which is worse. Everything here is pure Python over text: nothing
in this module opens a connection, and every parser is exercised against
captured real configuration in ``tests/scans/test_middleware_parsers.py``.

Scope addressing, and why it is exact rather than fuzzy
───────────────────────────────────────────────────────
``select_directives`` takes ``scope`` with three meanings, and the distinction
is the whole point of having a parser:

``None``   match at any depth — "is this set anywhere"
``()``     top level only — "is this set outside every block"
``(...)``  that exact block path

An "ends with" or "contains" rule would have been easier and is the wrong
answer: it makes a directive in ``http > server > location`` satisfy a rule
about ``http > server``, and the whole reason to parse structure is that those
are different statements.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("ccure.config_audit.structured")

__all__ = [
    "Directive",
    "ParsedConfig",
    "ParseError",
    "apache_includes",
    "apache_server_root",
    "json_pointer",
    "nginx_includes",
    "parse_apache",
    "parse_nginx",
    "render_value",
    "rescope",
    "select_directives",
    "xml_select",
]


class ParseError(ValueError):
    """The text could not be parsed as the format the rule declared."""


@dataclass(frozen=True)
class Directive:
    """One directive, and the block path it was found inside."""

    name: str
    value: str
    #: Enclosing block names, outermost first. ``()`` is the top level.
    scope: Tuple[str, ...] = ()
    line: int = 0
    #: Which file it came from, once includes have been expanded. Carried so
    #: evidence can name the file a finding is actually about — "set in
    #: conf.d/default.conf" and "set in nginx.conf" send an operator to
    #: different places.
    source: str = ""

    def as_evidence(self) -> str:
        where = " > ".join(self.scope) if self.scope else "(top level)"
        origin = f" [{self.source}]" if self.source else ""
        return f"{where}: {self.name} {self.value}{origin}"


@dataclass
class ParsedConfig:
    """Every directive found, plus what the parser could not resolve."""

    directives: List[Directive] = field(default_factory=list)
    #: Include targets that were not expanded. **Load-bearing**: a directive
    #: absent from what we read might be set in a file we did not read, so an
    #: ABSENT verdict is only trustworthy when this is empty. The collector
    #: turns a non-empty list plus an absent reading into UNAVAILABLE.
    unresolved_includes: List[str] = field(default_factory=list)
    #: Files whose contents were folded in, for the evidence record.
    sources: List[str] = field(default_factory=list)


# ── nginx ────────────────────────────────────────────────────────────────────

_NGINX_TOKEN = re.compile(
    r"""
    \#[^\n]*                      # comment
    | "(?:\\.|[^"\\])*"           # double-quoted string
    | '(?:\\.|[^'\\])*'           # single-quoted string
    | [{};]                       # structural
    | [^\s{};'"]+                 # bare word
    """,
    re.VERBOSE,
)


def parse_nginx(text: str, *, source: str = "") -> ParsedConfig:
    """
    Parse nginx configuration into a flat list of scoped directives.

    Quoting is honoured because nginx values legitimately contain braces and
    semicolons — ``log_format`` is the common case, and a naive split on ``;``
    turns one directive into six malformed ones and then reports the settings
    around it as absent.
    """
    parsed = ParsedConfig(sources=[source] if source else [])
    scope: List[str] = []
    current: List[str] = []
    line = 1
    position = 0

    for match in _NGINX_TOKEN.finditer(text or ""):
        line += text.count("\n", position, match.start())
        position = match.start()
        token = match.group(0)

        if token.startswith("#"):
            continue
        if token == "{":  # nosec B105 — a brace, not a secret
            if not current:
                raise ParseError(f"line {line}: block opened with no name")
            scope.append(current[0])
            current = []
            continue
        if token == "}":  # nosec B105 — a brace, not a secret
            if not scope:
                raise ParseError(f"line {line}: closing brace with no open block")
            scope.pop()
            current = []
            continue
        if token == ";":  # nosec B105 — a terminator, not a secret
            if current:
                parsed.directives.append(
                    Directive(
                        name=current[0],
                        value=" ".join(current[1:]),
                        scope=tuple(scope),
                        line=line,
                        source=source,
                    )
                )
            current = []
            continue
        current.append(_unquote(token))

    if scope:
        raise ParseError(f"{len(scope)} block(s) left unclosed at end of file")
    return parsed


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def nginx_includes(parsed: ParsedConfig) -> List[Directive]:
    """
    Every ``include`` directive, as directives rather than bare paths.

    The *scope* is what makes this return objects. nginx's stock layout has
    ``include /etc/nginx/conf.d/*.conf;`` inside ``http``, and the ``server``
    blocks in the included file are therefore ``http > server`` — not
    ``server``, which is what parsing that file on its own would say. Handing
    back only the path loses the one piece of information the caller needs to
    graft the child onto the right branch, and a rule asking about
    ``http > server`` then finds nothing and reports it as not configured.
    """
    return [d for d in parsed.directives if d.name.lower() == "include"]


# ── Apache httpd ─────────────────────────────────────────────────────────────

_APACHE_OPEN = re.compile(r"^<\s*([A-Za-z_][\w]*)\s*(.*?)\s*>$")
_APACHE_CLOSE = re.compile(r"^<\s*/\s*([A-Za-z_][\w]*)\s*>$")


def parse_apache(text: str, *, source: str = "") -> ParsedConfig:
    """
    Parse Apache configuration into scoped directives.

    Line-oriented with ``\\`` continuations, and section containers rather than
    braces. A mismatched ``</Section>`` raises rather than being ignored: a
    parser that silently recovers from one produces a directive tree whose
    scopes are wrong from that point on, and every verdict after it is about
    the wrong part of the filesystem.
    """
    parsed = ParsedConfig(sources=[source] if source else [])
    scope: List[str] = []
    pending = ""
    pending_line = 0

    for number, raw in enumerate((text or "").splitlines(), start=1):
        stripped = raw.strip()
        if not pending:
            pending_line = number
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        statement = (pending + stripped).strip()
        pending = ""
        if not statement or statement.startswith("#"):
            continue

        closing = _APACHE_CLOSE.match(statement)
        if closing:
            name = closing.group(1)
            if not scope:
                raise ParseError(f"line {number}: </{name}> with no open section")
            if scope[-1].lower() != name.lower():
                raise ParseError(f"line {number}: </{name}> closes <{scope[-1]}>")
            scope.pop()
            continue

        opening = _APACHE_OPEN.match(statement)
        if opening:
            scope.append(opening.group(1))
            continue

        parts = statement.split(None, 1)
        parsed.directives.append(
            Directive(
                name=parts[0],
                value=_unquote(parts[1].strip()) if len(parts) > 1 else "",
                scope=tuple(scope),
                line=pending_line,
                source=source,
            )
        )

    if scope:
        raise ParseError(f"section <{scope[-1]}> is never closed")
    return parsed


def apache_includes(parsed: ParsedConfig) -> List[Directive]:
    return [
        d for d in parsed.directives if d.name.lower() in ("include", "includeoptional")
    ]


def rescope(
    directives: Sequence[Directive], prefix: Tuple[str, ...]
) -> List[Directive]:
    """
    Re-root *directives* under *prefix*.

    Used when folding an included file into its parent: the file was parsed on
    its own, so its scopes start at nothing, and they have to be shifted under
    whatever block the ``include`` sat in.
    """
    if not prefix:
        return list(directives)
    return [
        Directive(
            name=d.name,
            value=d.value,
            scope=tuple(prefix) + d.scope,
            line=d.line,
            source=d.source,
        )
        for d in directives
    ]


def apache_server_root(parsed: ParsedConfig) -> Optional[str]:
    """
    The ``ServerRoot`` an Apache configuration declares.

    Apache resolves a relative ``Include`` against ServerRoot, **not** against
    the directory holding the file that contains it. Assuming the latter turned
    ``Include conf/extra/proxy-html.conf`` into
    ``/usr/local/apache2/conf/conf/extra/…`` on the stock image — a path that
    does not exist, an include that could not be expanded, and every absent
    directive in the file downgraded from a verdict to "could not assess".
    """
    hits = select_directives(parsed, "ServerRoot")
    return hits[-1].value.strip().strip('"') if hits else None


# ── Selection ────────────────────────────────────────────────────────────────


def select_directives(
    parsed: ParsedConfig,
    name: str,
    *,
    scope: Optional[Sequence[str]] = None,
) -> List[Directive]:
    """
    Directives called *name*, optionally confined to a block path.

    See the module docstring for why ``scope`` is matched exactly rather than
    by suffix.
    """
    wanted = name.strip().lower()
    matches = [d for d in parsed.directives if d.name.lower() == wanted]
    if scope is None:
        return matches
    target = tuple(str(s).lower() for s in scope)
    return [d for d in matches if tuple(s.lower() for s in d.scope) == target]


# ── XML ──────────────────────────────────────────────────────────────────────


#: Matches a DOCTYPE declaration outside a comment. Deliberately blunt: the
#: cost of a false positive is one configuration file reported UNAVAILABLE,
#: while the cost of a false negative is the scanner expanding an entity bomb
#: from a host it is auditing.
_DOCTYPE = re.compile(r"<!DOCTYPE", re.IGNORECASE)


def _reject_doctype(text: str) -> None:
    if _DOCTYPE.search(text):
        raise ParseError(
            "the document declares a DOCTYPE, which this parser refuses: "
            "internal entity expansion is a denial-of-service route into the "
            "scanner and no configuration file assessed here needs a DTD"
        )


def _strip_namespaces(element: Any) -> None:
    """
    Remove XML namespace prefixes from every tag and attribute, in place.

    **This is a correctness fix, not a convenience.** Tomcat 10 declares a
    default namespace on ``tomcat-users.xml``
    (``xmlns="http://tomcat.apache.org/xml"``), and ElementTree then requires
    ``.//{http://tomcat.apache.org/xml}user`` — a plain ``.//user`` matches
    nothing at all. Nothing about that failure looks like a failure: the parse
    succeeds, the selection is empty, the collector reports ABSENT, and a rule
    whose absence policy is PASS declares the server clean. That is a false
    negative produced by a namespace declaration, and it is exactly what this
    engine's collection states exist to prevent.

    Stripping is the right answer rather than making rules carry the URI,
    because the URI is a property of the product version — Tomcat 9 and Tomcat
    10 differ — so a rule pinned to one silently stops matching after an
    upgrade, which is the same failure again with a longer fuse.
    """
    for node in element.iter():
        if isinstance(node.tag, str) and node.tag.startswith("{"):
            node.tag = node.tag.split("}", 1)[1]
        for key in list(node.attrib):
            if key.startswith("{"):
                node.attrib[key.split("}", 1)[1]] = node.attrib.pop(key)


def xml_select(text: str, xpath: str, *, attribute: Optional[str] = None) -> List[str]:
    """
    Values selected from an XML document.

    ``attribute`` picks an attribute; without it the element's text is used.
    An element matched but missing the named attribute yields nothing rather
    than an empty string — "the Connector has no ``sslProtocol``" and "it has
    ``sslProtocol=''``" are different facts and only the parser can still tell
    them apart.

    ElementTree's XPath subset is deliberate rather than a limitation worked
    around: it has no expression evaluation, so a rule cannot smuggle
    executable content through the address the way a full XPath engine would
    allow.

    Entity expansion is refused, and it had to be measured
    ─────────────────────────────────────────────────────
    An earlier version of this docstring asserted that ElementTree has entity
    expansion disabled. It does not — a ten-line document expands to 300
    characters in this very interpreter, which is the billion-laughs shape. The
    documents parsed here come off a *target being audited*, so that is a real
    if modest denial-of-service route into the scanner.

    ``_reject_doctype`` refuses any document carrying a DOCTYPE before the
    parser sees it. That closes billion-laughs and quadratic blowup at the door
    without adding a dependency, and it costs nothing real: none of the
    configuration files this phase reads carries a DTD, and one that did would
    be worth looking at by hand. External entity resolution is genuinely off in
    ElementTree, so a DOCTYPE ban is the whole of the exposure.
    """
    _reject_doctype(text or "")

    from xml.etree import ElementTree  # nosec B405

    try:
        root = ElementTree.fromstring(text or "")  # nosec B314
    except ElementTree.ParseError as exc:
        raise ParseError(f"not well-formed XML: {exc}") from exc

    _strip_namespaces(root)

    try:
        found = root.findall(xpath)
    except SyntaxError as exc:
        raise ParseError(f"unsupported XPath {xpath!r}: {exc}") from exc

    # `findall` never returns the root itself, so a rule addressing the
    # document element gets it explicitly rather than silently nothing.
    if not found and xpath in (".", root.tag):
        found = [root]

    values: List[str] = []
    for element in found:
        if attribute:
            if attribute in element.attrib:
                values.append(str(element.attrib[attribute]))
        else:
            values.append((element.text or "").strip())
    return values


# ── JSON ─────────────────────────────────────────────────────────────────────

_MISSING = object()


def json_pointer(text: str, pointer: str) -> Any:
    """
    A value addressed by a dotted path, or ``None`` where the path is absent.

    Numeric segments index into arrays, so ``hosts.0`` reaches the first bound
    socket. A path that does not resolve returns ``None``, which the collector
    renders as ABSENT — for the Docker daemon that is the common and correct
    case, because a host with no ``daemon.json`` at all is running every
    setting at its default rather than having no settings.
    """
    try:
        document = json.loads(text or "")
    except json.JSONDecodeError as exc:
        raise ParseError(f"not valid JSON: {exc}") from exc

    node: Any = document
    for segment in [s for s in str(pointer).split(".") if s]:
        if isinstance(node, dict):
            node = node.get(segment, _MISSING)
        elif isinstance(node, list):
            try:
                node = node[int(segment)]
            except (ValueError, IndexError):
                node = _MISSING
        else:
            node = _MISSING
        if node is _MISSING:
            return None
    return node


def render_value(value: Any) -> Any:
    """
    Flatten a parsed value into something the comparison vocabulary handles.

    Lists stay lists — the operators already understand them, and ``in`` /
    ``not_in`` over a list of bound sockets is exactly the comparison a Docker
    rule wants. Booleans become their JSON spelling so ``is_true`` reads them,
    and everything else becomes a string.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return [render_value(v) for v in value]
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    if value is None:
        return None
    return str(value)


#: Parsers by the ``format`` a rule declares.
PARSERS: Dict[str, Any] = {
    "nginx": parse_nginx,
    "apache": parse_apache,
}

#: Which include-collector belongs to each directive format.
INCLUDE_READERS: Dict[str, Any] = {
    "nginx": nginx_includes,
    "apache": apache_includes,
}
