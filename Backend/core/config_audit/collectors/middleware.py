"""
core/config_audit/collectors/middleware.py
─────────────────────────────────────────────────────────────────────────────
The ``structured_config`` collector — reads one setting out of a configuration
document that has structure. Phase 8 of the gap-closure programme, closing
GAP-09.

One check type, four formats
────────────────────────────
``nginx``, ``apache``, ``xml`` and ``json`` share one check type rather than
having four, because from the engine's point of view they are one shape: a rule
names a file and an address inside it, and the collector answers COLLECTED,
ABSENT or UNAVAILABLE. Only the addressing differs, and that is a parameter.
Four check types would have meant four CHECK-constraint values on a table
holding customer rules and four registry entries, for no distinction the engine
can act on.

The parsing is in :mod:`core.config_audit.structured`, which touches no
transport at all. This module is only the part that has to talk to a host:
fetch bytes, expand includes, hand them to a parser, turn the answer into a
:class:`CollectedState`.

Includes, and the reason an unresolved one poisons an absence
─────────────────────────────────────────────────────────────
nginx and Apache both split configuration across files, and the default layout
of both puts the interesting settings in the *included* file rather than the
main one — nginx ships ``server`` blocks in ``conf.d/*.conf``, Apache ships
much of its posture in ``conf/extra/*.conf``.

So a directive missing from the file the rule names may simply be set
somewhere the collector did not look, and reporting ABSENT there would be a
verdict about a configuration that was never read. When expansion is
incomplete, an absent reading is therefore reported **UNAVAILABLE**, and only a
*found* value is trusted. Being unable to answer is a coverage gap; answering
"not configured" about a file you did not open is a false negative that reaches
a customer as a clean bill of health.

Target-supplied paths never reach a shell
─────────────────────────────────────────
Include globs come out of the *target's own configuration file*, so they are
attacker-influenced in exactly the way rule parameters are not. They are
resolved by listing the directory and matching with :func:`fnmatch.fnmatch` in
Python; the resolved paths are then quoted individually. A glob is never
handed to a shell for expansion, which is what would let a crafted
``include /etc/nginx/$(id).conf;`` become command execution on the target
during an audit.
"""

from __future__ import annotations

import fnmatch
import logging
import posixpath
import shlex
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector, CollectorRegistry, ShellRunner
from core.config_audit.collectors.windows import _parse_sentinel, ps_quote
from core.config_audit.spec import ConfigCheck
from core.config_audit.structured import (
    INCLUDE_READERS,
    PARSERS,
    ParsedConfig,
    ParseError,
    apache_server_root,
    json_pointer,
    render_value,
    rescope,
    select_directives,
    toml_pointer,
    xml_select,
    yaml_pointer,
)

log = logging.getLogger("ccure.config_audit.middleware")

__all__ = [
    "LinuxStructuredConfigCollector",
    "WindowsStructuredConfigCollector",
    "register_middleware_collectors",
]

_VALUE = "CCURE::VALUE::"
_ABSENT = "CCURE::ABSENT::"

#: Formats that carry directives in nested blocks, and therefore support
#: ``scope`` and include expansion.
_DIRECTIVE_FORMATS = ("nginx", "apache")

#: Formats that parse to a mapping and are addressed by a dotted path. They
#: share one navigator — see ``structured.navigate`` — because JSON, YAML and
#: TOML all parse to the same Python shapes, and three addressing schemes for
#: one idea is how two vocabularies for one idea begin.
_MAPPING_FORMATS = ("json", "yaml", "toml")

_FORMATS = (*_DIRECTIVE_FORMATS, "xml", *_MAPPING_FORMATS)

#: Which parser reads each mapping format.
_MAPPING_READERS = {
    "json": json_pointer,
    "yaml": yaml_pointer,
    "toml": toml_pointer,
}
_RESULT_SHAPES = ("value", "values", "count")

#: Bounds on include expansion. A configuration tree is not a filesystem crawl:
#: these exist so a target with a pathological include layout costs a bounded
#: number of round trips rather than an unbounded one.
_MAX_INCLUDE_FILES = 40
_MAX_BYTES = 512 * 1024


def _runner(ctx: CollectionContext) -> ShellRunner:
    key = "__shell_runner__"
    if key not in ctx.cache:
        ctx.cache[key] = ShellRunner(
            ctx.executor, ctx.platform, default_timeout=ctx.timeout
        )
    return ctx.cache[key]


class _StructuredConfigCollector(Collector):
    """Shared behaviour; the subclasses supply the platform's file commands."""

    check_type = "structured_config"

    # ── Platform hooks ───────────────────────────────────────────────────────

    def _read_command(self, path: str) -> str:
        raise NotImplementedError

    def _list_command(self, directory: str) -> str:
        raise NotImplementedError

    # ── Entry point ──────────────────────────────────────────────────────────

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "path", "format")
        if failure is not None:
            return failure
        params = params or {}

        fmt = str(params.get("format") or "").strip().lower()
        if fmt not in _FORMATS:
            return CollectedState.unavailable(
                f"rule declares format {fmt!r}; supported formats are "
                f"{', '.join(_FORMATS)}",
                collector=self.name,
            )

        shape = str(params.get("result") or "value").strip().lower()
        if shape not in _RESULT_SHAPES:
            return CollectedState.unavailable(
                f"rule asks for result shape {shape!r}; supported shapes are "
                f"{', '.join(_RESULT_SHAPES)}",
                collector=self.name,
            )

        path, text, read_state = self._locate(ctx, params)
        if read_state is not None:
            return read_state

        if fmt in _MAPPING_FORMATS:
            return self._from_mapping(params, path, str(text), fmt, shape)
        if fmt == "xml":
            return self._from_xml(params, path, str(text), shape)
        return self._from_directives(ctx, params, path, str(text), fmt, shape)

    # ── Locating ─────────────────────────────────────────────────────────────

    def _locate(
        self, ctx: CollectionContext, params: Dict[str, Any]
    ) -> Tuple[str, Optional[str], Optional[CollectedState]]:
        """
        Find the first candidate path that exists, and read it.

        ``path`` may be a list because the same product lives in different
        places on different distributions — Apache is ``/etc/apache2``,
        ``/etc/httpd/conf`` or ``/usr/local/apache2/conf`` depending on who
        packaged it, and a rule pinned to one of them reports "not configured"
        on the other two.

        **A missing file is UNSUPPORTED by default, not ABSENT**, and the
        distinction is the difference between a useful rule set and a useless
        one. A Linux host that does not run Apache is not *failing* Apache's
        hardening rules; the check was never in scope for it, which is exactly
        what UNSUPPORTED means and what NOT_APPLICABLE renders it as. Treating
        it as ABSENT would hand every host in the estate a pile of findings
        about software it does not have.

        ``missing_file: absent`` inverts that for the case where a missing file
        is itself a reading. The Docker daemon is the example and it is not a
        corner case: most installations have no ``daemon.json`` at all, and
        that means every setting is at its default — a real, knowable state
        that some rules pass on and others must defer.
        """
        raw_path = params["path"]
        candidates = (
            [str(p) for p in raw_path]
            if isinstance(raw_path, (list, tuple))
            else [str(raw_path)]
        )
        policy = str(params.get("missing_file") or "unsupported").strip().lower()
        if policy not in ("unsupported", "absent"):
            return (
                "",
                None,
                CollectedState.unavailable(
                    f"rule declares missing_file={policy!r}; expected 'unsupported' "
                    f"or 'absent'",
                    collector=self.name,
                ),
            )

        first_failure: Optional[CollectedState] = None
        for candidate in candidates:
            text, failure = self._fetch(ctx, candidate)
            if failure is None:
                return candidate, text, None
            # A transport problem is not a missing file, and must not be
            # rendered as "the product is not installed".
            if failure.status.name != "ABSENT":
                return candidate, None, failure
            first_failure = failure

        where = ", ".join(candidates)
        if policy == "absent":
            return (
                candidates[0],
                None,
                CollectedState.absent(
                    f"no configuration file at {where}, so the product is "
                    f"running entirely on its built-in defaults",
                    raw=where,
                    collector=self.name,
                ),
            )
        return (
            candidates[0],
            None,
            CollectedState.unsupported(
                f"no configuration file at {where}, so this product does not "
                f"appear to be installed on this host",
                collector=self.name,
            ),
        )

    # ── Reading ──────────────────────────────────────────────────────────────

    def _fetch(
        self, ctx: CollectionContext, path: str
    ) -> Tuple[Optional[str], Optional[CollectedState]]:
        """
        Read one file, memoised per target.

        Memoised because a middleware rule set reads the same handful of files
        many times over — twenty nginx rules against one ``nginx.conf`` — and
        without it the audit pays for the transport once per rule.
        """
        cache_key = f"__structured_file__{self.name}::{path}"

        def _read() -> Tuple[Optional[str], Optional[CollectedState]]:
            runner = _runner(ctx)
            if not runner.available:
                return None, CollectedState.unavailable(
                    "no authenticated session to the target", collector=self.name
                )
            out = runner.run(self._read_command(path), timeout=ctx.timeout)
            if not out.ok:
                return None, CollectedState.unavailable(
                    out.failure_detail(),
                    raw=out.stderr or out.stdout,
                    collector=self.name,
                )
            value, absent = _parse_sentinel(out.text)
            if absent is not None:
                return None, CollectedState.absent(
                    absent, raw=path, collector=self.name
                )
            if value is None:
                # Output carrying no sentinel means the command did not run the
                # way this collector expected. Reading it as file content would
                # parse a shell diagnostic as configuration.
                return None, CollectedState.unavailable(
                    "the read produced no sentinel, so the file contents could "
                    "not be established",
                    raw=out.text[:400],
                    collector=self.name,
                )
            return value, None

        return ctx.cached(cache_key, _read)

    def _list_directory(
        self, ctx: CollectionContext, directory: str
    ) -> Optional[List[str]]:
        """
        File names directly inside *directory*.

        Returns ``None`` where the listing could not be performed at all, and
        ``[]`` where the directory is genuinely empty. Collapsing the two would
        make an unreadable ``conf.d`` indistinguishable from an empty one — and
        the first means an include we could not follow, which has to poison any
        absence that follows it.
        """
        cache_key = f"__structured_ls__{self.name}::{directory}"

        def _read() -> Optional[List[str]]:
            runner = _runner(ctx)
            if not runner.available:
                return None
            out = runner.run(self._list_command(directory), timeout=ctx.timeout)
            if not out.ok:
                return None
            value, absent = _parse_sentinel(out.text)
            if absent is not None:
                return None
            if value is None:
                return None
            return [line.strip() for line in value.splitlines() if line.strip()]

        return ctx.cached(cache_key, _read)

    # ── Directive formats (nginx, apache) ────────────────────────────────────

    def _from_directives(
        self,
        ctx: CollectionContext,
        params: Dict[str, Any],
        path: str,
        text: str,
        fmt: str,
        shape: str,
    ) -> CollectedState:
        directive = params.get("directive")
        if not directive:
            return CollectedState.unavailable(
                f"a {fmt} rule must name the directive to read",
                collector=self.name,
            )

        try:
            parsed: ParsedConfig = PARSERS[fmt](text, source=path)
        except ParseError as exc:
            return CollectedState.unavailable(
                f"{path} could not be parsed as {fmt} configuration: {exc}",
                raw=text[:400],
                collector=self.name,
            )

        expand = bool(params.get("expand_includes", True))
        if expand:
            parsed = self._expand(ctx, parsed, path, fmt, params)
        else:
            parsed.unresolved_includes = [
                d.value.strip() for d in INCLUDE_READERS[fmt](parsed)
            ]

        scope = params.get("scope")
        matches = select_directives(
            parsed,
            str(directive),
            scope=None if scope is None else [str(s) for s in scope],
        )
        raw = self._raw(parsed, path, matches)

        if shape == "count":
            return CollectedState.collected(len(matches), raw=raw, collector=self.name)

        if not matches:
            # The property this whole collector exists for. An absence is only
            # trustworthy when everything the configuration pulls in was read.
            if parsed.unresolved_includes:
                return CollectedState.unavailable(
                    f"directive {directive!r} was not found, but "
                    f"{len(parsed.unresolved_includes)} include(s) could not be "
                    f"expanded ("
                    f"{', '.join(parsed.unresolved_includes[:3])}"
                    f"), so it may be set in a file that was not read",
                    raw=raw,
                    collector=self.name,
                )
            return CollectedState.absent(
                f"directive {directive!r} is not set in {path} or anything it "
                f"includes",
                raw=raw,
                collector=self.name,
            )

        if shape == "values":
            return CollectedState.collected(
                [m.value for m in matches], raw=raw, collector=self.name
            )
        # nginx and Apache both let a later directive in the same scope replace
        # an earlier one, so the last is the effective setting.
        return CollectedState.collected(matches[-1].value, raw=raw, collector=self.name)

    def _expand(
        self,
        ctx: CollectionContext,
        parsed: ParsedConfig,
        path: str,
        fmt: str,
        params: Dict[str, Any],
    ) -> ParsedConfig:
        """
        Fold one level of includes into *parsed*.

        One level, deliberately. It covers every default layout these products
        ship (nginx ``conf.d``, Apache ``conf-enabled`` and ``conf/extra``), and
        an include found inside an included file is recorded as unresolved
        rather than followed — which downgrades an absence to UNAVAILABLE
        instead of quietly answering from a partial read.
        """
        root = str(params.get("include_root") or "") or self._include_root(
            parsed, path, fmt
        )
        pending = list(INCLUDE_READERS[fmt](parsed))
        budget = _MAX_INCLUDE_FILES

        for directive in pending:
            pattern = directive.value.strip()
            if budget <= 0:
                parsed.unresolved_includes.append(pattern)
                continue
            target = (
                pattern if pattern.startswith("/") else posixpath.join(root, pattern)
            )
            resolved_paths = self._resolve(ctx, target)
            if resolved_paths is None:
                # The directory could not be listed, so we do not know what the
                # glob would have matched. Silently treating that as "nothing to
                # include" is the failure this whole mechanism exists to
                # prevent — it trusts an absence against files never read.
                parsed.unresolved_includes.append(pattern)
                continue
            for resolved in resolved_paths:
                if budget <= 0:
                    parsed.unresolved_includes.append(pattern)
                    break
                budget -= 1
                text, failed = self._fetch(ctx, resolved)
                if failed is not None or text is None:
                    parsed.unresolved_includes.append(resolved)
                    continue
                try:
                    child = PARSERS[fmt](text, source=resolved)
                except ParseError as exc:
                    log.debug("Could not parse include %s: %s", resolved, exc)
                    parsed.unresolved_includes.append(resolved)
                    continue
                # Grafted onto the branch the `include` sat on, not onto the
                # root. nginx ships its `server` blocks in a file included from
                # inside `http`, so without this they parse as `server` rather
                # than `http > server` and every rule about them finds nothing.
                parsed.directives.extend(rescope(child.directives, directive.scope))
                parsed.sources.append(resolved)
                # An include inside an include is not followed; recording it is
                # what keeps the absence honest.
                parsed.unresolved_includes.extend(
                    d.value.strip() for d in INCLUDE_READERS[fmt](child)
                )
        return parsed

    @staticmethod
    def _include_root(parsed: ParsedConfig, path: str, fmt: str) -> str:
        """
        The directory a relative include is resolved against.

        Apache resolves against ``ServerRoot``, which the configuration itself
        declares; nginx resolves against the prefix, for which the config
        file's own directory is the right approximation.
        """
        if fmt == "apache":
            declared = apache_server_root(parsed)
            if declared:
                return declared
        return posixpath.dirname(path) or "/"

    def _resolve(self, ctx: CollectionContext, target: str) -> Optional[List[str]]:
        """
        Turn an include target into concrete paths, matching in Python.

        The glob comes from the target's own configuration, so it is never
        handed to a shell — see the module docstring.

        ``None`` means the directory could not be listed, which is different
        from an empty list and must reach the caller as such.
        """
        if not any(ch in target for ch in "*?["):
            return [target]
        directory = posixpath.dirname(target) or "/"
        pattern = posixpath.basename(target)
        names = self._list_directory(ctx, directory)
        if names is None:
            return None
        return [
            posixpath.join(directory, name)
            for name in sorted(names)
            if fnmatch.fnmatch(name, pattern)
        ]

    # ── XML ──────────────────────────────────────────────────────────────────

    def _from_xml(
        self, params: Dict[str, Any], path: str, text: str, shape: str
    ) -> CollectedState:
        xpath = params.get("xpath")
        if not xpath:
            return CollectedState.unavailable(
                "an xml rule must name the xpath to read", collector=self.name
            )
        try:
            values = xml_select(
                text, str(xpath), attribute=params.get("attribute") or None
            )
        except ParseError as exc:
            return CollectedState.unavailable(
                f"{path} could not be read as XML: {exc}",
                raw=text[:400],
                collector=self.name,
            )

        raw = f"file: {path}\nxpath: {xpath}\nmatches: {len(values)}\n" + "\n".join(
            values[:20]
        )
        if shape == "count":
            return CollectedState.collected(len(values), raw=raw, collector=self.name)
        if not values:
            return CollectedState.absent(
                f"xpath {xpath!r} selected nothing in {path}",
                raw=raw,
                collector=self.name,
            )
        if shape == "values":
            return CollectedState.collected(values, raw=raw, collector=self.name)
        return CollectedState.collected(values[-1], raw=raw, collector=self.name)

    # ── Mapping formats: JSON, YAML, TOML ────────────────────────────────────

    def _from_mapping(
        self, params: Dict[str, Any], path: str, text: str, fmt: str, shape: str
    ) -> CollectedState:
        """
        One handler for all three mapping formats.

        They differ only in how the bytes become a Python mapping; the
        addressing, the shapes and — most importantly — the meaning of a path
        that does not resolve are identical, and writing that three times is
        how three subtly different notions of ABSENT come to exist.
        """
        pointer = params.get("pointer")
        if not pointer:
            return CollectedState.unavailable(
                f"a {fmt} rule must name the pointer to read", collector=self.name
            )
        # The pointer is passed through *without* str(), and that is not
        # incidental. A list pointer is how a rule reaches a key that itself
        # contains dots — containerd's `[plugins."io.containerd.grpc.v1.cri"]`
        # — and stringifying it produced "['plugins', 'io.containerd…']", which
        # navigate() then split on dots into segments matching nothing. The
        # result was ABSENT, which for these rules means "at the default", so
        # containerd reported clean no matter how it was configured.
        address = list(pointer) if isinstance(pointer, (list, tuple)) else str(pointer)
        try:
            value = _MAPPING_READERS[fmt](text, address)
        except ParseError as exc:
            return CollectedState.unavailable(
                f"{path} could not be read as {fmt.upper()}: {exc}",
                raw=text[:400],
                collector=self.name,
            )

        raw = f"file: {path}\npointer: {pointer}\nvalue: {value!r}"
        if shape == "count":
            if value is None:
                return CollectedState.collected(0, raw=raw, collector=self.name)
            size = len(value) if isinstance(value, (list, dict)) else 1
            return CollectedState.collected(size, raw=raw, collector=self.name)
        if value is None:
            return CollectedState.absent(
                f"{pointer!r} is not set in {path}, so it is at the product "
                f"default",
                raw=raw,
                collector=self.name,
            )
        rendered = render_value(value)
        if shape == "values" and not isinstance(rendered, list):
            rendered = [rendered]
        return CollectedState.collected(rendered, raw=raw, collector=self.name)

    # ── Evidence ─────────────────────────────────────────────────────────────

    @staticmethod
    def _raw(parsed: ParsedConfig, path: str, matches: Sequence[Any]) -> str:
        lines = [f"file: {path}"]
        if parsed.sources[1:]:
            lines.append("includes read: " + ", ".join(parsed.sources[1:][:8]))
        if parsed.unresolved_includes:
            lines.append(
                "includes NOT read: " + ", ".join(parsed.unresolved_includes[:8])
            )
        lines.append(f"matches: {len(matches)}")
        lines.extend(m.as_evidence() for m in matches[:20])
        return "\n".join(lines)


class LinuxStructuredConfigCollector(_StructuredConfigCollector):
    """Reads structured configuration from a POSIX target."""

    platforms = ("linux",)
    name = "linux_structured_config"

    def _read_command(self, path: str) -> str:
        quoted = shlex.quote(str(path))
        return (
            f"if [ -f {quoted} ]; then "
            f"printf '%s' '{_VALUE}'; head -c {_MAX_BYTES} -- {quoted}; "
            f"else printf '%s\\n' {shlex.quote(_ABSENT + 'file does not exist')}; fi"
        )

    def _list_command(self, directory: str) -> str:
        quoted = shlex.quote(str(directory))
        return (
            f"if [ -d {quoted} ]; then "
            f"printf '%s\\n' '{_VALUE}'; "
            f"find {quoted} -maxdepth 1 -type f -exec basename {{}} \\; ; "
            f"else printf '%s\\n' {shlex.quote(_ABSENT + 'directory does not exist')}; "
            f"fi"
        )


class WindowsStructuredConfigCollector(_StructuredConfigCollector):
    """
    Reads structured configuration from a Windows target.

    Apache, Tomcat and the Docker daemon all run on Windows, so the same rules
    have to reach a Windows host. Only the two file commands differ; the
    parsing, the include expansion and every absence decision are shared.
    """

    platforms = ("windows",)
    name = "windows_structured_config"

    def _read_command(self, path: str) -> str:
        quoted = ps_quote(path)
        return (
            f"$ErrorActionPreference='Stop'; $p = {quoted}; "
            f"if (-not (Test-Path -LiteralPath $p -PathType Leaf)) "
            f"{{ Write-Output '{_ABSENT}file does not exist' }} else "
            f"{{ $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop; "
            f"if ($raw.Length -gt {_MAX_BYTES}) "
            f"{{ $raw = $raw.Substring(0, {_MAX_BYTES}) }}; "
            f"Write-Output ('{_VALUE}' + $raw) }}"
        )

    def _list_command(self, directory: str) -> str:
        quoted = ps_quote(directory)
        return (
            f"$ErrorActionPreference='Stop'; $d = {quoted}; "
            f"if (-not (Test-Path -LiteralPath $d -PathType Container)) "
            f"{{ Write-Output '{_ABSENT}directory does not exist' }} else "
            f"{{ Write-Output '{_VALUE}'; "
            f"Get-ChildItem -LiteralPath $d -File | "
            f"ForEach-Object {{ Write-Output $_.Name }} }}"
        )


def register_middleware_collectors(registry: CollectorRegistry) -> None:
    """Register the structured-configuration collector on both host platforms."""
    registry.register(LinuxStructuredConfigCollector())
    registry.register(WindowsStructuredConfigCollector())
