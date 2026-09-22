"""
core/scap/probes.py
─────────────────────────────────────────────────────────────────────────────
Collecting OVAL objects from a live target.

One probe per OVAL object type. A probe answers exactly one question — "what
items does this object select on this host" — and never decides whether the
host is compliant. The state comparison happens once, in
:mod:`core.scap.evaluate`, for every object type.

Matching happens in Python, not in the shell
────────────────────────────────────────────
``textfilecontent54`` is 68% of the tests in the measured corpus, and its
object carries a **regular expression with capture groups** plus behaviour
flags for multiline and case sensitivity. Handing that to ``grep`` means
translating one regex dialect into another, on the target, with the rule's own
text as the input — which is both a correctness problem and a shell-injection
boundary. So the probe reads the file and applies :mod:`re` locally. The cost
is the file's bytes on the wire; the benefit is that the expression evaluated
is the one the content author wrote.

Every path still goes through ``shlex.quote``. The paths come out of a
benchmark, which is data an operator can edit, so this is the Phase 3
injection boundary in the same place for the same reason.

Not found is not the same as not read
─────────────────────────────────────
Every probe distinguishes three outcomes: items (possibly none), a target that
answered "no such file", and a read that failed. The first two are results and
the third is not. This is the Phase 3 collection-state discipline expressed at
a lower level: ``ProbeResult.ok`` False becomes UNAVAILABLE → ERROR, and an
empty ``items`` tuple with ``ok`` True is a real reading of "nothing matched",
which is what every ``none_exist`` check in the corpus depends on.
"""

from __future__ import annotations

import re
import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from core.config_audit.collection import CollectionContext
from core.config_audit.collectors.base import ShellRunner
from core.config_audit.structured import ParseError, navigate, xml_select, yaml_pointer
from core.scap.oval import literal_prefix, local_name

__all__ = [
    "PROBES",
    "PatternTranslationError",
    "ProbeResult",
    "collect_object",
    "supported_object_types",
]

#: Marker protocol. Distinct from Phase 3's ``CCURE::VALUE::`` because these
#: commands emit *many* records, and reusing a single-value protocol for a
#: multi-record one is how a parser comes to return the first line only.
_FOUND = "CCURE::FOUND::"
_MISSING = "CCURE::MISSING::"
_REC = "CCURE::REC::"

#: A single file is read up to this size. Configuration files are kilobytes;
#: the cap exists so a rule pointed at a log file costs a bounded transfer.
_MAX_FILE_BYTES = 512 * 1024

#: A directory listing is truncated here. ``/etc/cron.d`` has a handful of
#: entries; a rule that selects thousands is a rule this build should decline
#: rather than spend an hour on.
_MAX_LISTING = 500

#: ``find`` recursion ceiling, whatever the content asks for.
_MAX_RECURSE_DEPTH = 8

_TOOL_MISSING = 97

#: st_mode file-type bits → the vocabulary OVAL's ``file_state/type`` uses.
_FILE_TYPES = {
    0o140000: "socket",
    0o120000: "symbolic link",
    0o100000: "regular",
    0o060000: "block special",
    0o040000: "directory",
    0o020000: "character special",
    0o010000: "fifo",
}


@dataclass(frozen=True)
class ProbeResult:
    """What an object selected, or why it could not be established."""

    ok: bool
    items: Tuple[Mapping[str, Any], ...] = ()
    detail: str = ""
    raw: str = ""

    @classmethod
    def collected(
        cls, items: Sequence[Mapping[str, Any]], raw: str = ""
    ) -> "ProbeResult":
        return cls(ok=True, items=tuple(items), raw=raw)

    @classmethod
    def failed(cls, detail: str, raw: str = "") -> "ProbeResult":
        return cls(ok=False, detail=detail, raw=raw)


# ─────────────────────────────────────────────────────────────────────────────
# Shell plumbing, shared and memoised
# ─────────────────────────────────────────────────────────────────────────────


def _runner(ctx: CollectionContext) -> ShellRunner:
    key = "__shell_runner__"
    if key not in ctx.cache:
        ctx.cache[key] = ShellRunner(
            ctx.executor, ctx.platform, default_timeout=ctx.timeout
        )
    return ctx.cache[key]


def _memo(ctx: CollectionContext) -> Dict[str, Any]:
    """
    The per-audit read cache.

    A STIG reads ``/etc/ssh/sshd_config`` from dozens of rules. Without this,
    one benchmark run is hundreds of redundant round trips over SSH, and the
    audit's wall-clock cost is set by how many rules happen to share a file
    rather than by how many distinct things it looks at.
    """
    key = "__scap_reads__"
    if key not in ctx.cache:
        ctx.cache[key] = {}
    return ctx.cache[key]


def _read_file(
    ctx: CollectionContext, path: str
) -> Tuple[Optional[str], Optional[str]]:
    """
    Read one file. Returns ``(text, failure)`` — exactly one is not None,
    except for a missing file, which is ``(None, None)``.
    """
    memo = _memo(ctx)
    key = f"file:{path}"
    if key in memo:
        return memo[key]

    runner = _runner(ctx)
    if not runner.available:
        return None, "no authenticated session to the target"
    quoted = shlex.quote(path)
    command = (
        f"if [ -f {quoted} ]; then printf '%s' {shlex.quote(_FOUND)}; "
        f"head -c {_MAX_FILE_BYTES} -- {quoted}; "
        f"else printf '%s' {shlex.quote(_MISSING)}; fi"
    )
    out = runner.run(command, timeout=ctx.timeout)
    if not out.ok:
        result: Tuple[Optional[str], Optional[str]] = (None, out.failure_detail())
    elif out.stdout.startswith(_MISSING):
        result = (None, None)
    elif out.stdout.startswith(_FOUND):
        result = (out.stdout[len(_FOUND) :], None)
    else:
        result = (
            None,
            "the read produced no result marker, so the file's contents were "
            "not established",
        )
    memo[key] = result
    return result


def _list_directory(
    ctx: CollectionContext, directory: str
) -> Tuple[Optional[List[str]], Optional[str]]:
    """Entry names in *directory*. ``(None, None)`` where it does not exist."""
    memo = _memo(ctx)
    key = f"dir:{directory}"
    if key in memo:
        return memo[key]

    runner = _runner(ctx)
    if not runner.available:
        return None, "no authenticated session to the target"
    quoted = shlex.quote(directory)
    command = (
        f"if [ -d {quoted} ]; then printf '%s\\n' {shlex.quote(_FOUND)}; "
        f"ls -1A -- {quoted} | head -n {_MAX_LISTING}; "
        f"else printf '%s\\n' {shlex.quote(_MISSING)}; fi"
    )
    out = runner.run(command, timeout=ctx.timeout)
    if not out.ok:
        result: Tuple[Optional[List[str]], Optional[str]] = (
            None,
            out.failure_detail(),
        )
    else:
        lines = out.stdout.splitlines()
        head = lines[0].strip() if lines else ""
        if head == _MISSING.strip():
            result = (None, None)
        elif head == _FOUND.strip():
            result = ([line for line in lines[1:] if line], None)
        else:
            result = (
                None,
                "the listing produced no result marker, so the directory's "
                "contents were not established",
            )
    memo[key] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Entity helpers
# ─────────────────────────────────────────────────────────────────────────────


def _entity_values(entities: Mapping[str, Any], name: str) -> List[str]:
    entity = entities.get(name)
    if not isinstance(entity, Mapping):
        return []
    return [str(v) for v in entity.get("values") or []]


def _entity_one(entities: Mapping[str, Any], name: str) -> Optional[str]:
    values = _entity_values(entities, name)
    return values[0] if values else None


def _entity_operation(entities: Mapping[str, Any], name: str) -> str:
    entity = entities.get(name)
    if not isinstance(entity, Mapping):
        return "equals"
    return str(entity.get("operation") or "equals").strip().lower()


#: Inline global flags OVAL content puts anywhere in a pattern. Python requires
#: them at position 0 and raises otherwise, so they are hoisted into real flags.
_INLINE_FLAG = re.compile(r"\(\?([aiLmsux]+)\)")

#: A *scoped* inline flag: ``(?i)word(?-i)`` turns a mode on for a span and
#: off again. Python has no bare ``(?-i)``; the equivalent is the scoped group
#: ``(?i:word)``, which is what this rewrites the pair into.
#:
#: Handling only the opening half is worse than handling neither. Stripping
#: ``(?i)`` and leaving ``(?-i)`` produces ``missing :`` from Python — which
#: is at least visible — but hoisting the flag to the whole expression would
#: silently make the *rest* of the pattern case-insensitive too, and the
#: content wrote ``(?-i)`` precisely to stop that. Fourteen audit rules in the
#: RHEL 9 STIG profile use this shape.
_SCOPED_FLAG = re.compile(r"\(\?([aiLmsux]+)\)(.*?)\(\?-\1\)", re.DOTALL)

_INLINE_FLAG_BITS = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "x": re.VERBOSE,
    "a": re.ASCII,
    "L": re.LOCALE,
    "u": re.UNICODE,
}

#: PCRE escapes with no Python equivalent, and the character class each means.
#: Translated rather than declined because the content is written for PCRE and
#: these appear in rules about PAM and sudo — shapes a STIG cares most about.
#: Each mapping is the escape's documented definition, not an approximation:
#: ``\h`` is horizontal whitespace, ``\N`` is any character except a newline.
#: The leading group matches an even number of preceding backslashes, so an
#: escaped backslash followed by a literal ``h`` is left alone.
_PCRE_ESCAPES = (
    (re.compile(r"(?<!\\)((?:\\\\)*)\\h"), r"\1[ \\t]"),
    (re.compile(r"(?<!\\)((?:\\\\)*)\\H"), r"\1[^ \\t]"),
    (re.compile(r"(?<!\\)((?:\\\\)*)\\N(?!\{)"), r"\1[^\\n]"),
)


#: POSIX bracket expressions, and the Python character-class body each means.
#:
#: **Python does not support these and does not say so.** ``[[:blank:]]`` parses
#: as the class ``[[:blank]`` followed by a literal ``]`` — a set containing the
#: characters ``[ : b l a n k`` — so a pattern written to match whitespace
#: matches punctuation instead. Nothing raises; ``re`` emits at most a
#: ``FutureWarning`` about a nested set, which a scan run never shows anyone.
#:
#: The consequence is the direction that reaches a customer. The rule collects
#: no items, ``check_existence="all_exist"`` reads that as FALSE, and the host
#: acquires a finding about a line that is in fact present and correct.
_POSIX_CLASSES = {
    "alpha": "a-zA-Z",
    "digit": "0-9",
    "alnum": "a-zA-Z0-9",
    "upper": "A-Z",
    "lower": "a-z",
    "space": r"\s",
    "blank": r" \t",
    "xdigit": "0-9A-Fa-f",
    "word": r"\w",
    "punct": r"!-/:-@\[-`{-~",
    "print": r"\x20-\x7e",
    "graph": r"\x21-\x7e",
    "cntrl": r"\x00-\x1f\x7f",
}

_POSIX_CLASS = re.compile(r"\[:(\^?)([a-z]+):\]")


class PatternTranslationError(ValueError):
    """The pattern uses a construct this build will not guess the meaning of."""


def _expand_posix(pattern: str) -> str:
    """
    Replace ``[:name:]`` with the Python character-class body it denotes.

    An *unknown* class name is refused rather than left in place. Leaving it
    would reproduce exactly the silent mis-parse this function exists to
    prevent, and a refusal surfaces as a not-assessed rule, which is the
    correct answer for a pattern nobody can evaluate.
    """
    unknown = [
        name
        for _negated, name in _POSIX_CLASS.findall(pattern)
        if name not in _POSIX_CLASSES
    ]
    if unknown:
        raise PatternTranslationError(
            f"the pattern uses POSIX character class(es) {sorted(set(unknown))}, "
            f"which this build does not translate; Python would read them as a "
            f"set of literal characters and match the wrong text"
        )
    return _POSIX_CLASS.sub(
        lambda m: ("^" if m.group(1) else "") + _POSIX_CLASSES[m.group(2)], pattern
    )


def _translate_pattern(pattern: str) -> Tuple[str, int]:
    """
    An OVAL pattern as a Python regular expression, plus the flags it implied.

    Two dialect differences, both found by running real STIG content rather
    than anticipated:

    - **Inline global flags must lead.** ``^\\s*(?i)PermitRootLogin`` is valid
      PCRE and raises ``global flags not at the start of the expression`` in
      Python. Nine rules in the RHEL 9 STIG profile hit this.
    - **``\\N`` and ``\\h`` do not exist in Python.** ``\\N`` is not merely
      unsupported — Python reads it as the start of a named-Unicode escape and
      raises ``missing {``. Three rules hit it, all about PAM.

    Both are translations of the escape's documented meaning, so the expression
    evaluated is still the one the content author wrote.
    """
    # POSIX classes first: they change what a bracket expression contains,
    # and every later step operates on the expanded form.
    translated = _expand_posix(pattern)
    # Scoped pairs next: they must become a group, not a global flag.
    translated = _SCOPED_FLAG.sub(lambda m: f"(?{m.group(1)}:{m.group(2)})", translated)
    flags = 0
    for match in _INLINE_FLAG.finditer(translated):
        for letter in match.group(1):
            flags |= _INLINE_FLAG_BITS.get(letter, 0)
    # Whatever bare openers remain apply to the whole expression, which is what
    # PCRE means by them. An unpaired ``(?-i)`` is deliberately left in place so
    # ``re.compile`` refuses it: dropping one would quietly widen the match.
    translated = _INLINE_FLAG.sub("", translated)
    for expression, replacement in _PCRE_ESCAPES:
        translated = expression.sub(replacement, translated)
    return translated, flags


def _compile(pattern: str, *, ignore_case: bool = False) -> "re.Pattern[str]":
    translated, flags = _translate_pattern(pattern)
    return re.compile(translated, flags | (re.IGNORECASE if ignore_case else 0))


def _target_paths(
    ctx: CollectionContext, entities: Mapping[str, Any]
) -> Tuple[Optional[List[str]], Optional[str], Optional[str]]:
    """
    The concrete file paths an object's ``filepath`` / ``path`` + ``filename``
    entities select.

    Returns ``(paths, unsupported_reason, failure)``. A ``path`` that is itself
    a pattern is refused rather than walked: matching a directory *name* by
    regular expression means enumerating the filesystem, which on a production
    host is a cost this build will not impose without the content asking for it
    explicitly through ``behaviors``.
    """
    filepath_op = _entity_operation(entities, "filepath")
    if "filepath" in entities:
        if filepath_op in ("equals", "case insensitive equals"):
            return [p for p in _entity_values(entities, "filepath") if p], None, None
        if filepath_op == "pattern match":
            return _paths_matching(ctx, _entity_values(entities, "filepath"))
        return (
            None,
            f"the object selects filepath by {filepath_op!r}, which this build "
            f"does not resolve",
            None,
        )

    directories = [p for p in _entity_values(entities, "path") if p]
    if not directories:
        return None, "the object names neither a filepath nor a path", None
    path_op = _entity_operation(entities, "path")
    if path_op == "pattern match":
        # Same bounded walk as a patterned filepath: start at the expression's
        # literal directory prefix, never at the root.
        resolved, unsupported, failure = _paths_matching(ctx, directories)
        if unsupported or failure:
            return None, unsupported, failure
        directories = list(resolved or [])
        if not directories:
            return [], None, None
    elif path_op not in ("equals", "case insensitive equals"):
        return (
            None,
            f"the object selects its directory by {path_op!r}, which this "
            f"build does not resolve",
            None,
        )

    filename_op = _entity_operation(entities, "filename")
    filenames = [name for name in _entity_values(entities, "filename") if name]
    if "filename" not in entities or not filenames:
        # **An empty ``<filename/>`` selects the directory itself**, and so does
        # an absent one. Dropping the empty case cost a real finding: SSG's
        # journal-permission rules address ``/var/log/journal`` exactly this
        # way, the probe collected nothing, and ``check_existence="none_exist"``
        # read "no offending directory" off an empty set. ``oscap`` reported
        # the same rule as failing on the same host — a vacuous truth, and the
        # only disagreement between the two implementations.
        return list(directories), None, None

    if filename_op in ("equals", "case insensitive equals"):
        return (
            [
                f"{d.rstrip('/')}/{name}"
                for d in directories
                for name in filenames
                if name
            ],
            None,
            None,
        )
    if filename_op == "pattern match":
        resolved: List[str] = []
        for directory in directories:
            entries, failure = _list_directory(ctx, directory)
            if failure:
                return None, None, failure
            if entries is None:
                continue
            for pattern in filenames:
                try:
                    matcher = _compile(pattern)
                except (re.error, PatternTranslationError) as exc:
                    return (
                        None,
                        f"the object's filename pattern is not a regular "
                        f"expression this build can compile: {exc}",
                        None,
                    )
                resolved.extend(
                    f"{directory.rstrip('/')}/{entry}"
                    for entry in entries
                    if matcher.search(entry)
                )
        return sorted(set(resolved)), None, None
    return (
        None,
        f"the object selects filename by {filename_op!r}, which this build "
        f"does not resolve",
        None,
    )


#: How deep a ``filepath`` pattern is resolved below its literal prefix. Two
#: covers every shape in the measured content — ``/etc/sudoers`` and
#: ``/etc/sudoers.d/*`` are selected by one expression — while keeping the walk
#: to a directory rather than a filesystem.
_PATTERN_PATH_DEPTH = 2


def _paths_matching(
    ctx: CollectionContext, patterns: Sequence[str]
) -> Tuple[Optional[List[str]], Optional[str], Optional[str]]:
    """
    Resolve ``filepath`` regular expressions by walking their literal prefix.

    32 rules in the RHEL 9 STIG profile select their file this way — sudoers
    and its drop-in directory in one expression, ``sshd_config`` and its
    ``sshd_config.d`` fragments in another. Declining them costs a tenth of the
    benchmark.

    The walk is bounded twice over: it starts at the expression's literal
    directory prefix, never at ``/``, and it descends two levels.
    """
    compiled = []
    roots = []
    for pattern in patterns:
        if not pattern:
            continue
        prefix = literal_prefix(pattern)
        if not prefix:
            return (
                None,
                f"the object selects filepath by a pattern with no literal "
                f"directory to search from ({pattern[:60]!r}); resolving it "
                f"would mean walking the filesystem",
                None,
            )
        try:
            compiled.append(_compile(pattern))
        except (re.error, PatternTranslationError) as exc:
            return (
                None,
                f"the object's filepath pattern is not a regular expression "
                f"this build can compile: {exc}",
                None,
            )
        roots.append(prefix)

    if not compiled:
        return [], None, None

    runner = _runner(ctx)
    if not runner.available:
        return None, None, "no authenticated session to the target"

    candidates = []
    memo = _memo(ctx)
    for root in sorted(set(roots)):
        key = f"walk:{root}:{_PATTERN_PATH_DEPTH}"
        if key in memo:
            listing, failure = memo[key]
        else:
            quoted = shlex.quote(root)
            command = (
                f"if [ -d {quoted} ]; then "
                f"find {quoted} -maxdepth {_PATTERN_PATH_DEPTH} 2>/dev/null "
                f"| head -n {_MAX_LISTING}; fi"
            )
            out = runner.run(command, timeout=ctx.timeout)
            listing, failure = (
                ([line for line in out.stdout.splitlines() if line.strip()], None)
                if out.ok
                else (None, out.failure_detail())
            )
            memo[key] = (listing, failure)
        if failure:
            return None, None, failure
        candidates.extend(listing or [])

    matched = [
        path
        for path in sorted(set(candidates))
        if any(matcher.search(path) for matcher in compiled)
    ]
    return matched, None, None


def _recursed_paths(
    ctx: CollectionContext,
    roots: Sequence[str],
    behaviors: Mapping[str, str],
    *,
    directories_only: bool = False,
) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Expand ``recurse_direction="down"`` into concrete paths.

    **The root is part of the result**, not excluded. An object addressing a
    directory and recursing downward selects that directory *and* what is under
    it; leaving the root out makes a rule about ``/var/log/journal``'s own mode
    unable to see it.

    ``max_depth="-1"`` means unbounded in OVAL. It is clamped here rather than
    honoured: this product scans production and OT hosts, and an unbounded walk
    from a directory somebody chose is a cost the target pays.
    """
    direction = str(behaviors.get("recurse_direction") or "none").strip().lower()
    if direction in ("", "none"):
        return list(roots), None
    if direction != "down":
        return None, (
            f"the object recurses {direction!r}; only downward recursion is "
            f"implemented"
        )
    try:
        depth = int(str(behaviors.get("max_depth") or 1))
    except ValueError:
        depth = 1
    if depth < 0 or depth > _MAX_RECURSE_DEPTH:
        depth = _MAX_RECURSE_DEPTH

    runner = _runner(ctx)
    if not runner.available:
        return None, "no authenticated session to the target"
    found: List[str] = []
    for root in roots:
        quoted = shlex.quote(root)
        kind = " -type d" if directories_only else ""
        command = (
            f"if [ -e {quoted} ]; then "
            f"find {quoted} -maxdepth {depth}{kind} 2>/dev/null "
            f"| head -n {_MAX_LISTING}; fi"
        )
        out = runner.run(command, timeout=ctx.timeout)
        if not out.ok:
            return None, out.failure_detail()
        found.extend(line for line in out.stdout.splitlines() if line.strip())
    return sorted(set(found)), None


# ─────────────────────────────────────────────────────────────────────────────
# Probes
# ─────────────────────────────────────────────────────────────────────────────


def _probe_textfilecontent(
    ctx: CollectionContext, obj: Mapping[str, Any]
) -> ProbeResult:
    entities = obj.get("entities") or {}
    behaviors = obj.get("behaviors") or {}
    paths, unsupported, failure = _target_paths(ctx, entities)
    if unsupported:
        return ProbeResult.failed(unsupported)
    if failure:
        return ProbeResult.failed(failure)

    pattern = _entity_one(entities, "pattern")
    if pattern is None:
        return ProbeResult.failed("the object declares no pattern to match")

    flags = 0
    if str(behaviors.get("ignore_case") or "").lower() in ("true", "1"):
        flags |= re.IGNORECASE
    # OVAL's `multiline` defaults to true and means ^/$ anchor per line, which
    # is Python's re.MULTILINE. `singleline` means `.` also matches a newline,
    # which is re.DOTALL. They are independent; the corpus sets multiline
    # explicitly on most objects and relies on the default on the rest.
    if str(behaviors.get("multiline", "true")).lower() in ("true", "1"):
        flags |= re.MULTILINE
    if str(behaviors.get("singleline") or "").lower() in ("true", "1"):
        flags |= re.DOTALL
    try:
        translated, inline_flags = _translate_pattern(pattern)
        matcher = re.compile(translated, flags | inline_flags)
    except (re.error, PatternTranslationError) as exc:
        return ProbeResult.failed(
            f"the object's pattern is not a regular expression this build can "
            f"compile: {exc}"
        )

    items: List[Dict[str, Any]] = []
    for path in paths or []:
        text, read_failure = _read_file(ctx, path)
        if read_failure:
            return ProbeResult.failed(read_failure)
        if text is None:
            continue
        directory, _, filename = path.rpartition("/")
        for index, match in enumerate(matcher.finditer(text), start=1):
            groups = list(match.groups())
            items.append(
                {
                    "filepath": path,
                    "path": directory or "/",
                    "filename": filename,
                    "text": match.group(0),
                    # OVAL's `subexpression` is a multi-valued entity holding
                    # the capture groups. With no groups the whole match is
                    # the value, which is what content that only tests for
                    # presence relies on.
                    "subexpression": groups if groups else [match.group(0)],
                    "instance": index,
                }
            )
    return ProbeResult.collected(items)


def _probe_file(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    entities = obj.get("entities") or {}
    behaviors = obj.get("behaviors") or {}
    paths, unsupported, failure = _target_paths(ctx, entities)
    if unsupported:
        return ProbeResult.failed(unsupported)
    if failure:
        return ProbeResult.failed(failure)
    # ``recurse`` says what to descend *into*; with no filename the object is
    # selecting directories, so the walk collects those rather than every file
    # beneath them.
    directories_only = not [
        name for name in _entity_values(entities, "filename") if name
    ] and str(behaviors.get("recurse") or "").strip().lower() in (
        "directories",
        "symlinks and directories",
    )
    paths, recurse_failure = _recursed_paths(
        ctx, paths or [], behaviors, directories_only=directories_only
    )
    if recurse_failure:
        return ProbeResult.failed(recurse_failure)
    if not paths:
        return ProbeResult.collected([])

    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")

    # ``stat`` deliberately without ``-L``: OVAL's file_state/type distinguishes
    # a symbolic link from what it points at, and dereferencing here would
    # report the target's mode for the link — the inverse of the Phase 5 bug,
    # and wrong for the same reason.
    quoted = " ".join(shlex.quote(p) for p in paths)
    command = (
        f"for p in {quoted}; do "
        f'if [ -e "$p" ] || [ -L "$p" ]; then '
        f"printf '%s' {shlex.quote(_REC)}; "
        f"stat -c '%n|%f|%u|%g' -- \"$p\" 2>/dev/null || printf '\\n'; "
        f"fi; done"
    )
    out = runner.run(command, timeout=ctx.timeout)
    if not out.ok:
        return ProbeResult.failed(out.failure_detail(), raw=out.stderr or out.stdout)

    items: List[Dict[str, Any]] = []
    for line in out.stdout.splitlines():
        if not line.startswith(_REC):
            continue
        body = line[len(_REC) :].strip()
        parts = body.split("|")
        if len(parts) != 4:
            continue
        name, raw_mode, uid, gid = parts
        try:
            mode = int(raw_mode, 16)
        except ValueError:
            continue
        directory, _, filename = name.rpartition("/")
        items.append(
            {
                "filepath": name,
                "path": directory or "/",
                "filename": filename,
                "type": _FILE_TYPES.get(mode & 0o170000, "regular"),
                "user_id": uid,
                "group_id": gid,
                "suid": bool(mode & 0o4000),
                "sgid": bool(mode & 0o2000),
                "sticky": bool(mode & 0o1000),
                "uread": bool(mode & 0o400),
                "uwrite": bool(mode & 0o200),
                "uexec": bool(mode & 0o100),
                "gread": bool(mode & 0o040),
                "gwrite": bool(mode & 0o020),
                "gexec": bool(mode & 0o010),
                "oread": bool(mode & 0o004),
                "owrite": bool(mode & 0o002),
                "oexec": bool(mode & 0o001),
            }
        )
    return ProbeResult.collected(items, raw=out.stdout[:2000])


def _probe_rpminfo(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    entities = obj.get("entities") or {}
    names = [n for n in _entity_values(entities, "name") if n]
    operation = _entity_operation(entities, "name")
    if operation not in ("equals", "case insensitive equals", "pattern match"):
        return ProbeResult.failed(
            f"the object selects a package by {operation!r}, which this build "
            f"does not resolve"
        )
    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")

    query = "%{NAME}|%|EPOCH?{%{EPOCH}}:{0}||%{VERSION}|%{RELEASE}|%{ARCH}\\n"
    if operation == "pattern match":
        command = (
            "command -v rpm >/dev/null 2>&1 || exit 97; "
            f"rpm -qa --qf {shlex.quote(_REC + query)} 2>/dev/null || true"
        )
    else:
        quoted = " ".join(shlex.quote(n) for n in names)
        command = (
            "command -v rpm >/dev/null 2>&1 || exit 97; "
            f"for p in {quoted}; do "
            f'rpm -q --qf {shlex.quote(_REC + query)} -- "$p" 2>/dev/null || true; '
            "done"
        )
    out = runner.run(command, timeout=ctx.timeout)
    if out.exit_code == _TOOL_MISSING:
        return ProbeResult.failed(
            "rpm is not installed, so nothing was established about the "
            "package — which is not the same as it being absent"
        )
    if not out.ok:
        return ProbeResult.failed(out.failure_detail(), raw=out.stderr)

    wanted: Optional[List["re.Pattern[str]"]] = None
    if operation == "pattern match":
        try:
            wanted = [_compile(n) for n in names]
        except (re.error, PatternTranslationError) as exc:
            return ProbeResult.failed(f"the object's name pattern is invalid: {exc}")

    items: List[Dict[str, Any]] = []
    for line in out.stdout.splitlines():
        if not line.startswith(_REC):
            continue
        parts = line[len(_REC) :].strip().split("|")
        if len(parts) != 5:
            continue
        name, epoch, version, release, arch = parts
        if wanted is not None and not any(p.search(name) for p in wanted):
            continue
        items.append(
            {
                "name": name,
                "epoch": epoch,
                "version": version,
                "release": release,
                "arch": arch,
                "evr": f"{epoch}:{version}-{release}",
            }
        )
    return ProbeResult.collected(items, raw=out.stdout[:2000])


def _probe_dpkginfo(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    entities = obj.get("entities") or {}
    names = [n for n in _entity_values(entities, "name") if n]
    operation = _entity_operation(entities, "name")
    if operation not in ("equals", "case insensitive equals"):
        return ProbeResult.failed(
            f"the object selects a package by {operation!r}, which this build "
            f"does not resolve for dpkg"
        )
    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")

    quoted = " ".join(shlex.quote(n) for n in names)
    marker = shlex.quote(
        _REC + "${binary:Package}|${Version}|${Architecture}|${Status}\\n"
    )
    command = (
        "command -v dpkg-query >/dev/null 2>&1 || exit 97; "
        f"for p in {quoted}; do "
        f'dpkg-query -W -f={marker} -- "$p" 2>/dev/null || true; '
        "done"
    )
    out = runner.run(command, timeout=ctx.timeout)
    if out.exit_code == _TOOL_MISSING:
        return ProbeResult.failed(
            "dpkg-query is not installed, so nothing was established about the "
            "package"
        )
    if not out.ok:
        return ProbeResult.failed(out.failure_detail(), raw=out.stderr)

    items: List[Dict[str, Any]] = []
    for line in out.stdout.splitlines():
        if not line.startswith(_REC):
            continue
        parts = line[len(_REC) :].strip().split("|")
        if len(parts) != 4:
            continue
        name, version, arch, status = parts
        # A package can be known to dpkg while not installed — removed but not
        # purged leaves a row whose Status says so. Reporting that as an
        # installed package inverts every "must not be installed" rule.
        if "install ok installed" not in status:
            continue
        epoch, _, rest = version.partition(":")
        evr = version if rest else f"0:{version}"
        items.append(
            {
                "name": name,
                "version": version,
                "arch": arch,
                "evr": evr,
                "epoch": epoch if rest else "0",
            }
        )
    return ProbeResult.collected(items, raw=out.stdout[:2000])


def _split_xpath(xpath: str, text: str) -> Tuple[str, Optional[str]]:
    """
    Adapt an OVAL xpath to the subset ElementTree evaluates.

    Two differences, both structural rather than cosmetic:

    - **Attribute selection is a separate argument.** OVAL content writes
      ``/Server/@port``; ElementTree has no ``@`` step and raises on it, so the
      trailing attribute is split off and passed to ``xml_select`` as
      ``attribute``.
    - **ElementTree paths are relative to the root element**, not to the
      document. ``/Server/Service`` finds nothing against a document whose root
      *is* ``Server``; the leading step has to be dropped once it has been
      matched against the root's tag.

    Getting either wrong yields an empty selection, which the collector reports
    as ABSENT — and an absent reading is a verdict for any rule whose existence
    check permits zero items. That is the Phase 8 namespace defect in a new
    costume.
    """
    from xml.etree import ElementTree

    expression = (xpath or "").strip()
    attribute = None
    if "/@" in expression:
        expression, _, attribute = expression.partition("/@")
    elif expression.startswith("@"):
        attribute = expression[1:]
        expression = "."

    expression = expression.rstrip("/") or "."
    if expression.startswith("/"):
        stripped = expression.lstrip("/")
        head, _, tail = stripped.partition("/")
        try:
            root_tag = local_name(ElementTree.fromstring(text or "").tag)
        except Exception:
            root_tag = ""
        if head and head == root_tag:
            expression = tail or "."
        else:
            expression = stripped or "."
    return expression, attribute


def _probe_xmlfilecontent(
    ctx: CollectionContext, obj: Mapping[str, Any]
) -> ProbeResult:
    entities = obj.get("entities") or {}
    paths, unsupported, failure = _target_paths(ctx, entities)
    if unsupported:
        return ProbeResult.failed(unsupported)
    if failure:
        return ProbeResult.failed(failure)
    xpath = _entity_one(entities, "xpath")
    if not xpath:
        return ProbeResult.failed("the object declares no xpath")

    items: List[Dict[str, Any]] = []
    for path in paths or []:
        text, read_failure = _read_file(ctx, path)
        if read_failure:
            return ProbeResult.failed(read_failure)
        if text is None:
            continue
        try:
            expression, attribute = _split_xpath(xpath, text)
            values = xml_select(text, expression, attribute=attribute)
        except ParseError as exc:
            return ProbeResult.failed(f"{path}: {exc}")
        directory, _, filename = path.rpartition("/")
        for value in values:
            items.append(
                {
                    "filepath": path,
                    "path": directory or "/",
                    "filename": filename,
                    "xpath": xpath,
                    "value_of": value,
                }
            )
    return ProbeResult.collected(items)


def _probe_yamlfilecontent(
    ctx: CollectionContext, obj: Mapping[str, Any]
) -> ProbeResult:
    entities = obj.get("entities") or {}
    paths, unsupported, failure = _target_paths(ctx, entities)
    if unsupported:
        return ProbeResult.failed(unsupported)
    if failure:
        return ProbeResult.failed(failure)
    yamlpath = _entity_one(entities, "yamlpath")
    if not yamlpath:
        return ProbeResult.failed("the object declares no yamlpath")
    # The subset supported is a dotted path into mappings, which is what the
    # measured corpus uses. Anything with a filter, wildcard or index is
    # declined rather than approximated: a yamlpath this build silently read as
    # something else would produce a confident verdict about the wrong key.
    if any(token in yamlpath for token in ("[", "*", "(", "?", "..")):
        return ProbeResult.failed(
            f"the object's yamlpath {yamlpath!r} uses a construct beyond the "
            f"dotted-mapping subset this build resolves"
        )

    pointer = [seg for seg in yamlpath.strip().lstrip(".").split(".") if seg]
    items: List[Dict[str, Any]] = []
    for path in paths or []:
        text, read_failure = _read_file(ctx, path)
        if read_failure:
            return ProbeResult.failed(read_failure)
        if text is None:
            continue
        try:
            value = yaml_pointer(text, pointer)
        except ParseError as exc:
            return ProbeResult.failed(f"{path}: {exc}")
        if value is None:
            continue
        directory, _, filename = path.rpartition("/")
        found = value if isinstance(value, list) else [value]
        for entry in found:
            items.append(
                {
                    "filepath": path,
                    "path": directory or "/",
                    "filename": filename,
                    "yamlpath": yamlpath,
                    "value": entry,
                    "field": entry,
                }
            )
    return ProbeResult.collected(items)


def _probe_systemdunitproperty(
    ctx: CollectionContext, obj: Mapping[str, Any]
) -> ProbeResult:
    entities = obj.get("entities") or {}
    unit = _entity_one(entities, "unit")
    prop = _entity_one(entities, "property")
    if not unit or not prop:
        return ProbeResult.failed("the object names no unit or no property")
    if _entity_operation(entities, "unit") not in ("equals", "case insensitive equals"):
        return ProbeResult.failed(
            "the object selects its unit by pattern, which this build does not "
            "resolve"
        )
    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")

    command = (
        "command -v systemctl >/dev/null 2>&1 || exit 97; "
        f"printf '%s' {shlex.quote(_REC)}; "
        f"systemctl show -p {shlex.quote(prop)} --value -- {shlex.quote(unit)} "
        f"2>/dev/null || true"
    )
    out = runner.run(command, timeout=ctx.timeout)
    if out.exit_code == _TOOL_MISSING:
        return ProbeResult.failed(
            "systemctl is not present, so nothing was established about the " "unit"
        )
    if not out.ok:
        return ProbeResult.failed(out.failure_detail(), raw=out.stderr)
    if not out.stdout.startswith(_REC):
        return ProbeResult.failed(
            "the unit query produced no result marker", raw=out.stdout[:400]
        )
    value = out.stdout[len(_REC) :].strip()
    if not value:
        # systemd answers with an empty line for a property a unit does not
        # have, and for a unit it has never heard of. Neither is a reading of
        # the property, and both are ABSENT rather than a value of "".
        return ProbeResult.collected([])
    return ProbeResult.collected(
        [{"unit": unit, "property": prop, "value": value}], raw=out.stdout[:400]
    )


def _probe_family(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    """
    The target's OVAL family.

    Answered from the audit context rather than the target, because the family
    is what the credentialed scan already established in order to pick a
    collector set at all. Asking the host again could only disagree with the
    decision that got us here.
    """
    platform = (ctx.platform or "").strip().lower()
    family = {"linux": "unix", "windows": "windows"}.get(platform)
    if not family:
        return ProbeResult.failed(
            f"the target's platform is {platform!r}, which maps to no OVAL family"
        )
    return ProbeResult.collected([{"family": family}])


def _probe_uname(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")
    memo = _memo(ctx)
    if "uname" in memo:
        return memo["uname"]
    command = (
        f"printf '%s' {shlex.quote(_REC)}; "
        "printf '%s|%s|%s|%s|%s' "
        '"$(uname -s)" "$(uname -n)" "$(uname -r)" "$(uname -v)" "$(uname -m)"'
    )
    out = runner.run(command, timeout=ctx.timeout)
    if not out.ok:
        result = ProbeResult.failed(out.failure_detail(), raw=out.stderr)
    elif not out.stdout.startswith(_REC):
        result = ProbeResult.failed("uname produced no result marker")
    else:
        parts = out.stdout[len(_REC) :].strip().split("|")
        if len(parts) != 5:
            result = ProbeResult.failed("uname output was not in the expected shape")
        else:
            os_name, node, release, version, machine = parts
            result = ProbeResult.collected(
                [
                    {
                        "os_name": os_name,
                        "node_name": node,
                        "os_release": release,
                        "os_version": version,
                        "machine_class": machine,
                        "processor_type": machine,
                    }
                ],
                raw=out.stdout[:400],
            )
    memo["uname"] = result
    return result


def _probe_variable(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    """
    A ``variable_object`` yields the variable's own value.

    No target read: the variable was resolved to a literal at compile time, and
    a ``variable_test`` compares that literal against a state. This is how a
    benchmark asserts something about its own parameter — the corpus uses it to
    check that a refined value is within an allowed range.
    """
    entities = obj.get("entities") or {}
    values = _entity_values(entities, "var_ref")
    if not values:
        return ProbeResult.failed(
            "the variable object resolved to no value, so there is nothing to "
            "compare"
        )
    return ProbeResult.collected([{"value": value} for value in values])


#: Object type → probe. Read by ``core.scap.supported_areas`` through
#: :data:`core.scap.oval.SUPPORTED_TESTS`, so removing one removes both the
#: capability and its coverage credit.


# ─────────────────────────────────────────────────────────────────────────────
# Windows
# ─────────────────────────────────────────────────────────────────────────────
#
# Added for the DISA Microsoft Windows 11 STIG. Frequencies measured over
# V2R10, MAC-2_Classified, 219 rules: registry 117, audit subcategories 43,
# userright 25, password policy 7, lockout policy 3 — 195 of 219.
#
# Every one of these reads. None writes to the host except the `secedit`
# export, which lands in `$env:TEMP` under a GUID name and is removed in the
# same command — the shape `WindowsSecurityPolicyCollector._run_secedit`
# already established, reused here rather than reinvented.


def _win_native(ctx: CollectionContext, capability: str):
    """
    The executor's own implementation of *capability*, when it has one.

    The SMB transport reads the registry over Remote Registry, natively and
    without a shell. WinRM has no such method and returns None here, so it
    keeps running PowerShell. Same seam ``core/config_audit/collectors/
    windows.py`` uses, and for the same reason.
    """
    executor = getattr(ctx, "executor", None)
    method = getattr(executor, capability, None)
    return method if callable(method) else None


#: PowerShell sentinels. Three outcomes a registry read has to keep apart: the
#: key is not there, the key is there and the value is not, and a value was
#: read. Collapsing the first two loses the distinction between "this setting
#: was never configured" and "this whole feature is absent", and collapsing
#: either into a read produces a verdict about a value nobody found.
_WIN_NOKEY = "CCURE::NOKEY"
_WIN_NOVALUE = "CCURE::NOVALUE"
_WIN_TYPE = "CCURE::TYPE::"
_WIN_VALUE = "CCURE::VALUE::"
_WIN_FAILED = "CCURE::FAILED"

#: ``RegistryValueKind`` → the vocabulary OVAL's ``registry_state/type`` uses.
_WIN_REG_TYPES = {
    "string": "reg_sz",
    "expandstring": "reg_expand_sz",
    "binary": "reg_binary",
    "dword": "reg_dword",
    "multistring": "reg_multi_sz",
    "qword": "reg_qword",
    "none": "reg_none",
    "unknown": "reg_none",
}


def _ps_quote(value: str) -> str:
    """Single-quote for PowerShell, doubling any quote inside."""
    return "'" + str(value).replace("'", "''") + "'"


def _probe_registry(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    """
    One registry value.

    A missing key or a missing value is ``collected([])`` — an *absence*, which
    is what ``check_existence`` is there to judge. Only a read that failed is
    ``failed()``, and that becomes ERROR rather than a verdict. Getting that
    boundary wrong is the whole class of defect this package exists to avoid:
    ``none_exist`` over an absence the scanner invented reads as a clean host.
    """
    entities = obj.get("entities") or {}
    hive = _entity_one(entities, "hive")
    key = _entity_one(entities, "key")
    name = _entity_one(entities, "name")
    if not hive or key is None:
        return ProbeResult.failed("the registry object names no hive or no key")

    # A registry_object with no `name` addresses the key itself. The content
    # measured here always names a value, and a key-existence probe is a
    # different read, so it is declined rather than answered with a guess.
    if name is None:
        return ProbeResult.failed(
            "the registry object names no value, which addresses the key itself "
            "rather than a value; this build reads values"
        )

    common = {"hive": hive, "key": key, "name": name}

    native = _win_native(ctx, "read_registry_value")
    if native is not None:
        try:
            value = native(hive, key, name)
        except Exception as exc:
            return ProbeResult.failed(
                f"the registry read failed: {type(exc).__name__}: {exc}"
            )
        if value is None:
            # Remote Registry cannot separate a missing key from a missing
            # value; both are an absence, which is the answer this returns.
            return ProbeResult.collected([])
        # No `type`: this transport returns the data and not its kind. The
        # entity is therefore omitted rather than guessed, and a state that
        # checks `type` evaluates to UNKNOWN — never to a verdict.
        return ProbeResult.collected([{**common, "value": str(value)}])

    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")

    path = f"{hive}\\{key}" if key else hive
    command = (
        "$ErrorActionPreference='SilentlyContinue'; "
        f"$p = 'Registry::' + {_ps_quote(path)}; "
        "$k = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue; "
        f"if ($k -eq $null) {{ Write-Output '{_WIN_NOKEY}' }} else {{ "
        f"  $n = {_ps_quote(name)}; "
        f"  if ($k.GetValueNames() -notcontains $n) {{ Write-Output '{_WIN_NOVALUE}' }} "
        "  else { "
        "    $t = $k.GetValueKind($n); $v = $k.GetValue($n); "
        "    if ($v -is [System.Array]) { $v = ($v -join [char]10) } "
        f"    Write-Output ('{_WIN_TYPE}' + $t); "
        f"    Write-Output ('{_WIN_VALUE}' + $v) }} }}"
    )
    out = runner.run(command, timeout=ctx.timeout)
    if not out.ok:
        return ProbeResult.failed(out.failure_detail(), raw=out.stderr or out.stdout)

    text = out.stdout or ""
    if _WIN_NOKEY in text or _WIN_NOVALUE in text:
        return ProbeResult.collected([])
    if _WIN_VALUE not in text:
        # The command succeeded and printed nothing this probe recognises.
        # Reading that as an absence would let `none_exist` pass on a read
        # that never happened.
        return ProbeResult.failed(
            "the registry read produced no result marker", raw=text[:400]
        )

    reg_type = ""
    for line in text.splitlines():
        if line.startswith(_WIN_TYPE):
            reg_type = _WIN_REG_TYPES.get(
                line[len(_WIN_TYPE) :].strip().lower(), "reg_sz"
            )
    value = text.split(_WIN_VALUE, 1)[1]
    item = {**common, "value": value.strip("\r\n")}
    if reg_type:
        item["type"] = reg_type
    return ProbeResult.collected([item], raw=text[:400])


# ── Audit policy ─────────────────────────────────────────────────────────────

#: OVAL entity name → the subcategory GUID `auditpol /r` reports. GUIDs rather
#: than display names because the display name is localised: on a German or
#: Japanese install "Credential Validation" is not that string, and a probe
#: matching on it would report every audit subcategory as not-configured on a
#: correctly configured host. The GUIDs are read from the target's own
#: `auditpol` output, so this table maps entity → GUID and nothing is assumed
#: about spelling.
_AUDIT_SUBCATEGORY_ALIASES = {
    # Measured against a live host: 27 of the 28 entities the DISA Windows 11
    # STIG names normalise directly from `auditpol`'s own subcategory text.
    # This is the one that does not — Windows calls it "Plug and Play Events".
    # Listed rather than guessed, and the direction is OVAL entity → the
    # host's normalised name.
    "pnp_activity": ("plug_and_play_events",),
}


def _normalise_audit_name(text: str) -> str:
    """``Other Logon/Logoff Events`` → ``other_logon_logoff_events``."""
    out = []
    for ch in str(text).strip().lower():
        out.append(ch if ch.isalnum() else "_")
    collapsed = "_".join(part for part in "".join(out).split("_") if part)
    return collapsed


#: `auditpol /r`'s Inclusion Setting → OVAL's vocabulary.
#:
#: Measured against a live Windows 11 Pro host: the column holds a *phrase* —
#: "No Auditing", "Success and Failure" — not the numeric code the API uses.
#: An earlier version of this table was keyed on "0".."3", which matched no row
#: at all, emptied the policy and turned all forty-three audit rules into
#: errors. Keyed on the normalised phrase, so spacing and case cannot break it.
_AUDIT_SETTINGS = {
    "no_auditing": "AUDIT_NONE",
    "success": "AUDIT_SUCCESS",
    "failure": "AUDIT_FAILURE",
    "success_and_failure": "AUDIT_SUCCESS_FAILURE",
}


def _collect_audit_policy(ctx: CollectionContext) -> Any:
    """
    The whole audit policy, once per audit.

    Forty-three rules read this on a Windows 11 STIG; running `auditpol` once
    per rule would be forty-three round trips for one listing.
    """
    runner = _runner(ctx)
    if not runner.available:
        return "no authenticated session to the target"
    command = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "$o = auditpol /get /category:* /r 2>$null; "
        f"if (-not $o) {{ Write-Output '{_WIN_FAILED}' }} else {{ $o }}"
    )
    out = runner.run(command, timeout=max(ctx.timeout, 60))
    if not out.ok or _WIN_FAILED in (out.stdout or ""):
        return f"auditpol could not be read: {out.failure_detail()}"

    policy: Dict[str, str] = {}
    for line in (out.stdout or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5 or parts[0].lower().startswith("machine name"):
            continue
        subcategory, guid, setting = parts[2], parts[3], parts[4]
        if not subcategory:
            continue
        value = _AUDIT_SETTINGS.get(_normalise_audit_name(setting))
        if value is None:
            # A phrase this build does not know is not translated into one it
            # does. The subcategory is then simply absent from the item, and a
            # state naming it evaluates to UNKNOWN rather than to a verdict.
            continue
        policy[_normalise_audit_name(subcategory)] = value
        if guid:
            policy[guid.strip().lower()] = value

    # The entities whose OVAL name is not the host's name for them.
    for entity, host_names in _AUDIT_SUBCATEGORY_ALIASES.items():
        for host_name in host_names:
            if host_name in policy:
                policy.setdefault(entity, policy[host_name])
                break
    return policy or "auditpol returned no subcategories"


def _probe_auditeventpolicysubcategories(
    ctx: CollectionContext, obj: Mapping[str, Any]
) -> ProbeResult:
    """
    The local audit policy, as one item whose entities are the subcategories.

    The object names nothing — there is exactly one audit policy — so the
    single item carries every subcategory the host reported. A subcategory the
    host did not report is simply not a key on the item, and the evaluator
    reads a missing entity as UNKNOWN rather than as a verdict.
    """
    policy = ctx.cached("__scap_auditpol__", lambda: _collect_audit_policy(ctx))
    if isinstance(policy, str):
        return ProbeResult.failed(policy)
    if not isinstance(policy, dict) or not policy:
        return ProbeResult.failed("the audit policy could not be established")
    return ProbeResult.collected([dict(policy)])


# ── Local security policy: password, lockout and user rights ─────────────────

#: OVAL's ``SE_*`` constant → the name `secedit` exports under
#: ``[Privilege Rights]``. Every constant in this table appears in the DISA
#: Windows 11 STIG V2R10; the mapping is the Windows API's own and is stable.
_USER_RIGHTS = {
    "SE_BACKUP_NAME": "SeBackupPrivilege",
    "SE_CREATE_GLOBAL_NAME": "SeCreateGlobalPrivilege",
    "SE_CREATE_PAGEFILE_NAME": "SeCreatePagefilePrivilege",
    "SE_CREATE_PERMANENT_NAME": "SeCreatePermanentPrivilege",
    "SE_CREATE_SYMBOLIC_LINK_NAME": "SeCreateSymbolicLinkPrivilege",
    "SE_CREATE_TOKEN_NAME": "SeCreateTokenPrivilege",
    "SE_DEBUG_NAME": "SeDebugPrivilege",
    "SE_DENY_BATCH_LOGON_NAME": "SeDenyBatchLogonRight",
    "SE_DENY_INTERACTIVE_LOGON_NAME": "SeDenyInteractiveLogonRight",
    "SE_DENY_NETWORK_LOGON_NAME": "SeDenyNetworkLogonRight",
    "SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME": "SeDenyRemoteInteractiveLogonRight",
    "SE_DENY_SERVICE_LOGON_NAME": "SeDenyServiceLogonRight",
    "SE_ENABLE_DELEGATION_NAME": "SeEnableDelegationPrivilege",
    "SE_IMPERSONATE_NAME": "SeImpersonatePrivilege",
    "SE_INTERACTIVE_LOGON_NAME": "SeInteractiveLogonRight",
    "SE_LOAD_DRIVER_NAME": "SeLoadDriverPrivilege",
    "SE_LOCK_MEMORY_NAME": "SeLockMemoryPrivilege",
    "SE_MANAGE_VOLUME_NAME": "SeManageVolumePrivilege",
    "SE_NETWORK_LOGON_NAME": "SeNetworkLogonRight",
    "SE_PROF_SINGLE_PROCESS_NAME": "SeProfileSingleProcessPrivilege",
    "SE_REMOTE_SHUTDOWN_NAME": "SeRemoteShutdownPrivilege",
    "SE_RESTORE_NAME": "SeRestorePrivilege",
    "SE_SECURITY_NAME": "SeSecurityPrivilege",
    "SE_SYSTEMTIME_NAME": "SeSystemtimePrivilege",
    "SE_SYSTEM_ENVIRONMENT_NAME": "SeSystemEnvironmentPrivilege",
    "SE_TAKE_OWNERSHIP_NAME": "SeTakeOwnershipPrivilege",
    "SE_TCB_NAME": "SeTcbPrivilege",
    "SE_TRUSTED_CREDMAN_ACCESS_NAME": "SeTrustedCredManAccessPrivilege",
}

#: Prefixes Windows puts in front of *built-in* principals when it resolves a
#: SID, and which the content does not write.
#:
#: Measured on a live host: `S-1-5-32-544` translates to
#: ``BUILTIN\Administrators`` and `S-1-5-19` to ``NT AUTHORITY\LOCAL
#: SERVICE``, while the DISA Windows 11 STIG compares `trustee_name` against
#: bare ``Administrators`` and ``LOCAL SERVICE``. Left qualified, every user-
#: right rule on a correctly configured host reports FAIL — a false finding
#: that looks exactly like a real one.
#:
#: Only these two are stripped. A genuinely qualified trustee the content does
#: write — ``RESTRICTED SERVICES\PrintSpoolerService`` — keeps its prefix, and
#: the content's own optional-prefix patterns (``^(?i)(.+\\)?Domain
#: Admins$``) match a domain account either way. Emitting both spellings under
#: one entity is not an option: `entity_check` defaults to "all", so a second
#: spelling would have to match too.
_TRUSTEE_AUTHORITIES = ("builtin\\", "nt authority\\")


def _bare_trustee(name: str) -> str:
    lowered = str(name or "").lower()
    for prefix in _TRUSTEE_AUTHORITIES:
        if lowered.startswith(prefix):
            return str(name)[len(prefix) :]
    return str(name)


_SEC_INI = "INI::"
_SEC_SID = "SID::"

#: Well-known SIDs whose *on-target* translation routinely fails, and the name
#: Windows documents for each.
#:
#: Translation is done on the target for a reason (see
#: ``_collect_security_policy``): a non-English install resolves its own group
#: names correctly, which a table could not. This does not replace that — it is
#: consulted **only** where the target returned nothing, so the on-target answer
#: always wins and the non-English property is preserved.
#:
#: The gap is real and not an edge case. ``S-1-5-83-0`` is the Hyper-V virtual
#: machines group, and Windows 11 grants it ``SeCreateSymbolicLinkPrivilege``
#: out of the box — but ``SecurityIdentifier.Translate`` throws for it unless
#: the Hyper-V management service is running. Measured on a real Windows 11 Pro
#: host, 22 Sep 2026: the right is held by ``*S-1-5-32-544,*S-1-5-83-0``, the
#: first resolved and the second did not.
#:
#: An item that carries no ``trustee_name`` cannot be compared against a state
#: that names one, so the comparison returned UNKNOWN and WN11-UR-000060
#: reported **ERROR on a host whose configuration is perfectly readable**. That
#: is the wrong answer twice over: it is not a product gap, and the rule has a
#: determinate verdict (DISA's automated content admits only ``""`` and
#: ``Administrators``, so a host also granting the Hyper-V group fails it —
#: the Hyper-V allowance lives in the STIG's manual check text, not the OVAL).
#:
#: A SID that is in neither the target's answer nor this table still yields an
#: item with no ``trustee_name``, and still reads UNKNOWN. That is deliberate:
#: naming a trustee we could not identify would assert something about the host
#: that nothing established, and substituting the SID string itself would
#: compare a SID against a group name and fail every rule it appears in.
_WELL_KNOWN_SIDS = {
    # Hyper-V. Holds SeCreateSymbolicLinkPrivilege on a stock Windows 11.
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    # The desktop window manager's group; holds several rights by default and
    # translates only intermittently.
    "S-1-5-90-0": "Window Manager\\Window Manager Group",
    # The user-mode driver framework host.
    "S-1-5-84-0-0-0-0-0": "NT AUTHORITY\\UMFD",
}


def _collect_security_policy(ctx: CollectionContext) -> Any:
    """
    Export the local security policy and user rights, once per audit.

    One `secedit` run covers password policy, lockout policy and all
    twenty-eight user rights. The export lands in ``$env:TEMP`` under a GUID
    name and is removed in the same command — this is the only write any probe
    in this module performs, and it is the shape the Phase 3 security-policy
    collector already established.

    SIDs are translated on the target in the same round trip. ``secedit``
    writes trustees as ``*S-1-5-32-544`` and the content compares against
    ``Administrators``; translating here rather than by table means a
    non-English install resolves correctly, which matching the group *name*
    would not.
    """
    runner = _runner(ctx)
    if not runner.available:
        return "no authenticated session to the target"
    command = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "$f = Join-Path $env:TEMP ('ccure_scap_' + [guid]::NewGuid().ToString() + '.inf'); "
        "secedit /export /areas SECURITYPOLICY USER_RIGHTS /cfg $f | Out-Null; "
        "if (-not (Test-Path -LiteralPath $f)) { "
        f"  Write-Output '{_WIN_FAILED}' }} else {{ "
        "  $lines = Get-Content -LiteralPath $f; "
        "  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue; "
        f"  foreach ($l in $lines) {{ Write-Output ('{_SEC_INI}' + $l) }} "
        "  $joined = ($lines -join [char]10); "
        "  $sids = [regex]::Matches($joined, '\\*(S-1-[0-9\\-]+)') | "
        "    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique; "
        "  foreach ($s in $sids) { "
        "    $n = ''; "
        "    try { $n = (New-Object System.Security.Principal.SecurityIdentifier($s))."
        "Translate([System.Security.Principal.NTAccount]).Value } catch { $n = '' } "
        f"    Write-Output ('{_SEC_SID}' + $s + '::' + $n) }} }}"
    )
    out = runner.run(command, timeout=max(ctx.timeout, 90))
    if not out.ok or _WIN_FAILED in (out.stdout or ""):
        return f"the security policy could not be exported: {out.failure_detail()}"

    ini: Dict[str, str] = {}
    sids: Dict[str, str] = {}
    for line in (out.stdout or "").splitlines():
        if line.startswith(_SEC_INI):
            body = line[len(_SEC_INI) :].strip()
            if not body or body.startswith((";", "#", "[")):
                continue
            key, sep, value = body.partition("=")
            if sep:
                ini[key.strip()] = value.strip()
        elif line.startswith(_SEC_SID):
            _, _, rest = line.partition(_SEC_SID)
            sid, _, display = rest.partition("::")
            if sid:
                sid = sid.strip()
                # The target's own answer wins wherever it gave one; the table
                # only fills a blank. See _WELL_KNOWN_SIDS for why a blank is
                # common and why an unknown SID is still left blank.
                sids[sid] = display.strip() or _WELL_KNOWN_SIDS.get(sid, "")
    if not ini:
        return "the exported security policy contained no settings"
    return {"ini": ini, "sids": sids}


def _security_policy(ctx: CollectionContext) -> Any:
    return ctx.cached("__scap_secpol__", lambda: _collect_security_policy(ctx))


def _as_number(text: Any) -> Optional[int]:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


#: ``secedit`` INI name → (OVAL entity, multiplier). OVAL's Windows schema
#: states these ages and windows in **seconds**; `secedit` exports the ages in
#: days and the lockout figures in minutes. Comparing the exported number
#: directly against the content's would report a 60-day maximum password age
#: as 60 seconds and fail a correctly configured host — a wrong verdict that
#: looks exactly like a right one.
_PASSWORD_POLICY_MAP = {
    "PasswordHistorySize": ("password_hist_len", 1),
    "MaximumPasswordAge": ("max_passwd_age", 86400),
    "MinimumPasswordAge": ("min_passwd_age", 86400),
    "MinimumPasswordLength": ("min_passwd_len", 1),
    "PasswordComplexity": ("password_complexity", 1),
    "ClearTextPassword": ("reversible_encryption", 1),
    # OVAL's passwordpolicy_item is wider than its name: it carries the LSA
    # anonymous SID/name translation flag too, which WN11-SO-000140 reads.
    # Without it that rule collected an item the state could not be compared
    # against and reported ERROR — correct, but avoidable.
    "LSAAnonymousNameLookup": ("anonymous_name_lookup", 1),
}

_LOCKOUT_POLICY_MAP = {
    "LockoutBadCount": ("lockout_threshold", 1),
    "LockoutDuration": ("lockout_duration", 60),
    "ResetLockoutCount": ("lockout_observation_window", 60),
    "ForceLogoffWhenHourExpire": ("force_logoff", 1),
}

#: What Windows reports for "locked out until an administrator unlocks".
#: `secedit` writes -1; the Win32 API and the OVAL content both use the
#: unsigned sentinel.
_FOREVER = 4294967295


def _policy_items(ctx: CollectionContext, mapping) -> ProbeResult:
    policy = _security_policy(ctx)
    if isinstance(policy, str):
        return ProbeResult.failed(policy)
    ini = policy.get("ini") or {}
    item: Dict[str, Any] = {}
    for ini_name, (entity, multiplier) in mapping.items():
        if ini_name not in ini:
            # Absent from the export is not zero. Leaving the entity off the
            # item is what makes the evaluator answer UNKNOWN for it.
            continue
        number = _as_number(ini[ini_name])
        if number is None:
            continue
        if number < 0:
            item[entity] = str(_FOREVER)
        else:
            item[entity] = str(number * multiplier)
    if not item:
        return ProbeResult.failed(
            "the exported security policy carried none of the entities this "
            "object selects"
        )
    return ProbeResult.collected([item])


def _probe_passwordpolicy(
    ctx: CollectionContext, obj: Mapping[str, Any]
) -> ProbeResult:
    return _policy_items(ctx, _PASSWORD_POLICY_MAP)


def _probe_lockoutpolicy(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    return _policy_items(ctx, _LOCKOUT_POLICY_MAP)


def _probe_userright(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    """
    Who holds one user right.

    One item per trustee, which is what the OVAL schema describes and what
    ``check`` values such as "all" and "at least one" are written against. A
    right nobody holds is ``collected([])`` — an absence, and the correct
    reading for the many STIG rules of the form "no account shall hold this".
    """
    entities = obj.get("entities") or {}
    right = _entity_one(entities, "userright")
    if not right:
        return ProbeResult.failed("the object names no user right")
    ini_name = _USER_RIGHTS.get(right.strip().upper())
    if ini_name is None:
        return ProbeResult.failed(
            f"user right {right!r} has no known secedit name in this build"
        )

    policy = _security_policy(ctx)
    if isinstance(policy, str):
        return ProbeResult.failed(policy)
    ini = policy.get("ini") or {}
    sids = policy.get("sids") or {}

    if ini_name not in ini:
        # `secedit` omits a right nobody holds, and the reading is "no trustee"
        # rather than "could not look" — so this is data, not a failure.
        #
        # It is reported as **one item carrying an empty trustee**, not as zero
        # items, because that is what the content is written against. Every
        # userright rule in the DISA Windows 11 STIG uses
        # `check_existence="at_least_one_exists"`, and the rules that mean "this
        # right must not be assigned to anyone" — WN11-UR-000015, -000045 and
        # their siblings — compare against a state of `trustee_name equals ''`.
        # Returning zero items makes `at_least_one_exists` fail, so a host that
        # correctly grants the right to nobody is reported as violating the very
        # rule it satisfies. Measured against a real Windows 11 host: with zero
        # items, 0 of 25 userright rules could pass.
        return ProbeResult.collected([{"userright": right, "trustee_name": ""}])

    items = []
    for raw in str(ini[ini_name]).split(","):
        trustee = raw.strip()
        if not trustee:
            continue
        if trustee.startswith("*"):
            sid = trustee[1:]
            display = sids.get(sid, "")
            item = {"userright": right, "trustee_sid": sid}
            if display:
                item["trustee_name"] = _bare_trustee(display)
                item["trustee_qualified_name"] = display
        else:
            # secedit writes a bare name where it could not resolve a SID.
            item = {"userright": right, "trustee_name": trustee}
        items.append(item)
    return ProbeResult.collected(items)


_WMI_ROWS = "CCURE::WMI::"

#: The namespace ``SMBExecutor.wmi_query`` is bound to. A WQL query against any
#: other namespace — BitLocker's
#: ``root/cimv2/security/microsoftvolumeencryption``, for instance — cannot be
#: served by that method and falls through to PowerShell rather than being run
#: against the wrong namespace, which would answer confidently about the wrong
#: class.
_WMI_DEFAULT_NAMESPACE = "root/cimv2"


def _normalise_namespace(text: str) -> str:
    return str(text or "").strip().lower().replace("\\", "/").strip("/")


def _probe_wmi57(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    """
    One WQL query, as one item per row.

    The item carries a single ``result`` entity holding the row as a mapping,
    because that is the shape ``wmi57_state`` compares against: a ``record``
    whose ``<field name=…>`` children name columns. Field names are lower-cased
    on both sides — WMI answers ``DomainRole`` where the content writes
    ``domainrole``.

    A query that returns no rows is ``collected([])``: an absence, which is
    what ``check_existence`` judges. Only a query that could not be run is
    ``failed()``, and that is an ERROR rather than a verdict about the host.
    """
    entities = obj.get("entities") or {}
    namespace = _entity_one(entities, "namespace") or _WMI_DEFAULT_NAMESPACE
    wql = _entity_one(entities, "wql")
    if not wql:
        return ProbeResult.failed("the wmi57 object names no WQL query")

    native = _win_native(ctx, "wmi_query")
    if native is not None and _normalise_namespace(namespace) == _WMI_DEFAULT_NAMESPACE:
        try:
            rows = native(wql)
        except Exception as exc:
            return ProbeResult.failed(
                f"the WMI query failed: {type(exc).__name__}: {exc}"
            )
        return ProbeResult.collected(
            [
                {
                    "result": {
                        str(k).strip().lower(): "" if v is None else str(v)
                        for k, v in (row or {}).items()
                    }
                }
                for row in (rows or [])
            ]
        )

    runner = _runner(ctx)
    if not runner.available:
        return ProbeResult.failed("no authenticated session to the target")

    command = (
        "$ErrorActionPreference='Stop'; "
        "try { "
        f"  $r = @(Get-CimInstance -Namespace {_ps_quote(namespace)} "
        f"-Query {_ps_quote(wql)} -ErrorAction Stop); "
        "  $out = $r | ForEach-Object { $h=@{}; "
        "    $_.CimInstanceProperties | ForEach-Object { $h[$_.Name] = "
        "      $(if ($_.Value -eq $null) { '' } else { [string]$_.Value }) }; $h }; "
        f"  Write-Output ('{_WMI_ROWS}' + (ConvertTo-Json -InputObject @($out) "
        "-Compress -Depth 3)) "
        "} catch { Write-Output ('" + _WIN_FAILED + "::' + $_.Exception.Message) }"
    )
    out = runner.run(command, timeout=max(ctx.timeout, 60))
    text = out.stdout or ""
    if not out.ok or _WIN_FAILED in text:
        detail = (
            text.split(_WIN_FAILED + "::", 1)[-1].strip()
            if _WIN_FAILED in text
            else out.failure_detail()
        )
        return ProbeResult.failed(
            f"the WMI query failed: {detail}"[:300], raw=text[:400]
        )
    if _WMI_ROWS not in text:
        return ProbeResult.failed(
            "the WMI query produced no result marker", raw=text[:400]
        )

    payload = text.split(_WMI_ROWS, 1)[1].strip()
    try:
        rows = json.loads(payload) if payload else []
    except ValueError as exc:
        return ProbeResult.failed(
            f"the WMI result did not parse as JSON: {exc}", raw=payload[:400]
        )
    if isinstance(rows, dict):
        rows = [rows]
    items = []
    for row in rows or []:
        if not isinstance(row, Mapping):
            continue
        items.append(
            {
                "result": {
                    str(k).strip().lower(): "" if v is None else str(v)
                    for k, v in row.items()
                }
            }
        )
    return ProbeResult.collected(items, raw=payload[:400])


PROBES: Mapping[str, Callable[[CollectionContext, Mapping[str, Any]], ProbeResult]] = {
    "independent:textfilecontent54_object": _probe_textfilecontent,
    "unix:file_object": _probe_file,
    "linux:rpminfo_object": _probe_rpminfo,
    "linux:dpkginfo_object": _probe_dpkginfo,
    "independent:xmlfilecontent_object": _probe_xmlfilecontent,
    "independent:yamlfilecontent_object": _probe_yamlfilecontent,
    "linux:systemdunitproperty_object": _probe_systemdunitproperty,
    "independent:family_object": _probe_family,
    "unix:uname_object": _probe_uname,
    "independent:variable_object": _probe_variable,
    "windows:registry_object": _probe_registry,
    "windows:auditeventpolicysubcategories_object": (
        _probe_auditeventpolicysubcategories
    ),
    "windows:userright_object": _probe_userright,
    "windows:passwordpolicy_object": _probe_passwordpolicy,
    "windows:lockoutpolicy_object": _probe_lockoutpolicy,
    "windows:wmi57_object": _probe_wmi57,
}


def supported_object_types() -> Tuple[str, ...]:
    return tuple(sorted(PROBES))


def collect_object(ctx: CollectionContext, obj: Mapping[str, Any]) -> ProbeResult:
    """
    Run the probe for *obj*, memoised for the life of the audit.

    A probe that raises becomes a failed :class:`ProbeResult`, never an
    exception out of the collector and never an empty item list — a defect in
    our own probe must not read as "the host has none of these".
    """
    object_type = str(obj.get("type") or "")
    probe = PROBES.get(object_type)
    if probe is None:
        return ProbeResult.failed(
            f"no probe implements OVAL object type {object_type!r}"
        )

    memo = _memo(ctx)
    key = f"obj:{object_type}:{_signature(obj)}"
    if key in memo:
        return memo[key]
    try:
        result = probe(ctx, obj)
    except Exception as exc:  # a defect in our probe, not a fact about the host
        result = ProbeResult.failed(
            f"the {object_type} probe raised {type(exc).__name__}: {exc}"
        )
    memo[key] = result
    return result


def _signature(obj: Mapping[str, Any]) -> str:
    """A stable key for the memo, from the entities and behaviours only."""
    import json

    return json.dumps(
        {"e": obj.get("entities") or {}, "b": obj.get("behaviors") or {}},
        sort_keys=True,
        default=str,
    )
