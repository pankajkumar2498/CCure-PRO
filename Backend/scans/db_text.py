"""
Text that is safe to hand to PostgreSQL.

Network probes return whatever the target sends: an SNMP agent's OctetString,
a service banner, a TLS certificate field. Any of them can carry NUL or other
C0 control bytes. PostgreSQL refuses NUL outright — psycopg2 raises
``ValueError: A string literal cannot contain NUL (0x00) characters`` for a
text parameter, and JSONB rejects ``\\u0000`` — so one such byte anywhere in a
host record aborts the statement that carries it.

The phase payload was already cleaned before it reached JSONB. The finding
sync was not: it received the raw host records, so a single NUL in one SNMP
evidence line aborted the whole sync, the asynchronous retry failed the same
way, and every finding the scan produced was lost while the scan still read
"complete" (13 Oct 2026, scans of 10.180.6.45).

Tab, line feed and carriage return are kept: evidence is multi-line text.
"""

from __future__ import annotations

from typing import Any

#: C0 control characters PostgreSQL text/JSONB will not store or that only
#: ever appear as binary noise in probe output. Tab, LF and CR are kept.
UNSAFE_DB_CHARS = {
    codepoint: None for codepoint in range(32) if codepoint not in (9, 10, 13)
}


def clean_db_text(value: str) -> str:
    """Remove the characters in :data:`UNSAFE_DB_CHARS` from one string."""
    return value.translate(UNSAFE_DB_CHARS)


def sanitize_for_db(value: Any) -> Any:
    """
    Return a cleaned copy of *value*.

    Dict keys are cleaned as well as values, bytes are decoded as UTF-8 with
    replacement, and tuples and sets become lists — the shapes JSONB stores.
    """
    if isinstance(value, str):
        return clean_db_text(value)
    if isinstance(value, bytes):
        return clean_db_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, dict):
        return {
            sanitize_for_db(key): sanitize_for_db(item) for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_db(item) for item in value]
    return value


def sanitize_for_db_in_place(value: Any) -> Any:
    """
    Clean every string inside *value*, mutating dicts and lists in place.

    The asset sync annotates and reads the host records it is given, and its
    callers hold references to the same objects, so the records are cleaned
    where they are rather than replaced with copies. Returns *value* for
    convenience; a bare string or bytes value is returned cleaned, because a
    string cannot be changed in place.
    """
    if isinstance(value, (str, bytes)):
        return sanitize_for_db(value)
    if isinstance(value, dict):
        for key in list(value.keys()):
            item = value[key]
            cleaned_key = clean_db_text(key) if isinstance(key, str) else key
            cleaned_item = sanitize_for_db_in_place(item)
            if cleaned_key != key:
                del value[key]
            value[cleaned_key] = cleaned_item
        return value
    if isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = sanitize_for_db_in_place(item)
        return value
    if isinstance(value, (tuple, set)):
        return [sanitize_for_db_in_place(item) for item in value]
    return value
