"""
core/user_agent.py
──────────────────
Best-effort description of the client behind a session, for the "your active
sessions" screen.

`refresh_token_sessions.device_info` has existed since the table was created and
was never written to — every session rendered as an empty object, so the screen
could show a user two rows and nothing to tell them apart. A list of
indistinguishable sessions is worse than no list: it invites someone to revoke
the wrong one, or to conclude nothing is wrong because they cannot see that
anything is.

Scope, deliberately narrow
──────────────────────────
This does substring matching against a table a reviewer can read. It is not a
user-agent database and does not try to be — no dependency, no version
extraction, no device fingerprinting. `raw` is kept alongside the parsed labels
precisely because the parse is approximate: when the labels are wrong or say
"Unknown", the string that produced them is right there.

The User-Agent header is supplied by the client and is trivially forged, so
nothing here is evidence. It is a memory aid — "this is the laptop I logged in
on at the office" — and every security decision is made from the session row
itself, which the client does not control.
"""

from __future__ import annotations

# Order matters: the first match wins, and several of these strings appear in
# each other's user agents. Every Chromium browser says "Chrome", Edge says both
# "Chrome" and "Edg", and Safari is claimed by nearly everything — so the
# specific names have to be tested before the generic ones.
_BROWSERS = (
    ("Edg", "Edge"),
    ("OPR", "Opera"),
    ("Brave", "Brave"),
    ("Vivaldi", "Vivaldi"),
    ("SamsungBrowser", "Samsung Internet"),
    ("Firefox", "Firefox"),
    ("Chromium", "Chromium"),
    ("Chrome", "Chrome"),
    ("Safari", "Safari"),
    # Not browsers, but a session opened by one of these is exactly what a user
    # scanning the list should notice, so they are named rather than lumped in
    # with "Unknown".
    ("curl", "curl"),
    ("Wget", "Wget"),
    ("python-requests", "python-requests"),
    ("httpx", "httpx"),
    ("PostmanRuntime", "Postman"),
    ("insomnia", "Insomnia"),
)

# Android carries "Linux" in its user agent and iPadOS claims "Mac OS X", so
# again the specific cases come first.
_PLATFORMS = (
    ("Android", "Android"),
    ("iPhone", "iOS"),
    ("iPad", "iPadOS"),
    ("Windows NT 10.0", "Windows"),
    ("Windows", "Windows"),
    ("Mac OS X", "macOS"),
    ("Macintosh", "macOS"),
    ("CrOS", "ChromeOS"),
    ("Ubuntu", "Ubuntu"),
    ("Linux", "Linux"),
)

# The header is attacker-controlled and lands in a JSONB column that is read
# back into an API response. Bounded so a multi-kilobyte agent string cannot be
# used to inflate the session table or the response that lists it.
_MAX_RAW_LENGTH = 400


def _match(haystack: str, table: tuple[tuple[str, str], ...]) -> str:
    for needle, label in table:
        if needle.lower() in haystack:
            return label
    return "Unknown"


def describe(user_agent: str | None) -> dict:
    """
    Turn a User-Agent header into the dict stored on a session row.

    Always returns the same three keys, so the API response shape does not
    change depending on whether the header was present or parseable.
    """
    raw = (user_agent or "").strip()[:_MAX_RAW_LENGTH]
    if not raw:
        return {"browser": "Unknown", "platform": "Unknown", "raw": ""}

    lowered = raw.lower()
    return {
        "browser": _match(lowered, _BROWSERS),
        "platform": _match(lowered, _PLATFORMS),
        "raw": raw,
    }


def describe_request(request) -> dict:
    """`describe` for the User-Agent of a request, tolerating no request."""
    if request is None:
        return describe(None)
    try:
        return describe(request.headers.get("user-agent"))
    except Exception:
        return describe(None)
