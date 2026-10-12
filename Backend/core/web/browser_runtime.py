"""Select the supported browser channel for web scanning.

The release image sets CCURE_BROWSER_CHANNEL=chrome and installs authenticated,
fixed Chrome Stable. An unset channel preserves Playwright's default for local
development. An unreviewed channel must fail rather than silently fall back.
"""

import os


def launch_options():
    channel = os.getenv("CCURE_BROWSER_CHANNEL") or None
    if channel not in (None, "chrome"):
        raise ValueError("CCURE_BROWSER_CHANNEL must be unset or chrome")
    return {"channel": channel}
