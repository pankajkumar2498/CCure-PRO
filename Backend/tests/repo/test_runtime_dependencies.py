"""
tests/repo/test_runtime_dependencies.py
─────────────────────────────────────────────────────────────────────────────
Guards against an environment that is stale relative to ``requirements.txt``.

Why this matters here
─────────────────────
``requirements.txt`` declared ``impacket==0.12.0`` from the Phase 12 commit that
added the SMB / Remote Registry / WMI transport (``4a88723``, 1 Sep 2026). The
worker virtualenv — ``Backend/.venv``, which
``scripts/scan/start_host_scanner_worker.ps1`` launches Celery from — was never
reinstalled afterwards, so it carried 44 of the 45 declared distributions with
impacket the only one absent.

The capability therefore could not run at all in the runtime that matters:
``SMBExecutor.__init__`` raises ``SMBConfigurationError`` before doing anything
when ``IMPACKET_AVAILABLE`` is False, so an estate of Windows client-edition
hosts — the exact reach gap Phase 12 exists to close — silently fell back to
WinRM or was not reached.

It survived for a day and two phases because the *developer's global* Python
had been given impacket by hand, so `tests/credentialed/test_smb_transport.py`
passed there while failing in the venv. A green suite in one interpreter said
nothing about the interpreter the worker uses. This test closes that: it runs
in whichever interpreter the suite runs in, so a stale environment fails it
wherever it is stale.

What it deliberately does NOT check
───────────────────────────────────
**Versions.** Only presence. `pytest` and `python-docx` are both installed at
versions *newer* than their pins, and downgrading a test runner to satisfy a
pin is a larger and riskier change than the drift it would fix. The defect this
guards is a declared distribution that is entirely absent, which is the one that
turns a shipped capability into a runtime error.

It also resolves distribution names rather than import names on purpose:
``python-docx`` imports as ``docx`` and ``pysnmp-lextudio`` as ``pysnmp``, so
importing by the declared name would produce false failures. ``importlib.metadata``
answers the question actually being asked — is this distribution installed.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import List, Tuple

import pytest

from testpaths import BACKEND_ROOT

REQUIREMENTS = Path(BACKEND_ROOT) / "requirements.txt"

#: Environment markers this suite does not evaluate. A line carrying one may be
#: legitimately absent on this platform, so it is not a drift signal.
_MARKER = ";"


def _declared() -> List[Tuple[str, str]]:
    """Every distribution ``requirements.txt`` requires, as (name, raw line)."""
    out: List[Tuple[str, str]] = []
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-") or _MARKER in line:
            continue
        name = re.split(r"[<>=!~\[]", line)[0].strip()
        if name:
            out.append((name, line))
    return out


def test_requirements_txt_is_parseable_and_not_empty():
    """A parser that silently matches nothing would make every test below pass."""
    declared = _declared()
    assert len(declared) > 30, (
        f"only {len(declared)} requirements parsed from {REQUIREMENTS}; the "
        "parser is probably wrong, and a guard that checks nothing is worse "
        "than no guard"
    )
    names = {n.lower() for n, _ in declared}
    # Three that must always be there, so a silently-empty parse cannot pass.
    for anchor in ("impacket", "pyasn1", "sqlalchemy"):
        assert anchor in names, f"{anchor} missing from parsed requirements"


@pytest.mark.parametrize("name,line", _declared(), ids=lambda v: str(v))
def test_every_declared_distribution_is_installed(name, line):
    """
    A declared dependency that is not installed is a capability that cannot run.

    This is not a style check. ``impacket`` was declared and absent for a day,
    and the SMB transport it carries raised ``SMBConfigurationError`` on every
    Windows host the worker tried to reach over SMB.
    """
    try:
        version(name)
    except PackageNotFoundError:
        pytest.fail(
            f"'{name}' is declared in requirements.txt ({line!r}) but is not "
            f"installed in the interpreter running this suite. Reinstall with "
            f"`pip install -r {REQUIREMENTS}`. If this is the worker "
            f"virtualenv, the capability that dependency carries cannot run at "
            f"all."
        )


def test_the_smb_transport_dependency_is_importable():
    """
    The narrower, behavioural version of the above for the one that bit.

    ``importlib.metadata`` says a distribution is installed; only importing the
    modules the executor actually uses proves the transport can open a session.
    """
    from engines.credentialed import smb_executor

    assert smb_executor.IMPACKET_AVAILABLE is True, (
        "impacket is not importable, so SMBExecutor refuses every target. "
        "Phase 12's Windows-over-SMB reach is unavailable in this environment."
    )


def test_snmp_still_decodes_after_any_impacket_change():
    """
    impacket declares ``pyasn1>=0.2.3`` with no upper bound, and pyasn1 6
    removed ``pyasn1.compat.octets``, which ``pysnmp-lextudio`` 6.1.2 imports.

    The failure that follows is not an import error — it is an FDB table that
    decodes to one entry instead of three, so a switch's MAC table comes back
    nearly empty and the topology looks sparse rather than broken. That is why
    this asserts a multi-entry decode rather than merely that pysnmp imports.
    """
    from pyasn1.codec.ber import decoder, encoder
    from pysnmp.proto import rfc1902

    macs = [
        b"\x00\x1b\x21\x3c\x4d\x5e",
        b"\xac\xde\x48\x00\x11\x22",
        b"\x00\x50\x56\xc0\x00\x08",
    ]
    blob = b"".join(encoder.encode(rfc1902.OctetString(m)) for m in macs)

    decoded, rest = [], blob
    while rest:
        value, rest = decoder.decode(rest, asn1Spec=rfc1902.OctetString())
        decoded.append(bytes(value))

    assert decoded == macs, (
        "a three-entry FDB-shaped walk did not round-trip; pyasn1 and "
        "pysnmp-lextudio have diverged and SNMP topology will silently "
        "under-report"
    )
