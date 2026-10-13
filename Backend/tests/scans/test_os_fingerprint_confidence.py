"""
An OS named only by an Nmap fingerprint is never High confidence.

10.180.6.30 runs Windows 11 Pro, build 26300. Asset Discovery and both
unauthenticated audits reported "Microsoft Windows 10 1703" at High (stored as
90%): Nmap's accuracy scores the packet match, and its database cannot tell
those releases apart. High is kept for a host that states its own identity.
"""

import pytest
from engines.port.port_engine import fingerprint_os_confidence


@pytest.mark.parametrize(
    "accuracy,expected",
    [(100, "Medium"), (95, "Medium"), (90, "Medium"), (89, "Low"), (75, "Low")],
)
def test_a_fingerprint_tops_out_at_medium(accuracy, expected):
    assert fingerprint_os_confidence(accuracy) == expected
