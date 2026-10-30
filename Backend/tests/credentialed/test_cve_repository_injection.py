"""
The credentialed version matcher is handed its CVE repository (Group 3): the
vulnerability-intelligence database — an engine, the SQL construct and the
errors a failed query raises — is passed in, or is the one Audit's composition
root registers (``core/vuln_intel_repository.py``, ``ccure_audit/engine_ports.py``).
So the matcher imports no SQLAlchemy and builds no engine.
"""

import subprocess
import sys

import pytest
from engines.credentialed import vuln_matcher
from engines.credentialed.vuln_matcher import VulnMatcher
from testpaths import BACKEND_ROOT


class _Refused(Exception):
    pass


class _Connection:
    def __enter__(self):
        raise _Refused("the feed is down")

    def __exit__(self, *exc):
        return False


class _Engine:
    def connect(self):
        return _Connection()


class _Repository:
    engine = _Engine()
    errors = (_Refused,)

    @staticmethod
    def sql(statement):
        return statement


def test_importing_the_matcher_loads_no_sqlalchemy():
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import engines.credentialed.vuln_matcher; "
            "print('sqlalchemy' in sys.modules)",
        ],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "False"


def test_a_handed_repository_is_the_one_used():
    matcher = VulnMatcher(repository=_Repository())
    assert matcher.engine is _Repository.engine
    assert matcher._sql("SELECT 1") == "SELECT 1"
    assert matcher._db_errors == (_Refused,)


def test_the_repository_errors_are_what_a_failed_lookup_catches():
    matcher = VulnMatcher(repository=_Repository())
    findings = matcher._match_packages_batch({"openssl": "3.0.2"})
    assert findings == []
    assert any("the feed is down" in failure for failure in matcher._lookup_failures)


def test_without_one_the_registered_repository_is_used():
    from core.vuln_intel_repository import REPOSITORY

    assert vuln_matcher.registered_cve_repository() is REPOSITORY
    assert VulnMatcher().repository is REPOSITORY


def test_none_registered_and_none_handed_in_is_refused(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "_cve_repository", None)
    with pytest.raises(vuln_matcher.CveRepositoryMissing):
        VulnMatcher()
