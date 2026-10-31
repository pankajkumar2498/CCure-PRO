"""
The vulnerability-intelligence connection has no password in the source (config.py).

VulnIntelConfig.PASSWORD used to fall back to a literal, so a deployment that
never set VULN_DB_PASSWORD connected with a password published in the
repository. Now an unset password is an explicit configuration problem: the
URL is still built (importing config never fails), the probe says so at ERROR
instead of degrading quietly to the bundled snapshot, and every path that
actually connects refuses with the name of the missing setting.
"""

import logging
import os
import subprocess
import sys

import pytest

from config import VulnIntelConfig, VulnIntelConfigError
from testpaths import BACKEND_ROOT

KEYS = (
    "VULNERABILITY_INTEL_DATABASE_URL",
    "DATABASE_URL",
    "VULN_DB_HOST",
    "VULN_DB_PORT",
    "VULN_DB_NAME",
    "VULN_DB_USER",
    "VULN_DB_PASSWORD",
)


@pytest.fixture
def clean_env(monkeypatch):
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(VulnIntelConfig, "PASSWORD", "")
    return monkeypatch


def _host(env, value="db"):
    # HOST is read at import; the environment says the URL is assembled.
    env.setenv("VULN_DB_HOST", value)
    env.setattr(VulnIntelConfig, "HOST", value)


def test_an_assembled_url_without_a_password_is_refused_by_name(clean_env):
    _host(clean_env)
    problem = VulnIntelConfig.configuration_problem()
    assert problem and "VULN_DB_PASSWORD" in problem
    with pytest.raises(VulnIntelConfigError, match="VULN_DB_PASSWORD is not set"):
        VulnIntelConfig.require_database_url()
    # the URL is still built, with no password in it
    assert "@db:" in VulnIntelConfig.database_url()
    assert ":@" not in VulnIntelConfig.database_url()


def test_a_configured_password_is_used_and_never_reported(clean_env):
    _host(clean_env)
    clean_env.setattr(VulnIntelConfig, "PASSWORD", "s3cret-value")
    assert VulnIntelConfig.configuration_problem() is None
    assert ":s3cret-value@db:" in VulnIntelConfig.require_database_url()


def test_an_explicit_url_carries_its_own_credentials(clean_env):
    clean_env.setenv("VULNERABILITY_INTEL_DATABASE_URL", "postgresql://u@h/vuln_intel")
    assert VulnIntelConfig.require_database_url() == "postgresql://u@h/vuln_intel"


def test_a_shared_database_url_needs_nothing_more(clean_env):
    clean_env.setenv("DATABASE_URL", "postgresql://u:p@h/app")
    assert VulnIntelConfig.require_database_url() == "postgresql://u:p@h/app"


def test_no_configuration_at_all_is_refused(clean_env):
    with pytest.raises(
        VulnIntelConfigError, match="No vulnerability-intelligence database"
    ):
        VulnIntelConfig.require_database_url()


def test_the_problem_text_holds_no_value(clean_env):
    clean_env.setenv("VULN_DB_HOST", "db")
    clean_env.setenv("VULN_DB_USER", "admin-user-xyz")
    assert "admin-user-xyz" not in VulnIntelConfig.configuration_problem()


def test_the_probe_reports_a_configuration_fault_at_error(clean_env, caplog):
    from core import vuln_intel

    clean_env.setenv("VULN_DB_HOST", "db")
    vuln_intel.get_vuln_engine.cache_clear()
    try:
        with caplog.at_level(logging.ERROR, logger=vuln_intel.logger.name):
            assert vuln_intel.can_connect_vuln_db() is False
        assert any("VULN_DB_PASSWORD" in r.getMessage() for r in caplog.records)
    finally:
        vuln_intel.get_vuln_engine.cache_clear()


def test_no_password_literal_remains_in_the_source():
    source = (BACKEND_ROOT / "config.py").read_text(encoding="utf-8")
    assert "ccure_admin_2026" not in source


def test_importing_config_without_any_environment_does_not_fail():
    env = {k: v for k, v in os.environ.items() if k not in KEYS and k != "PGPASSWORD"}
    env["SKIP_DOTENV_LOAD"] = "1"
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import config; print(repr(config.VulnIntelConfig.PASSWORD))",
        ],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "''"
