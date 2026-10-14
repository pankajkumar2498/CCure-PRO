"""Select the dedicated disposable DB without exposing inherited credentials."""

import os
import sys
from urllib.parse import urlsplit, urlunsplit

source = urlsplit(os.environ["TEST_DATABASE_URL"])
os.environ["TEST_DATABASE_URL"] = urlunsplit(
    source._replace(path="/ccure_plugin_remediation_pytest_db")
)

import pytest

raise SystemExit(pytest.main(sys.argv[1:]))
