"""A privileged historical fixture cannot escape the vetted scratch target."""

import pytest
from audit_historical_support import validate_historical_target


@pytest.mark.parametrize(
    "target",
    [
        "postgresql://dba@elsewhere:5432/pytest_history",
        "postgresql://dba@db:5433/pytest_history",
        "postgresql://dba@db:5432/pytest_other",
        "postgresql://dba@db:5432/ccure_db",
        "postgresql://app@db:5432/pytest_history",
        "postgresql://dba@db:5432/pytest_history?host=elsewhere",
        "postgresql+psycopg2://dba@db:5432/pytest_history?hostaddr=192.0.2.1",
    ],
)
def test_historical_fixture_rejects_unsafe_or_mismatched_targets(target):
    with pytest.raises(AssertionError):
        validate_historical_target("postgresql://app@db:5432/pytest_history", target)


def test_historical_fixture_accepts_only_separate_credentials_on_the_same_scratch_target():
    target = validate_historical_target(
        "postgresql://app@db:5432/pytest_history",
        "postgresql://dba@db:5432/pytest_history",
    )
    assert target.database == "pytest_history" and target.username == "dba"
