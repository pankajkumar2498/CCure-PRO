"""
tests/test_package_identity.py
─────────────────────────────────────────────────────────────────────────────
Resolving an installed package to the CPE identity NVD publishes it under.

Every case below came from a live Windows inventory of 193 packages. The two
failure modes are opposite and both were observed on that host: too strict and
Chrome's CVEs never surfaced on a machine running Chrome 138; too loose and
"Microsoft .NET Framework" resolved to ``golang:net``.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

from engines.credentialed.package_identity import (  # noqa: E402
    candidate_products,
    normalize_vendor,
    resolve_identities,
    version_space_contains,
)


def test_publisher_normalizes_to_a_cpe_vendor():
    assert normalize_vendor("Google LLC") == "google"
    assert normalize_vendor("Siemens AG") == "siemens"
    assert normalize_vendor("Oracle Corporation") == "oracle"
    assert normalize_vendor("JetBrains s.r.o.") == "jetbrains"
    assert normalize_vendor("AnyDesk Software GmbH") == "anydesk"
    assert normalize_vendor("") == ""


def test_product_candidates_drop_vendor_version_and_edition_noise():
    assert "chrome" in candidate_products("Google Chrome", "google")
    assert "visual_studio" in candidate_products(
        "Visual Studio Community 2022", "microsoft"
    )
    assert "nmap" in candidate_products("Nmap 7.95", "nmap")
    assert "user_management_component" in candidate_products(
        "User Management Component", "siemens"
    )


def test_publisher_corroborated_identity_is_preferred():
    """The publisher agreeing with the CPE vendor is the strongest signal there is."""
    resolved = resolve_identities(
        [{"name": "Google Chrome", "vendor": "Google LLC"}],
        {"chrome": [("google", "chrome"), ("bogusvendor", "chrome")]},
    )
    assert resolved["Google Chrome"] == [("google", "chrome")]


def test_a_fragment_never_resolves_without_the_publisher_agreeing():
    """
    Observed for real: "Microsoft .NET Framework 4.7.2 Targeting Pack" matched
    ``golang:net`` and "Microsoft ASP.NET Core" matched ``centra:asp``. Both
    came from a single generic token, and both would have had Go's and Centra's
    version ranges compared against .NET's version numbers.
    """
    resolved = resolve_identities(
        [
            {
                "name": "Microsoft .NET Framework 4.7.2 Targeting Pack",
                "vendor": "Microsoft Corporation",
            }
        ],
        {"net": [("golang", "net")], "asp": [("centra", "asp")]},
    )
    assert resolved == {}


def test_a_distinctive_whole_name_resolves_without_the_publisher():
    """
    Windows registers WinSCP under "Martin Prikryl", which normalizes to
    nothing like the CPE vendor. The full name still identifies the product.
    """
    resolved = resolve_identities(
        [{"name": "WinSCP 6.5.6", "vendor": "Martin Prikryl"}],
        {"winscp": [("winscp", "winscp")]},
    )
    assert resolved["WinSCP 6.5.6"] == [("winscp", "winscp")]


# ─────────────────────────────────────────────────────────────────────────────
# Version-space agreement
# ─────────────────────────────────────────────────────────────────────────────

# Distributions read from the live CPE dictionary.
MYSQL_BOUNDS = ["1.0"] + ["5.6.48", "5.7.2", "5.1.48", "5.0.40", "8.0.1"] * 20
CHROME_BOUNDS = ["0.1"] + ["11.0", "53.0", "98.0", "140.0.7339.185", "150.0"] * 20
VISUAL_STUDIO_BOUNDS = ["2012"]
UMC_BOUNDS = ["2.15.1.1", "2.15.1.3", "2.15.2.1"]


def test_a_version_inside_the_published_range_is_assessed():
    """
    The space check answers one question — are both sides numbered the same way
    — and nothing else. Whether a version is old is the audit's job to report,
    not this check's job to filter.
    """
    assert version_space_contains("5.6.40", MYSQL_BOUNDS) is True
    assert version_space_contains("1.6.12.0", MYSQL_BOUNDS) is True


def test_a_release_number_is_not_compared_against_year_based_versions():
    """Visual Studio Build Tools 18.7.4 against a CPE numbered by year."""
    assert version_space_contains("18.7.4", VISUAL_STUDIO_BOUNDS) is False
    assert version_space_contains("2012", VISUAL_STUDIO_BOUNDS) is True


def test_a_version_inside_the_published_space_is_kept():
    assert version_space_contains("138.0.7204.184", CHROME_BOUNDS) is True
    assert version_space_contains("V2.12 Sp0 Upd0", UMC_BOUNDS) is True


def test_the_two_checks_divide_the_work():
    """
    Two different problems, two different signals. A companion package is
    identified by its *name* — "MySQL Installer" is not MySQL whatever its
    version says. A different numbering scheme is identified by the *version
    space* — 18.7.4 against year-based CPE versions. Using the version space
    for both meant trimming it to percentiles, which then also rejected
    software that was merely old.
    """
    from engines.credentialed.package_identity import is_companion_package

    # Companion: caught by name, before any version is compared.
    assert is_companion_package("MySQL Installer") is True
    # Scheme mismatch: caught by the version space.
    assert is_companion_package("Visual Studio Build Tools 2026") is False
    assert version_space_contains("18.7.4", VISUAL_STUDIO_BOUNDS) is False


def test_no_version_means_no_claim():
    assert version_space_contains("", CHROME_BOUNDS) is False
    assert version_space_contains("not-a-version", CHROME_BOUNDS) is False


# ─────────────────────────────────────────────────────────────────────────────
# Companion packages
# ─────────────────────────────────────────────────────────────────────────────


def test_an_installer_is_not_treated_as_the_product_it_installs():
    """
    "MySQL Installer" carries the installer's version (1.6.12) while MySQL
    Server is at 8.x. Mapping it to oracle:mysql compared two unrelated
    numbering schemes and reported server CVEs against software that is not the
    server.
    """
    from engines.credentialed.package_identity import is_companion_package

    assert is_companion_package("MySQL Installer") is True
    assert is_companion_package("Microsoft Visual C++ 2015 Redistributable") is True
    assert is_companion_package("Java Auto Updater") is True

    assert is_companion_package("MySQL Server 8.0") is False
    assert is_companion_package("Google Chrome") is False
    assert is_companion_package("User Management Component") is False


def test_companions_never_resolve_to_an_identity():
    resolved = resolve_identities(
        [{"name": "MySQL Installer", "vendor": "Oracle Corporation"}],
        {"mysql": [("oracle", "mysql")], "mysql_installer": [("oracle", "mysql")]},
    )
    assert resolved == {}


def test_merely_old_software_is_still_assessed():
    """
    The version-space check exists to catch a different *numbering scheme*, not
    to judge whether a version is current. Trimming the published range to the
    5th–95th percentile also withheld software that is simply out of date —
    which is exactly what an audit is for.
    """
    published = ["1.0"] + ["5.6.48", "5.7.2", "8.0.1"] * 20
    assert version_space_contains("4.0.1", published) is True
    assert version_space_contains("8.0.0", published) is True
