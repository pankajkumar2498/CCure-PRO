"""
tests/credentialed/test_platform_scope.py
─────────────────────────────────────────────────────────────────────────────
A CVE published for one platform's build of a product is not a finding on a
host running another.

Scan #9 (10.180.6.30, Windows 11, 12 Oct 2026) reported 1,736 Google Chrome
CVEs; 410 of them were published for Chrome on Android, Mac, iOS, Linux or
ChromeOS. CVE-2025-14174 — a Mac-only flaw — sat in the executive report's
"known exploited, immediate action" table. The matcher read the product and
the version range and nothing that said which platform the record was about.

Every record and phrasing below is taken from that scan's data.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

from core.checks.platform_scope import (  # noqa: E402
    configuration_platforms,
    declared_platforms,
    describe_scope,
    host_platform,
    platforms_named_in,
    scope_excludes_host,
)

CHROME = "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
WINDOWS = "Microsoft Windows 11 Pro"


def _always(_match):
    return True


def _chrome(end_excluding, criteria=CHROME):
    return {
        "criteria": criteria,
        "vulnerable": True,
        "versionEndExcluding": end_excluding,
    }


def _running_on(*criteria):
    return {
        "operator": "OR",
        "negate": False,
        "cpeMatch": [{"criteria": c, "vulnerable": False} for c in criteria],
    }


# ── The host ────────────────────────────────────────────────────────────────


def test_a_host_os_string_is_placed_in_one_family():
    assert host_platform(WINDOWS) == "windows"
    assert host_platform("Ubuntu 24.04.1 LTS") == "linux"
    assert host_platform("Rocky Linux 9.8 (Blue Onyx)") == "linux"
    assert host_platform("Android 14 (Linux 5.15)") == "android"
    assert host_platform("Mac OS X 14.4") == "macos"


def test_a_host_that_cannot_be_placed_is_placed_nowhere():
    """Guessing would let a record be ruled out against the wrong platform."""
    assert host_platform("") == ""
    assert host_platform("Unknown") == ""
    # Not Apple's iOS: there is deliberately no bare "ios" token.
    assert host_platform("Cisco IOS 15.2(4)M") == ""
    # Two unrelated families named at once.
    assert host_platform("Windows Subsystem for Linux") == ""


# ── The CNA's description ───────────────────────────────────────────────────


def test_chromium_names_its_platform_before_prior_to():
    cases = {
        "Incorrect security UI in Google Chrome on Android prior to "
        "144.0.7559.59 allowed a remote attacker to spoof": ("android",),
        "Insufficient validation of untrusted input in Chrome for iOS in "
        "Google Chrome on iOS prior to 150.0.7871.47": ("ios",),
        "Out of bounds memory access in ANGLE in Google Chrome on Mac prior "
        "to 143.0.7499.110": ("macos",),
        "in Google Chrome on Linux and ChromeOS prior to 142.0.7444.59": (
            "linux",
            "chromeos",
        ),
        "in Google Chrome on Android, Linux, ChromeOS prior to 140.0.7339.127": (
            "android",
            "linux",
            "chromeos",
        ),
        "in Google Chrome on Mac,Windows prior to 148.0.7778.96": (
            "macos",
            "windows",
        ),
        "in Google Chrome on Linux, Mac, Windows, ChromeOS prior to 148.0": (
            "linux",
            "macos",
            "windows",
            "chromeos",
        ),
    }
    for description, expected in cases.items():
        assert platforms_named_in(description) == expected, description


def test_desktop_means_every_non_mobile_build():
    assert "windows" in platforms_named_in(
        "Inappropriate implementation in Google Chrome on Desktop prior to 140.0"
    )


def test_mozilla_says_only_affects():
    assert platforms_named_in(
        "This bug only affects Firefox on Windows. Other operating systems are "
        "unaffected."
    ) == ("windows",)
    assert platforms_named_in(
        "This vulnerability only affects Firefox for Android."
    ) == ("android",)


def test_a_description_that_names_no_platform_restricts_nothing():
    # A real Chromium record with the platform missing from its own template.
    assert (
        platforms_named_in(
            "Heap buffer overflow in WebRTC in Google Chrome on prior to "
            "148.0.7778.179 allowed a remote attacker"
        )
        == ()
    )
    assert (
        platforms_named_in(
            "Type confusion in V8 in Google Chrome prior to 140.0.7339.185"
        )
        == ()
    )
    # Mentioning an operating system is not restricting to it.
    assert platforms_named_in("A flaw in the Windows build tooling") == ()
    # One word that is not a platform voids the list.
    assert platforms_named_in("depends on a crafted page prior to load") == ()


# ── NVD's configuration ─────────────────────────────────────────────────────


def test_a_running_on_node_restricts_the_product():
    """CVE-2026-13843 as NVD publishes it: chrome AND running on iphone_os."""
    configurations = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("150.0.7871.47")]},
                _running_on("cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*"),
            ],
        }
    ]
    assert configuration_platforms(configurations, "google", "chrome", _always) == (
        "ios",
    )


def test_nvds_desktop_template_applies_on_windows():
    """CVE-2026-0906's configuration, which its own description contradicts."""
    configurations = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("144.0.7559.59")]},
                _running_on(
                    "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                    "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                ),
            ],
        },
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("144.0.7559.60")]},
                _running_on("cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"),
            ],
        },
    ]
    assert configuration_platforms(configurations, "google", "chrome", _always) == (
        "linux",
        "macos",
        "windows",
    )


def test_the_description_outranks_nvds_template():
    """The vendor is the authority on which of its builds carries a flaw."""
    assert declared_platforms(
        "Incorrect security UI in Google Chrome on Android prior to 144.0.7559.59",
        ("linux", "macos", "windows"),
    ) == ("android",)


def test_target_sw_pins_the_platform_without_a_running_on_node():
    configurations = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        _chrome(
                            "147.0.7727.101",
                            "cpe:2.3:a:google:chrome:*:*:*:*:*:android:*:*",
                        )
                    ],
                }
            ]
        }
    ]
    assert configuration_platforms(configurations, "google", "chrome", _always) == (
        "android",
    )


def test_a_configuration_with_no_platform_condition_restricts_nothing():
    configurations = [
        {"nodes": [{"operator": "OR", "cpeMatch": [_chrome("140.0.7339.185")]}]},
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("140.0.7339.185")]},
                _running_on("cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"),
            ],
        },
    ]
    assert configuration_platforms(configurations, "google", "chrome", _always) == ()


def test_an_unrecognised_platform_restricts_nothing():
    configurations = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("1.0")]},
                _running_on("cpe:2.3:o:haiku:haiku:-:*:*:*:*:*:*:*"),
            ],
        }
    ]
    assert configuration_platforms(configurations, "google", "chrome", _always) == ()


def test_only_configurations_covering_the_installed_version_count():
    """A Mac range the host's version is past says nothing about this host."""
    configurations = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("100.0")]},
                _running_on("cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"),
            ],
        },
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("200.0")]},
                _running_on("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"),
            ],
        },
    ]

    def below_200_only(match):
        return match.get("versionEndExcluding") == "200.0"

    assert configuration_platforms(
        configurations, "google", "chrome", below_200_only
    ) == ("windows",)


def test_nothing_to_read_restricts_nothing():
    for configurations in (None, [], "not a list", [{"nodes": []}]):
        assert (
            configuration_platforms(configurations, "google", "chrome", _always) == ()
        )


# ── The decision ────────────────────────────────────────────────────────────


def test_a_host_outside_the_scope_is_ruled_out_and_only_then():
    assert scope_excludes_host(("android",), WINDOWS) == "windows"
    assert scope_excludes_host(("macos", "windows"), WINDOWS) == ""
    assert scope_excludes_host((), WINDOWS) == ""
    assert scope_excludes_host(("android",), "Unknown") == ""


def test_scope_reads_as_a_list():
    assert describe_scope(("android",)) == "Android"
    assert describe_scope(("linux", "chromeos")) == "Linux and ChromeOS"
    assert describe_scope(("android", "linux", "chromeos")) == (
        "Android, Linux and ChromeOS"
    )


# ── Through the verifier ────────────────────────────────────────────────────


def _host(*cves, os_guess=WINDOWS):
    return {"ip_address": "10.180.6.30", "os_guess": os_guess, "cves": list(cves)}


def _package_finding(cve_id, description, **extra):
    return {
        "cve_id": cve_id,
        "severity": "High",
        "description": description,
        "package": "Google Chrome",
        "installed_version": "138.0.7204.184",
        "detection_method": "credentialed_package",
        "affected_software": [
            {
                "vendor": "google",
                "product": "chrome",
                "cpe_uri": CHROME,
                "version_end_excluding": "150.0.7871.47",
            }
        ],
        **extra,
    }


def test_another_platforms_record_is_withheld_with_its_reason():
    from core.checks.finding_normalizer import verify_host_findings

    result = verify_host_findings(
        _host(
            _package_finding(
                "CVE-2025-14174",
                "Out of bounds memory access in ANGLE in Google Chrome on Mac "
                "prior to 143.0.7499.110",
                in_kev=True,
            ),
            _package_finding(
                "CVE-2025-10585",
                "Type confusion in V8 in Google Chrome prior to 140.0.7339.185",
            ),
        )
    )

    assert [c["cve_id"] for c in result.verified] == ["CVE-2025-10585"]
    assert [s.identifier for s in result.suppressed] == ["CVE-2025-14174"]
    assert result.suppressed[0].reason == (
        "Ruled out: this record is published for macOS only, and this host "
        "runs Windows."
    )


def test_the_matchers_configuration_scope_is_honoured():
    """No platform in the prose; the matcher read it off NVD's configuration."""
    from core.checks.finding_normalizer import verify_host_findings

    finding = _package_finding(
        "CVE-2026-13843",
        "Insufficient validation of untrusted input in Chrome.",
        affected_platforms=["ios"],
    )
    result = verify_host_findings(_host(finding))
    assert result.verified == []
    assert "published for iOS only" in result.suppressed[0].reason


def test_the_platforms_own_host_keeps_the_finding():
    from core.checks.finding_normalizer import verify_host_findings

    android = _package_finding(
        "CVE-2026-0906",
        "Incorrect security UI in Google Chrome on Android prior to 144.0.7559.59",
    )
    result = verify_host_findings(_host(android, os_guess="Android 14"))
    assert [c["cve_id"] for c in result.verified] == ["CVE-2026-0906"]


def test_a_host_whose_platform_is_unknown_keeps_the_finding():
    """Absence of evidence is not evidence of absence."""
    from core.checks.finding_normalizer import verify_host_findings

    android = _package_finding(
        "CVE-2026-0906",
        "Incorrect security UI in Google Chrome on Android prior to 144.0.7559.59",
    )
    result = verify_host_findings(_host(android, os_guess=""))
    assert [c["cve_id"] for c in result.verified] == ["CVE-2026-0906"]


# ── The matcher records the scope ───────────────────────────────────────────


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _Conn:
    def __init__(self, rows, seen):
        self._rows, self._seen = rows, seen

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, params):
        self._seen.append(params)
        return _Rows(self._rows)


class _Engine:
    def __init__(self, rows):
        self.rows, self.seen = rows, []

    def connect(self):
        return _Conn(self.rows, self.seen)


def _matcher(rows):
    from engines.credentialed.vuln_matcher import VulnMatcher

    from core.vuln_intel_repository import REPOSITORY

    matcher = VulnMatcher.__new__(VulnMatcher)
    matcher.engine = _Engine(rows)
    # Built without __init__: the SQL construct and the errors the matcher
    # is handed by its repository (G3) are set the same way.
    matcher._sql = REPOSITORY.sql
    matcher._db_errors = REPOSITORY.errors
    return matcher


def _cve(cve_id, description, end_excluding="150.0"):
    from engines.credentialed.vuln_matcher import CredentialedCVE

    return CredentialedCVE(
        cve_id=cve_id,
        severity="High",
        cvss_score=8.8,
        description=description,
        package_name="Google Chrome",
        installed_ver="138.0.7204.184",
        matched_by="cpe",
        cpe_uri=CHROME,
        affected_software=[
            {
                "vendor": "google",
                "product": "chrome",
                "cpe_uri": CHROME,
                "version_end_excluding": end_excluding,
            }
        ],
    )


def test_the_matcher_reads_configurations_once_and_records_the_scope():
    ios = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [_chrome("150.0.7871.47")]},
                _running_on("cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*"),
            ],
        }
    ]
    matcher = _matcher([{"cve_id": "CVE-2026-13843", "configurations": ios}])
    findings = [
        _cve("CVE-2026-13843", "Insufficient validation in Chrome."),
        _cve("CVE-2026-0906", "UI spoof in Google Chrome on Android prior to 144.0"),
        _cve("CVE-2025-10585", "Type confusion in V8 in Google Chrome prior to 140.0"),
    ]

    matcher._attach_platform_scope(findings)

    assert [f.affected_platforms for f in findings] == [["ios"], ["android"], []]
    assert len(matcher.engine.seen) == 1
    assert matcher.engine.seen[0]["ids"] == [
        "CVE-2025-10585",
        "CVE-2026-0906",
        "CVE-2026-13843",
    ]
    assert matcher.to_report_format(findings[:1])[0]["affected_platforms"] == ["ios"]


def test_an_inclusive_bound_is_not_reported_as_a_fixed_version():
    """'Nmap through 7.99' was reported as fixed in 7.99."""
    matcher = _matcher([])
    assert matcher._row_fixed_version({"version_end_including": "7.99"}) == ""
    assert (
        matcher._row_fixed_version(
            {"version_end_excluding": "140.0.7339.185", "version_end_including": None}
        )
        == "140.0.7339.185"
    )
