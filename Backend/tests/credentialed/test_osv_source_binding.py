"""
OSV advisories bind to the package they name, and a range-less row proves nothing.

Two false-positive classes found on an Ubuntu 24.04 desktop (10.180.6.45,
13 Oct 2026), both reported as "Confirmed, QoD 97":

* **Name binding.** Distribution advisories name the *source* package. The
  matcher guessed it by stripping ``python3-``/``lib`` from the binary name,
  so python3-git (GitPython, source python-git) drew Git's advisories —
  CVE-2024-32002 among them, Critical, while the installed git
  1:2.43.0-1ubuntu7.3 is past its fix. ~48 findings across python3-git,
  -cups, -systemd, -libvirt and -cairo.
* **Withdrawn advisories.** UBUNTU-CVE-2024-3094 was withdrawn in July 2025.
  The sync skipped it but never deleted what an earlier run had stored, so its
  affected rows lingered with no ranges, and the matcher read "no range" as
  affected: the xz backdoor reported against the safe 5.6.1+really5.4.5 build.
  4,175 withdrawn Ubuntu/Debian advisories were still stored.
"""

from __future__ import annotations

import json
import zipfile

import pytest
from engines.credentialed.linux_collector import (
    _attach_dpkg_sources,
    _parse_dpkg_output,
)
from engines.credentialed.vuln_matcher import VulnMatcher


def _matcher(sources: dict[str, str] | None = None) -> VulnMatcher:
    matcher = VulnMatcher.__new__(VulnMatcher)
    matcher._package_sources = dict(sources or {})
    matcher._osv_rows_without_range = 0
    return matcher


# ── the collector records the source package ─────────────────────────────────

DPKG_L = """\
Desired=Unknown/Install/Remove/Purge/Hold
||/ Name            Version                       Architecture Description
+++-===============-=============================-============-==========
ii  python3-git     3.1.37-3                      all          Python Git Library
ii  git             1:2.43.0-1ubuntu7.3           amd64        fast, scalable
ii  libwine:amd64   9.0~repack-4build3            amd64        Windows API
ii  xz-utils        5.6.1+really5.4.5-1ubuntu0.3  amd64        XZ-format compression
"""

DPKG_QUERY = (
    "python3-git\tpython-git\n"
    "git\tgit\n"
    "libwine:amd64\twine\n"
    "xz-utils\txz-utils\n"
)


def test_each_package_carries_its_source():
    packages = _parse_dpkg_output(DPKG_L)
    _attach_dpkg_sources(packages, DPKG_QUERY)
    sources = {p["name"]: p.get("source") for p in packages}
    assert sources == {
        "python3-git": "python-git",
        "git": "git",
        "libwine": "wine",
        "xz-utils": "xz-utils",
    }


def test_a_package_the_query_missed_has_no_source_rather_than_a_guess():
    packages = _parse_dpkg_output(DPKG_L)
    _attach_dpkg_sources(packages, "git\tgit\n")
    assert "source" not in next(p for p in packages if p["name"] == "python3-git")
    _attach_dpkg_sources(packages, "")  # dpkg-query unavailable
    assert next(p for p in packages if p["name"] == "git")["source"] == "git"


# ── the matcher binds by source ──────────────────────────────────────────────


def test_a_recorded_source_is_the_only_name_matched():
    matcher = _matcher({"python3-git": "python-git", "libwine": "wine"})
    assert matcher._osv_names_for("python3-git") == ["python-git"]
    assert "git" not in matcher._osv_names_for("python3-git")
    # The heuristic was right for this one, and the source agrees.
    assert matcher._osv_names_for("libwine") == ["wine"]


def test_without_a_source_the_name_heuristics_still_apply():
    names = _matcher()._osv_names_for("libwine")
    assert "libwine" in names and "wine" in names


# ── an advisory's range is in the source's version space ─────────────────────
#
# Binding by source (above) made a second defect reachable: the range was
# compared against the *binary's* version. telnet 0.17+2.5-3ubuntu4.2 is built
# from inetutils 2:2.5-3ubuntu4.2; without the epoch it compared older than the
# fix 2:2.5-3ubuntu4.1, so the patched host was reported vulnerable. 53 such
# findings on 10.180.6.45, most of them aspnetcore-runtime-8.0 (source dotnet8,
# numbered 8.0.131-8.0.31-…).

TELNET = {"name": "telnet", "version": "0.17+2.5-3ubuntu4.2"}


def test_the_source_version_is_recorded():
    packages = [dict(TELNET), {"name": "git", "version": "1:2.43.0-1ubuntu7.3"}]
    _attach_dpkg_sources(packages, "telnet\tinetutils\t2:2.5-3ubuntu4.2\ngit\tgit\n")
    telnet, git = packages
    assert telnet["source"] == "inetutils"
    assert telnet["source_version"] == "2:2.5-3ubuntu4.2"
    # An older collector line with no version: the source, and nothing invented.
    assert git["source"] == "git" and "source_version" not in git


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _OsvConn:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _query, _params):
        return _Rows(self._rows)


def _osv_row(fixed):
    return {
        "cve_id": "CVE-2026-24061",
        "description": "inetutils telnetd",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "ecosystem": "Ubuntu:24.04:LTS",
        "package_name": "inetutils",
        "introduced": "0",
        "fixed": fixed,
    }


def _telnet_matcher(source_version):
    matcher = _matcher({"telnet": "inetutils"})
    matcher._package_source_versions = (
        {"telnet": source_version} if source_version else {}
    )
    matcher._osv_ecosystems = ["Ubuntu:24.04:LTS"]
    return matcher


def test_a_patched_package_is_not_reported_against_its_sources_fix():
    matcher = _telnet_matcher("2:2.5-3ubuntu4.2")
    found = matcher._batch_query_osv(
        _OsvConn([_osv_row("2:2.5-3ubuntu4.1")]),
        ["telnet"],
        {"telnet": TELNET["version"]},
    )
    assert found == []


def test_an_unpatched_package_is_reported_in_the_sources_numbering():
    matcher = _telnet_matcher("2:2.5-3ubuntu4.2")
    (finding,) = matcher._batch_query_osv(
        _OsvConn([_osv_row("2:2.5-3ubuntu4.3")]),
        ["telnet"],
        {"telnet": TELNET["version"]},
    )
    assert finding.package_name == "telnet"
    # Installed and fixed in one numbering, so the pair can be read.
    assert finding.installed_ver == "2:2.5-3ubuntu4.2"
    assert finding.fixed_ver == "2:2.5-3ubuntu4.3"


def test_without_a_source_version_the_binary_version_is_compared():
    matcher = _telnet_matcher(None)
    assert matcher._osv_version_for("telnet", "0.17+2.5-3ubuntu4.2") == (
        "0.17+2.5-3ubuntu4.2"
    )
    assert _matcher()._osv_version_for("git", "1:2.43.0") == "1:2.43.0"


# ── a row with no range establishes nothing ─────────────────────────────────


def test_a_row_with_no_range_is_not_a_match_and_is_counted():
    matcher = _matcher()
    row = {"introduced": None, "fixed": None}
    assert (
        matcher._installed_version_matches_osv("5.6.1+really5.4.5-1ubuntu0.3", row)
        is False
    )
    assert matcher._osv_rows_without_range == 1


@pytest.mark.parametrize(
    "row,installed,expected",
    [
        # Ubuntu's "affected, no fix released": introduced 0, open window.
        ({"introduced": "0", "fixed": None}, "2:1snap1-0ubuntu3", True),
        # The published fix for noble xz-utils; the rollback build is past it.
        (
            {"introduced": "0", "fixed": "5.4.5-0.3"},
            "5.6.1+really5.4.5-1ubuntu0.3",
            False,
        ),
        (
            {"introduced": "0", "fixed": "1:2.43.0-1ubuntu7.1"},
            "1:2.43.0-1ubuntu7.0",
            True,
        ),
    ],
)
def test_real_ranges_are_still_evaluated(row, installed, expected):
    assert _matcher()._installed_version_matches_osv(installed, row) is expected


# ── the sync removes withdrawn advisories it stored earlier ──────────────────


class _Cursor:
    def __init__(self, log):
        self.log = log
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.log.append((" ".join(sql.split()), params))
        if sql.strip().startswith("DELETE"):
            self.rowcount = len(params[0])

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class _Conn:
    def __init__(self):
        self.log = []

    def cursor(self):
        return _Cursor(self.log)

    def commit(self):
        pass


def _archive(tmp_path, records):
    path = tmp_path / "Ubuntu.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for record in records:
            zf.writestr(f"{record['id']}.json", json.dumps(record))
    return path


def test_a_withdrawn_advisory_is_deleted_not_merely_skipped(tmp_path, monkeypatch):
    from scripts.vuln import sync_osv

    flushed = []
    monkeypatch.setattr(sync_osv, "_flush", lambda conn, *rows: flushed.append(rows))
    live = {
        "id": "UBUNTU-CVE-2026-0001",
        "modified": "2026-10-01T00:00:00Z",
        "aliases": ["CVE-2026-0001"],
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "curl"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "8.5.0-2ubuntu10.16"},
                        ],
                    }
                ],
            }
        ],
    }
    withdrawn = {
        "id": "UBUNTU-CVE-2024-3094",
        "modified": "2025-07-16T07:47:12Z",
        "withdrawn": "2025-07-18T16:56:17Z",
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "xz-utils"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "5.4.5-0.3"}],
                    }
                ],
            }
        ],
    }
    conn = _Conn()
    counts = sync_osv.sync_ecosystem(
        conn, _archive(tmp_path, [live, withdrawn]), "Ubuntu", False
    )

    deletes = [params for sql, params in conn.log if sql.startswith("DELETE FROM osv")]
    assert deletes == [(["UBUNTU-CVE-2024-3094"],)]
    assert counts["withdrawn_removed"] == 1
    assert counts["records"] == 1
    # The live advisory is still loaded, the withdrawn one is not.
    loaded_ids = [row[0] for batch in flushed for row in batch[0]]
    assert loaded_ids == ["UBUNTU-CVE-2026-0001"]
