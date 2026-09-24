"""
tests/reports/test_report_field_coverage.py
─────────────────────────────────────────────────────────────────────────────
The report-gap closure: three per-finding fields the generators dropped, and
three host-level readings no report has ever printed.

Every assertion here is about the same thing in a different costume — **a
report must never make an assessment look more complete than it was.** A
missing `has_exploit` is not "no exploit exists"; a control nobody read is not
a pass; a host whose package collection failed is not a clean host; a listener
whose reachability was never established is neither exposed nor filtered.

These tests are deliberately free of database, TestClient and fixtures. They
drive `build_scan_report`, the CSV writer and the PDF's own flowable builders
directly, so they run against a scratch database that nothing in them touches.
"""

from testpaths import BACKEND_ROOT

import csv
import sys

import pytest

sys.path.insert(0, str(BACKEND_ROOT))

from reporting.csv_generator import (  # noqa: E402
    INTEL_HEADERS,
    NETWORK_HEADERS,
    REMEDIATION_HEADERS,
    generate_scan_csv,
)
from reporting.host_assessment import (  # noqa: E402
    ListenerExposure,
    exposure_sentence,
    host_assessments,
)
from scans.finding_normalizer import build_scan_report  # noqa: E402


HOST = "10.0.0.5"

CPE = [
    {
        "vendor": "postgresql",
        "product": "postgresql",
        "versionEndExcluding": "9.6.6",
        "cpe23Uri": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    }
]

SERVICE = {
    "port": 5432,
    "protocol": "tcp",
    "service": "postgresql",
    "product": "PostgreSQL DB",
    "version": "9.6.2",
}


def _cve(**extra):
    base = {
        "cve_id": "CVE-2017-7546",
        "title": "PostgreSQL Authentication Bypass",
        "description": "Empty password accepted.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_v3_score": 9.8,
        "affected_software": CPE,
        "port": 5432,
    }
    base.update(extra)
    return base


def _payload(cves, credentialed_report=None):
    host = {
        "ip_address": HOST,
        "hostname": "db-01",
        "os_guess": "Ubuntu 22.04",
        "open_ports": [SERVICE],
        "cves": cves,
    }
    if credentialed_report is not None:
        host["credentialed"] = True
        host["credentialed_report"] = credentialed_report
    return {
        "metadata": {"target": HOST, "scan_no": "SCAN-TEST-1"},
        "data": [host],
    }


def _one(cves):
    findings = build_scan_report(_payload(cves)).vulnerabilities
    assert len(findings) == 1
    return findings[0]


# ─────────────────────────────────────────────────────────────────────────────
# The normalizer carries what the generators need
# ─────────────────────────────────────────────────────────────────────────────


class TestFindingCarriesTheFields:
    def test_has_exploit_true_is_carried(self):
        assert _one([_cve(has_exploit=True)]).has_exploit is True

    def test_has_exploit_false_is_carried_as_false(self):
        # Not None. The feeds were consulted and answered; that is a real
        # negative and is worth saying.
        assert _one([_cve(has_exploit=False)]).has_exploit is False

    def test_absent_has_exploit_is_none_and_never_false(self):
        """
        The single most important assertion in this file.

        `bool(finding_dict.get("has_exploit"))` would make this False, and a
        report would then state that no public exploit exists for a CVE nothing
        ever looked up.
        """
        finding = _one([_cve()])
        assert finding.has_exploit is None
        assert finding.has_exploit is not False

    def test_priority_level_is_carried_verbatim(self):
        assert _one([_cve(priority_level="P1")]).priority_level == "P1"

    def test_absent_priority_is_empty_not_a_default_band(self):
        # "P4" is the matcher's own default for a record it scored; inventing
        # one here would put a priority on a finding nothing prioritised.
        assert _one([_cve()]).priority_level == ""

    def test_vendor_remediation_keeps_its_advisory_prefix(self):
        text = "SIEMENS SSA-123456: Update TIA Portal to V17 Update 4."
        assert _one([_cve(vendor_remediation=text)]).vendor_remediation == text

    def test_absent_vendor_remediation_is_empty(self):
        assert _one([_cve()]).vendor_remediation == ""


# ─────────────────────────────────────────────────────────────────────────────
# CSV — appended, never reordered
# ─────────────────────────────────────────────────────────────────────────────


def _write_csv(tmp_path, cves):
    path = str(tmp_path / "findings.csv")
    generate_scan_csv(_payload(cves), path, scan_type="network")
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.reader(handle))


class TestCsvCompatibility:
    def test_existing_columns_keep_their_exact_positions(self, tmp_path):
        """
        The compatibility contract, asserted by index rather than by name.

        A consumer reading this file by column number — a spreadsheet macro,
        most ETL — is what the append-only rule exists for. Adding the new
        columns to the end of NETWORK_HEADERS would have read better and pushed
        all nine remediation columns three places to the right.
        """
        rows = _write_csv(tmp_path, [_cve()])
        header = rows[0]

        assert header[: len(NETWORK_HEADERS)] == list(NETWORK_HEADERS)
        start = len(NETWORK_HEADERS)
        assert header[start : start + len(REMEDIATION_HEADERS)] == list(
            REMEDIATION_HEADERS
        )
        assert header[start + len(REMEDIATION_HEADERS) :] == list(INTEL_HEADERS)

        # Named anchors, so a future reorder fails here and not somewhere
        # downstream in a customer's spreadsheet.
        assert header[0] == "Host"
        assert header[NETWORK_HEADERS.index("In CISA KEV")] == "In CISA KEV"
        assert header[NETWORK_HEADERS.index("Status")] == "Status"
        assert header[len(NETWORK_HEADERS)] == "Remediation State"

    def test_new_columns_are_appended_at_the_very_end(self, tmp_path):
        header = _write_csv(tmp_path, [_cve()])[0]
        assert header[-3:] == ["Exploit Availability", "Priority", "Vendor Remediation"]

    def test_every_row_is_as_wide_as_the_header(self, tmp_path):
        rows = _write_csv(tmp_path, [_cve()])
        assert len(rows) > 1
        for row in rows[1:]:
            assert len(row) == len(rows[0])

    def test_existing_cells_keep_their_meaning(self, tmp_path):
        rows = _write_csv(tmp_path, [_cve(has_exploit=True, priority_level="P1")])
        header, row = rows[0], rows[1]
        assert row[header.index("Host")] == HOST
        assert row[header.index("CVE")] == "CVE-2017-7546"
        assert row[header.index("CVSS Score")] == "9.8"
        # The pre-existing KEV column is untouched by the new exploit column
        # beside it: they are different claims.
        assert row[header.index("In CISA KEV")] == "No"

    @pytest.mark.parametrize(
        "value,expected",
        [(True, "Yes"), (False, "No")],
    )
    def test_recorded_exploit_availability_renders(self, tmp_path, value, expected):
        rows = _write_csv(tmp_path, [_cve(has_exploit=value)])
        header, row = rows[0], rows[1]
        assert row[header.index("Exploit Availability")] == expected

    def test_unrecorded_exploit_availability_is_empty_never_no(self, tmp_path):
        """
        An empty cell is this file's established way of saying "not published".
        Writing "No" here would report a negative finding on the strength of
        never having looked, and the reader cannot tell that from a real one.
        """
        rows = _write_csv(tmp_path, [_cve()])
        header, row = rows[0], rows[1]
        assert row[header.index("Exploit Availability")] == ""

    def test_priority_and_vendor_remediation_round_trip(self, tmp_path):
        text = "CISA ICSA-24-100-01: Apply the vendor's firmware update."
        rows = _write_csv(
            tmp_path, [_cve(priority_level="P2", vendor_remediation=text)]
        )
        header, row = rows[0], rows[1]
        assert row[header.index("Priority")] == "P2"
        # Verbatim, prefix included.
        assert row[header.index("Vendor Remediation")] == text

    def test_missing_values_are_empty_not_zero_or_false(self, tmp_path):
        rows = _write_csv(tmp_path, [_cve()])
        header, row = rows[0], rows[1]
        for column in ("Exploit Availability", "Priority", "Vendor Remediation"):
            cell = row[header.index(column)]
            assert cell == ""
            assert cell not in ("0", "False", "false", "None", "P4")

    def test_web_export_is_untouched(self, tmp_path):
        """
        The web sheet is rendered by the /web-scans path and has no remediation
        block; it must not grow an intel block either. Altering an existing
        deliverable was not this package's business.
        """
        from reporting.csv_generator import WEB_HEADERS

        path = str(tmp_path / "web.csv")
        generate_scan_csv(_payload([_cve()]), path, scan_type="web")
        with open(path, newline="", encoding="utf-8-sig") as handle:
            header = next(csv.reader(handle))
        assert header == list(WEB_HEADERS)
        assert "Exploit Availability" not in header


# ─────────────────────────────────────────────────────────────────────────────
# PDF — the per-finding card
# ─────────────────────────────────────────────────────────────────────────────


def _flowable_text(flowables) -> str:
    """Every Paragraph string in a flowable list, including nested tables."""
    out = []

    def walk(item):
        if isinstance(item, (list, tuple)):
            for sub in item:
                walk(sub)
            return
        text = getattr(item, "text", None)
        if isinstance(text, str):
            out.append(text)
        rows = getattr(item, "_cellvalues", None)
        if rows:
            walk(rows)

    walk(flowables)
    return "\n".join(out)


def _card_text(cves):
    from reporting.pdf_generator import _build_styles, _finding_card

    return _flowable_text(_finding_card(_one(cves), _build_styles()))


class TestPdfPerFinding:
    def test_available_exploit_is_labelled_availability_not_exploitable(self):
        text = _card_text([_cve(has_exploit=True)])
        assert "Exploit availability:" in text
        assert "a public exploit exists" in text
        # The words the brief forbids, because `has_exploit` establishes none
        # of them about this host.
        lowered = text.lower()
        assert "host exploitable" not in lowered
        assert "confirmed exploitation" not in lowered

    def test_available_exploit_carries_the_host_caveat(self):
        text = _card_text([_cve(has_exploit=True)])
        assert "not a statement that this host is exploitable" in text

    def test_recorded_absence_of_an_exploit_is_stated(self):
        text = _card_text([_cve(has_exploit=False)])
        assert "no public exploit known" in text

    def test_unrecorded_exploit_availability_prints_no_claim(self):
        text = _card_text([_cve()])
        assert "Exploit availability:" not in text
        assert "no public exploit known" not in text

    def test_priority_is_the_backend_value_and_is_attributed(self):
        text = _card_text([_cve(priority_level="P1")])
        assert "Remediation priority:" in text
        assert "P1" in text
        assert "platform's own prioritisation" in text

    def test_absent_priority_prints_no_priority_line(self):
        assert "Remediation priority:" not in _card_text([_cve()])

    def test_vendor_remediation_is_verbatim_with_its_advisory_prefix(self):
        advisory = "SIEMENS SSA-661247: Update to V19 Update 2 or later."
        text = _card_text([_cve(vendor_remediation=advisory)])
        assert "Vendor remediation" in text
        assert "SIEMENS SSA-661247:" in text
        assert "Update to V19 Update 2 or later." in text

    def test_absent_vendor_remediation_prints_no_block(self):
        assert "Vendor remediation" not in _card_text([_cve()])


# ─────────────────────────────────────────────────────────────────────────────
# Host-level: hardening, collection failures, listener uncertainty
# ─────────────────────────────────────────────────────────────────────────────


def _credentialed_report(**extra):
    report = {"target": HOST}
    report.update(extra)
    return report


def _sections_text(**extra):
    from reporting.pdf_generator import _build_styles, _host_assessment_sections

    payload = _payload([_cve()], credentialed_report=_credentialed_report(**extra))
    records = host_assessments(payload)
    if not records:
        return ""
    return _flowable_text(_host_assessment_sections(records[0], _build_styles()))


class TestHardeningAudits:
    """
    The verdicts are produced by `core.tasks._credentialed_hardening_audits`,
    so the fixtures are built by calling it rather than by hand. A hand-written
    shape proves the renderer agrees with my memory of the producer; this
    proves it agrees with the producer.
    """

    @staticmethod
    def _audits(system_data, os_type="linux"):
        from core.tasks import _credentialed_hardening_audits

        return _credentialed_hardening_audits(system_data, os_type)

    def test_a_pass_renders_as_a_pass(self):
        audits = self._audits({"security_issues": [], "telnet_disabled": True})
        assert audits["telnet"]["status"] == "PASS"
        text = _sections_text(hardening_audits=audits)
        assert "Host hardening posture" in text
        assert "Telnet Status" in text
        assert "PASS" in text

    def test_a_fail_renders_with_the_collector_s_own_detail(self):
        audits = self._audits({"security_issues": [], "telnet_disabled": False})
        assert audits["telnet"]["status"] == "FAIL"
        text = _sections_text(hardening_audits=audits)
        assert "FAIL" in text
        assert "Telnet service/daemon is running" in text

    def test_an_unread_setting_is_not_assessed_and_never_a_pass(self):
        """
        The defect this whole tri-state exists to prevent. The SMB transport
        serves a subset of the Windows inventory, so an unread setting is a
        normal outcome — and printing PASS for it claims a control was
        satisfied on evidence that was never gathered.
        """
        audits = self._audits({"security_issues": []})
        assert audits["smbv1"]["status"] == "NOT_ASSESSED"
        text = _sections_text(hardening_audits=audits)
        assert "NOT ASSESSED" in text
        assert "did not read the setting" in text

    def test_the_lede_says_how_many_controls_were_not_read(self):
        audits = self._audits({"security_issues": []})
        text = _sections_text(hardening_audits=audits)
        assert "not assessed" in text
        assert "carries no verdict" in text

    def test_no_hardening_record_renders_no_section(self):
        assert "Host hardening posture" not in _sections_text(collection_errors={})


class TestCollectionErrors:
    def test_a_collection_failure_is_reported_with_its_reason(self):
        text = _sections_text(
            collection_errors={"packages": "dpkg-query: command not found"}
        )
        assert "Data this scan could not collect" in text
        assert "packages" in text
        assert "dpkg-query: command not found" in text

    def test_a_failure_is_stated_as_not_assessed_not_as_no_findings(self):
        text = _sections_text(collection_errors={"packages": "timed out"})
        assert "not assessed" in text
        assert "not an absence of findings" in text

    def test_an_unserved_item_is_separated_from_an_attempted_failure(self):
        """
        The SMB transport records what it structurally does not serve under an
        `item:` prefix. Folding that in with a section that was attempted and
        failed makes a transport's known limits read as a broken scan.
        """
        text = _sections_text(
            collection_errors={
                "packages": "connection reset",
                "item:tls_status": "not served by this transport",
            }
        )
        assert "Not served by the transport used" in text
        assert "tls_status" in text
        assert "nothing is claimed about them either way" in text

    def test_no_collection_error_fabricates_no_section(self):
        text = _sections_text(
            collection_errors={},
            exposure_summary={"listeners_total": 1, "listeners_exposed": 1},
        )
        assert "Data this scan could not collect" not in text
        assert "could not collect" not in text

    def test_an_incomplete_inventory_is_declared(self):
        text = _sections_text(
            collection_errors={"packages": "failed"}, inventory_complete=False
        )
        assert "software inventory for this host is incomplete" in text

    def test_an_unrecorded_inventory_flag_makes_no_claim(self):
        text = _sections_text(collection_errors={"packages": "failed"})
        assert "incomplete" not in text


class TestListenerExposure:
    """
    Exposure counts are produced by `engines.credentialed.coverage`, so the
    fixture is that function's own output.
    """

    @staticmethod
    def _summary(listeners, open_ports, network_scanned=True):
        from engines.credentialed.coverage import correlate_listeners

        _annotated, summary = correlate_listeners(
            listeners, open_ports, network_scanned=network_scanned
        )
        return summary

    def test_known_listeners_are_accounted_for(self):
        summary = self._summary(
            [{"port": 22, "protocol": "tcp", "address": "0.0.0.0"}],
            [{"port": 22, "protocol": "tcp", "state": "open"}],
        )
        text = _sections_text(exposure_summary=summary)
        assert "Listening service exposure" in text
        assert "confirmed reachable from the scanner" in text

    def test_an_undetermined_listener_is_named_and_not_resolved(self):
        """
        A listener outside the scanned port range had nothing established about
        it. Reading it as exposed invents attack surface; reading it as
        filtered invents a control.
        """
        summary = self._summary(
            [{"port": 9999, "protocol": "tcp", "address": "0.0.0.0"}],
            [{"port": 22, "protocol": "tcp", "state": "open"}],
        )
        assert summary["listeners_undetermined"] == 1
        text = _sections_text(exposure_summary=summary)
        assert "reachability was not established" in text
        assert "neither exposed nor filtered" in text

    def test_an_uncorrelated_pass_says_so(self):
        summary = self._summary(
            [{"port": 22, "protocol": "tcp", "address": "0.0.0.0"}],
            [],
            network_scanned=False,
        )
        text = _sections_text(exposure_summary=summary)
        assert "No network port scan ran alongside" in text

    def test_no_exposure_record_renders_no_section(self):
        assert "Listening service exposure" not in _sections_text(
            collection_errors={"packages": "failed"}
        )


class TestExposureSentence:
    def test_an_unrecorded_count_is_omitted_rather_than_printed_as_zero(self):
        """
        The line this replaces read "{exposed or 0} ... {host_only or 0} ...",
        which turned "nobody counted" into "none were found".
        """
        sentence = exposure_sentence(ListenerExposure(host_only=2))
        assert "2 bound to loopback" in sentence
        assert "0 confirmed reachable" not in sentence
        assert "confirmed reachable" not in sentence

    def test_all_four_categories_are_named_when_all_four_are_recorded(self):
        sentence = exposure_sentence(
            ListenerExposure(
                total=10, exposed=4, host_only=3, filtered=2, undetermined=1
            )
        )
        assert "10 listening service(s)" in sentence
        assert "4 confirmed reachable" in sentence
        assert "3 bound to loopback" in sentence
        assert "2 listening but filtered" in sentence
        assert "1 whose reachability was not established" in sentence

    def test_nothing_recorded_produces_no_sentence(self):
        assert exposure_sentence(ListenerExposure()) == ""


# ─────────────────────────────────────────────────────────────────────────────
# Scan parameters
# ─────────────────────────────────────────────────────────────────────────────


class TestScanConfiguration:
    @staticmethod
    def _rows(meta=None, summary=None):
        from reporting.pdf_generator import _scan_configuration

        findings = build_scan_report(_payload([_cve()]))
        return dict(
            _scan_configuration(meta or {}, summary or {}, findings, "vulnerability")
        )

    def test_recorded_parameters_are_reported(self):
        rows = self._rows(
            {
                "port_range": "1-1024",
                "discovery_profile": "BALANCED",
                "os_detection": "Enabled",
                "service_detection": "Enabled",
                "timing_template": "T3",
                "scanner": "nmap 7.94",
            }
        )
        assert rows["Port selection"] == "1-1024"
        assert rows["Discovery profile"] == "BALANCED"
        assert rows["OS fingerprinting"] == "Enabled"
        assert rows["Service detection"] == "Enabled"
        assert rows["Timing profile"] == "T3"
        assert rows["Scanner engine"] == "nmap 7.94"

    def test_an_unrecorded_parameter_says_so_rather_than_claiming_a_default(self):
        rows = self._rows({})
        for label in (
            "Port selection",
            "Discovery profile",
            "OS fingerprinting",
            "Service detection",
            "Timing profile",
        ):
            assert rows[label] == "Not recorded"

    def test_listener_counts_do_not_fabricate_a_zero(self):
        rows = self._rows({"listeners_host_only": 2})
        assert "Service exposure" in rows
        assert "0 confirmed reachable" not in rows["Service exposure"]

    def test_undetermined_listeners_reach_the_appendix(self):
        rows = self._rows(
            {
                "listeners_total": 5,
                "listeners_exposed": 3,
                "listeners_host_only": 1,
                "listeners_undetermined": 1,
            }
        )
        assert "1 whose reachability was not established" in rows["Service exposure"]

    def test_no_listener_counts_means_no_exposure_row(self):
        assert "Service exposure" not in self._rows({})


# ─────────────────────────────────────────────────────────────────────────────
# The walk that finds the records
# ─────────────────────────────────────────────────────────────────────────────


class TestHostAssessmentWalk:
    def test_a_record_nested_under_phase_data_is_found(self):
        payload = {
            "_phase_data": [
                {
                    "credentialed_report": {
                        "target": "10.0.0.9",
                        "collection_errors": {"packages": "failed"},
                    }
                }
            ]
        }
        records = host_assessments(payload)
        assert [r.host for r in records] == ["10.0.0.9"]

    def test_a_record_stored_under_options_is_found(self):
        payload = {
            "options": {
                "credentialed_report": {
                    "target": "10.0.0.8",
                    "collection_errors": {"services": "denied"},
                }
            }
        }
        assert [r.host for r in host_assessments(payload)] == ["10.0.0.8"]

    def test_the_same_report_stored_twice_is_not_listed_twice(self):
        """
        A multi-host credentialed scan stores the first host's report once as
        `report` and once inside `reports`, so a plain walk returns it twice
        and the posture table would print that host's controls twice over.
        """
        record = {"target": "10.0.0.7", "collection_errors": {"packages": "failed"}}
        payload = {"report": record, "reports": [record]}
        assert len(host_assessments(payload)) == 1

    def test_one_host_s_failures_are_never_attributed_to_another(self):
        payload = {
            "reports": [
                {"target": "10.0.0.1", "collection_errors": {"packages": "a"}},
                {"target": "10.0.0.2", "collection_errors": {"services": "b"}},
            ]
        }
        by_host = {r.host: r for r in host_assessments(payload)}
        assert [f.section for f in by_host["10.0.0.1"].collection_failures] == [
            "packages"
        ]
        assert [f.section for f in by_host["10.0.0.2"].collection_failures] == [
            "services"
        ]

    def test_a_payload_with_no_credentialed_pass_yields_nothing(self):
        assert host_assessments(_payload([_cve()])) == []


# ─────────────────────────────────────────────────────────────────────────────
# The GAP-15 export dataset
# ─────────────────────────────────────────────────────────────────────────────


class TestFindingExportColumns:
    def test_the_two_stored_fields_are_appended_last(self):
        from reporting.exports import FINDING_EXPORT_COLUMNS as columns

        assert columns[-2:] == ("Exploit Availability", "Vendor Remediation")
        assert columns[0] == "Finding ID"
        assert columns[-4] == "Policy Name"
        assert columns[-3] == "Configuration ID"

    def test_no_priority_column_is_emitted_here(self):
        """
        Deliberate asymmetry with the scan findings CSV. Priority is not stored
        on `asset_vulnerabilities`; the findings API derives it in a SQL CASE at
        read time. Emitting it here would be a second derivation, and the rule
        governing this whole field is that the report carries the backend's
        value rather than computing its own.
        """
        from reporting.exports import FINDING_EXPORT_COLUMNS as columns

        assert "Priority" not in columns
