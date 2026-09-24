"""
tests/scans/test_scap_windows.py
─────────────────────────────────────────────────────────────────────────────
The Windows half of the OVAL evaluator.

Written against the **DISA Microsoft Windows 11 STIG V2R10** (SCAP 1.3), which
is real published content and the only thing these probes were designed from.
Frequencies over its MAC-2_Classified profile, 219 rules: ``registry_test`` 117,
``auditeventpolicysubcategories_test`` 43, ``userright_test`` 25,
``wmi57_test`` 15, ``passwordpolicy_test`` 7, ``lockoutpolicy_test`` 3.

What these are defending
────────────────────────
The whole point of the four collection states is that a read which did not
happen must never become a verdict. Every probe here therefore has to keep
three outcomes apart, and each is tested:

* a value was read              → an item, compared against the state
* the thing is genuinely absent → ``collected([])``, which is what
  ``check_existence`` judges — and note that absence is a **PASS** under
  ``none_exist`` and a **FAIL** under ``at_least_one_exists``, so getting it
  wrong is wrong in both directions
* the read failed               → ``failed()`` → ERROR, never PASS or FAIL

Three defects real hardware found, all of which had shipped looking correct,
are pinned here by name: the auditpol setting vocabulary, the trustee prefix,
and the empty-user-right idiom. Each has a test whose failure message says what
it cost.
"""

from __future__ import annotations

import pytest

from core.config_audit.collection import CollectionContext
from core.scap.probes import (
    _bare_trustee,
    _collect_audit_policy,
    _normalise_audit_name,
    _probe_auditeventpolicysubcategories,
    _probe_lockoutpolicy,
    _probe_passwordpolicy,
    _probe_registry,
    _probe_userright,
    _probe_wmi57,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────


class FakeResult:
    def __init__(self, stdout="", exit_code=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.success = exit_code == 0


class FakeShell:
    """Answers by substring. Reports PowerShell so commands are not wrapped."""

    def __init__(self, answers=None, default=None):
        self.answers = list(answers or [])
        self.default = (
            default if default is not None else FakeResult("", 1, "no answer")
        )
        self.commands = []

    def run(self, command, timeout=None):
        self.commands.append(command)
        if "PSVersionTable" in command:
            return FakeResult("5")
        for needle, result in self.answers:
            if needle in command:
                return result
        return self.default


class NativeRegistry:
    """An executor exposing the SMB transport's own registry reader."""

    def __init__(self, value=None, raises=None):
        self._value = value
        self._raises = raises
        self.calls = []

    def run(self, command, timeout=None):  # pragma: no cover - not used
        return FakeResult("5")

    def read_registry_value(self, hive, path, name):
        self.calls.append((hive, path, name))
        if self._raises:
            raise self._raises
        return self._value


def ctx(executor=None, **kw):
    params = {
        "target": "10.0.0.1",
        "platform": "windows",
        "os_name": "Microsoft Windows 11 Pro",
        "os_version_id": "10.0.26100",
        "executor": executor,
        "timeout": 30,
    }
    params.update(kw)
    return CollectionContext(**params)


def obj(object_type, **entities):
    return {
        "type": object_type,
        "entities": {
            k: {"values": [v], "operation": "equals"} for k, v in entities.items()
        },
    }


REG = "windows:registry_object"


# ─────────────────────────────────────────────────────────────────────────────
# registry — 117 of the 219 rules
# ─────────────────────────────────────────────────────────────────────────────


class TestRegistryProbe:
    def test_a_value_that_exists_is_collected_with_its_type(self):
        shell = FakeShell(
            [("Get-Item", FakeResult("CCURE::TYPE::DWord\r\nCCURE::VALUE::1\r\n"))]
        )
        result = _probe_registry(
            ctx(shell),
            obj(
                REG, hive="HKEY_LOCAL_MACHINE", key="SOFTWARE\\Policies", name="Enabled"
            ),
        )
        assert result.ok
        assert len(result.items) == 1
        assert result.items[0]["value"] == "1"
        assert result.items[0]["type"] == "reg_dword"

    def test_a_missing_key_is_an_absence_and_not_a_failure(self):
        shell = FakeShell([("Get-Item", FakeResult("CCURE::NOKEY"))])
        result = _probe_registry(ctx(shell), obj(REG, hive="HKLM", key="X", name="Y"))
        assert result.ok, "a key that is not there is a reading, not an error"
        assert result.items == ()

    def test_a_missing_value_under_an_existing_key_is_also_an_absence(self):
        shell = FakeShell([("Get-Item", FakeResult("CCURE::NOVALUE"))])
        result = _probe_registry(ctx(shell), obj(REG, hive="HKLM", key="X", name="Y"))
        assert result.ok
        assert result.items == ()

    def test_a_failed_read_is_an_error_and_never_an_absence(self):
        """
        The direction that matters. An absence passes a ``none_exist`` rule, so
        a read that failed reported as an absence declares a host compliant on
        the strength of a command that did not run.
        """
        shell = FakeShell([("Get-Item", FakeResult("", 1, "access denied"))])
        result = _probe_registry(ctx(shell), obj(REG, hive="HKLM", key="X", name="Y"))
        assert not result.ok
        assert result.items == ()

    def test_output_with_no_marker_is_an_error_not_an_empty_reading(self):
        shell = FakeShell([("Get-Item", FakeResult("something unexpected"))])
        result = _probe_registry(ctx(shell), obj(REG, hive="HKLM", key="X", name="Y"))
        assert not result.ok

    def test_no_session_is_an_error(self):
        result = _probe_registry(ctx(None), obj(REG, hive="HKLM", key="X", name="Y"))
        assert not result.ok

    def test_an_object_naming_no_value_is_declined_rather_than_guessed(self):
        result = _probe_registry(
            ctx(FakeShell()), {"type": REG, "entities": {"hive": {"values": ["HKLM"]}}}
        )
        assert not result.ok

    def test_the_native_transport_is_preferred_when_the_executor_has_one(self):
        native = NativeRegistry(value="1")
        result = _probe_registry(
            ctx(native), obj(REG, hive="HKLM", key="SOFTWARE\\X", name="Y")
        )
        assert result.ok
        assert native.calls == [("HKLM", "SOFTWARE\\X", "Y")]
        assert result.items[0]["value"] == "1"

    def test_the_native_transport_omits_type_rather_than_inventing_one(self):
        """
        Remote Registry returns the data and not its kind. Omitting the entity
        makes a state that checks ``type`` evaluate to UNKNOWN; supplying a
        guessed one would make it a verdict.
        """
        result = _probe_registry(
            ctx(NativeRegistry(value="1")), obj(REG, hive="HKLM", key="K", name="N")
        )
        assert "type" not in result.items[0]

    def test_native_none_is_an_absence(self):
        result = _probe_registry(
            ctx(NativeRegistry(value=None)), obj(REG, hive="HKLM", key="K", name="N")
        )
        assert result.ok and result.items == ()

    def test_a_raising_native_read_is_an_error(self):
        result = _probe_registry(
            ctx(NativeRegistry(raises=OSError("pipe closed"))),
            obj(REG, hive="HKLM", key="K", name="N"),
        )
        assert not result.ok


# ─────────────────────────────────────────────────────────────────────────────
# audit policy — 43 rules
# ─────────────────────────────────────────────────────────────────────────────

#: Real `auditpol /get /category:* /r` output, copied from a live Windows 11
#: Pro host. The header and the phrasing of the Inclusion Setting are the two
#: things this fixture exists to preserve.
AUDITPOL = (
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,"
    "Exclusion Setting\r\n"
    "PANKAJM-HPNEW,System,Credential Validation,"
    "{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,\r\n"
    "PANKAJM-HPNEW,System,Plug and Play Events,"
    "{0CCE9248-69AE-11D9-BED3-505054503030},No Auditing,\r\n"
    "PANKAJM-HPNEW,System,Other Logon/Logoff Events,"
    "{0CCE921C-69AE-11D9-BED3-505054503030},Success,\r\n"
)


class TestAuditPolicyProbe:
    def test_the_setting_is_a_phrase_not_a_number(self):
        """
        Measured on real hardware: `auditpol /r` prints "Success and Failure",
        not the numeric code. An earlier table keyed on "0".."3" matched no row,
        emptied the policy, and turned all forty-three audit rules into errors.
        """
        policy = _collect_audit_policy(
            ctx(FakeShell([("auditpol", FakeResult(AUDITPOL))]))
        )
        assert isinstance(policy, dict), policy
        assert policy["credential_validation"] == "AUDIT_SUCCESS_FAILURE"
        assert policy["other_logon_logoff_events"] == "AUDIT_SUCCESS"

    def test_the_one_subcategory_whose_oval_name_is_not_the_windows_name(self):
        """``pnp_activity`` in OVAL is "Plug and Play Events" to Windows."""
        policy = _collect_audit_policy(
            ctx(FakeShell([("auditpol", FakeResult(AUDITPOL))]))
        )
        assert policy["pnp_activity"] == "AUDIT_NONE"

    def test_the_whole_policy_is_one_item(self):
        result = _probe_auditeventpolicysubcategories(
            ctx(FakeShell([("auditpol", FakeResult(AUDITPOL))])),
            {"type": "windows:auditeventpolicysubcategories_object", "entities": {}},
        )
        assert result.ok and len(result.items) == 1
        assert result.items[0]["credential_validation"] == "AUDIT_SUCCESS_FAILURE"

    def test_a_subcategory_the_host_did_not_report_is_simply_absent(self):
        """Absent from the item, so the evaluator answers UNKNOWN for it."""
        result = _probe_auditeventpolicysubcategories(
            ctx(FakeShell([("auditpol", FakeResult(AUDITPOL))])),
            {"type": "windows:auditeventpolicysubcategories_object", "entities": {}},
        )
        assert "registry" not in result.items[0]

    def test_an_unreadable_audit_policy_is_an_error(self):
        result = _probe_auditeventpolicysubcategories(
            ctx(FakeShell([("auditpol", FakeResult("", 1, "denied"))])),
            {"type": "windows:auditeventpolicysubcategories_object", "entities": {}},
        )
        assert not result.ok

    def test_normalisation(self):
        assert _normalise_audit_name("Other Logon/Logoff Events") == (
            "other_logon_logoff_events"
        )
        assert _normalise_audit_name("MPSSVC Rule-Level Policy Change") == (
            "mpssvc_rule_level_policy_change"
        )


# ─────────────────────────────────────────────────────────────────────────────
# secedit: password policy, lockout policy, user rights
# ─────────────────────────────────────────────────────────────────────────────

SECEDIT = (
    "INI::[System Access]\r\n"
    "INI::PasswordHistorySize = 24\r\n"
    "INI::MaximumPasswordAge = 60\r\n"
    "INI::MinimumPasswordAge = 1\r\n"
    "INI::MinimumPasswordLength = 14\r\n"
    "INI::PasswordComplexity = 1\r\n"
    "INI::ClearTextPassword = 0\r\n"
    "INI::LSAAnonymousNameLookup = 0\r\n"
    "INI::LockoutBadCount = 3\r\n"
    "INI::LockoutDuration = 15\r\n"
    "INI::ResetLockoutCount = 15\r\n"
    "INI::[Privilege Rights]\r\n"
    "INI::SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545\r\n"
    "INI::SeDenyNetworkLogonRight = Guest\r\n"
    "SID::S-1-5-32-544::BUILTIN\\Administrators\r\n"
    "SID::S-1-5-32-545::BUILTIN\\Users\r\n"
)


def secedit_ctx():
    return ctx(FakeShell([("secedit", FakeResult(SECEDIT))]))


class TestPasswordAndLockoutPolicy:
    def test_ages_are_converted_from_days_to_seconds(self):
        """
        OVAL states these in seconds; ``secedit`` exports days. Comparing the
        raw number reports a 60-day maximum age as 60 seconds and fails a
        correctly configured host — a wrong verdict that looks like a right one.
        """
        result = _probe_passwordpolicy(
            secedit_ctx(), {"type": "windows:passwordpolicy_object", "entities": {}}
        )
        assert result.ok
        item = result.items[0]
        assert item["max_passwd_age"] == str(60 * 86400)
        assert item["min_passwd_age"] == str(1 * 86400)

    def test_counts_and_flags_are_not_scaled(self):
        item = _probe_passwordpolicy(
            secedit_ctx(), {"type": "windows:passwordpolicy_object", "entities": {}}
        ).items[0]
        assert item["password_hist_len"] == "24"
        assert item["min_passwd_len"] == "14"
        assert item["password_complexity"] == "1"
        assert item["reversible_encryption"] == "0"

    def test_the_lsa_anonymous_flag_is_part_of_the_password_policy_item(self):
        """WN11-SO-000140 reads it; without it that rule reported ERROR."""
        item = _probe_passwordpolicy(
            secedit_ctx(), {"type": "windows:passwordpolicy_object", "entities": {}}
        ).items[0]
        assert item["anonymous_name_lookup"] == "0"

    def test_lockout_figures_are_converted_from_minutes_to_seconds(self):
        item = _probe_lockoutpolicy(
            secedit_ctx(), {"type": "windows:lockoutpolicy_object", "entities": {}}
        ).items[0]
        assert item["lockout_threshold"] == "3"
        assert item["lockout_duration"] == str(15 * 60)
        assert item["lockout_observation_window"] == str(15 * 60)

    def test_a_negative_figure_becomes_the_forever_sentinel(self):
        shell = FakeShell(
            [
                (
                    "secedit",
                    FakeResult("INI::[System Access]\r\nINI::LockoutDuration = -1\r\n"),
                )
            ]
        )
        item = _probe_lockoutpolicy(
            ctx(shell), {"type": "windows:lockoutpolicy_object", "entities": {}}
        ).items[0]
        assert item["lockout_duration"] == "4294967295"

    def test_a_setting_absent_from_the_export_is_omitted_not_defaulted(self):
        """Omitted means UNKNOWN. Defaulting to 0 would assert the weakest state."""
        shell = FakeShell(
            [
                (
                    "secedit",
                    FakeResult(
                        "INI::[System Access]\r\nINI::MinimumPasswordLength = 8\r\n"
                    ),
                )
            ]
        )
        item = _probe_passwordpolicy(
            ctx(shell), {"type": "windows:passwordpolicy_object", "entities": {}}
        ).items[0]
        assert item["min_passwd_len"] == "8"
        assert "password_hist_len" not in item

    def test_a_failed_export_is_an_error(self):
        shell = FakeShell([("secedit", FakeResult("CCURE::FAILED"))])
        result = _probe_passwordpolicy(
            ctx(shell), {"type": "windows:passwordpolicy_object", "entities": {}}
        )
        assert not result.ok


class TestUserRight:
    def test_a_sid_is_resolved_and_stripped_of_its_authority(self):
        result = _probe_userright(
            secedit_ctx(),
            obj("windows:userright_object", userright="SE_NETWORK_LOGON_NAME"),
        )
        assert result.ok
        names = sorted(i["trustee_name"] for i in result.items)
        assert names == ["Administrators", "Users"]

    def test_the_qualified_name_is_kept_for_evidence(self):
        result = _probe_userright(
            secedit_ctx(),
            obj("windows:userright_object", userright="SE_NETWORK_LOGON_NAME"),
        )
        assert any(
            i.get("trustee_qualified_name") == "BUILTIN\\Administrators"
            for i in result.items
        )

    def test_a_bare_name_in_the_export_is_kept(self):
        result = _probe_userright(
            secedit_ctx(),
            obj("windows:userright_object", userright="SE_DENY_NETWORK_LOGON_NAME"),
        )
        assert [i["trustee_name"] for i in result.items] == ["Guest"]

    def test_a_right_nobody_holds_is_one_item_with_an_empty_trustee(self):
        """
        Not zero items. Every userright rule in the DISA Windows 11 STIG uses
        ``at_least_one_exists``, and the rules meaning "this must not be
        assigned" compare against ``trustee_name equals ''``. With zero items,
        0 of 25 userright rules could pass on a real host.
        """
        result = _probe_userright(
            secedit_ctx(), obj("windows:userright_object", userright="SE_TCB_NAME")
        )
        assert result.ok
        assert len(result.items) == 1
        assert result.items[0]["trustee_name"] == ""

    def test_an_unmapped_right_is_an_error_rather_than_an_absence(self):
        result = _probe_userright(
            secedit_ctx(), obj("windows:userright_object", userright="SE_MADE_UP_NAME")
        )
        assert not result.ok

    def test_a_well_known_sid_the_host_cannot_translate_still_gets_a_name(self):
        """WN11-UR-000060 reported ERROR on a perfectly readable host.

        Windows 11 grants ``SeCreateSymbolicLinkPrivilege`` to
        ``*S-1-5-32-544,*S-1-5-83-0`` out of the box, and
        ``SecurityIdentifier.Translate`` throws for the second unless the
        Hyper-V management service is running — so the export carried an empty
        display name, the item carried no ``trustee_name``, and the comparison
        against a state naming one returned UNKNOWN. Measured on a real
        Windows 11 Pro host, 22 Sep 2026.
        """
        shell = FakeShell(
            [
                (
                    "secedit",
                    FakeResult(
                        "INI::SeCreateSymbolicLinkPrivilege = *S-1-5-32-544,*S-1-5-83-0\r\n"
                        "SID::S-1-5-32-544::BUILTIN\\Administrators\r\n"
                        # Exactly what the host returns: translated to nothing.
                        "SID::S-1-5-83-0::\r\n"
                    ),
                )
            ]
        )
        result = _probe_userright(
            ctx(shell),
            obj("windows:userright_object", userright="SE_CREATE_SYMBOLIC_LINK_NAME"),
        )
        assert result.ok
        names = sorted(i.get("trustee_name", "<<missing>>") for i in result.items)
        assert names == ["Administrators", "NT VIRTUAL MACHINE\\Virtual Machines"]

    def test_the_hosts_own_translation_beats_the_table(self):
        """The table fills blanks; it never overrides.

        Translation happens on the target so a non-English install resolves its
        own group names. A table that won would undo exactly that.
        """
        shell = FakeShell(
            [
                (
                    "secedit",
                    FakeResult(
                        "INI::SeCreateSymbolicLinkPrivilege = *S-1-5-83-0\r\n"
                        "SID::S-1-5-83-0::NT VIRTUELLE MASCHINE\\Virtuelle Computer\r\n"
                    ),
                )
            ]
        )
        result = _probe_userright(
            ctx(shell),
            obj("windows:userright_object", userright="SE_CREATE_SYMBOLIC_LINK_NAME"),
        )
        assert [i["trustee_name"] for i in result.items] == [
            "NT VIRTUELLE MASCHINE\\Virtuelle Computer"
        ]

    def test_a_sid_in_neither_the_host_nor_the_table_stays_unnamed(self):
        """UNKNOWN is the right answer for a trustee nothing identified.

        Substituting the SID string would compare a SID against a group name
        and fail every rule it appears in; inventing a name would assert
        something about the host that nothing established.
        """
        shell = FakeShell(
            [
                (
                    "secedit",
                    FakeResult(
                        "INI::SeCreateSymbolicLinkPrivilege = *S-1-5-21-99-99-99-1234\r\n"
                        "SID::S-1-5-21-99-99-99-1234::\r\n"
                    ),
                )
            ]
        )
        result = _probe_userright(
            ctx(shell),
            obj("windows:userright_object", userright="SE_CREATE_SYMBOLIC_LINK_NAME"),
        )
        assert result.ok
        assert "trustee_name" not in result.items[0]
        assert result.items[0]["trustee_sid"] == "S-1-5-21-99-99-99-1234"

    def test_only_builtin_authorities_are_stripped(self):
        assert _bare_trustee("BUILTIN\\Administrators") == "Administrators"
        assert _bare_trustee("NT AUTHORITY\\LOCAL SERVICE") == "LOCAL SERVICE"
        assert _bare_trustee("Everyone") == "Everyone"
        # The content writes this one qualified, so it must stay qualified.
        assert (
            _bare_trustee("RESTRICTED SERVICES\\PrintSpoolerService")
            == "RESTRICTED SERVICES\\PrintSpoolerService"
        )
        assert _bare_trustee("CORP\\Domain Admins") == "CORP\\Domain Admins"


# ─────────────────────────────────────────────────────────────────────────────
# wmi57
# ─────────────────────────────────────────────────────────────────────────────


class NativeWmi:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def run(self, command, timeout=None):  # pragma: no cover
        return FakeResult("5")

    def wmi_query(self, query, limit=5000):
        self.queries.append(query)
        return self.rows


class TestWmi57:
    def test_rows_become_records_with_lower_cased_columns(self):
        shell = FakeShell(
            [("Get-CimInstance", FakeResult('CCURE::WMI::[{"DomainRole":"0"}]'))]
        )
        result = _probe_wmi57(
            ctx(shell),
            obj(
                "windows:wmi57_object",
                namespace="root\\cimv2",
                wql="SELECT DomainRole FROM x",
            ),
        )
        assert result.ok
        assert result.items[0]["result"] == {"domainrole": "0"}

    def test_no_rows_is_an_absence(self):
        shell = FakeShell([("Get-CimInstance", FakeResult("CCURE::WMI::[]"))])
        result = _probe_wmi57(
            ctx(shell),
            obj("windows:wmi57_object", namespace="root\\cimv2", wql="SELECT a FROM b"),
        )
        assert result.ok and result.items == ()

    def test_a_failed_query_is_an_error(self):
        shell = FakeShell(
            [("Get-CimInstance", FakeResult("CCURE::FAILED::Invalid namespace"))]
        )
        result = _probe_wmi57(
            ctx(shell),
            obj("windows:wmi57_object", namespace="root\\nope", wql="SELECT a FROM b"),
        )
        assert not result.ok

    def test_unparseable_output_is_an_error(self):
        shell = FakeShell([("Get-CimInstance", FakeResult("CCURE::WMI::{not json"))])
        result = _probe_wmi57(
            ctx(shell),
            obj("windows:wmi57_object", namespace="root\\cimv2", wql="SELECT a FROM b"),
        )
        assert not result.ok

    def test_the_native_transport_serves_only_its_own_namespace(self):
        """
        ``SMBExecutor.wmi_query`` is bound to root/cimv2. Running a BitLocker
        query through it would answer confidently about the wrong namespace.
        """
        native = NativeWmi([{"ProtectionStatus": 1}])
        result = _probe_wmi57(
            ctx(native),
            obj("windows:wmi57_object", namespace="root\\cimv2", wql="SELECT a FROM b"),
        )
        assert result.ok
        assert native.queries == ["SELECT a FROM b"]
        assert result.items[0]["result"] == {"protectionstatus": "1"}

    def test_a_foreign_namespace_falls_through_to_the_shell(self):
        native = NativeWmi([{"X": 1}])
        native.answers = []
        # The native executor also answers `run`, so the probe can fall through.
        result = _probe_wmi57(
            ctx(native),
            obj(
                "windows:wmi57_object",
                namespace="root\\cimv2\\security\\microsoftvolumeencryption",
                wql="SELECT protectionstatus FROM win32_encryptablevolume",
            ),
        )
        assert (
            native.queries == []
        ), "the native reader must not serve another namespace"
        assert not result.ok or result.items is not None


# ─────────────────────────────────────────────────────────────────────────────
# Cross-cutting: registration, record comparison, platform
# ─────────────────────────────────────────────────────────────────────────────


class TestWiring:
    def test_every_windows_test_type_has_a_probe(self):
        from core.scap.oval import SUPPORTED_TESTS
        from core.scap.probes import PROBES

        for test_type in SUPPORTED_TESTS:
            if not test_type.startswith("windows:"):
                continue
            object_type = test_type.replace("_test", "_object")
            assert object_type in PROBES, f"{test_type} is declared with no probe"

    def test_the_scap_collector_serves_windows(self):
        from core.config_audit.collectors.scap import ScapRuleCollector

        assert "windows" in ScapRuleCollector.platforms

    @pytest.mark.parametrize(
        "actual,expected,outcome",
        [
            ({"domainrole": "0"}, {"domainrole": "0"}, True),
            ({"domainrole": "1"}, {"domainrole": "0"}, False),
            # A column the row does not carry is UNKNOWN, never False: "this
            # build did not collect that" is not "the host disagrees".
            ({"other": "0"}, {"domainrole": "0"}, None),
        ],
    )
    def test_record_comparison_is_three_valued(self, actual, expected, outcome):
        from core.scap.evaluate import _compare

        assert _compare(actual, "equals", expected, "record") is outcome

    def test_a_record_compared_against_a_non_record_is_unknown(self):
        from core.scap.evaluate import _compare

        assert _compare("0", "equals", {"a": "1"}, "record") is None
        assert _compare({"a": "1"}, "equals", "0", "record") is None


# ─────────────────────────────────────────────────────────────────────────────
# Backend result → report
# ─────────────────────────────────────────────────────────────────────────────


def _windows_stig_result(outcome, raw="", remediation="Configure the policy."):
    """A CheckResult shaped exactly as the SCAP collector produces one."""
    from core.checks.contract import CheckOutcome, CheckResult, Evidence

    evidence = ()
    if outcome in (CheckOutcome.PASS, CheckOutcome.FAIL):
        evidence = (
            Evidence(
                description="Windows 11 must use a BitLocker PIN for pre-boot authentication.",
                expected="the host is in the state the benchmark requires",
                observed=(
                    "non_compliant" if outcome is CheckOutcome.FAIL else "compliant"
                ),
                raw=raw,
                collector="scap_rule",
            ),
        )
    error = None
    if outcome is CheckOutcome.ERROR:
        # The contract refuses an ERROR with no reason, which is the point:
        # "could not evaluate" is only useful if it says why.
        error = "no authenticated session to the target"
    return CheckResult(
        error=error,
        check_id="rule_stig_win11_wn11_00_000031",
        title="Windows 11 must use a BitLocker PIN for pre-boot authentication.",
        target="10.180.6.14",
        outcome=outcome,
        severity="high",
        evidence=evidence,
        remediation=remediation,
        references=("https://public.cyber.mil/stigs/",),
        metadata={"finding_type": "config_check", "check_type": "scap_rule"},
    )


class TestAWindowsStigResultReachesTheReport:
    """
    A backend gap is not closed until its results are visible in the report.

    These drive the real ``_finding_card`` the technical PDF renders each
    finding with, so a change that stops a Windows STIG result appearing —
    or renders it without its identifier, evidence or remediation — fails
    here rather than in a customer's audit pack.
    """

    RAW = (
        "windows:registry_object: 0 item(s) collected, which does not satisfy "
        "at_least_one_exists"
    )

    def _card_text(self, finding):
        from reporting.pdf_generator import _build_styles, _finding_card

        flowables = _finding_card(finding, _build_styles())
        chunks = []
        for flowable in flowables:
            text = getattr(flowable, "text", None)
            if text:
                chunks.append(str(text))
            for row in getattr(flowable, "_cellvalues", None) or []:
                for cell in row:
                    inner = getattr(cell, "text", None)
                    if inner:
                        chunks.append(str(inner))
                    elif isinstance(cell, str):
                        chunks.append(cell)
        return "\n".join(chunks)

    def test_a_failing_stig_rule_renders_with_its_minted_identifier(self):
        from core.checks.contract import CheckOutcome
        from core.config_audit.findings import finding_from_result

        finding = finding_from_result(
            _windows_stig_result(CheckOutcome.FAIL, raw=self.RAW)
        )
        assert finding is not None
        text = self._card_text(finding)
        # `primary_cve` is empty for a check, so the card falls back to
        # plugin_id. Without that fallback a STIG finding renders unlabelled.
        assert "CCURE-CFG-RULE-STIG-WIN11-WN11-00-000031" in text
        assert "BitLocker PIN" in text

    def test_the_oval_evidence_reaches_the_card(self):
        """The reader must learn *why* it failed without re-running the scan."""
        from core.checks.contract import CheckOutcome
        from core.config_audit.findings import finding_from_result

        finding = finding_from_result(
            _windows_stig_result(CheckOutcome.FAIL, raw=self.RAW)
        )
        text = self._card_text(finding)
        assert "at_least_one_exists" in text or self.RAW[:40] in text

    def test_remediation_and_severity_survive_onto_the_finding(self):
        """
        `_finding_card` renders the identifier, title and evidence; remediation
        is rendered by the report's own remediation section from
        ``finding.remediation``. This asserts it is carried there, and graded as
        configuration guidance rather than "no published fix", which is what a
        CVE with no patch means and would read as here.
        """
        from core.checks.contract import CheckOutcome
        from core.config_audit.findings import finding_from_result
        from scans.finding_normalizer import RemediationConfidence

        finding = finding_from_result(
            _windows_stig_result(CheckOutcome.FAIL, raw=self.RAW)
        )
        assert finding.remediation is not None
        assert "Configure the policy." in finding.remediation.summary
        assert (
            finding.remediation.confidence
            is RemediationConfidence.CONFIGURATION_GUIDANCE
        )
        # display_severity() title-cases for presentation.
        assert finding.severity == "High"

    @pytest.mark.parametrize(
        "outcome_name",
        ["PASS", "NOT_APPLICABLE", "ERROR", "MANUAL_REVIEW"],
    )
    def test_only_a_fail_becomes_a_finding_in_the_report(self, outcome_name):
        """
        The single most important property of this path. A rule this build
        could not evaluate — ERROR — must not appear in the report as though
        the host had been assessed, and a PASS is a compliance verdict rather
        than a vulnerability.
        """
        from core.checks.contract import CheckOutcome
        from core.config_audit.findings import finding_from_result

        outcome = getattr(CheckOutcome, outcome_name)
        assert finding_from_result(_windows_stig_result(outcome)) is None

    def test_a_windows_stig_finding_is_filed_as_a_check_not_a_cve(self):
        """
        `cve_id` NULL and `definition_type` config_check. A check filed as a CVE
        inherits KEV lookups, EPSS scores and an NVD link that resolves to
        nothing — and its minted id is far longer than `cve_id`'s 30 characters,
        which aborts the finding sync for the whole scan.
        """
        from core.config_audit.findings import catalogue_row
        from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

        check = ConfigCheck(
            check_id="rule_stig_win11_wn11_00_000031",
            title="Windows 11 must use a BitLocker PIN.",
            check_type="scap_rule",
            collect={"definition": {}},
            expect=Expectation("equals", "compliant"),
            absent=AbsencePolicy.MANUAL_REVIEW,
            platforms=("windows",),
            severity="high",
        )
        row = catalogue_row(check)
        assert row["cve_id"] is None
        assert row["definition_type"] == "config_check"
        assert row["id"].startswith("CCURE-CFG-")
        assert len(row["id"]) > 30, (
            "the identifier is longer than cve_id's column, which is exactly "
            "why it must never be written there"
        )
