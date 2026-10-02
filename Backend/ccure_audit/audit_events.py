"""
ccure_audit/audit_events.py — Audit's audit-event definitions.

The audit log is the platform's. Which severity an *Audit* event carries — a scan
starting, a credential being created, a risk being accepted — is Audit's call, and
it used to be rows in the platform's one table. They are here now, registered with
the platform (``ccure_platform.api.register_event_severities``).

The values are exactly the ones the single table held; a test pins the merged
table to a fingerprint of the old one. Severity is stored on the row when the
event is written, so this module has to be loaded in **every process that writes
an Audit event** — the API, the Celery workers and the web worker all do. The
manifest declares it (``audit_event_modules`` in ``ccure_audit/manifest.toml``)
and the platform imports it by name the first time it resolves a severity, so no
emitter has to remember to.
"""

from __future__ import annotations

from ccure_platform.api import register_event_severities

INFO, LOW, MEDIUM, HIGH, CRITICAL = "info", "low", "medium", "high", "critical"

AUDIT_EVENT_SEVERITIES: dict[str, str] = {
    # ── Scanning ────────────────────────────────────────────────────────────
    "scan.created": LOW,
    "scan.completed": INFO,
    "scan.failed": MEDIUM,
    "scan.cancelled": LOW,
    # ── Web application scanning ────────────────────────────────────────────
    # Launching a web scan sends sqlmap, ffuf and nuclei at a URL the caller
    # names — active attack traffic from this host against somebody's
    # application — so it outranks launching a network scan. The entry also
    # records the authorisation confirmation the caller gave, which is the
    # only durable evidence it was given.
    "web_scan.created": MEDIUM,
    "web_scan.cancelled": LOW,
    # Triage outcomes, one per status, weighted like their network-finding
    # counterparts: accepting a risk is the decision an auditor looks for;
    # marking one false positive removes it from every count built on it.
    "web_finding.open": INFO,
    "web_finding.reopened": LOW,
    "web_finding.confirmed": LOW,
    "web_finding.fixed": LOW,
    "web_finding.false_positive": MEDIUM,
    "web_finding.accepted_risk": HIGH,
    # ── Scan scheduling (Phase 1) ───────────────────────────────────────────
    # Creating or editing a schedule decides what this platform will point at
    # a network unattended, repeatedly, from now on — so it outranks starting
    # one scan by hand ("scan.created": LOW). Deleting one is the same weight
    # as creating: an assurance scan that silently stops running is a
    # compliance gap nobody is told about.
    "scan_schedule.created": MEDIUM,
    "scan_schedule.updated": MEDIUM,
    "scan_schedule.deleted": MEDIUM,
    # Enable/disable is the switch that decides whether the above happens at
    # all, and is the most likely thing to be changed quietly.
    "scan_schedule.enabled": MEDIUM,
    "scan_schedule.disabled": MEDIUM,
    # A person pressing Run Now is one scan, deliberately taken, and is
    # rated like the manual scan it produces.
    "scan_schedule.run_now": LOW,
    # The scheduler switching a schedule off after repeated failures. HIGH
    # because nobody asked for it and the effect is that assurance scanning
    # silently stops — exactly the state a reviewer needs to find.
    "scan_schedule.auto_disabled": HIGH,
    # ── Credentials (Phase 2) ───────────────────────────────────────────────
    # Storing a credential gives this platform a way into a host, so it
    # outranks ordinary configuration changes. Deletion matches: a scheduled
    # assurance scan whose credential vanished stops producing findings, and
    # nothing else announces that.
    "credential.created": HIGH,
    "credential.updated": HIGH,
    "credential.deleted": HIGH,
    # A validation is one deliberate authentication attempt against one named
    # host. LOW on its own; the value is the trail — repeated failures against
    # many hosts is credential spraying wearing an administrator's session.
    "credential.validated": LOW,
    # ── Assets ──────────────────────────────────────────────────────────────
    "asset_updated": LOW,
    "amt_inventory_imported": MEDIUM,
    # ── Findings ────────────────────────────────────────────────────────────
    # Accepting or ignoring a finding is a decision to live with a risk, and
    # is the finding action an auditor comes looking for.
    "finding_open": INFO,
    "finding_resolved": LOW,
    "finding_false_positive": MEDIUM,
    "finding_accepted": HIGH,
    "finding_ignored": HIGH,
    # ── Remediation (GAP-14) ────────────────────────────────────────────────
    # Ownership and workflow are routine bookkeeping. Accepting a risk is not:
    # it is a decision to live with a finding, and it is the remediation action
    # an auditor comes looking for — the same reading `finding_accepted` above
    # already gets. Withdrawing one is HIGH for the mirror reason: it is the
    # record of a decision being reversed.
    "remediation.assigned": INFO,
    "remediation.unassigned": LOW,
    "remediation.state_changed": LOW,
    "remediation.note_added": INFO,
    "remediation.risk_accepted": HIGH,
    "remediation.acceptance_withdrawn": HIGH,
    # Changing the SLA changes when every future finding is reported overdue,
    # across the whole organisation, from one settings edit.
    "remediation.sla_policy_updated": HIGH,
    # ── Compliance ──────────────────────────────────────────────────────────
    "install_framework": MEDIUM,
    "uninstall_framework": HIGH,
    "compliance.rule_updated": HIGH,
    "create_policy": MEDIUM,
    "trigger_scan": LOW,
    "attest_control": HIGH,
    "upload_evidence": LOW,
    "delete_evidence": HIGH,
    "create_schedule": LOW,
    "update_schedule": LOW,
    "delete_schedule": MEDIUM,
    "create_credential": HIGH,
    "delete_credential": MEDIUM,
    "export_soa": MEDIUM,
    "export_report": MEDIUM,
    # Remediation: requesting is routine, approving executes something on a
    # host, and bypassing the maker-checker queue removes the second pair of
    # eyes that the queue exists to provide.
    "request_remediation": LOW,
    "approve_remediation": HIGH,
    "reject_remediation": MEDIUM,
    "cancel_remediation": LOW,
    "request_rollback": LOW,
    "approve_rollback": HIGH,
    "emergency_bypass_remediation": CRITICAL,
    "emergency_bypass_rollback": CRITICAL,
    "request_waiver": MEDIUM,
    "approve_waiver": HIGH,
    # ── Reports ─────────────────────────────────────────────────────────────
    "report.downloaded": LOW,
}

register_event_severities("audit", AUDIT_EVENT_SEVERITIES)
