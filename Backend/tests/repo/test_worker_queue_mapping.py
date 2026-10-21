"""
Which queue every Celery task runs on, and which worker consumes each queue.

A characterisation, not a design: it pins today's routing so that splitting the
workers (docs/architecture/WORKER_PRIVILEGE_SEPARATION.md, finding S3) moves a
task or a queue only on purpose. Two failures it exists to catch:

* **A task changing queue silently.** Task names and queues are strings in the
  broker and the beat schedule; a decorator edited in passing reroutes work to
  a worker that may lack the privileges, credentials or network it needs.
* **A queue nobody consumes.** On the Windows deployment the ``compliance``
  queue's only consumer sat behind a profile that was not started, and beat
  published 1,440 messages a day into it (CLAUDE.md, "Policy Compliance
  Engine"). A split that drops a queue from every worker's ``--queues`` would
  repeat that.

Changing an entry here is legitimate — it is how a split is reviewed — but it
must come with the matching docker-compose.yml change.
"""

import pytest

#: Every task this application registers, by name, and its queue.
EXPECTED_TASK_QUEUES = {
    # Network scanning: raw sockets, host network (Scapy, nmap)
    "ccure.tasks.run_host_discovery": "scanner",
    "ccure.tasks.run_asset_discovery": "scanner",
    "ccure.tasks.run_vulnerability_audit": "scanner",
    "ccure.tasks.run_topology_mapping": "scanner",
    "ccure.tasks.run_traditional_scan": "scanner",
    "ccure.tasks.run_credentialed_scan": "scanner",
    "ccure.tasks.sync_host_discovery_task": "scanner",
    "ccure.tasks.sync_asset_discovery_task": "scanner",
    "ccure.tasks.sync_vulnerability_audit_task": "scanner",
    # On the scanner queue, though neither opens a socket to a target: the
    # schedule dispatcher enqueues scans, and the AMT reconciliation reads the
    # database. Recorded as they are; S3 proposes no move for them.
    "ccure.tasks.run_due_scan_schedules": "scanner",
    "ccure.tasks.reconcile_amt_inventory_task": "scanner",
    # Web application scanning
    "ccure.web.run_recon": "web_recon",
    "ccure.web.run_crawl": "web_crawl",
    "ccure.web.run_detect": "web_dast",
    "ccure.web.run_audit": "web_audit",
    # Compliance
    "compliance.run_scan": "compliance",
    "compliance.run_scheduled_scans": "compliance",
    "compliance.run_remediation": "compliance",
    "compliance.run_reverify": "compliance",
    "compliance.prune_remediation_logs": "compliance",
    # Platform and housekeeping
    "ccure.tasks.send_verification_email": "default",
    "ccure.tasks.send_password_reset_email": "default",
    "ccure.tasks.send_mfa_otp": "default",
    "ccure.tasks.send_password_changed_email": "default",
    "ccure.tasks.send_account_approved_email": "default",
    "ccure.tasks.enrich_email_risk": "default",
    "ccure.tasks.retro_scan_email_risk": "default",
    "ccure.tasks.purge_stale_unapproved_accounts": "default",
    "ccure.tasks.purge_stale_unverified_accounts": "default",
    "ccure.tasks.purge_expired_refresh_sessions": "default",
    "ccure.tasks.sync_disposable_domains": "default",
    "ccure.tasks.purge_expired_audit_logs": "default",
    "ccure.tasks.expire_risk_acceptances": "default",
    "ccure.tasks.update_mac_vendor_registry": "default",
    "ccure.tasks.reap_stalled_scans": "default",
    "ccure.tasks.reap_stalled_web_scans": "default",
}

#: Which compose service consumes which queues, today.
EXPECTED_CONSUMERS = {
    "worker": {"scanner", "default", "compliance"},
    "web-worker": {"web_recon", "web_crawl", "web_dast", "web_audit"},
}


def _application_tasks() -> dict:
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    default = celery_app.conf.task_default_queue
    return {
        name: (task.queue or default)
        for name, task in celery_app.tasks.items()
        if not name.startswith("celery.")
    }


def test_every_task_runs_on_its_recorded_queue():
    assert _application_tasks() == EXPECTED_TASK_QUEUES


def test_every_task_queue_is_declared():
    from core.celery_app import celery_app

    declared = {q.name for q in celery_app.conf.task_queues}
    assert set(EXPECTED_TASK_QUEUES.values()) <= declared


def _compose_consumers() -> dict:
    import shlex

    import yaml
    from testpaths import REPO_ROOT

    compose = REPO_ROOT / "docker-compose.yml"
    if not compose.is_file():
        pytest.skip("docker-compose.yml is not reachable from this runtime")
    services = yaml.safe_load(compose.read_text(encoding="utf-8"))["services"]
    consumers = {}
    for name, service in services.items():
        command = service.get("command") or []
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        if "worker" not in argv:
            continue
        for arg in argv:
            if arg.startswith("--queues="):
                consumers[name] = set(arg.split("=", 1)[1].split(","))
    return consumers


def test_each_worker_consumes_its_recorded_queues():
    assert _compose_consumers() == EXPECTED_CONSUMERS


def test_no_task_queue_is_left_without_a_consumer():
    consumed = set().union(*_compose_consumers().values())
    orphaned = set(EXPECTED_TASK_QUEUES.values()) - consumed
    assert not orphaned, f"queues no worker consumes: {sorted(orphaned)}"


def test_the_beat_schedule_names_only_registered_tasks():
    from core.celery_app import celery_app

    scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    assert scheduled <= set(EXPECTED_TASK_QUEUES)
