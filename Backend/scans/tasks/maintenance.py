"""
Bookkeeping tasks: expiring risk acceptances, reconciling the AMT inventory
after an import, refreshing the MAC vendor registry.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Logs under ``ccure.tasks``, as the hub did.
"""

import logging
import os
from core import task_names
from core.celery_app import celery_app
from db.base import SessionLocal

log = logging.getLogger("ccure.tasks")


@celery_app.task(name="ccure.tasks.expire_risk_acceptances", queue="default")
def expire_risk_acceptances() -> dict:
    """
    Return findings whose risk acceptance has run out to the remediation queue.

    GAP-14. An acceptance with an expiry is a decision with a shelf life: when
    it lapses the finding is outstanding again, and it goes back to
    ``assigned`` if it still has an owner or ``open`` if it does not. Not to
    ``verified_fixed`` and not to an "expired" state of its own — the finding
    is simply un-dealt-with, and the remediation queue is where un-dealt-with
    findings belong.

    ``status`` returns to ``open`` alongside ``remediation_state``, so the
    dashboard and the asset risk score stop treating it as handled. Those two
    disagreeing is the confusion the two-column split exists to avoid.

    An acceptance with **no** expiry is untouched. That is a legitimate
    decision for a permanent compensating control, and expiring it because
    nobody set a date would silently overrule somebody's judgement.

    Every expiry writes a ``FindingRemediationEvent`` carrying the original
    reason and the date it lapsed, so the trail shows what the acceptance was
    for and that it ended on its own rather than being withdrawn.
    """
    from core.remediation import expire_due_exceptions

    db = SessionLocal()
    try:
        expired = expire_due_exceptions(db)
        db.commit()
        if expired:
            log.info("Expired %d risk acceptance(s)", expired)
        return {"success": True, "expired": expired}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        # Recorded with its traceback rather than swallowed. A silently failing
        # expiry leaves lapsed acceptances suppressing findings indefinitely,
        # which looks exactly like an estate with nothing outstanding.
        log.exception("Risk-acceptance expiry failed")
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


@celery_app.task(name=task_names.RECONCILE_AMT_INVENTORY, queue="scanner")
def reconcile_amt_inventory_task(org_id: str) -> dict:
    """Async background task to run AMT reconciliation for an organization."""
    db = SessionLocal()
    try:
        from core.amt_reconciliation import reconcile_amt_inventory

        return reconcile_amt_inventory(db, org_id)
    except Exception as exc:
        log.exception(f"AMT Reconciliation background task failed for org {org_id}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="ccure.tasks.update_mac_vendor_registry", queue="default")
def update_mac_vendor_registry_task() -> dict:
    """
    Downloads the latest raw OUI manufacturer registry from Wireshark
    and updates the local manuf.txt file.
    """
    import requests
    from core.oui_lookup import get_oui_db

    url = "https://www.wireshark.org/download/automated/data/manuf"
    log.info("Starting MAC vendor registry update from %s", url)

    try:
        db_path = get_oui_db().db_path
        if not db_path:
            log.warning("OUI database path is not defined. Skipping registry update.")
            return {"success": False, "error": "No database path configured"}

        # 1. Fetch from URL with a reasonable timeout
        response = requests.get(url, timeout=30.0)
        if response.status_code != 200:
            log.warning(
                "Failed to fetch OUI registry. HTTP Status: %d", response.status_code
            )
            return {"success": False, "error": f"HTTP status {response.status_code}"}

        content = response.text

        # 2. Basic validation: ensure the file contains comments and some common MAC prefixes
        if not content.startswith("#") or "00:00:00" not in content:
            log.warning(
                "Fetched OUI registry failed validation checks. Update aborted."
            )
            return {"success": False, "error": "Invalid file format"}

        # 3. Write to a temporary file first to prevent corruption on write failure
        temp_path = db_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)

        # 4. Safely rename/overwrite target file
        if os.path.exists(db_path):
            os.remove(db_path)
        os.rename(temp_path, db_path)

        # 5. Reload the OUIDatabase mapping dict in memory
        get_oui_db()._loaded = False
        get_oui_db()._database.clear()
        get_oui_db()._load()

        log.info(
            "MAC vendor registry updated successfully. Loaded %d entries.",
            len(get_oui_db()._database),
        )
        return {"success": True, "entries": len(get_oui_db()._database)}

    except Exception as exc:
        log.exception("MAC vendor registry background update task failed")
        return {"success": False, "error": str(exc)}
