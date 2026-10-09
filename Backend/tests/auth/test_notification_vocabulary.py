"""
Notification vocabulary ownership (backend alignment, follow-up 5).

The notification infrastructure is the platform's; what a scan raises is Audit's
(``scans/notification_vocabulary.py``). ``type`` and ``category`` are plain
strings in the table and the API, so moving the Audit members out of the
platform's enums changes no stored or returned value. These pin:

* the platform's enums hold only the platform's own values, Audit's hold
  Audit's, and every value is spelled as before;
* ``create_notification`` / ``fan_out_notification`` take an enum or a plain
  string and store the same text either way;
* the summary still lists every category, zero when nothing is unread, in the
  order it always did — including in a process that never imported ``main``
  (a Celery worker), where only ``scans.db_helpers`` registers Audit's category;
* rows written before the move are read and serialised unchanged, with
  ``related_scan_id``.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from ccure_platform.notifications import service
from scans import notification_vocabulary as vocab


def test_the_platform_enums_hold_only_the_platforms_own_values():
    assert [t.value for t in service.NotificationType] == [
        "system_message",
        "admin_notice",
    ]
    assert [c.value for c in service.NotificationCategory] == [
        "security",
        "system",
        "admin",
    ]


def test_audits_vocabulary_is_audits_and_spelled_as_before():
    assert [t.value for t in vocab.AuditNotificationType] == [
        "scan_completed",
        "scan_failed",
        "scan_paused",
        "vulnerability_found",
    ]
    assert [c.value for c in vocab.AuditNotificationCategory] == ["scan"]


def test_the_summary_lists_every_category_in_the_original_order():
    assert service.known_categories() == ["scan", "security", "system", "admin"]


def test_registering_a_category_twice_or_a_platform_one_is_a_no_op():
    before = list(service.known_categories())
    service.register_notification_categories("scan", "security", "system")
    assert service.known_categories() == before


def test_a_worker_process_registers_audits_category_without_main():
    """The worker imports scans.db_helpers, not main; that alone must register it."""
    code = (
        "import scans.db_helpers\n"
        "from ccure_platform.notifications.service import known_categories\n"
        "import sys\n"
        "assert 'main' not in sys.modules\n"
        "print(known_categories())\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(__import__("testpaths").BACKEND_ROOT),
    )
    assert out.returncode == 0, out.stderr[-800:]
    assert (
        out.stdout.strip().splitlines()[-1] == "['scan', 'security', 'system', 'admin']"
    )


@pytest.mark.parametrize(
    "ntype, category",
    [
        (
            vocab.AuditNotificationType.SCAN_COMPLETED,
            vocab.AuditNotificationCategory.SCAN,
        ),
        ("scan_completed", "scan"),
    ],
)
def test_an_enum_or_a_plain_string_stores_the_same_text(
    db_session, test_user, ntype, category
):
    row = service.create_notification(
        db_session,
        test_user.id,
        ntype,
        category,
        "t",
        "m",
        related_scan_id="scn_1",
    )
    assert (row.type, row.category, row.related_scan_id) == (
        "scan_completed",
        "scan",
        "scn_1",
    )
    payload = service.notification_payload(row)
    assert payload["type"] == "scan_completed" and payload["related_scan_id"] == "scn_1"


def test_the_platforms_own_values_still_work(db_session, test_user):
    row = service.create_notification(
        db_session,
        test_user.id,
        service.NotificationType.ADMIN_NOTICE,
        service.NotificationCategory.ADMIN,
        "t",
        "m",
    )
    assert (row.type, row.category) == ("admin_notice", "admin")


def test_unread_counts_and_zero_filled_categories(db_session, test_user):
    from db.models import Notification

    db_session.query(Notification).filter(Notification.user_id == test_user.id).delete()
    db_session.commit()
    empty = service.summary_payload(db_session, test_user.id)
    assert empty["by_category"] == {"scan": 0, "security": 0, "system": 0, "admin": 0}
    assert empty["total_unread"] == 0

    service.create_notification(
        db_session, test_user.id, "scan_completed", "scan", "a", "b"
    )
    service.create_notification(
        db_session, test_user.id, "vulnerability_found", "security", "a", "b"
    )
    got = service.summary_payload(db_session, test_user.id)
    assert got["by_category"] == {"scan": 1, "security": 1, "system": 0, "admin": 0}
    assert got["total_unread"] == 2
    db_session.query(Notification).filter(Notification.user_id == test_user.id).delete()
    db_session.commit()


def test_a_category_nobody_registered_is_still_counted(db_session, test_user):
    """Rows are never hidden because a product was not imported."""
    from db.models import Notification

    service.create_notification(
        db_session, test_user.id, "x", "future_product", "a", "b"
    )
    got = service.summary_payload(db_session, test_user.id)
    assert got["by_category"]["future_product"] == 1
    db_session.query(Notification).filter(Notification.user_id == test_user.id).delete()
    db_session.commit()
