"""
scans/notification_vocabulary.py — Audit's notification types and category.

The notification service is the platform's (``ccure_platform/notifications``);
what a scan raises is Audit's. ``type`` and ``category`` are stored as plain
strings, so the platform never needed these as members of its own enums — they
used to sit there, which put Audit's words in the platform. The values are
unchanged, so existing rows and the API read exactly as before.

Importing this module registers the ``scan`` category with the platform, so the
unread summary keeps listing it (zero when nothing is unread). It is imported by
``scans/db_helpers.py`` — the only place a scan raises one, in the API and in the
Celery workers alike — and by ``main.py``.
"""

from __future__ import annotations

from enum import Enum

from ccure_platform.api import register_notification_categories


class AuditNotificationType(str, Enum):
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_PAUSED = "scan_paused"
    VULNERABILITY_FOUND = "vulnerability_found"


class AuditNotificationCategory(str, Enum):
    SCAN = "scan"


register_notification_categories(AuditNotificationCategory.SCAN)
