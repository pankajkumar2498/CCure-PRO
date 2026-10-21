"""
Remediation SLA — an organisation setting.

The deadlines an organisation has configured for remediating findings. Stored
under ``organizations.settings["remediation_sla"]``, written through
``PUT /remediation/sla-policy`` by anyone holding ``settings:update``.

Only the *setting* is here, exactly as stored and **uninterpreted**. What it
means for a finding — the severity names it is keyed by, the product defaults
that apply where it says nothing, the KEV rule, due dates, and how a partial or
malformed value is read — is Audit's, in ``core.remediation.sla``, the one
Audit module allowed to call this feature. Passing the stored value through
unchanged is what keeps every edge case that function handles behaving as it
always has.

Stored independently of scan execution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ccure_platform.models import Organization
from sqlalchemy.orm import Session

#: Where the setting is stored inside ``organizations.settings``. Moved from
#: ``core.remediation.sla.SETTINGS_KEY`` in Phase 8.4: where a setting is kept
#: is its owner's business.
SETTINGS_KEY = "remediation_sla"


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationSlaSettingView:
    """
    ``stored`` is the setting as JSON text, or None when the organisation has
    never set one. Text rather than typed fields, deliberately: typing it would
    mean interpreting it, and the interpretation is the consumer's.
    """

    org_id: str
    stored: str | None


def _row(db: Session, org_id: str | None):
    if not org_id:
        return None
    return db.query(Organization).filter(Organization.id == str(org_id)).first()


def remediation_sla_setting(
    db: Session, org_id: str | None
) -> RemediationSlaSettingView | None:
    """The organisation's stored setting, or None if the organisation does not exist."""
    row = _row(db, org_id)
    if row is None:
        return None
    settings = row.settings or {}
    stored = json.dumps(settings[SETTINGS_KEY]) if SETTINGS_KEY in settings else None
    return RemediationSlaSettingView(org_id=str(row.id), stored=stored)


def store_remediation_sla_setting(
    db: Session, org_id: str, value: Mapping[str, Any]
) -> None:
    """
    Replace the organisation's stored setting with ``value``.

    The caller validates and merges; this stores. Nothing is committed — the
    caller's transaction also carries its audit event, so the setting and the
    record of changing it land together or not at all.
    """
    row = _row(db, org_id)
    if row is None:
        raise LookupError(f"organisation {org_id!r} does not exist")
    settings = dict(row.settings or {})
    settings[SETTINGS_KEY] = dict(value)
    row.settings = settings
