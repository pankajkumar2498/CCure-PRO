"""
db/models/scan_policies.py
──────────────────────────────────────────────────────────────────────────────
Reusable assessment policies — what a scan assesses, named and versioned.

Table
─────
  scan_policies — the reusable configuration a scan or a schedule points at

Why a new table rather than reusing ``compliance_policies``
───────────────────────────────────────────────────────────
``CompliancePolicy`` is the right *pattern* and Phase 0 recorded it as such.
It is not the right table, for the same reason ``compliance_scan_schedules``
was not the right table for ``scan_schedules``:

* ``compliance_policies.framework_id`` is a **NOT NULL** foreign key into
  ``compliance_frameworks``. A network scan policy has no framework, and a
  configuration policy may legitimately name *several* — the Ubuntu 24.04 STIG
  and the built-in pack together. Widening that column to nullable and adding
  a CHECK saying "a framework is required unless the policy is a scan policy"
  is a discriminated union wearing a compliance table's name.
* Its rule bridge, ``compliance_policy_rules``, expresses "these specific rule
  versions are in force". A scan policy selects by framework, profile,
  platform, family and severity — a *predicate*, not an enumeration. Storing
  the resolved rule set would freeze it: a benchmark reloaded next month would
  not reach a policy written today, which is the opposite of what an operator
  who selected "the Ubuntu 24.04 STIG" asked for.

What **is** copied from ``CompliancePolicy``, deliberately, is its lifecycle:
``policy_family_code`` + ``version_number`` under a UNIQUE constraint,
``status`` in draft/active/archived, and ``superseded_by_policy_id``. That
shape is what lets a completed scan name the exact configuration that produced
it while the family goes on being edited.

Why the settings are one JSONB column
─────────────────────────────────────
Same reason ``scan_schedules.scan_options`` is: a later phase's scan kind
brings its own parameters, and a column per setting means a migration on a
table holding customer policies every time one is added. The schema that
matters is enforced in code — ``core/scan_policy/validation.py`` refuses an
unknown key, so a misspelled setting is rejected at the API rather than stored
and never read. A JSONB blob nobody validates is the failure this avoids; a
JSONB blob with a validator in front of it is a schema that does not need
DDL to evolve.

**No secret ever goes in ``config``.** It is returned by the policy API, copied
into ``scans.options`` — which is client-visible — and printed in the report.
A credential is referenced by ``compliance_credentials.id`` on the scan or the
schedule, never carried here.
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

# ─────────────────────────────────────────────────────────────────────────────
# Vocabularies
# ─────────────────────────────────────────────────────────────────────────────

#: Lifecycle, spelled exactly as ``compliance_policies.status`` spells it. Two
#: vocabularies for one idea is how they drift.
POLICY_STATUS_DRAFT = "draft"
POLICY_STATUS_ACTIVE = "active"
POLICY_STATUS_ARCHIVED = "archived"

POLICY_STATUSES = (
    POLICY_STATUS_DRAFT,
    POLICY_STATUS_ACTIVE,
    POLICY_STATUS_ARCHIVED,
)

_STATUS_SQL = "status IN (" + ", ".join(f"'{s}'" for s in POLICY_STATUSES) + ")"

#: Which pipeline a policy may drive. One definition, shared with the spec, so
#: the API, the model and the resolver cannot disagree about what
#: "credentialed" means.
from db.scan_policy_kinds import POLICY_SCAN_KINDS  # noqa: E402

_KIND_SQL = "scan_kind IN (" + ", ".join(f"'{k}'" for k in POLICY_SCAN_KINDS) + ")"


class ScanPolicy(Base):
    """
    One reusable assessment configuration.

    ID: ``spol_{org_token}_{rand}`` — e.g. ``spol_defa_x9v1``.

    A policy is **always** tenant-owned. ``compliance_policies.tenant_id`` is
    nullable so a global baseline can ship, and that is right for a catalogue
    somebody else authored; it is wrong here, because a platform-wide scan
    policy would let an edit in one workspace change what another workspace's
    scans assess. There is no such thing as a shared scan policy in this model,
    and ``org_id`` is NOT NULL to make that structural rather than a convention
    the query layer has to remember.
    """

    __tablename__ = "scan_policies"
    __table_args__ = (
        # A family's versions are unique *within a tenant*. Two organisations
        # may each have a "linux-baseline" family and they are unrelated.
        UniqueConstraint(
            "org_id",
            "policy_family_code",
            "version_number",
            name="uq_scan_policy_family_version",
        ),
        CheckConstraint(_STATUS_SQL, name="ck_scan_policy_status"),
        CheckConstraint(_KIND_SQL, name="ck_scan_policy_scan_kind"),
        CheckConstraint("version_number >= 1", name="ck_scan_policy_version_positive"),
        Index("ix_scan_policies_org_status", "org_id", "status"),
        Index("ix_scan_policies_org_enabled", "org_id", "is_enabled"),
    )

    id = Column(String(100), primary_key=True)
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by = Column(
        String(150),
        ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    #: Stable across versions. A scan snapshot records the family and the
    #: version, so "which configuration produced this scan" survives every
    #: later edit of the family.
    policy_family_code = Column(String(100), nullable=False, index=True)
    version_number = Column(Integer, nullable=False, default=1)

    #: ``network`` | ``credentialed`` | ``any``. A policy is refused for a scan
    #: of a kind it does not cover, rather than being applied with the fields
    #: that happen to overlap — a network policy silently governing a
    #: credentialed audit would restrict nothing it was written to restrict.
    scan_kind = Column(String(32), nullable=False, default="any", index=True)

    #: The whole assessment configuration. Validated by
    #: ``core/scan_policy/validation.py`` before it is stored; never contains a
    #: secret, because this column reaches the API response, ``scans.options``
    #: and the generated report.
    config = Column(JSONB, nullable=False, default=dict)

    status = Column(String(20), nullable=False, default=POLICY_STATUS_DRAFT)
    #: Separate from ``status`` on purpose, exactly as ``ScanSchedule`` keeps
    #: ``is_enabled`` separate. "Archived" is a lifecycle statement about the
    #: configuration; "disabled" is an operational one about whether it may be
    #: used right now, and an operator wants to switch a policy off for a week
    #: without retiring it.
    is_enabled = Column(Boolean, nullable=False, default=True)
    superseded_by_policy_id = Column(
        String(100),
        ForeignKey("scan_policies.id", ondelete="SET NULL"),
        nullable=True,
    )

    #: Denormalised so the list view can warn before a delete without a
    #: correlated subquery per row. Incremented at dispatch, never decremented:
    #: it counts scans that were run under this policy, and a deleted scan does
    #: not un-run them.
    use_count = Column(Integer, nullable=False, default=0)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    schedules = relationship(
        "ScanSchedule",
        back_populates="policy",
        foreign_keys="ScanSchedule.policy_id",
    )

    def __repr__(self):
        return (
            f"<ScanPolicy {self.id!r} {self.policy_family_code!r} "
            f"v{self.version_number} status={self.status!r} "
            f"enabled={self.is_enabled}>"
        )

    @property
    def is_usable(self) -> bool:
        """
        Whether a new scan may be started with this policy.

        Draft is deliberately **not** usable. A policy nobody has finished
        writing must not be the thing a scheduled scan runs at 02:00, and the
        alternative — treating draft as usable — makes the status column
        decorative.
        """
        return bool(self.is_enabled) and self.status == POLICY_STATUS_ACTIVE
