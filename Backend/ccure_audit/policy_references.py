"""
The scheduling capability, registered as the answer to the policy API's
schedule references.

The scan-policy router reads the schedules that name a policy only through
its port, ``core.scan_policy.schedule_references``; scheduling answers it
(``core/scheduling/policy_references.py``). Registered here, not by
scheduling itself, so that scheduling imports no scan-policy code for it and
what Audit plugs into what is said in its composition root, as
``ccure_audit/scan_directory.py`` registers the scans capability's answers.

Only the API reads it (the policy routes), so ``main.py`` imports this module.
A process without it raises ``ScheduleReferencesMissing``.
"""

from __future__ import annotations

from core.scan_policy.schedule_references import register_schedule_references
from core.scheduling.policy_references import REFERENCES

register_schedule_references(REFERENCES)
