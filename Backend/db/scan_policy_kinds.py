"""
Which pipeline a scan policy may drive — the domain of ``scan_policies.scan_kind``.

Moved here from ``core/scan_policy/spec.py`` (Phase 3 of the modular-platform
programme). The model builds its CHECK constraint from this tuple and had to
import the policy package to get it — the models layer depending on a
capability. The values are unchanged and ``core.scan_policy.spec`` re-exports
every name. This module imports nothing, so reading it loads no database code.
"""

from typing import Tuple

#: Which pipeline a policy may drive. ``any`` is a policy whose settings are
#: meaningful to both — a severity floor, say — and is what a policy defaults
#: to. The kinds match ``db.models.scan_schedules.SCAN_KINDS`` deliberately:
#: two vocabularies for "what sort of scan is this" is how they diverge.
POLICY_KIND_NETWORK = "network"
POLICY_KIND_CREDENTIALED = "credentialed"
POLICY_KIND_ANY = "any"

POLICY_SCAN_KINDS: Tuple[str, ...] = (
    POLICY_KIND_NETWORK,
    POLICY_KIND_CREDENTIALED,
    POLICY_KIND_ANY,
)
