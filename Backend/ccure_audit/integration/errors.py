"""The one exception the integration adapter raises."""

from __future__ import annotations


class MappingError(ValueError):
    """
    Audit's stored data cannot be expressed in the contract without inventing
    something — a ``verified_fixed`` finding with no verifying scan, a risk
    acceptance with no reason, a vocabulary value the contract does not define.

    The adapter refuses rather than fills the gap: a contract message that
    papers over inconsistent data is a false statement to another module. The
    message names the object and the field, so the inconsistency can be found
    and fixed where it lives.
    """
