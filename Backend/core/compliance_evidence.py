"""
core/compliance_evidence.py
Normalized evidence payloads for rule check evaluations, from the providers
the producing capabilities register.

Compliance consumes evidence and queries no other capability's table (G4, C4
of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md). It declares the
evidence sources a rule may name, keeps the registry of who answers each, and
caches the answers. The answers live with the tables they read — the findings
store, the asset registry, the network topology and web application scanning
— and Audit's composition root, ``ccure_audit/evidence_providers.py``,
registers them. Until G4 this module queried those tables itself, through
eight adapters that moved, body for body, to the producers.
"""

import json
import logging
from typing import Any, Callable, Dict, Optional

from core.redis_client import get_redis_client
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.compliance.evidence")
redis = get_redis_client()


EPL_CACHE_TTL = 300  # 5 minutes cache

# The complete set of evidence sources a rule may declare. This is the single
# source of truth: a provider is registered for each, cache invalidation
# iterates it, and `tests/compliance/test_compliance_rule_wiring.py` asserts
# that every active rule names one of these and reads a key its provider
# actually emits.
#
# `manual` is included because it is a legitimate rule declaration — the scan
# loop skips those rules and produces an org-level attestation placeholder
# instead — but it has no provider and never reaches `_fetch_and_translate`.
EVIDENCE_SOURCES: tuple[str, ...] = (
    "vulnerability_audit",
    "malware_scan",
    "services_ports",
    "tls_certificates",
    "network_topology",
    "credential_validation",
    "offline_configuration",
    "web_vulnerability_audit",
)

VALID_RULE_EVIDENCE_SOURCES: frozenset = frozenset(EVIDENCE_SOURCES) | {"manual"}

#: What answers one evidence source for one asset: ``(db, asset_id) -> payload``.
#: The payload is a dict of the keys the rules read; a key whose value was not
#: collected is absent, which the engine reads as not assessed.
EvidenceProvider = Callable[[Session, str], Dict[str, Any]]

_PROVIDERS: Dict[str, EvidenceProvider] = {}


class EvidenceProviderMissing(RuntimeError):
    """A declared evidence source has no provider in this process."""


def register_evidence_provider(source: str, provider: EvidenceProvider) -> None:
    """
    Register who answers *source*. Registering the same provider again does
    nothing; a second, different provider for one source is refused, because
    which of the two answered would then depend on import order.
    """
    if source not in EVIDENCE_SOURCES:
        raise ValueError(
            f"{source!r} is not an evidence source; the sources are "
            f"{', '.join(EVIDENCE_SOURCES)}"
        )
    current = _PROVIDERS.get(source)
    if current is provider:
        return
    if current is not None:
        raise ValueError(f"evidence source {source!r} already has a provider")
    _PROVIDERS[source] = provider


def evidence_provider(source: str) -> Optional[EvidenceProvider]:
    """The provider registered for *source*, or None."""
    return _PROVIDERS.get(source)


def registered_evidence_sources() -> tuple[str, ...]:
    """The declared sources that have a provider in this process, in order."""
    return tuple(s for s in EVIDENCE_SOURCES if s in _PROVIDERS)


class ComplianceEvidenceProvider:
    @staticmethod
    def get_cache_key(asset_id: str, source: str) -> str:
        return f"compliance:evidence:{asset_id}:{source}"

    @classmethod
    def invalidate_asset_evidence_cache(
        cls, asset_ids: list, sources: list = None
    ) -> None:
        """Batch-flushes evidence cache keys in Redis using a pipeline."""
        if not redis or not asset_ids:
            return

        # These must be the names `_fetch_and_translate` dispatches on, because
        # that is what `get_cache_key` uses to build the key. Three of the
        # names here used to be inventions — `active_services`,
        # `tls_ssl_configuration` and `network_link_topology` are not evidence
        # sources — so the flush deleted keys that never existed and left the
        # real ones in place. A scan that had just re-collected a host's ports
        # then evaluated against evidence up to five minutes old.
        known_sources = sources or list(EVIDENCE_SOURCES)

        try:
            pipe = redis.pipeline()
            keys_count = 0
            for aid in asset_ids:
                for src in known_sources:
                    pipe.delete(cls.get_cache_key(aid, src))
                    keys_count += 1
            pipe.execute()
            log.info(
                f"Invalidated {keys_count} Redis evidence cache keys for assets: {asset_ids}"
            )
        except Exception as e:
            log.warning(f"Failed to clear Redis evidence cache pipeline: {e!s}")

    @classmethod
    def get_normalized_evidence(
        cls, db: Session, asset_id: str, source: str
    ) -> dict[str, Any]:
        """Resolves normalise evidence, utilizing Redis cache."""
        cache_key = cls.get_cache_key(asset_id, source)
        try:
            cached_data = redis.get(cache_key)
            if cached_data:
                log.debug(f"Cache hit for evidence {cache_key}")
                return json.loads(cached_data)
        except Exception as e:
            log.warning(f"Failed to query Redis cache: {e!s}")

        # Cache miss - fetch and translate
        log.info(
            f"Cache miss. Resolving raw findings for asset {asset_id}, source {source}"
        )
        payload = cls._fetch_and_translate(db, asset_id, source)

        try:
            redis.setex(cache_key, EPL_CACHE_TTL, json.dumps(payload))
        except Exception as e:
            log.warning(f"Failed to save evidence to Redis cache: {e!s}")

        return payload

    @classmethod
    def _fetch_and_translate(
        cls, db: Session, asset_id: str, source: str
    ) -> dict[str, Any]:
        """Asks the provider registered for *source*.

        A declared source with no provider raises ``EvidenceProviderMissing``:
        a process that evaluated compliance without its providers would
        otherwise report every automated rule as not assessed, a result that
        looks like a quiet host rather than a broken deployment.
        """
        if source in EVIDENCE_SOURCES:
            provider = _PROVIDERS.get(source)
            if provider is None:
                raise EvidenceProviderMissing(
                    f"No evidence provider is registered for '{source}' in this "
                    "process. ccure_audit.evidence_providers registers them; it "
                    "is in core/celery_app.py's imports."
                )
            return provider(db, asset_id)

        # No adapter for this source. Returning an empty payload made every key
        # look absent, and an absent key evaluated to a failed control — so an
        # unsupported or not-yet-collected evidence source reported the asset as
        # non-compliant rather than as unassessed. The caller has to be able to
        # tell those apart.
        log.warning(
            "No evidence adapter for source '%s'; asset %s cannot be assessed "
            "against rules that depend on it",
            source,
            asset_id,
        )
        return {
            "_evidence_available": False,
            "_reason": f"No evidence adapter is implemented for source '{source}'.",
        }
