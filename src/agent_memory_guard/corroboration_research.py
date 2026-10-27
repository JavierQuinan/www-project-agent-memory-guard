"""Experimental corroboration policy primitive for OWASP issue #15.

Evidence must be attested by a trusted host adapter. Caller-supplied
authenticated=True or source_class='system' is NOT authentication.
This evaluator never commits writes or grants reusable authorization.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


MAX_EVIDENCE = 256
MAX_IDENTIFIER_LENGTH = 256
MAX_THRESHOLD = 32


@dataclass(frozen=True)
class Evidence:
    domain: str
    tenant: str
    source_class: str
    authenticated: bool
    upstream_origin: str


@dataclass(frozen=True)
class CorroborationDecision:
    allowed: bool
    independent_domains: tuple[str, ...]
    reason: str


def _maximum_matching(pairs):
    """Find a deterministic maximum domain-to-origin matching."""
    edges = {}
    for domain, origin in pairs:
        edges.setdefault(domain, set()).add(origin)
    occupied = {}

    def augment(domain, seen):
        for origin in sorted(edges[domain]):
            if origin in seen:
                continue
            seen.add(origin)
            if origin not in occupied or augment(occupied[origin], seen):
                occupied[origin] = domain
                return True
        return False

    for domain in sorted(edges):
        augment(domain, set())
    return tuple(sorted(occupied.values()))


def evaluate_corroboration(
    evidence: Iterable[Evidence],
    *,
    tenant: str,
    threshold: int = 2,
    trusted_source_classes: frozenset[str] = frozenset({"system"}),
) -> CorroborationDecision:
    """Evaluate independent provenance domains; no authorization is issued.

    Maximum matching makes the result independent of evidence arrival order.
    A trusted adapter must authenticate provenance and normalize opaque IDs.
    """
    if (
        not isinstance(tenant, str)
        or not tenant
        or len(tenant) > MAX_IDENTIFIER_LENGTH
        or type(threshold) is not int
        or not 1 <= threshold <= MAX_THRESHOLD
        or not isinstance(trusted_source_classes, frozenset)
        or not trusted_source_classes
        or any(
            not isinstance(value, str)
            or not value
            or len(value) > MAX_IDENTIFIER_LENGTH
            for value in trusted_source_classes
        )
    ):
        return CorroborationDecision(False, (), "invalid_policy")
    pairs = set()
    try:
        for count, item in enumerate(evidence):
            if count >= MAX_EVIDENCE:
                return CorroborationDecision(False, (), "evidence_limit_exceeded")
            if not isinstance(item, Evidence):
                return CorroborationDecision(False, (), "invalid_evidence")
            if not all(
                isinstance(value, str) and 0 < len(value) <= MAX_IDENTIFIER_LENGTH
                for value in (item.domain, item.tenant, item.source_class, item.upstream_origin)
            ) or type(item.authenticated) is not bool:
                return CorroborationDecision(False, (), "invalid_evidence")
            if (
                item.authenticated
                and item.tenant == tenant
                and item.source_class in trusted_source_classes
            ):
                pairs.add((item.domain, item.upstream_origin))
    except (TypeError, ValueError, RuntimeError, OverflowError):
        return CorroborationDecision(False, (), "invalid_evidence")
    independent = _maximum_matching(pairs)
    if len(independent) < threshold:
        return CorroborationDecision(False, independent, "insufficient_independent_evidence")
    return CorroborationDecision(True, independent, "corroborated")
