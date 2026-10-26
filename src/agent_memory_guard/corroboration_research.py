"""Experimental fail-closed corroboration policy for issue #15.

This module does not commit writes or authenticate callers. The trusted
provenance records MUST be supplied by an authenticated host integration,
never copied from untrusted model/tool payload metadata.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Optional, Tuple


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
    independent_domains: Tuple[str, ...]
    reason: str


def evaluate_corroboration(
    evidence: Iterable[Evidence],
    *,
    tenant: str,
    threshold: int = 2,
    trusted_source_classes: FrozenSet[str] = frozenset({"system"}),
) -> CorroborationDecision:
    """Count independently authenticated, same-tenant provenance origins.

    An origin shared across tools counts once. This function is only a policy
    primitive: it cannot provide authentication, persistence, or atomic commit.
    """
    if not tenant or threshold < 1 or not trusted_source_classes:
        return CorroborationDecision(False, (), "invalid_policy")
    domains = set()
    origins = set()
    for item in evidence:
        if not isinstance(item, Evidence):
            return CorroborationDecision(False, (), "invalid_evidence")
        if not item.authenticated or item.tenant != tenant:
            continue
        if item.source_class not in trusted_source_classes:
            continue
        if not item.domain or not item.upstream_origin:
            continue
        if item.domain in domains or item.upstream_origin in origins:
            continue
        domains.add(item.domain)
        origins.add(item.upstream_origin)
    independent = tuple(sorted(domains))
    if len(independent) < threshold:
        return CorroborationDecision(False, independent, "insufficient_independent_evidence")
    return CorroborationDecision(True, independent, "corroborated")
