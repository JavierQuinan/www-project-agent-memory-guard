"""Regression tests for experimental trusted corroboration policy."""
from itertools import permutations

from agent_memory_guard.corroboration_research import Evidence, evaluate_corroboration


def ev(domain, origin, tenant="a", source="system", authenticated=True):
    return Evidence(domain, tenant, source, authenticated, origin)


def test_order_independence_regression():
    records = [ev("A", "X"), ev("A", "Y"), ev("B", "X")]
    for ordered in permutations(records):
        result = evaluate_corroboration(ordered, tenant="a")
        assert result.allowed
        assert len(result.independent_domains) == 2


def test_duplicate_origin_rejected():
    assert not evaluate_corroboration(
        [ev("A", "X"), ev("B", "X")], tenant="a"
    ).allowed


def test_duplicate_domain_rejected():
    assert not evaluate_corroboration(
        [ev("A", "X"), ev("A", "Y")], tenant="a"
    ).allowed


def test_cross_tenant_and_untrusted_class_rejected():
    assert not evaluate_corroboration(
        [ev("A", "X"), ev("B", "Y", tenant="b")], tenant="a"
    ).allowed
    assert not evaluate_corroboration(
        [ev("A", "X"), ev("B", "Y", source="user_input")], tenant="a"
    ).allowed


def test_unauthenticated_record_rejected():
    assert not evaluate_corroboration(
        [ev("A", "X"), ev("B", "Y", authenticated=False)], tenant="a"
    ).allowed


def test_invalid_threshold_and_types_fail_closed():
    assert evaluate_corroboration([], tenant="a", threshold=True).reason == "invalid_policy"
    assert evaluate_corroboration([object()], tenant="a").reason == "invalid_evidence"


def test_evidence_budget_is_enforced():
    records = [ev("A", str(i)) for i in range(257)]
    assert evaluate_corroboration(records, tenant="a").reason == "evidence_limit_exceeded"


def test_valid_two_independent_sources_pass():
    assert evaluate_corroboration(
        [ev("A", "X"), ev("B", "Y")], tenant="a"
    ).allowed


def test_matching_is_permutation_invariant_for_multiple_domains():
    records = [
        ev("A", "X"), ev("A", "Y"), ev("B", "X"),
        ev("C", "Z"), ev("D", "Z"),
    ]
    expected = evaluate_corroboration(records, tenant="a", threshold=3)
    assert expected.allowed
    for shift in range(len(records)):
        rotated = records[shift:] + records[:shift]
        assert evaluate_corroboration(rotated, tenant="a", threshold=3) == expected


def test_exact_budget_boundary():
    records = [ev("A", str(i)) for i in range(256)]
    assert evaluate_corroboration(records, tenant="a").reason == (
        "insufficient_independent_evidence"
    )


def test_oversized_identifier_fails_closed():
    assert evaluate_corroboration(
        [ev("A" * 257, "X")], tenant="a"
    ).reason == "invalid_evidence"


def test_bad_authentication_type_fails_closed():
    assert evaluate_corroboration(
        [ev("A", "X", authenticated=1)], tenant="a"
    ).reason == "invalid_evidence"


def test_iterator_exception_fails_closed():
    def hostile():
        yield ev("A", "X")
        raise RuntimeError("source unavailable")
    assert evaluate_corroboration(hostile(), tenant="a").reason == "invalid_evidence"


def test_policy_class_configuration_must_be_immutable():
    assert evaluate_corroboration(
        [], tenant="a", trusted_source_classes={"system"}
    ).reason == "invalid_policy"


def test_no_evidence_never_authorizes():
    assert not evaluate_corroboration([], tenant="a", threshold=1).allowed
