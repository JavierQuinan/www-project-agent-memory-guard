"""Adversarial tests for the isolated, non-production approval gate."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from agent_memory_guard.write_gate_research import ResearchApprovalGate, WriteEnvelope


def sample():
    return WriteEnvelope("w1", "tenant-a", "notes/key", "set", b"safe", "v1", "agent", 100)


def test_approval_is_required_and_consumed_once():
    gate, item = ResearchApprovalGate(), sample()
    assert gate.stage(item).reason == "pending"
    assert gate.consume(item, now=1).reason == "approval_required"
    assert gate.approve(item.write_id, approver="reviewer", now=1).accepted
    assert gate.consume(item, now=1).reason == "consumed"
    assert gate.consume(item, now=1).reason == "not_found"


def test_requester_cannot_approve_own_write():
    gate, item = ResearchApprovalGate(), sample()
    gate.stage(item)
    assert gate.approve(item.write_id, approver="agent", now=1).reason == "invalid_approver"


def test_approval_is_bound_to_all_critical_fields():
    for field, value in (
        ("tenant", "tenant-b"),
        ("target", "other/key"),
        ("operation", "delete"),
        ("payload", b"tampered"),
        ("policy_revision", "v0"),
        ("requester", "other-agent"),
        ("expires_at", 200),
    ):
        gate, item = ResearchApprovalGate(), sample()
        assert gate.stage(item).accepted
        assert gate.approve(item.write_id, approver="reviewer", now=1).accepted
        assert gate.consume(replace(item, **{field: value}), now=1).reason == "payload_changed"
        assert gate.consume(item, now=1).accepted


def test_expired_approval_rejected():
    gate, item = ResearchApprovalGate(), sample()
    gate.stage(item)
    assert gate.approve(item.write_id, approver="reviewer", now=100).reason == "expired"
    assert gate.consume(item, now=100).reason == "expired"


def test_duplicate_write_id_cannot_replace_pending():
    gate, item = ResearchApprovalGate(), sample()
    assert gate.stage(item).accepted
    assert gate.stage(replace(item, payload=b"replacement")).reason == "duplicate_write_id"


def test_concurrent_consume_has_exactly_one_winner():
    gate, item = ResearchApprovalGate(), sample()
    gate.stage(item)
    gate.approve(item.write_id, approver="reviewer", now=1)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: gate.consume(item, now=1), range(32)))
    assert sum(result.accepted for result in results) == 1


def test_invalid_expiry_is_rejected_at_stage():
    gate = ResearchApprovalGate()
    assert gate.stage(replace(sample(), expires_at=True)).reason == "invalid_envelope"
    assert gate.stage(replace(sample(), expires_at=-1)).reason == "invalid_envelope"


def test_approval_cannot_be_granted_twice():
    gate, item = ResearchApprovalGate(), sample()
    gate.stage(item)
    assert gate.approve(item.write_id, approver="reviewer", now=1).accepted
    assert gate.approve(item.write_id, approver="other", now=1).reason == "already_approved"


def test_consumed_write_id_cannot_be_restaged_in_same_process():
    gate, item = ResearchApprovalGate(), sample()
    assert gate.stage(item).accepted
    assert gate.approve(item.write_id, approver="reviewer", now=1).accepted
    assert gate.consume(item, now=1).accepted
    assert gate.stage(item).reason == "duplicate_write_id"
    assert gate.stage(replace(item, payload=b"replay")).reason == "duplicate_write_id"


def test_concurrent_restaging_after_consumption_fails():
    gate, item = ResearchApprovalGate(), sample()
    gate.stage(item)
    gate.approve(item.write_id, approver="reviewer", now=1)
    assert gate.consume(item, now=1).accepted
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: gate.stage(item), range(24)))
    assert all(result.reason == "duplicate_write_id" for result in results)


def test_pending_write_is_not_exposed_as_committed_memory():
    gate, item = ResearchApprovalGate(), sample()
    assert gate.stage(item).accepted
    assert not hasattr(gate, "get")
    assert not hasattr(gate, "set")
    assert gate.consume(item, now=1).reason == "approval_required"


def test_expiry_change_does_not_extend_approval():
    gate, item = ResearchApprovalGate(), sample()
    assert gate.stage(item).accepted
    assert gate.approve(item.write_id, approver="reviewer", now=1).accepted
    assert gate.consume(replace(item, expires_at=1000), now=99).reason == "payload_changed"
    assert gate.consume(item, now=100).reason == "expired"
