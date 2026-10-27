"""Isolated approval-gate research primitive for OWASP issue #15.

This is an in-memory test model, NOT a durable authorization service.
Only trusted host code may invoke approve(); callers must never control approver
identity or role claims. A production implementation requires transactional
storage, authenticated actors, revocation and persistent audit.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class WriteEnvelope:
    write_id: str
    tenant: str
    target: str
    operation: str
    payload: bytes
    policy_revision: str
    requester: str
    expires_at: int


@dataclass(frozen=True)
class GateResult:
    accepted: bool
    reason: str


class ResearchApprovalGate:
    """Thread-safe, single-process approval model; never stores committed memory."""

    def __init__(self):
        self._lock = threading.RLock()
        self._pending: Dict[str, tuple[WriteEnvelope, bytes, str | None]] = {}
        self._consumed_ids: set[str] = set()

    @staticmethod
    def _digest(envelope: WriteEnvelope) -> bytes:
        fields = (
            envelope.write_id, envelope.tenant, envelope.target,
            envelope.operation, envelope.policy_revision, envelope.requester,
            str(envelope.expires_at),
        )
        if any(not isinstance(value, str) or not value for value in fields):
            raise ValueError("invalid envelope")
        if type(envelope.expires_at) is not int or envelope.expires_at <= 0:
            raise ValueError("invalid expiry")
        if not isinstance(envelope.payload, bytes):
            raise ValueError("payload must be bytes")
        encoded = b"".join(
            len(value.encode("utf-8")).to_bytes(8, "big") + value.encode("utf-8")
            for value in fields
        )
        encoded += len(envelope.payload).to_bytes(8, "big") + envelope.payload
        return hashlib.sha256(encoded).digest()

    def stage(self, envelope: WriteEnvelope) -> GateResult:
        try:
            digest = self._digest(envelope)
        except (ValueError, AttributeError, OverflowError):
            return GateResult(False, "invalid_envelope")
        with self._lock:
            if envelope.write_id in self._pending or envelope.write_id in self._consumed_ids:
                return GateResult(False, "duplicate_write_id")
            self._pending[envelope.write_id] = (envelope, digest, None)
            return GateResult(True, "pending")

    def approve(self, write_id: str, *, approver: str, now: int) -> GateResult:
        """Caller MUST be a trusted host adapter, not a model/tool message."""
        with self._lock:
            record = self._pending.get(write_id)
            if record is None:
                return GateResult(False, "not_found")
            envelope, digest, existing = record
            if type(now) is not int or now >= envelope.expires_at:
                return GateResult(False, "expired")
            if not isinstance(approver, str) or not approver or approver == envelope.requester:
                return GateResult(False, "invalid_approver")
            if existing is not None:
                return GateResult(False, "already_approved")
            self._pending[write_id] = (envelope, digest, approver)
            return GateResult(True, "approved")

    def consume(self, envelope: WriteEnvelope, *, now: int) -> GateResult:
        """Atomically consume in this process; does NOT commit to MemoryStore."""
        try:
            digest = self._digest(envelope)
        except (ValueError, AttributeError, OverflowError):
            return GateResult(False, "invalid_envelope")
        with self._lock:
            record = self._pending.get(envelope.write_id)
            if record is None:
                return GateResult(False, "not_found")
            staged, expected, approver = record
            if type(now) is not int or now >= staged.expires_at:
                return GateResult(False, "expired")
            if not hmac.compare_digest(digest, expected):
                return GateResult(False, "payload_changed")
            if approver is None:
                return GateResult(False, "approval_required")
            self._consumed_ids.add(envelope.write_id)
            del self._pending[envelope.write_id]
            return GateResult(True, "consumed")
