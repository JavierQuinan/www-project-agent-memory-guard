# Trusted corroboration and approval gates — security research

Scope: OWASP Agent Memory Guard issue #15. Draft design in the JavierQuinan fork; no upstream integration or public PR.

## Threat model
An attacker may control USER_INPUT, EXTERNAL_TOOL, UNKNOWN, retrieved text, repeated submissions, and arbitrary claimed SourceClass metadata in untrusted integrations. A caller-supplied SYSTEM label is not authentication. Treat the trust decision as a property of an authenticated adapter or policy boundary, not a claim inside the write payload.

## Fail-closed contract
1. Pending writes are distinct from committed memories; default retrieval, search, embeddings, and summaries MUST exclude them.
2. Evidence counts by independently authenticated provenance domain, not by number of writes or asserted source labels. Copies, retries, and shared upstream origins do not add votes.
3. A pending request is bound to a canonical digest of payload, target key, operation, tenant, agent, actor, policy version, and expiry. Changing any bound field invalidates prior approvals.
4. Approval is authenticated, scoped, expires, and is single-use. Requesting actors cannot approve their own writes unless explicitly authorized by policy.
5. A write commits only via atomic compare-and-set after checking current policy and authorization; failures never silently commit. Idempotent retries return the original decision.
6. Reject cross-tenant evidence and approval; log a durable, append-only audit event for transitions without logging sensitive payloads.
7. Revalidate provenance and policy on commit. Rejected, expired, revoked, and quarantined requests remain unavailable to ordinary memory reads.
8. Treat clock changes, malformed metadata, missing trust context, storage failures, and concurrent duplicate approvals as non-authorizing.

## Adversarial test matrix (must pass before proposing upstream PR)
- USER_INPUT/EXTERNAL_TOOL/UNKNOWN claiming SYSTEM does not gain trusted provenance.
- Two copies of one tool result count as one source; two tools using the same underlying document also count as one.
- Agent-authored self-corroboration never authorizes a write.
- Evidence from another tenant, namespace, or actor cannot be reused.
- Pending data is invisible to normal retrieval, search, embeddings, and summaries.
- Payload, target, scope, or policy changes invalidate approval.
- Expired/revoked/replayed approvals and double-submit races cannot commit twice.
- Simultaneous corroborations are atomic and respect the independence threshold.
- Missing metadata, failed storage, and audit failure fail closed.
- Legitimate independent evidence and a properly scoped human approval still succeed.

## Upstream collaboration
Issue #15 already contains a design by mironovisa covering distinct pending objects, provenance domains, exact approval binding, atomic transitions, and append-only auditing. Build on that work rather than duplicate it. Confirm maintainers' preferred API and storage interface before a feature implementation. Keep this research branch independent of the earlier self-reinforcement PR #124.

## Exit criteria
Working isolated implementation, unit and concurrency tests, integration tests for all read paths, static checks, CI green on exact HEAD, security review, then a narrowly scoped upstream PR with threat model and evidence. No merge or deploy without explicit authorization.

## Baseline audit — 2026-10-26
- Fork research branch was created from JavierQuinan/main. Its src/agent_memory_guard/__init__.py still reports 0.3.2; upstream has subsequently reported 0.3.3 and pyproject.toml currently reports 0.4.0. Verify upstream sync and compare commits before any runtime implementation.
- Current MemoryStore protocol exposes get/set/delete/keys/items/contains only. It does not expose an atomic compare-and-set transaction, a pending-write type, or a durable audit log. A gate implemented as ordinary get followed by set would be race-prone and must not be presented as secure.
- InMemoryStore uses an unguarded dict; it is suitable for isolated experiments but not a cross-process approval coordinator. Pending writes must not be stored in the same enumerable keyspace as committed memories.
- Start with a standalone pure policy evaluator and adversarial unit tests only after confirming upstream interfaces. Keep storage-specific commit logic out of the initial patch until maintainers agree on an atomic backend contract.
- Compatibility: Python >=3.9. Do not rely on Python 3.10-only syntax or external authentication claims supplied by untrusted callers.
