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

## Deep security review — hidden failure modes (2026-10-26)

Classification: **OBSERVED** = directly visible in the research code/interface; **HYPOTHESIS** = credible attack to validate; **REQUIRED** = acceptance criterion, not an implemented protection. Severity is preliminary until exploitability and impact are measured.

| ID | Finding | Classification | Priority | Required verification / remediation |
| --- | --- | --- | --- | --- |
| C01 | The evaluator greedily accepts the first unique domain/origin pair. With overlapping domains and origins, changing input order can change the count of independent corroborations. | OBSERVED | P1 | Define independence mathematically (maximum bipartite matching or explicit unique attested provenance roots), make result permutation-invariant; property-based permutation tests. |
| C02 | Evidence.authenticated is a caller-populated boolean and source_class/domain/origin are plain strings. An untrusted caller could forge these if the integration passes them through. | OBSERVED boundary limitation | P0 before integration | Construct attested provenance inside a trusted adapter; verify identity, authorization and provenance chain; never accept trust claims from model/tool data. |
| C03 | A decision contains only allowed/domains/reason; it is not bound to a specific write, key, tenant, policy revision, or expiry. | OBSERVED | P0 before integration | Bind decisions cryptographically or transactionally to canonical request identity and current policy; never treat the standalone decision as an authorization token. |
| C04 | The evaluator accepts arbitrary iterables and accumulates sets without an explicit evidence-count/size/time budget. | OBSERVED | P1 | Reject over-budget batches and oversized fields before iteration; bound CPU, memory and request time; reject malformed/nonfinite inputs. |
| C05 | Invalid Evidence objects cause failure only when reached; hostile or infinite iterators can block before rejection. | HYPOTHESIS | P1 | Validate materialized bounded input; test malicious generators, exceptions during iteration, and huge evidence lists. |
| C06 | Plain string provenance identifiers may differ by case, Unicode normalization, whitespace, encoding, or aliases while referring to the same real source. | HYPOTHESIS | P1 | Use stable, attested opaque IDs and canonicalization at ingestion; reject ambiguous aliases and collision cases. |
| C07 | Distinct tools may relay the same document, account, or attacker-controlled origin, creating false independence even if their domain strings differ. | HYPOTHESIS | P0 | Derive independence from authenticated upstream provenance roots and control relationships, not tool names or counts. |
| C08 | Tenant is checked but agent, namespace, key, operation, requester and trust domain are not parameters to the standalone evaluator. | OBSERVED | P0 before integration | Bind all scopes in the pending-write envelope; test cross-tenant, cross-agent, cross-key, cross-operation replay. |
| C09 | SourceClass.SYSTEM is a configuration classification, not authentication, as noted by the upstream maintainer. | CONFIRMED design caveat | P0 | Define which authenticated principals may assert SYSTEM; deny privilege escalation through client-controlled metadata. |
| C10 | No atomic commit or durable pending state exists in the current MemoryStore protocol; get/set checks would be race-prone. | OBSERVED | P0 | Specify transactional compare-and-set, unique idempotency keys, immutable pending records, and crash recovery. |
| C11 | Approvals can become stale after payload, policy, actor permissions, key state or expiry changes. | HYPOTHESIS | P0 | Revalidate inside the commit transaction and invalidate on any bound-field or authorization change. |
| C12 | Approval can be replayed across concurrent workers or after a crash unless consumed atomically. | HYPOTHESIS | P0 | Single-use approval records and durable monotonic state machine; fault-injection and concurrency tests. |
| C13 | Pending content may leak through keys(), items(), snapshot(), search, embeddings, summaries, logs, metrics, caches or replication. | HYPOTHESIS | P0 | Store pending separately; enumerate every read/export path and prove default invisibility. |
| C14 | An append-only audit trail may still leak sensitive content or be silently lost on partial failures. | HYPOTHESIS | P1 | Record minimal metadata, redact secrets, make transitions and audit durable together, test storage failures. |
| C15 | A compromised or malicious approver can approve their own write or coordinate multiple nominally independent approvals. | HYPOTHESIS | P1 | Separation of duties, authenticated approver identities, anti-collusion controls where feasible, configurable quorum. |
| C16 | Policy downgrade, trusted-class expansion or tenant reconfiguration can silently turn previously untrusted evidence into valid evidence. | HYPOTHESIS | P0 | Bind policy version; invalidate or re-evaluate pending writes on changes; privileged change audit. |
| C17 | Expiry based on wall-clock time alone is vulnerable to clock skew, rollback, and inconsistent distributed nodes. | HYPOTHESIS | P1 | Server-authoritative time and transaction-time checks; test skew and boundary conditions. |
| C18 | Deleting or revoking evidence after approval may leave an authorized pending write unless commit rechecks provenance. | HYPOTHESIS | P1 | Verify evidence freshness/revocation at commit; define evidence lifetime and retention. |
| C19 | A malicious actor may exhaust pending-write quotas, approvals, or evidence indexes to deny service to other tenants. | HYPOTHESIS | P1 | Per-tenant/actor quotas, expiry, bounded queues, rate limits and fairness tests. |
| C20 | A legitimate approval path could be permanently blocked by overly strict source policies or duplicate detection. | HYPOTHESIS | P2 | Positive-path tests, clear rejection reasons and measurable false-positive rates. |
| C21 | The fork baseline reports 0.3.2 while upstream moved beyond 0.3.3; implementing against stale APIs risks regressions and loss of upstream fixes. | OBSERVED | P0 before PR | Sync fork with upstream, compare changes and rerun full suite before integrating. |
| C22 | The current evaluator returns a mutable-meaning decision after a time-of-check; its validity may change before time-of-use. | OBSERVED design limitation | P0 | Make evaluator advisory only; final authorization must happen atomically against current state. |
| C23 | Policy threshold accepts bool as an int in Python (True == 1), and does not enforce an upper bound or exact integer type. | OBSERVED | P2 | Validate strict int range, reject bool, enforce configured quorum maximum. |
| C24 | Trusted source classes may be provided as arbitrary objects; malformed policy values may behave unpredictably or be mutable across calls. | HYPOTHESIS | P2 | Validate policy schema and immutable typed enums at trusted configuration load. |

### Reproducible order-dependence example (C01)

For threshold=2, all records authenticated, tenant=A, source_class=system:
- E1=(domain=A, origin=X)
- E2=(domain=A, origin=Y)
- E3=(domain=B, origin=X)

Order [E1,E2,E3] selects E1 then rejects E2 (same domain) and E3 (same origin), yielding one independent record and DENY.
Order [E2,E3,E1] selects E2 and E3, yielding two independent records and ALLOW.
This is a code-derived counterexample, **not yet an executed regression test**. A security policy should not grant or deny solely because the evidence order changes.

### Priority execution gates

**P0 — block upstream PR:** trusted provenance attestation; immutable request/decision binding; atomic commit and replay protection; pending isolation; source independence; policy revision binding; synchronize fork and run regression suite.

**P1 — hardening:** deterministic independence algorithm; bounded inputs; alias handling; revocation, crash recovery, concurrent worker tests; audit integrity; tenant quotas.

**P2 — correctness/operability:** strict schema and type validation, error semantics, positive-path compatibility, metrics and documentation.

### Required test evidence and reporting discipline

- Unit tests: permutation invariance, duplicate roots, spoofed SYSTEM, cross-tenant/cross-agent, malformed/oversized/infinite evidence, invalid threshold and policy.
- Stateful tests: payload mutation, replay, expiry, revocation, concurrent approve/commit, crash between transition and audit, stale policy.
- Integration tests: every read/export path excludes pending data, real backend transactional behavior, Python supported versions, backwards compatibility.
- CI: pin exact commit SHA and record workflow URLs, job conclusions and counts; missing notifications or a published commit are **not** evidence of green CI.
- Record each issue as confirmed, reproduced, or hypothetical. Never claim exploitation or resolution without a passing targeted test and code review.
- No upstream PR, public comment, merge, or deployment until separately authorized.
