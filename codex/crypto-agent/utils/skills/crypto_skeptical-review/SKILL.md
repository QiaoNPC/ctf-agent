---
name: crypto_skeptical-review
description: Perform adversarial review as a manager-invoked skill. Challenge optimistic narratives, find stale dependencies, demand discriminative tests, and emit durable skeptical review artifacts before hypotheses, validation claims, or solver readiness are accepted.
---

# Crypto Skeptical Review

## Purpose
Use this skill whenever the manager needs a structured skeptical pass. This is **not** a second agent. It is a review skill invoked by the single manager to deliberately shift from proposal mode into challenge mode. The goal is to reduce overconfidence, surface hidden assumptions, and produce a durable challenge record that a human can audit.

The skill exists because proof-oriented cryptanalysis fails when promising stories are allowed to mature into solver logic without resistance. The manager must therefore pause at specific checkpoints and run a skepticism pass that tries to break the current narrative using the existing artifacts, dependency graph, invalidation map, and branch-specific evidence.

## When to use
Invoke this skill at a minimum in the following moments:
1. after hypotheses have been constructed and prioritized
2. after meaningful validation results exist and before a hypothesis is treated as operationally verified
3. before solver readiness is accepted and before the final solver is treated as deterministic

Also invoke it when:
- a branch changes materially
- a specialist path introduces new assumptions
- remote behavior looks stateful or unstable
- artifacts were invalidated and then regenerated
- the leading path changed because of research or decode reinterpretation
- two plausible paths remain live and the manager is tempted to collapse them too early

## Required inputs
Review all relevant upstream artifacts, including but not limited to:
- `artifacts/hypotheses.json`
- `artifacts/out/hypothesis_matrix.json`
- `artifacts/out/hypothesis_priority.json`
- `artifacts/out/hypothesis_scores.json`
- `artifacts/out/validation/validation_index.json`
- `artifacts/out/validation/validation_summary.json`
- `artifacts/out/findings.json`
- `artifacts/out/solver_plan.json`
- `artifacts/out/solver_verification.json`
- `artifacts/out/dependency_graph.json`
- `artifacts/out/invalidation_rules.json`
- `artifacts/out/hash_report.json`
- any branch-specific decode, hybrid, oracle, or specialist artifacts

## Required outputs
Produce the review artifact that matches the review moment:
- `artifacts/out/verifier/hypothesis_challenge.json`
- `artifacts/out/verifier/validation_challenge.json`
- `artifacts/out/verifier/solver_readiness_review.json`

You may also write supporting notes under `artifacts/out/verifier/` when the challenge cannot be captured cleanly in a single structured artifact, but the canonical review artifact for the phase is still mandatory.

## Review method
For each claim set under review:
1. restate the claim narrowly and without flourish
2. identify every dependency artifact the claim relies on
3. mark the weakest dependency in the chain
4. identify the cheapest discriminative test that would falsify the claim
5. check whether that test already exists and whether it still survives invalidation rules
6. identify stale assumptions, removed alternatives, and branch-merge mistakes
7. record whether the claim is accepted, disputed, or conditionally acceptable
8. if conditional, state the exact gating evidence still missing

## What to challenge
The skill should aggressively search for:
- unsupported jumps from data to interpretation
- decode ambiguity quietly treated as certainty
- transport or formatting artifacts mistaken for cryptographic evidence
- stale summaries whose inputs changed after hashing or invalidation
- vulnerability-family confusion, especially across RSA, stream/XOR, oracle, or hybrid routes
- branch collapse where multiple plausible paths were merged too early
- solver determinism claims that still depend on timing, luck, or manual judgment
- feasibility claims without measured throughput or bounded cost
- findings summaries that still mention removed hypotheses, removed caps, or invalidated sub-results

## Edge-case catalog
Pay extra attention to recurring process failures:
- score inflation after research without new local evidence
- repeated-key or nonce-reuse claims from too few samples
- remote transcripts assumed stateless when the remote is actually stateful
- RSA routes chosen because of large integers without checking framing or encoding first
- oracle routes chosen because of response variance that is really transport noise
- decode branches accepted without preserving ambiguity and confidence
- final summaries that retain indirect references to removed routes
- solver plans that silently rely on fixtures, comments, or hardcoded examples rather than live challenge values

## Validation gate
A skeptical review artifact passes only if it:
- names the reviewed claim set
- lists the dependency artifact set
- names the main disputes or confirms that no material disputes remain
- states the missing tests, if any
- records the final disposition as `accepted`, `disputed`, or `conditional`
- contains enough detail that the manager can act on it without re-deriving the challenge logic

An empty agreement note is not a valid review. A rubber stamp is a failure. The review must either challenge the path or explain why the path survived challenge.
