---
name: crypto_artifacts-reuse
description: Reuse prior work only when hashes, dependencies, and artifact semantics still support it.
metadata:
  short-description: Resume safely from prior artifacts without inheriting stale state
---

## Purpose
This skill decides whether existing artifacts can be trusted, partially reused, or must be invalidated. It prevents the workflow from repeatedly starting over while also preventing the more dangerous failure mode of inheriting obsolete conclusions.

## Inputs
- existing `artifacts/` tree
- hash-state artifacts
- dependency graph and invalidation rules
- current challenge files and any newly observed remote or decode inputs

## Required outputs
- refreshed hash-state artifacts
- updated stale report
- updated continuation plan
- updated phase status
- explicit invalidation notes for every downstream artifact that lost freshness

## Detailed operating rules
1. Inventory the current artifact graph, not just top-level files.
2. Compute freshness using hashes of inputs, scripts, and upstream canonical artifacts.
3. Preserve reusable artifacts when their dependency chain is intact.
4. Mark stale artifacts aggressively when upstream conditions changed.
5. Record why an artifact is stale and what must be rerun to recover it.
6. If an artifact is semantically reusable but structurally outdated under a new artifact-contract, rewrite it or block its use.

## Edge cases
- same file path but different remote endpoint contents
- challenge files unchanged but operational guide-guided branch logic changed materially
- a decode result still valid, but the hypothesis ranking derived from it is stale
- helper logs reusable for context but not admissible as current validation evidence
- partial runs that created evidence artifacts without summary/index files


## Reuse decision operational guide
Classify every important artifact into one of four buckets:
1. **fresh and reusable**
2. **fresh but informational only**
3. **stale but salvageable with partial rerun**
4. **unsafe and must not influence decisions**

For each bucket, write the practical consequence into continuation planning. Do not merely label an artifact stale; say exactly what workflow branches are blocked by that staleness.

## Indirect-reference cleanup
When invalidating a route, remove or rewrite all references to it in:
- continuation plans
- findings summaries
- next-action queues
- solver notes
- skeptical review notes
- ranking tables


## Validation gate
Pass only if continuation plan, stale report, and invalidation consequences all agree on what is safe to reuse and what must be rebuilt.
