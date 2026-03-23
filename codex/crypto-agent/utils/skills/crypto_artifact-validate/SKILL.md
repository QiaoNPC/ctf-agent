---
name: crypto_artifact-validate
description: Enforce artifact-contract, presence, dependency, freshness, and cross-reference correctness for the artifact graph.
metadata:
  short-description: Validate the artifact graph and block progression on hidden state failures
---

## Purpose
This skill is the enforcement layer for the architecture. Its job is to make sure the artifact trail is real, current, internally consistent, and phase-appropriate. It should catch the common workflow failure where the manager writes a few files, forgets to update dependent files, and then keeps reasoning as if the graph were coherent.

## When to use
Use this skill after every skill that writes or materially changes artifacts. Also use it before resuming prior work, after invalidation events, before skeptical review skill execution, and before solver readiness claims.

## Inputs
- all canonical artifacts that exist for the current workflow stage
- `artifacts/out/artifact_manifest.json`
- `artifacts/out/dependency_graph.json`
- `artifacts/out/invalidation_rules.json`
- hash-state artifacts

## Required outputs
- `artifacts/out/validation_reports/latest.json`
- one phase-scoped validation report when a phase gate is being checked
- updated stale-state reporting when dependencies changed
- explicit failure notes in findings or continuation artifacts when progression is blocked

## Clause-by-clause operating rules
1. **Presence validation.** Confirm that every required artifact for the current phase exists. Missing required files are a hard failure.
2. **Artifact-contract validation.** Validate canonical JSON files against their artifact-contracts. A syntactically valid but semantically incomplete artifact still fails.
3. **Reference validation.** Every artifact path referenced by another artifact must exist unless it is explicitly marked pending and gated from use.
4. **Dependency validation.** If an artifact depends on upstream files that changed, mark it stale and block any downstream claim that still uses it.
5. **Cross-field validation.** Catch mismatches such as a verified hypothesis without evidence files, a solver plan referencing a rejected HID, or a writeup that names an attack path not present in findings.
6. **Removal hygiene.** When clauses or branches were removed, confirm there are no lingering references in summaries, next actions, or stale reports.

## Edge cases
- optional artifacts becoming implicitly required due to downstream references
- old logs still present after a plan was redesigned
- two hypotheses sharing evidence paths accidentally
- manual edits to artifacts that bypass the producing workflow and silently break artifact-contracts
- stale solver verification surviving after a script change
- reports that validate a phase globally while one HID-specific file is missing


## Review checklist
Before declaring a phase valid, explicitly ask:
- are all required canonical artifacts present for this phase?
- do all referenced files exist on disk?
- do stale dependencies invalidate any seemingly successful result?
- do findings, continuation plan, and phase status tell the same story?
- did any removed branch survive indirectly in notes, scores, or writeup text?

## Common failure patterns this skill must catch
- a result file was regenerated but the summary still points to an older log
- a new hypothesis was added but no dependency edge was recorded
- a script changed and benchmark claims were not refreshed
- a artifact-contract changed but a legacy artifact still passes informal human inspection
- a hybrid branch changed while solver readiness remained marked true


## Validation gate
This skill passes only if the latest validation report says the current phase is coherent and any stale-state issues are either resolved or explicitly blocking continuation.
