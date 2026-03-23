---
name: crypto_validate
description: Validate hypotheses with focused scripts, explicit evidence artifacts, feasibility checks, and skeptical-review-ready proof trails.
metadata:
  short-description: Prove, reject, or bound hypotheses using per-HID plans, results, and evidence bundles
---

## Purpose
This skill turns hypotheses into proof, rejection, or bounded inconclusive status. It must create a visible evidence trail for every hypothesis it touches and it must update scores when evidence materially changes. This is the skill where narrative becomes adjudicated state.

## Inputs
- `artifacts/hypotheses.json`
- `artifacts/params.json`
- optional decode, hybrid, remote, probe, and specialist artifacts
- optional prior findings and validation artifacts
- relevant embedded operational guidance in the manager and skills when choosing discriminators and rejection criteria

## Required outputs
- update `artifacts/hypotheses.json`
- `artifacts/out/validation/validation_index.json`
- `artifacts/out/validation/validation_summary.json`
- for each actively validated hypothesis:
  - `artifacts/out/validation/<HID>_plan.json`
  - `artifacts/out/validation/<HID>_result.json`
  - `artifacts/out/validation/<HID>_evidence.json`
  - `artifacts/logs/<HID>_run1.txt` and additional run logs as needed
  - `artifacts/scripts/<HID>_validate_*.py` or `.sage` when code is required
- update `artifacts/out/findings.json`
- update `artifacts/out/hypothesis_scores.json` when evidence changes materially

## Core rules
1. One hypothesis, one focused validation plan.
2. Check preconditions before expensive work.
3. Record disproof signals, not just success signals.
4. Every validator run must leave a result artifact.
5. If a validator changes materially, update its plan artifact before rerunning.
6. Evidence artifacts must cite the concrete outputs that justified the resulting status.
7. When a hypothesis weakens, reduce its score explicitly instead of leaving confidence stale.
8. A rejected path should say what would have to change for it to be reopened.

## Validation operational guide requirements
Every per-HID plan should include:
- the concrete vulnerability path being tested
- the exact preconditions being checked
- the expected positive signal
- the strongest likely falsifier
- cost estimate and runtime risks
- dependency artifacts and freshness assumptions
- how outputs will update findings and scores

## Potential vulnerability-path operational guides to consider
- decode leakage turning into usable crypto parameters
- repeated-keystream recovery with offset uncertainty
- padding or format oracle partitioning
- RSA family splits including textbook misuse, shared-prime, and modulus linkage
- PRNG or seed recovery from low-entropy metadata
- protocol-state leakage through menus, retries, or transcript resets

## Validation cap policy
The hard caps below are tripled from earlier smaller defaults:
- maximum validation cycles per top hypothesis: **18**
- maximum validator redesign passes per hypothesis: **18**
- maximum targeted research assists per hypothesis after concrete blockage: **9**
- maximum simultaneously active top hypotheses in one validation sweep: **18**

## Feasibility rule for brute force or large search
For any non-trivial search, you must:
1. estimate expected trials or effective search space
2. microbenchmark ops/sec on this host
3. compute ETA
4. record the estimate in the validation plan and result artifacts
5. redesign when naive ETA exceeds 24 hours unless a clear reduction argument is recorded

## Edge cases
- a validator appears to succeed but only on a malformed subset of inputs
- remote probes introduce nondeterminism into what looked like a local proof
- a decode-dependent validator is invalidated after decode branching changes
- a rejection is caused by wrong byte order rather than wrong attack family
- a hypothesis is too broad and needs to split into children rather than being accepted or rejected whole


## Rejection and reopening policy
A rejected hypothesis should still be useful. Record:
- the strongest contradicting evidence
- whether the failure came from missing preconditions, wrong family, wrong parameters, or wrong modeling assumptions
- what future observation would justify reopening it

## Evidence-bundle checklist
A good `<HID>_evidence.json` should tell a skeptic:
- what was tested
- what concrete outputs mattered
- which outputs were noise or irrelevant
- why the result status was chosen over alternatives
- how scores changed because of this evidence


## Validation gate
This skill passes only if:
- validation index and summary exist and validate
- each active HID has plan, result, evidence, and logs
- findings and hypothesis scores were updated consistently
- any verified claim can be traced directly to scripts, logs, and evidence artifacts without hidden reasoning steps
