---
name: crypto_solver-build
description: Build a deterministic reproducer only after verification, and prove that it works repeatably under recorded conditions.
metadata:
  short-description: Turn a verified weakness into a reproducible solver with verification artifacts
---

## Purpose
This skill packages the validated weakness into an executable reproducer. It is not the place to discover the attack. It is the place to encode an already-verified path cleanly, document its assumptions, and verify repeatability.

## Inputs
- verified hypothesis artifacts
- validation evidence and summary
- skeptical review readiness inputs
- current params, decode, and remote artifacts as needed

## Required outputs
- `artifacts/out/solver_plan.json`
- `artifacts/out/solver_verification.json`
- `artifacts/logs/solve_run1.txt`
- `artifacts/logs/solve_run2.txt`
- solver scripts under `artifacts/scripts/`
- updates to findings and writeup inputs

## Operating rules
1. Build from the verified path only.
2. Record all assumptions, required inputs, and environmental dependencies.
3. Keep the solver deterministic where the challenge permits.
4. Run it at least twice under recorded conditions.
5. If live interaction is required, record enough context to explain any variability.

## Edge cases
- solver succeeds only because of stale intermediate files
- hidden manual transformations between validation and solve stages
- live remote dependence that makes reruns non-identical
- probabilistic attacks requiring success-rate accounting rather than false determinism claims
- solve scripts that quietly implement a different attack than the validated one


## Solver readiness checklist
Do not build or approve a solver until you can answer yes to all of these:
- is the winning hypothesis verified rather than merely plausible?
- are all required upstream artifacts fresh?
- is the solver path identical to the validated path?
- are runtime assumptions documented?
- are success criteria observable and logged?

## Solver edge cases
- probabilistic attacks needing retry budgets and observed success rates
- remote state that changes between runs
- one-time flags or secrets requiring careful wording around reproducibility


## Validation gate
Pass only if the solver plan matches the verified hypothesis path and the verification artifact proves reproducible success or honestly documents the bounded non-determinism.
