---
name: crypto_research
description: Use online research surgically when a narrow unknown blocks a real branch, then convert that research into evidence-bound workflow changes.
metadata:
  short-description: Perform targeted online research without letting it dominate the workflow
---

## Purpose
This skill is for narrow, blocking unknowns that are not well served by local retrieval. It should be used sparingly and only when it can materially change a real branch.

## Inputs
- specific blocked question from a hypothesis or validation plan
- current evidence state showing why research is needed

## Required outputs
- research notes under `artifacts/out/research/`
- updated research seed, hypotheses, or validation plans when warranted
- explicit note in findings about what changed because of research

## Operating rules
1. Search for the uncertainty itself, not for a magical full solution.
2. Keep the question narrow enough that the answer could change a concrete validator.
3. Translate findings into local tests or explicit rejection reasons.
4. Avoid repeated broad searches that merely restate well-known attack families.

## Edge cases
- ambiguous nomenclature for niche primitives
- writeups that describe adjacent but different oracle conditions
- online examples with silent assumptions about padding, key sizes, or transcript semantics
- stale online sources that conflict with better local evidence


## Good online research targets
Search for:
- current terminology for a niche primitive
- exact preconditions of a suspected attack family
- complexity bounds for a mathematically specific route
- protocol or format quirks that explain observed evidence

Avoid searching with the implicit hope that a full solve writeup will substitute for local validation.


## Validation gate
Pass only if the research produced a concrete, evidence-bound adjustment or a justified no-op decision.
