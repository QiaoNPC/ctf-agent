---
name: crypto_ragdb
description: Retrieve attack-family references, precondition checklists, and solver templates without letting retrieval replace local proof.
metadata:
  short-description: Use local retrieval as a bounded hypothesis and validation aid
---

## Purpose
This skill provides bounded retrieval over a curated knowledge base. It should accelerate recognition of attack families and validation structure, but never substitute for local evidence.

## Inputs
- current hypotheses or blocked validation questions
- specific unknowns such as attack preconditions, complexity heuristics, or known invariants

## Required outputs
- notes or research artifacts under `artifacts/out/research/`
- updates to research seed or validation plans when retrieval changed next actions

## Operating rules
1. Query narrowly.
2. Translate retrieval results into concrete local checks.
3. Record which external idea changed which artifact.
4. Prefer checklists and discriminators over full copied solve paths.
5. Drop retrieval outputs that cannot be grounded locally.

## Edge cases
- retrieval finding a very similar but not identical primitive
- known attack names anchoring the manager too early
- solver templates that smuggle in assumptions not present in current evidence


## Good retrieval targets
Use retrieval for:
- attack precondition checklists
- common discriminators for a family
- complexity estimates
- solver skeleton reminders
- failure-mode reminders for niche primitives

Avoid using retrieval as proof that your current challenge matches a famous writeup.


## Validation gate
Pass only if retrieval outputs are reflected in bounded next actions or explicit rejections, not in hand-wavy confidence inflation.
