---
name: crypto_hybrid-analysis
description: Map mixed decode-plus-crypto chains into explicit stages, transitions, and evidence-backed branch routes.
metadata:
  short-description: Build and validate hybrid stage maps instead of hand-waving mixed workflows
---

## Purpose
This skill handles challenges that are neither pure decoding nor clean cryptanalysis. Its job is to decompose the chain into stages, identify where representation work ends and cryptographic reasoning begins, and prevent the manager from treating a fuzzy chain as if it were already understood.

## Inputs
- decode outputs
- parameter artifacts
- remote or probe artifacts
- intake summary and candidate vulnerability-family notes

## Required outputs
- `artifacts/out/hybrid_route.json`
- `artifacts/out/hybrid_stage_map.json`
- `artifacts/out/hybrid_transition_checks.json`
- updates to findings and hypotheses when a stage becomes stable

## Operating rules
1. Name every stage explicitly: ingest, decode layer, parse layer, key derivation, crypto primitive interaction, oracle interaction, or final reconstruction.
2. Define the evidence supporting each transition between stages.
3. Record uncertainties separately for each stage so the whole chain does not appear stronger than its weakest link.
4. When one stage changes, mark downstream stages stale.
5. Use the hybrid route to decide where specialist skills belong.

## Edge cases
- decode output that could be either plaintext or key material
- remote interactions that both reveal and consume decoded data
- challenges where a transcript encodes parameters but also acts as an oracle input format
- mixed symbolic and binary stages where naive text assumptions break
- two competing stage maps both plausible from the same evidence


## Stage-map operational guide
For every stage, record:
- input artifact
- transformation applied
- output artifact
- certainty level
- evidence supporting the transition
- what downstream artifacts depend on it

This stage map should make invalidation easy. If a stage changes, you should instantly know what else must be marked stale.


## Validation gate
Pass only if the stage map is explicit, transitions are evidenced, and the route explains exactly where later validation should focus.
