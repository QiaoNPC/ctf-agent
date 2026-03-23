---
name: crypto_writeup
description: Produce a concise but evidence-linked writeup that matches the validated path and preserves rejected alternatives.
metadata:
  short-description: Convert verified workflow state into a clean final explanation
---

## Purpose
This skill turns the validated artifact graph into a human-readable report. The writeup should be concise in style but deep in evidentiary integrity. It must not silently import old narratives, unexplained constants, or rejected paths.

## Inputs
- findings
- verified hypotheses and validation summaries
- solver verification artifacts
- skeptical review artifacts

## Required outputs
- `artifacts/writeup.md`
- optional supporting notes or appendices under `artifacts/out/`
- final phase-status update if completion is being declared

## Operating rules
1. Describe the real vulnerability path, not the most dramatic story.
2. Explain how the weakness was validated.
3. Mention important rejected alternatives when they matter for trust.
4. Tie claims back to concrete artifacts.
5. Keep the causal chain readable from intake through solver verification.

## Edge cases
- multiple verified weaknesses with only one needed for solve
- probabilistic solver behavior needing careful wording
- hybrid chains where representation and crypto both matter materially
- stale narrative fragments from earlier hypotheses surviving in summaries or findings


## Writeup structure guide
A good final writeup usually has:
- challenge framing
- route taken and why
- validated weakness explanation
- key evidence summary
- rejected alternatives that matter for trust
- deterministic solve path or bounded note on non-determinism

Do not let style overwrite truthfulness. It is better to write a plain but accurate report than a polished one that silently invents causal links.


## Validation gate
Pass only if the writeup matches the validated artifact graph, references the right path, and does not reintroduce removed or rejected explanations.
