---
name: crypto_hypotheses-build
description: Build explicit vulnerability hypotheses with preconditions, discriminators, costs, scores, and attack-family context.
metadata:
  short-description: Turn attack ideas into ranked, testable models with evidence expectations
---

## Purpose
This skill transforms raw clues into a bounded set of explicit hypotheses. It should not emit vague labels like “RSA issue” or “oracle problem.” Each hypothesis must name a concrete vulnerability path, its required preconditions, its distinguishing tests, its expected evidence, and the main ways it could be wrong.

## Inputs
- params, decode, hybrid, remote, probe, and findings artifacts
- relevant embedded operational guidance in the manager and skills and specialist outputs

## Required outputs
- `artifacts/hypotheses.json`
- `artifacts/out/hypothesis_matrix.json`
- `artifacts/out/hypothesis_priority.json`
- `artifacts/out/hypothesis_scores.json`
- `artifacts/out/research_seed.json`
- updates to continuation plan and findings

## Operating rules
1. Keep the set bounded but diverse enough to cover the real attack surface.
2. For each hypothesis, state: concrete weakness, evidence already supporting it, missing preconditions, best discriminating validator, cost profile, and likely failure modes.
3. Score confidence and evidence separately. A familiar attack family may have high prior familiarity but weak current evidence.
4. Prefer hypotheses that can be falsified cheaply.
5. When a specialist path is likely, say exactly which one and why.

## Potential vulnerability paths to enumerate when relevant
- reused keystream or nonce reuse
- padding or format oracle leaks
- textbook RSA misuse variants
- shared-prime or common-modulus RSA issues
- weak randomness or predictable seed recovery
- decode-to-key leakage chains
- protocol-state confusion that creates a crypto side channel
- malformed parser behavior that exposes plaintext or intermediate state

## Edge cases
- a clue supports multiple families at once
- an oracle hypothesis depends on unproven statefulness assumptions
- a decode result suggests a key but could be a decoy or unrelated metadata
- confidence drift after research produces a good-looking but weakly grounded attack template


## Hypothesis quality checklist
A high-quality hypothesis has:
- a sharply named weakness family
- a concrete entry point into validation
- a cheap discriminator
- at least one meaningful falsifier
- a plausible exploit or recovery consequence
- an honest note about what the evidence does **not** yet show

## When to split a hypothesis
Split a hypothesis when the same label hides materially different preconditions or validators. Examples:
- “RSA issue” splitting into textbook misuse, shared-prime, or signature confusion
- “oracle issue” splitting into padding, format, or timing partitions
- “stream reuse” splitting by exact reuse mechanism or alignment assumptions


## Validation gate
Pass only if each top hypothesis can be directly mapped to a validation plan and no surviving hypothesis remains purely narrative.
