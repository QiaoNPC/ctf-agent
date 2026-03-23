---
name: crypto_specialist-oracle
description: Deepen oracle-family reasoning for padding, format, timing, and protocol-partition leaks.
metadata:
  short-description: Specialist support for oracle-style vulnerability paths
---

## Purpose
This specialist skill refines oracle-family hypotheses. It exists because generic “oracle” reasoning is often too vague. The skill should force concrete classification of what the oracle leaks and what partitions are actually observable.

## Inputs
- remote and probe artifacts
- active oracle-family hypotheses
- validation plans needing oracle-specific discrimination

## Required outputs
- oracle-specific notes or evidence folded into per-HID artifacts
- updates to hypothesis scores or validation plans when classification changes

## Focus areas
- padding oracle versus format oracle versus timing oracle
- response partition count and stability
- statefulness and replay behavior
- chosen-ciphertext feasibility and cost
- false-positive risks caused by transport instability or menu logic

## Edge cases
- response text differs but the semantic class is the same
- timing-only leak with noisy network conditions
- menu-driven paths where the oracle is exposed only after a prior state transition
- apparent oracle behavior that is really parser rejection before crypto occurs


## Oracle discrimination checklist
To classify an oracle cleanly, ask:
- what exactly changes between response classes?
- are the classes stable across sessions?
- does the divergence happen before decryption, during parsing, or after semantic checks?
- can a single controlled mutation move an input between classes predictably?


## Validation gate
Pass only if the oracle family is narrowed meaningfully and the next validator becomes more discriminative as a result.
