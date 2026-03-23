---
name: crypto_intake
description: Inventory the challenge, classify the route, map the attack surface, and create the first durable state snapshot.
metadata:
  short-description: Build the initial challenge map and choose the right workflow branch
---

## Purpose
This skill is the first substantive pass over the challenge. It should inventory files, identify likely entry points, classify the problem route, and leave behind enough structure that later phases are working from a shared operational picture instead of hazy first impressions.

## Inputs
- entire challenge repository or drop
- readme files, scripts, binaries, source, data blobs, transcripts, and configs

## Required outputs
- `artifacts/metadata.json`
- `artifacts/out/file_inventory.json`
- `artifacts/out/intake_summary.json`
- updated phase status, artifact manifest, dependency graph, and findings

## Operating rules
1. Inventory everything with categories, not just filenames.
2. Identify likely challenge entry points and supporting materials.
3. Classify the route as decode, cryptanalysis, or hybrid, and justify the classification.
4. Start an attack-surface map naming plausible vulnerability families.
5. Flag environmental constraints such as remote-only behavior, binaries that must be reversed, or large datasets that affect cost.

## Edge cases
- files intentionally mislabeled by extension
- binaries or scripts that dynamically generate the real challenge data
- multiple nested challenge components where only one matters
- challenge text that suggests crypto but the real failure is representation or protocol state
- hidden or compressed artifacts not obvious from filenames


## Intake attack-surface operational guide
The initial intake summary should already answer:
- where the likely challenge boundary is
- whether remote interaction is central or optional
- whether decoding is probably a first-class phase
- which vulnerability families deserve immediate attention
- what evidence is missing before serious modeling can start

## Common intake mistakes to avoid
- assuming the largest file is the important one
- assuming a service challenge is purely remote when local source reveals the weakness
- assuming crypto is central when the real problem is format or protocol confusion


## Validation gate
Pass only if the inventory is usable, the route classification is justified, and the attack surface is visible enough to guide the next phase.
