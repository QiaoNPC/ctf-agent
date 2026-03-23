---
name: crypto_oracle-probe
description: Collect bounded, reproducible remote transcripts and characterize oracle behavior without wasting or poisoning the service.
metadata:
  short-description: Probe safely, capture transcripts, and model oracle response partitions
---

## Purpose
This skill performs controlled interaction with the remote service. Its goal is not to “hack live” in an unstructured way. It should capture enough evidence to model the oracle, menu, protocol, or challenge state so that most later reasoning can occur offline.

## Inputs
- `artifacts/remote.json`
- `artifacts/out/probe_plan.json`
- any prior transcripts or known service constraints

## Required outputs
- `artifacts/out/oracle_profile.json`
- `artifacts/out/probe_index.json`
- transcript and log files under `artifacts/logs/` or `artifacts/in/`
- updates to findings and phase status

## Operating rules
1. Execute the probe plan conservatively.
2. Label every transcript with enough context to replay or compare it.
3. Record response dimensions that may leak state: message text, status code, timing bands, output length, connection resets, and menu transitions.
4. Distinguish transport noise from oracle signal.
5. Stop early if the service appears one-shot, rate-limited, or stateful in a way that makes naive probing dangerous.

## Edge cases
- state carried across commands in a single connection
- state reset on reconnect
- challenges that randomize prompts or padding lengths
- TLS or proxy issues masquerading as oracle variance
- menu-driven services where an error path changes later behavior


## Probe design operational guide
Good probes are minimal, discriminative, and easy to replay. Favor probes that separate classes cleanly, such as:
- structurally valid versus invalid ciphertexts
- correct-length versus malformed-length inputs
- repeated submissions under fresh sessions
- controlled single-field mutations

## What not to do
- spray many malformed inputs without a logging plan
- assume timing differences are meaningful from one or two observations
- mix probe types so heavily that the resulting transcript becomes uninterpretable


## Validation gate
Pass only if probe artifacts make the observed behavior reproducible enough for offline modeling or clearly explain why probing had to stop.
