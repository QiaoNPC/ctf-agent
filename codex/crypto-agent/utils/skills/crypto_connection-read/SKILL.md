---
name: crypto_connection-read
description: Normalize remote configuration and connection hints into machine-readable, ambiguity-aware remote artifacts.
metadata:
  short-description: Parse remote specs, document ambiguity, and prepare safe probing
---

## Purpose
This skill converts challenge connection hints, YAML fragments, Docker notes, scripts, README snippets, and ad hoc instructions into a single normalized remote model. Its job is not only to parse obvious host/port details, but also to surface uncertainty that can affect probe design and downstream validation.

## Inputs
- challenge README files
- connection YAML or other config hints
- scripts or wrappers that embed connection parameters
- environment notes, Docker compose files, or launcher snippets

## Required outputs
- `artifacts/remote.json`
- `artifacts/out/remote_assessment.json`
- `artifacts/out/probe_plan.json`
- updates to findings if remote behavior changes the attack surface

## Detailed operating rules
1. Normalize host, port, transport, TLS, prompt style, and expected handshake state.
2. Record all ambiguities explicitly, such as multiple candidate endpoints or conditional auth steps.
3. Capture whether the remote appears stateless, stateful, per-session randomized, menu-driven, or transcript-sensitive.
4. Distinguish parsing certainty from inference. Do not claim certainty about a menu protocol you have not yet observed.
5. Emit a probe plan that minimizes service disturbance and maximizes discriminating evidence.

## Edge cases
- nested YAML or shell wrappers that mask the true endpoint
- multiple services where one is setup and another is the real challenge
- local Docker environment differing from hosted environment
- prompt banners that include random tokens or state IDs
- one-shot challenges that cannot safely tolerate repeated trial-and-error probing


## Remote parsing operational guide
The normalized remote model should answer these questions clearly:
- what exact endpoint or endpoints might matter?
- what transport is used?
- what user-visible prompts or menu states are expected?
- what is known versus inferred about authentication, sessioning, and reset behavior?
- what probe sequence is safe enough to try first?

## Common ambiguity classes
- endpoint ambiguity: several host/port candidates or launcher wrappers
- protocol ambiguity: raw TCP versus line-oriented versus menu-driven
- state ambiguity: stateless-looking service that actually tracks prior actions
- environment ambiguity: local container behavior differs from hosted instance


## Validation gate
Pass only if the normalized remote artifact is present, ambiguities are recorded, and the probe plan is specific enough to be executed without ad hoc guessing.
