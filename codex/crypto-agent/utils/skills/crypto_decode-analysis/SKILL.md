---
name: crypto_decode-analysis
description: Drive decode-first problems through explicit candidate generation, convergence tests, and branch stop conditions.
metadata:
  short-description: Analyze decode stacks deeply and decide when decode work is sufficient, stale, or dead
---

## Purpose
This skill owns decode-first reasoning. It should explore structured decoding possibilities without collapsing into endless “try another codec” behavior. The goal is to produce a stable decode model, not a grab bag of random transformations.

## Inputs
- encoded blobs, strings, transcripts, file fragments, and parameter candidates
- file inventory, intake route, and entropy or structural hints

## Required outputs
- `artifacts/out/decode_assessment.json`
- `artifacts/out/decode_candidates.json`
- `artifacts/out/decode_results.json`
- updates to findings, params, and hybrid routing when decode results expose cryptographic material

## Operating rules
1. Characterize the representation before decoding: alphabet, delimiters, length modularity, entropy profile, and chunk structure.
2. Generate candidate decode stacks deliberately, not exhaustively. Each candidate should have a rationale.
3. Record intermediate layers when they materially change structure.
4. Stop when a decode path stabilizes into meaningful structure or clearly fails convergence.
5. Promote outputs to later phases only when they are internally coherent and evidenced.

## Edge cases
- nested base encodings with custom separators
- encodings wrapped around compressed or encrypted payloads
- little-endian integer dumps mistaken for text encodings
- malformed encodings that are actually clues to custom packing logic
- decodes that produce binary structures, not plaintext
- multiple plausible decode outputs requiring branch management rather than forced selection

## Potential vulnerability paths to surface
- encoded key material or IV leakage
- hidden modulus/exponent values
- embedded nonce or seed disclosure
- staged hybrid challenge where decode output is itself a crypto oracle transcript
- accidental leakage in comments, metadata, or serialized objects


## Decode convergence criteria
A decode path is converging when successive transformations increase structure in a repeatable way. Signs of convergence include:
- stable printable regions with meaningful delimiters
- emergent binary structure such as fixed-width fields or headers
- outputs that match known parameter sizes or protocol layouts
- reduction in ambiguity rather than merely different-looking gibberish

## When to split instead of choose
If two decode chains remain plausible and each would imply a different downstream crypto path, preserve both as separate branches until a discriminator exists.


## Validation gate
Pass only if decode artifacts show what was tried, what converged, what failed, and why the surviving decode outputs deserve downstream use.
