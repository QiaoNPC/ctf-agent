---
name: crypto_params-extract
description: Extract, normalize, and provenance-track cryptographic and representational parameters from all available evidence.
metadata:
  short-description: Turn raw challenge evidence into machine-readable parameter state with ambiguity tracking
---

## Purpose
This skill converts raw challenge material into structured parameters. It should extract not just obvious values like modulus and ciphertext, but also uncertain candidates, provenance, and gaps that matter later. This is the bridge between observation and modeling.

## Inputs
- challenge files
- transcripts
- decode outputs
- source code or binaries when available
- findings from intake and probe phases

## Required outputs
- `artifacts/params.json`
- `artifacts/out/params_candidates.json`
- `artifacts/out/params_provenance.json`
- `artifacts/out/params_gaps.json`
- updates to findings and continuation plan

## Operating rules
1. Normalize values into machine-usable forms where possible.
2. Preserve provenance for every extracted claim.
3. Separate confident values from candidates and from gaps.
4. Record representation assumptions such as endian, signedness, block size, or alphabet.
5. If values conflict, preserve the conflict explicitly instead of picking one silently.

## Edge cases
- same numeric field appearing in hex, base64, and integer text forms
- truncated values in transcripts
- duplicate candidate parameters from multiple sources with slightly different formatting
- block size inferred from padding-like structure that may actually be framing
- values that are decoys or examples rather than live challenge inputs


## Parameter extraction operational guide
Look for parameters in all of these places:
- challenge text and comments
- encoded blobs and decoded layers
- network transcripts
- source constants and helper functions
- filenames, metadata, and test fixtures
- error messages that echo values or lengths

## Parameter ambiguity classes
- type ambiguity: integer versus byte string
- width ambiguity: bytes, bits, blocks, limbs
- origin ambiguity: live challenge value versus example fixture
- interpretation ambiguity: ciphertext, nonce, tag, key, seed, or checksum


## Validation gate
Pass only if parameters, provenance, and gaps together explain what is known, what is merely suspected, and what still blocks reliable modeling.
