---
name: crypto_cribdrag
description: Run a bounded, evidence-heavy cribdrag workflow for suspected keystream reuse and XOR-style leakage.
metadata:
  short-description: Test repeated-keystream hypotheses with disciplined cribdrag artifacts
---

## Purpose
This skill handles the very specific but common case where multiple ciphertexts appear to share a keystream or OTP segment. It should not be invoked as a generic “maybe XOR” reflex. It exists to transform that suspicion into structured evidence.

## Inputs
- ciphertext sets or XOR pairs
- parameter artifacts describing lengths, alignments, or known plaintext hints
- hypothesis artifacts naming a repeated-keystream route

## Required outputs
- crib candidate notes or artifacts under `artifacts/out/validation/`
- per-HID evidence updates tying cribdrag outcomes to a repeated-keystream hypothesis
- logs showing tested offsets, scoring rationale, and rejected cribs

## Operating rules
1. Confirm that repeated-keystream conditions are at least plausible before dragging.
2. Prefer short, high-signal cribs derived from known structure, headers, flags, JSON syntax, protocol words, or repeated menu strings.
3. Track offsets explicitly. A good crib at the wrong alignment is not evidence.
4. Record rejected cribs to avoid re-testing the same low-value ideas.
5. Escalate to broader stream analysis only if crib evidence meaningfully improves confidence.

## Edge cases
- ciphertexts of unequal length causing misleading overlap impressions
- compressed plaintexts defeating natural-language crib assumptions
- structured binary plaintext where text-based cribdragging is weak
- one message partly known and others not aligned at the same origin
- apparent reuse caused by repeated plaintext rather than repeated keystream


## Crib selection operational guide
High-value crib sources include:
- known flag formats
- JSON punctuation and key names
- shell or Python syntax
- menu strings from transcripts
- file headers and magic bytes
- repeated protocol markers

Low-value cribs include generic English words with weak structural constraints. Prefer cribs that also constrain alignment and character class plausibility.


## Validation gate
Pass only if the skill leaves enough evidence to justify why repeated-keystream confidence increased, decreased, or stayed inconclusive.
