---
name: crypto_specialist-rsa
description: Deepen RSA-family reasoning across textbook misuse, modulus failures, prime reuse, exponent mistakes, and signature confusion.
metadata:
  short-description: Specialist support for RSA-family vulnerability paths
---

## Purpose
This specialist skill handles RSA-specific branching. It should separate the many distinct RSA failure modes that are often conflated and help shape precise validators.

## Inputs
- RSA-like parameters from params artifacts
- hypotheses mentioning RSA families
- decode or hybrid outputs that appear to expose key material or RSA metadata

## Required outputs
- RSA-specific notes or evidence folded into per-HID artifacts
- validation-plan refinements
- score updates when a particular RSA path becomes more or less plausible

## Focus areas
- small exponent and unpadded message conditions
- common modulus and shared-prime paths
- close-prime or factorability hints
- CRT mishandling and faulty recombination
- signature verification confusion, parser mismatch, or malleability
- encoding and padding assumptions that make textbook-looking paths invalid

## Edge cases
- integers that resemble RSA inputs but are actually unrelated packed data
- moduli extracted from examples rather than live challenge data
- PKCS-style padding assumptions without proof of padding use
- signature and encryption paths coexisting in the same challenge


## RSA discrimination checklist
When narrowing RSA routes, check:
- whether padding is present or merely assumed absent
- whether message size relative to modulus supports a small-exponent route
- whether multiple moduli share factors or other relationships
- whether signatures and encryption are being conflated
- whether decoded material is truly RSA structure or just large integers


## Validation gate
Pass only if the RSA family is narrowed concretely enough to change validator design or reject misleading RSA narratives.
