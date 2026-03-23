---
name: rev_apk_hardening
description: Handle hardened or packed APKs by recovering a usable static corpus with evidence-backed static analysis and the smallest justified runtime extraction.
metadata:
  short-description: Hardened APK workflow with mandatory artifact production and validation
---

## Purpose
When an APK uses packing, encrypted dex, native loaders, runtime decryption, reflection routers, or VM-like protection, recover a usable static corpus and hand clear next targets back to the main APK flow. The goal is not dynamic exploration for its own sake. The goal is to recover a corpus that can be analyzed statically and reproducibly.

## Inputs
- Decompiled corpus from `rev_apk`
- Target APK
- Existing manager and APK artifacts if present
- Optional device or emulator access
- Optional Frida or equivalent runtime instrumentation if available

## Required artifact subtree
Create and maintain:

```text
artifacts/apk/hardening/
  findings.json
  evidence_index.json
  candidate_payloads.json
  extraction_plan.md
  runtime_capture_log.json
  dumped_artifacts.json
  next_static_targets.json
  validation.json
  logs/
  dumps/
  snippets/
  scripts/
```

## Outputs
At minimum, this skill must produce:
- `artifacts/apk/hardening/findings.json`
- `artifacts/apk/hardening/evidence_index.json`
- `artifacts/apk/hardening/candidate_payloads.json`
- `artifacts/apk/hardening/next_static_targets.json`
- `artifacts/apk/hardening/validation.json`

When applicable, also produce:
- `artifacts/apk/hardening/extraction_plan.md`
- dumped or extracted artifacts under `artifacts/apk/hardening/dumps/`
- `artifacts/apk/hardening/dumped_artifacts.json`
- runtime logs under `artifacts/apk/hardening/logs/`
- helper scripts under `artifacts/apk/hardening/scripts/`
- focused evidence notes under `artifacts/apk/hardening/snippets/`

## What counts as hardening evidence
Record at least one pointer for any claimed hardening mechanism, such as:
- `DexClassLoader`, `InMemoryDexClassLoader`, `loadDex`, or `BaseDexClassLoader`
- encrypted or obfuscated dex payloads in assets, resources, or unusual blobs
- native loaders that decrypt, unpack, or map code at runtime
- reflection-based routers with runtime string resolution
- VM-like dispatchers, opcode loops, or bytecode handlers
- delayed class loading tied to anti-analysis or environment checks

## Steps (each has required artifacts and a gate)

### 1) Confirm hardening evidence statically
Locate and record:
- loader entrypoint classes or functions
- where payload bytes originate
- where unpacking, decryption, or class loading occurs
- what condition triggers the protected path

Required artifacts:
- `artifacts/apk/hardening/evidence_index.json`
- `artifacts/apk/hardening/findings.json` initial population
- `artifacts/apk/hardening/snippets/loader_paths.txt`
- `artifacts/apk/hardening/validation.json` update

Gate:
- at least one concrete hardening pointer exists with file, class or function, and location reference

### 2) Extract candidate payloads statically first
Search for payloads directly in:
- assets
- `res/raw`
- native libraries
- secondary archives or blobs under apktool output
- serialized or encoded constants within jadx output

Identify likely types using magic headers or structure hints.

Required artifacts:
- `artifacts/apk/hardening/candidate_payloads.json`
- copied candidates under `artifacts/apk/hardening/dumps/` when directly extractable
- `artifacts/apk/hardening/snippets/payload_inventory.txt`
- hashes for every copied candidate
- `artifacts/apk/hardening/validation.json` update

Gate:
- at least one candidate payload is recorded, and every saved candidate has a SHA256

### 3) Decide the minimum necessary extraction path
Choose the least invasive path that can recover a usable corpus:
- fully static local decryptor if keys or seeds are recoverable statically
- targeted runtime hook only if key material or plaintext exists solely at runtime
- VM handoff if the protected code is implemented as bytecode or an interpreter

The decision must explicitly name the expected output artifact, such as a dumped dex, decoded blob, or opcode stream.

Required artifacts:
- `artifacts/apk/hardening/extraction_plan.md`
- `artifacts/apk/hardening/findings.json` decision update
- `artifacts/apk/hardening/validation.json` update

Gate:
- no runtime capture proceeds without a written plan tied to evidence and naming the expected artifact

### 4) Perform controlled runtime extraction when required
If runtime extraction is justified, keep it tightly scoped:
- hook dex-loading APIs to capture buffers
- hook native decrypt or unpack boundaries to capture plaintext
- capture only the necessary buffers
- keep logs of exactly what was hooked and why

Required artifacts:
- scripts under `artifacts/apk/hardening/scripts/`
- logs under `artifacts/apk/hardening/logs/`
- captured artifacts under `artifacts/apk/hardening/dumps/`
- `artifacts/apk/hardening/runtime_capture_log.json`
- `artifacts/apk/hardening/dumped_artifacts.json`
- `artifacts/apk/hardening/validation.json` update

Gate:
- dumped artifacts exist, are hashed, and the capture path is reproducible or explicitly blocked with reason

### 5) Re-integrate into static analysis
Once a usable corpus has been recovered:
- place dumped dex or recovered blobs where the main APK flow can reason over them
- record exact class names, entrypoints, loaders, or artifacts to inspect next
- update manager and APK-level findings so the protected path becomes part of the normal analysis graph

Required artifacts:
- `artifacts/apk/hardening/next_static_targets.json`
- updates to `artifacts/apk/next_targets.json`
- updates to `artifacts/findings.json`
- updates to `artifacts/validation.json`

Gate:
- `next_static_targets.json` contains concrete pointers that allow the next analyst step to begin immediately

## Increased hard caps (tripled)
Use larger bounded ceilings to avoid under-capturing protected artifacts:
- maximum candidate payloads tracked before prioritization: **180**
- maximum buffer captures retained before curation: **90**
- maximum loader or decryptor snippets written before consolidation: **45**
- maximum dumped artifact variants retained per protected stage unless clearly distinct: **12**

## Skill validation gate
PASS only if one of the following is true:
- a usable static corpus was produced with hashes and next targets, or
- a clear handoff to `rev_custom_vm` was produced with evidence pointers and pending targets

In either case, required hardening artifacts and validation records must exist.

## Command style reminder
Run shell commands:
`{"command":["bash","-lc","<command>"]}`
