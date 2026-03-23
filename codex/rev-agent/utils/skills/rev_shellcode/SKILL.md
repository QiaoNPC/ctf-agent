---
name: rev_shellcode
description: Reverse shellcode or staged raw code safely through bounded emulation and artifact-backed extraction.
metadata:
  short-description: Safe shellcode workflow with explicit artifact and validation requirements
---

## Purpose
When raw shellcode, a staged loader, or an extracted executable code blob is present, analyze it in a way that is safe, reproducible, and inspectable. The goal is to extract the executed behavior, next-stage payloads, and any verified output without inventing semantics that are not supported by emulator or tool output.

## Inputs
- Shellcode bytes or a file containing shellcode
- Context about where the blob executes, if known
- Architecture or calling-context hints if available
- Existing manager artifacts if present

## Required artifact subtree
Create and maintain:

```text
artifacts/shellcode/
  shellcode.bin
  shellcode_context.json
  architecture_assessment.json
  emulator_config.json
  trace.txt
  trace_summary.json
  stage_inventory.json
  behavior.md
  validation.json
  next_targets.json
  logs/
  snippets/
  extracts/
  scripts/
```

## Outputs
At minimum, this skill must produce:
- `artifacts/shellcode/shellcode.bin`
- `artifacts/shellcode/shellcode_context.json`
- `artifacts/shellcode/architecture_assessment.json`
- `artifacts/shellcode/emulator_config.json`
- `artifacts/shellcode/trace.txt`
- `artifacts/shellcode/trace_summary.json`
- `artifacts/shellcode/behavior.md`
- `artifacts/shellcode/validation.json`
- `artifacts/shellcode/next_targets.json`

When applicable, also produce:
- extracted next stages under `artifacts/shellcode/extracts/`
- `artifacts/shellcode/stage_inventory.json`
- helper scripts under `artifacts/shellcode/scripts/`
- runtime or emulator logs under `artifacts/shellcode/logs/`

## Steps (each has required artifacts and a gate)

### 1) Extract bytes and hash them
Save the exact bytes that are being analyzed and record their provenance.

Required artifacts:
- `artifacts/shellcode/shellcode.bin`
- `artifacts/shellcode/shellcode_context.json`
- hashes for the saved bytes
- `artifacts/shellcode/validation.json` update

Gate:
- the analyzed bytes are materialized and hashed before any behavioral claim is made

### 2) Assess architecture and execution context
Use evidence such as:
- loader context
- calling convention hints
- disassembly patterns
- known packer or exploit context
- memory layout assumptions from the loader

Required artifacts:
- `artifacts/shellcode/architecture_assessment.json`
- `artifacts/shellcode/snippets/arch_notes.txt`
- `artifacts/shellcode/validation.json` update

Gate:
- architecture and mode claims are tied to evidence pointers or clear emulator observations

### 3) Configure safe emulation
Run emulation with explicit safety boundaries:
- instruction budget
- memory bounds
- controlled stack region
- disabled syscalls and network by default unless explicitly justified and controlled
- logging enabled for important state changes

Required artifacts:
- `artifacts/shellcode/emulator_config.json`
- emulator logs under `artifacts/shellcode/logs/`
- `artifacts/shellcode/validation.json` update

Gate:
- no emulation begins until the safety configuration artifact exists

### 4) Emulate and capture trace output
Capture enough trace to support behavior claims without drowning the workflow in noise.

Required artifacts:
- `artifacts/shellcode/trace.txt`
- `artifacts/shellcode/trace_summary.json`
- `artifacts/shellcode/logs/` entries as needed
- `artifacts/shellcode/validation.json` update

Gate:
- emulator output exists and includes enough evidence to support later claims

### 5) Extract next stages or decoded artifacts
If the shellcode unpacks, decrypts, or writes a next stage, extract it with hashes and provenance.

Required artifacts:
- extracted payloads under `artifacts/shellcode/extracts/`
- `artifacts/shellcode/stage_inventory.json`
- `artifacts/shellcode/validation.json` update

Gate:
- every extracted stage has a saved artifact, provenance, and hash

### 6) Summarize behavior and hand back next targets
Summarize only what the emulator or strongly supporting tool output shows:
- decode or decrypt logic
- API or syscall usage
- stage loading behavior
- payload direction or intent, but only where evidence supports it

Also name the next likely targets if the shellcode analysis reveals additional loaders or payloads to inspect.

Required artifacts:
- `artifacts/shellcode/behavior.md`
- `artifacts/shellcode/next_targets.json`
- updates to `artifacts/findings.json`
- updates to `artifacts/validation.json`

Gate:
- each behavior claim ties to emulator or tool output, and next targets are explicit if the analysis is incomplete

## Increased hard caps (tripled)
Use larger bounded limits to reduce premature truncation while keeping emulation safe:
- maximum instruction limit default: **3,000,000**
- maximum trace lines retained before summary curation: **30,000**
- maximum extracted stage artifacts retained before prioritization: **24**
- maximum focused behavior claims before forced consolidation into `behavior.md`: **60**

## Skill validation gate
PASS only if:
- all claims tie to emulator or tool output
- extracted next stages, if any, are saved and hashed
- behavior summary remains evidence-backed and bounded
- next targets are recorded when additional stages remain

## Command style reminder
Run shell commands:
`{"command":["bash","-lc","<command>"]}`
