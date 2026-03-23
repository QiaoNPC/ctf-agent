---
name: rev_custom_vm
description: Solve a custom VM by recovering an evidence-backed VM specification, extracting bytecode, implementing a safe emulator, and validating the resulting output.
metadata:
  short-description: Artifact-rich custom VM solving workflow
---

## Purpose
When the target implements a custom VM or bytecode interpreter, reconstruct the VM in a disciplined way. The output of this skill is not just a final answer. It is a set of artifacts that let a human inspect the VM design, bytecode source, emulator behavior, traces, and extracted outputs.

## Inputs
- Target binary and associated files or blobs
- IDA decompile or disassembly evidence, or equivalent decompilation evidence
- Existing manager artifacts if present
- Any extracted payloads that appear to contain bytecode or VM state

## Required artifact subtree
Create and maintain:

```text
artifacts/vm/
  vm_entrypoints.json
  vm_state_model.json
  opcode_candidates.json
  opcode_map.json
  bytecode_sources.json
  bytecode.bin
  emulator.py
  emulator_config.json
  trace_summary.json
  trace.txt
  validation.json
  output.txt
  next_targets.json
  logs/
  snippets/
  scripts/
```

## Outputs
At minimum, this skill must produce:
- `artifacts/vm/vm_entrypoints.json`
- `artifacts/vm/vm_state_model.json`
- `artifacts/vm/opcode_candidates.json`
- `artifacts/vm/opcode_map.json`
- `artifacts/vm/bytecode_sources.json`
- `artifacts/vm/bytecode.bin` or an equivalent extracted bytecode artifact
- `artifacts/vm/emulator.py`
- `artifacts/vm/trace.txt`
- `artifacts/vm/validation.json`
- `artifacts/vm/output.txt` if final output is extracted
- `artifacts/vm/next_targets.json`

## Steps (each has required artifacts and a gate)

### 1) Confirm VM evidence
Look for and record:
- opcode dispatch loops
- jump tables or switch dispatch
- bytecode buffers or instruction streams
- VM state structures such as stack, registers, memory, flags, or cursor objects

Required artifacts:
- `artifacts/vm/vm_entrypoints.json`
- `artifacts/vm/snippets/dispatcher_notes.txt`
- updates to `artifacts/findings.json`
- `artifacts/vm/validation.json` update

Gate:
- at least one concrete VM evidence pointer exists with enough provenance to reopen the exact location later

### 2) Recover the VM state model
Define the VM state model from evidence:
- program counter representation
- operand stack or register bank
- memory model or heap representation
- flags, condition state, or exception state if present

Required artifacts:
- `artifacts/vm/vm_state_model.json`
- `artifacts/vm/snippets/state_notes.txt`
- `artifacts/vm/validation.json` update

Gate:
- every major element of the state model ties back to evidence

### 3) Recover opcode candidates and semantics
Build the opcode picture incrementally:
- raw opcode values
- operand widths and encoding hints
- stack or register effects
- branch behavior
- decode or transform behavior

Separate uncertain opcode candidates from validated opcode semantics.

Required artifacts:
- `artifacts/vm/opcode_candidates.json`
- `artifacts/vm/opcode_map.json`
- `artifacts/vm/snippets/opcode_notes.txt`
- `artifacts/vm/validation.json` update

Gate:
- every claimed opcode semantic in `opcode_map.json` references evidence or trace support

### 4) Extract bytecode and record provenance
Extract the bytecode into a stable artifact and record where it came from:
- file offset
- blob name
- function that loads it
- transform applied before extraction if any

Required artifacts:
- `artifacts/vm/bytecode.bin`
- `artifacts/vm/bytecode_sources.json`
- hashes for the extracted bytecode
- `artifacts/vm/validation.json` update

Gate:
- bytecode artifact exists and provenance is recorded

### 5) Implement a safe emulator
Implement a bounded emulator or interpreter with:
- safe memory access
- explicit step accounting
- checked stack growth and underflow handling
- deterministic logging and trace capture
- configuration separated from code where useful

Required artifacts:
- `artifacts/vm/emulator.py`
- `artifacts/vm/emulator_config.json`
- optional helpers under `artifacts/vm/scripts/`
- `artifacts/vm/validation.json` update

Gate:
- emulator runs on the extracted bytecode without uncontrolled crashing

### 6) Validate correctness
Use multiple validation methods where possible:
- invariants such as PC progression or stack depth sanity
- spot checks against disassembly or decompiler evidence
- trace agreement at selected instruction points
- reproduction of known constants, strings, or expected transformations

Required artifacts:
- `artifacts/vm/trace.txt`
- `artifacts/vm/trace_summary.json`
- `artifacts/vm/snippets/validation_notes.txt`
- `artifacts/vm/validation.json` update

Gate:
- at least one strong validation method passes with supporting evidence recorded

### 7) Extract final output and hand back next targets
Extract the final output if available:
- string
- config
- decoded blob
- routing table
- reconstructed script or command list

If the VM solve is partial, clearly record what remains unknown and what function or opcode family should be analyzed next.

Required artifacts:
- `artifacts/vm/output.txt` if output exists
- `artifacts/vm/next_targets.json`
- updates to `artifacts/findings.json`
- updates to `artifacts/WRITEUP.md`
- `artifacts/vm/validation.json` final update

Gate:
- output is reproducible, or the remaining blocker is explicitly documented with actionable next targets

## Increased hard caps (tripled)
Use bounded but larger ceilings to prevent premature truncation of VM solving work:
- maximum emulator step limit default: **3,000,000**
- maximum opcode candidates tracked before consolidation: **384**
- maximum trace lines preserved before summary curation: **30,000**
- maximum focused opcode notes before forced consolidation: **96**

These are safety bounds, not encouragement to generate noise. Curate results into summary artifacts as you work.

## Skill validation gate
PASS only if:
- emulator claims are evidenced
- the emulator was validated by at least one strong method
- extracted bytecode and key VM artifacts are hashed or otherwise stably materialized
- next targets are explicit when the solve is incomplete

## Command style reminder
Run shell commands:
`{"command":["bash","-lc","<command>"]}`
