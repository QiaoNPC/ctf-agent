---
name: rev_apk
description: Reverse an APK comprehensively with artifact-rich static analysis first, then minimal dynamic validation only when static evidence requires it.
metadata:
  short-description: Artifact-heavy APK reversing with strict validation gates
---

## Purpose
Produce an evidence-backed understanding of an APK’s behavior, protections, entrypoints, data flows, and extracted outputs. This skill must leave a dense artifact trail so a human can inspect what was discovered at each stage. Static analysis is the default. Dynamic steps are allowed only when static evidence shows they are necessary to confirm behavior, bypass a blocker, or recover a static corpus.

This skill does not replace the manager. It enriches the manager’s corpus and findings, then returns control to the manager with explicit next targets.

## Inputs
- Target APK (for example `base.apk`)
- Existing manager artifacts if present
- Optional device or emulator access
- Optional ADB or Frida environment if available

## Required artifact subtree
Create and maintain:

```text
artifacts/apk/
  apk_metadata.json
  manifest_summary.json
  component_map.json
  permissions_summary.json
  resource_inventory.txt
  jadx_index.txt
  apktool_index.txt
  hardening_findings.json
  dynamic_plan.md
  runtime_observations.json
  extracted_outputs.json
  next_targets.json
  validation.json
  WRITEUP.md
  logs/
  snippets/
  extracts/
  scripts/
```

## Outputs
At minimum, this skill must produce or update:
- `artifacts/metadata.json`
- `artifacts/decompile/apktool/`
- `artifacts/decompile/jadx/`
- `artifacts/signals.json`
- `artifacts/WRITEUP.md`
- `artifacts/apk/apk_metadata.json`
- `artifacts/apk/manifest_summary.json`
- `artifacts/apk/component_map.json`
- `artifacts/apk/permissions_summary.json`
- `artifacts/apk/hardening_findings.json`
- `artifacts/apk/next_targets.json`
- `artifacts/apk/validation.json`

When applicable, also produce:
- `artifacts/apk/runtime_observations.json`
- `artifacts/apk/extracted_outputs.json`
- payloads, configs, DBs, or decoded blobs under `artifacts/apk/extracts/`
- helper scripts under `artifacts/apk/scripts/`
- focused evidence snippets under `artifacts/apk/snippets/`

## Working rules
- Treat apktool and jadx outputs as the analysis corpus.
- Do **not** use archive listing as a substitute for decompilation.
- Keep the artifact tree synchronized with the real state of analysis.
- If strong hardening or packing is detected, invoke `rev_apk_hardening`, then return here and continue.
- If a custom VM emerges, hand off to `rev_custom_vm`, then merge the resulting artifacts back into APK-specific findings.

## Steps (each has required artifacts and a gate)

### 1) Inventory and APK metadata
Collect:
- file type, size, MD5, SHA256
- package name, version, SDK levels if available
- launchable activity
- signing or packaging metadata if easily accessible
- permissions and major app identifiers via `aapt dump badging` or equivalent

Required artifacts:
- `artifacts/metadata.json` update
- `artifacts/apk/apk_metadata.json`
- `artifacts/apk/permissions_summary.json`
- `artifacts/investigation_log.md` update
- `artifacts/apk/validation.json` phase update

Gate:
- APK identity is recorded and includes package name and launchable activity when present

### 2) Decompile corpus with apktool and jadx
Use the standard absolute-path pattern so tool behavior is reproducible:
`{"command":["bash","-lc","APK=\"$(pwd)/base.apk\"; OUT=\"$(pwd)/artifacts/decompile\"; mkdir -p \"$OUT/apktool\" \"$OUT/jadx\" \"$(pwd)/artifacts/logs\" \"$(pwd)/artifacts/apk/logs\" \"$(pwd)/artifacts/apktool-framework\"; apktool d -f -p \"$(pwd)/artifacts/apktool-framework\" -o \"$OUT/apktool\" \"$APK\" >\"$(pwd)/artifacts/logs/apktool.out\" 2>\"$(pwd)/artifacts/logs/apktool.err\" || true; jadx --show-bad-code -d \"$OUT/jadx\" \"$APK\" >\"$(pwd)/artifacts/logs/jadx.out\" 2>\"$(pwd)/artifacts/logs/jadx.err\" || true"]}`

Then materialize a lightweight corpus map:
- important manifest and resource paths
- key package directories in jadx output
- any obvious native libraries or secondary dex artifacts

Required artifacts:
- `artifacts/decompile/apktool/`
- `artifacts/decompile/jadx/`
- `artifacts/logs/apktool.out`
- `artifacts/logs/apktool.err`
- `artifacts/logs/jadx.out`
- `artifacts/logs/jadx.err`
- `artifacts/apk/apktool_index.txt`
- `artifacts/apk/jadx_index.txt`
- `artifacts/apk/resource_inventory.txt`
- `artifacts/apk/validation.json` update

Gate:
- both corpora exist and are non-empty
- errors were checked for fatal failure
- index artifacts point to locations worth analyzing next

### 3) Manifest, components, and entrypoint mapping
From the corpus, identify and record:
- manifest package and app class
- activities, services, receivers, providers
- launch activity, deep links, intent filters, exported components
- high-level flow of where external inputs enter and where outputs leave

Required artifacts:
- `artifacts/apk/manifest_summary.json`
- `artifacts/apk/component_map.json`
- `artifacts/apk/snippets/entrypoints.txt`
- `artifacts/apk/next_targets.json` initial population
- `artifacts/findings.json` updates with APK pointers
- `artifacts/apk/validation.json` update

Gate:
- at least one concrete entrypoint is recorded with file path, class or component name, and location pointer

### 4) Resource, config, and data-store inventory
Inspect and record:
- assets and `res/raw`
- embedded configuration files
- local databases, shared-preference names, content-provider URIs
- native library inventory and suspicious filenames
- secondary dex or unusual blobs

Required artifacts:
- `artifacts/apk/resource_inventory.txt`
- `artifacts/apk/snippets/config_locations.txt`
- `artifacts/apk/snippets/native_inventory.txt`
- extracted candidate payloads under `artifacts/apk/extracts/` when directly copied out
- `artifacts/apk/validation.json` update

Gate:
- at least one concrete resource, config, database, or payload location is recorded with provenance

### 5) Hardening and protection review (static, evidence-backed)
Look for and record pointers for:
- root, emulator, debugger, or tamper detection
- SSL pinning, custom trust managers, or certificate checks
- anti-Frida, anti-hooking, anti-instrumentation logic
- JNI transitions and native bridge points
- reflection-heavy routing or dynamic string resolution
- dynamic class loading, encrypted dex, packers, or loaders
- custom interpreter or VM evidence

If evidence indicates packing, encrypted dex, custom loaders, or runtime corpus reconstruction, invoke `rev_apk_hardening`.

Required artifacts:
- `artifacts/apk/hardening_findings.json`
- `artifacts/apk/snippets/hardening_evidence.txt`
- `artifacts/apk/next_targets.json` update
- `artifacts/apk/validation.json` update

Gate:
- every hardening finding has a corpus pointer or confirmed tool output
- if hardening is severe enough to block normal analysis, the handoff decision is recorded and justified

### 6) Behavior-focused static tracing
Trace only the code paths that matter most first:
- configuration loading
- credential or token handling
- request construction and response handling
- storage writes and persistence paths
- command routing or feature gates

For each focused class or method, reduce it into a compact structured note.

Required artifacts:
- one or more files under `artifacts/apk/snippets/` for focused methods
- `artifacts/findings.json` updates
- `artifacts/signals.json` updates for promoted signals
- `artifacts/hypothesis_tracker.json` updates
- `artifacts/apk/next_targets.json` reprioritized

Gate:
- at least one important behavior path is traced from entrypoint toward a concrete action

### 7) Minimal dynamic plan (only when justified)
Only after static evidence says it is required, define the smallest dynamic plan needed to:
- confirm a network behavior
- verify pinning or trust-manager logic
- capture a decrypted artifact
- confirm database, file, or IPC side effects

The plan must name:
- what evidence justified the dynamic step
- what exact artifact or observation is expected
- what success and failure look like
- what bypasses or hooks are allowed

Required artifacts:
- `artifacts/apk/dynamic_plan.md`
- `artifacts/apk/next_targets.json` update
- `artifacts/apk/validation.json` update

Gate:
- no dynamic step proceeds without a written plan tied to specific evidence pointers

### 8) Apply bypasses and verify them
Prefer the smallest reliable bypass:
- known SSL pinning bypasses
- minimal custom hooks
- focused environment or anti-analysis bypasses

Do not treat a bypass as successful unless behavior changes in an observable way.

Required artifacts:
- hook or bypass scripts under `artifacts/apk/scripts/`
- logs under `artifacts/apk/logs/`
- `artifacts/apk/runtime_observations.json` update
- `artifacts/apk/validation.json` update

Gate:
- bypass verification evidence exists as log, trace, observed behavior change, or captured runtime artifact

### 9) Traffic capture or runtime validation (if needed)
Observe only what is necessary:
- request and response shapes
- headers, auth tokens, or key-exchange markers
- encrypted payload boundaries
- file or database side effects

Required artifacts:
- `artifacts/apk/runtime_observations.json`
- capture transcripts, logs, or traces under `artifacts/apk/logs/`
- extracted runtime data under `artifacts/apk/extracts/` when applicable
- `artifacts/apk/validation.json` update

Gate:
- at least one concrete runtime observation is captured and tied back to the static hypothesis it was meant to confirm

### 10) VM handoff or specialized escalation (optional)
If a custom dispatcher or opcode VM appears, invoke `rev_custom_vm`.
If shellcode-like staged payloads appear in native or extracted blobs, invoke `rev_shellcode`.

Required artifacts:
- handoff record in `artifacts/apk/next_targets.json`
- decision entry in `artifacts/decisions.json`
- returned artifacts merged into APK findings after the skill finishes

Gate:
- handoff evidence pointer is recorded before escalation

### 11) Extract verified outputs and summarize behavior
Extract any verified artifacts of interest, such as:
- decoded configs
- schema or records from local storage
- API maps
- payloads or secondary dex files
- token or routing formats where safely appropriate

Hash every extracted artifact and make the extraction reproducible.

Required artifacts:
- `artifacts/apk/extracted_outputs.json`
- extracted files under `artifacts/apk/extracts/`
- reproduction helpers under `artifacts/apk/scripts/` if used
- `artifacts/apk/WRITEUP.md`
- `artifacts/WRITEUP.md` update
- `artifacts/apk/validation.json` final update

Gate:
- extracted outputs are verified and repeatable, or clearly documented as blocked with reason

## Increased hard caps (tripled)
Where bounded operations are necessary, use larger but still safe ceilings to reduce premature truncation:
- maximum focused APK methods summarized before forcing consolidation: **36**
- maximum manifest or component lines copied into one snippet artifact: **180**
- maximum runtime observations kept before curating into the summary artifact: **90**
- maximum candidate endpoints or signals kept before prioritization: **300**

## Skill validation gate
PASS only if:
- required APK artifacts exist
- hardening decisions are evidenced
- dynamic actions, if any, were justified in writing first
- extracted outputs are hashed and reproducible or clearly blocked
- next targets for the manager are explicitly recorded

## Command style reminder
Run shell commands:
`{"command":["bash","-lc","<command>"]}`
