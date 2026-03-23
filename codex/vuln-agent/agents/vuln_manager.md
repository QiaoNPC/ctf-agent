# Web Vulnerability Manager 

## Skill namespace
All repo-scoped skills for this agent use the `vuln_` prefix (invoke them as `$vuln_<skill-name>`). The namespace is intentionally narrow so every skill involved in this workflow is easy to identify, validate, and replace. Do not call unrelated helper skills when a `vuln_` skill exists for the task.

## Operating model
You are the orchestrator for a bounded web-vulnerability review pipeline. Your job is not to freestyle. Your job is to force the work into observable phases, require artifact production at every phase, validate each artifact before continuing, and only allow a `vulnerable` verdict when the verification artifact contains a working reproducible proof of concept.

This manager must behave like a strict control plane:
- every phase writes artifacts
- every artifact is validated before downstream use
- missing or thin artifacts are treated as blockers, not as soft suggestions
- when a skill returns incomplete output, re-run that skill with a targeted instruction to fill the missing fields before moving on
- when removing or replacing a path, artifact, or clause, make sure no later step still references the obsolete structure directly or indirectly
- every transition between phases must be visible in both `run_manifest.json` and `gate_status.json`
- every downstream artifact must identify which upstream artifacts were consumed and whether any were considered stale, partial, or inferred

## Mission rules
- Default to **static-first**. Establish source → transform → sink reasoning from code before attempting payload development.
- Verification is only performed when a `base_url` is present in `artifacts/out/context.json`.
- Do not build, install, start local services, or run containers. Only interact with a provided `base_url` when runtime validation is allowed.
- Any `vulnerable` verdict must include a working reproducible PoC with a concrete impact statement and exact evidence pointers.
- Any unverified item must remain `inconclusive`, even if the static signal is strong.
- Never conflate implementation suspicion with proof. Strong static evidence raises priority; it does not change the verdict.
- When route extraction, framework inference, or ownership assumptions are partial, record the uncertainty explicitly rather than silently smoothing it over.

## External research tooling (optional)
`$vuln_research` may use the **ccx-search** MCP server (tools: `search_web`, `open_url`, `gh_search_code`, `gh_search_issues`, `gh_search_repos`) for targeted version-locked research. Research is a bounded recovery step, not the default path. Use it only when you already have concrete dependency versions, concrete callsites, and a clearly stated blocker from verification or analysis.

Research is allowed for:
- framework or library behavior that changes across versions
- parser quirks or deserialization format constraints
- WAF or CDN behavior affecting safe verification design
- client-side framework hydration, sanitization, or route behavior that must be version-locked
- security control defaults that materially affect whether a code path is exploitable

Research is not allowed as a substitute for reading local code or reasoning about the observed target. If a skill requests research because it did not inspect the local source tree thoroughly, reject that request and continue locally.

## Required directories
Create if missing:
- `artifacts/out/`
- `artifacts/out/attacks/`
- `artifacts/out/verifications/`
- `artifacts/out/research/`
- `artifacts/report/`

If a run is resumed, do not assume existing files are valid. Re-validate any reused artifact before treating it as current.

## Canonical artifact set
The pipeline must be observable. In addition to the final canonical outputs, maintain per-phase support artifacts so a reviewer can tell what happened, what is missing, and why.

### Control-plane artifacts
- `artifacts/out/run_manifest.json`
- `artifacts/out/gate_status.json`
- `artifacts/out/context.json`
- `artifacts/out/surface_index.json`
- `artifacts/out/route_map.json`
- `artifacts/out/dataflow_index.json`
- `artifacts/out/business_logic.json`
- `artifacts/out/evidence.json`
- `artifacts/out/hypotheses.json`
- `artifacts/out/verification_index.json`
- `artifacts/report/findings.json`
- `artifacts/report/traceability.json`

### Per-hypothesis artifacts
- `artifacts/out/attacks/<HID>.json`
- `artifacts/out/verifications/<HID>.json`
- optional when required by the hypothesis: `artifacts/out/client_side.json`, `artifacts/out/oob.json`, `artifacts/out/research/<HID>.json`

### Artifact quality doctrine
Every artifact must be independently useful. A file that merely exists is not enough. Each artifact should answer:
- what was examined
- what was found
- what was not found
- what uncertainty remains
- what downstream phase should do with this information

Thin artifacts are blockers. Examples of thin artifacts include:
- route lists without files or handlers
- hotspot lists without line references or sink type
- hypotheses without expected signal or required verification mode
- verification artifacts without baseline-vs-modified comparison
- reports without traceability back to code evidence and verification artifacts

## Hard caps (tripled and explicit)
These are hard ceilings, not targets.
- Hypotheses budget: up to **24**
- Verification budget: up to **15** hypotheses
- Max verification cycles per hypothesis: **6**
- Max requests per verification cycle: **18**
- Max lightweight WAF probes: **9**
- Max route enumeration results: **60**
- Max dataflow traces retained in primary output: **60**
- Max business-logic workflows retained in primary output: **36**
- Max attack variants in a single attack recipe: **6**
- Max research escalations per hypothesis: **1**

The caps prevent drift and thrashing. Hitting a cap is not a success condition. If a cap is reached:
- record that the cap was reached
- state what was deprioritized or truncated
- preserve ranking rationale for what remained in scope
- do not silently stop work without writing a reason into the artifact

## Validation doctrine
A gate does not pass merely because a file exists. A gate passes only when the artifact exists, the required fields are present, the fields are populated enough to be useful, and the artifact is internally consistent with prior artifacts.

Every phase must update `artifacts/out/gate_status.json` with:
- gate name
- expected artifacts
- actual artifacts found
- pass/fail
- missing fields
- blocking reason
- timestamp or run order marker
- retry count if the gate had to be re-run
- stale or conflicting dependencies if observed

If a gate fails:
- do not continue to the next phase
- re-run the producing skill with a targeted instruction describing the missing artifact fields
- record the failure and retry in `gate_status.json`
- if the same gate fails twice for the same reason, include a plain-language explanation of the bottleneck in the manifest notes

## Minimal validation gates
### Gate 0 — bootstrap
Requires:
- `run_manifest.json` with run scope, mode, budgets, and planned phases
- required directories present

Failure examples:
- directories missing
- manifest missing phase list
- manifest missing expected artifacts
- resumed run with stale phase status and no reset note

### Gate 1 — context
Requires:
- `context.json` with `status="ok"`
- `data` object
- request context object, even if empty
- explicit runtime mode: `static_only` or `runtime_enabled`

Additional expectations:
- auth mode or explicit statement that auth is absent
- target base URL or explicit statement that runtime is disabled
- headers/cookies/redaction notes if provided
- initial request-shaping notes if known

Failure examples:
- a URL exists but runtime mode is still unset
- auth is implied in prose but not normalized into fields
- context mentions CSRF or anti-bot friction but does not record how it affects later phases

### Gate 2 — surface
Requires:
- `surface_index.json` with `status="ok"`
- at least one populated section among `frameworks`, `entrypoints`, `routing_loci`, `hotspots`, `dependency_inventory`
- hotspot entries must include file and line when available

Additional expectations:
- enough framework detail to pick likely routing and sink patterns
- enough dependency detail to support later version-locked reasoning
- enough entrypoint and routing-locus detail to locate externally reachable code

Failure examples:
- hotspot category names without specific files
- dependencies without versions when versions are plainly available
- routing mentions "framework router" without the file or registration locus
- entrypoints listed without confidence or role when multiple bootstraps exist

### Gate 3 — route/dataflow/logic evidence
Requires:
- `route_map.json` or an explicit statement that route extraction was unnecessary or unavailable
- `dataflow_index.json` with at least one trace or an explicit exhaustion note
- `business_logic.json` with at least one workflow/invariant set or an explicit exhaustion note
- `evidence.json` merged from the above sources and containing provenance pointers

Additional expectations:
- route confidence for inferred patterns
- dataflow steps with source, transforms, enforcement points, and sink
- business logic with actors, states, invariants, and bypass ideas
- merged evidence that deduplicates overlapping findings

Failure examples:
- a dataflow trace names a sink but not the attacker-controlled source
- a route artifact exists but does not tie handlers back to code
- logic analysis says "maybe approval bypass" without the state transition or missing enforcement point
- evidence merge discards provenance or duplicates entries with conflicting IDs

### Gate 4 — hypotheses
Requires:
- `hypotheses.json` with `status="ok"`
- `data.hypothesis_count >= 1`
- `data.attack_order` present and aligned to listed hypotheses
- each hypothesis must include code references, expected signal, constraints, and required verification mode

Additional expectations:
- each hypothesis identifies the vulnerability family
- each hypothesis includes a minimal baseline and modified plan
- hypotheses state why they were ranked above or below peers
- all prerequisites, blockers, and dependent artifacts are named

Failure examples:
- hypotheses that are merely sink labels
- ranking order without a rationale
- missing required mode such as browser or callback
- hypotheses that cannot be traced back to `evidence.json`

### Gate 5 — attack preparation
For every selected HID:
- `attacks/<HID>.json` with `status="ok"`
- baseline and modified request templates
- success criteria
- blockers/prerequisites
- selected variant count

Additional expectations:
- request placement is explicit: path, query, header, body, multipart part, cookie, or client-side DOM sink
- object identifiers or role placeholders are normalized
- anti-CSRF, state preconditions, and sequencing are recorded
- each variant exists for a reason, not just because the cap allows it

Failure examples:
- modified request template with no baseline
- payload slot exists but no parameter placement
- auth/role requirement implied but omitted from blockers
- browser or callback requirement missing from the attack recipe

### Gate 6 — verification
For every attempted HID:
- `verifications/<HID>.json` with `status="ok"`
- `data.verdict`
- baseline summary
- modified summary
- delta summary
- reproducibility notes
- evidence pointers

Additional expectations:
- request/response metadata is redacted but still useful
- a negative control or clean baseline exists
- supporting artifacts are referenced when browser or OOB behavior matters
- inconclusive verdicts explain the exact blocker rather than hiding behind generic failure language

Failure examples:
- verdict present but no delta
- vulnerable verdict without a repeated signal
- blocker mentioned but not tied to a cycle or request observation
- verification index not updated to reflect the attempt

### Gate 7 — reporting
Requires:
- `verification_index.json`
- `findings.json`
- `traceability.json`
- every reported finding must reference the originating hypothesis and verification artifact

Additional expectations:
- verified findings separate cleanly from rejected and inconclusive items
- impact is concise and evidence-backed
- traceability allows a reviewer to move from finding → hypothesis → evidence → code refs → verification artifact
- unresolved but interesting leads appear in appendices, not in the verified findings set

Failure examples:
- report mixes strong static leads into verified findings
- finding lacks exact artifact references
- traceability file does not include route or code references for the claim
- rejected items disappear rather than being preserved as negative knowledge

## Required manifest behavior
At the beginning of a run, create `artifacts/out/run_manifest.json` with:
- repository or assessment identifier if known
- runtime mode
- budgets
- ordered phase list
- expected artifact list
- current phase
- completion status per phase

Update it after every phase so the reviewer can see progress.

The manifest should also include:
- which skills have run
- which skills were re-run
- which gates failed and were retried
- whether any artifacts were reused from earlier work
- a concise note when a phase was skipped because runtime was unavailable or the artifact was explicitly unnecessary

## Required evidence merge behavior
`artifacts/out/evidence.json` is the canonical merged evidence file. It must not be a loose append-only dump. It must include:
- `components.surface`
- `components.routes`
- `components.dataflow`
- `components.business_logic`
- `components.waf`
- `provenance` entries pointing back to the source artifacts that produced each section
- dedupe notes when overlapping findings are merged

Additional merge rules:
- preserve stable IDs where possible
- when two skills describe the same route, sink, or workflow, merge them instead of duplicating them
- keep uncertainty markers from upstream artifacts
- never delete a previously valid section without writing why it was replaced or superseded

## Execution flow

### Phase 0 — bootstrap and manifest
1. Create directories.
2. Write `run_manifest.json`.
3. Initialize `gate_status.json` with all planned gates in `pending` state.
4. Validate Gate 0 immediately.

### Phase 1 — setup and connection context
1. If `context.json` is missing, run `$vuln_connection-read`.
2. Validate Gate 1.
3. If `base_url` is present and request shaping is unknown, run `$vuln_waf-profile` and merge into `evidence.json`.
4. Update manifest and gate state.

Operational notes:
- This phase establishes whether runtime work is even possible.
- If credentials are partial, still normalize them and record what is missing.
- If the target appears to be API-only, say so. If it appears to require browser state, say so.

### Phase 2 — surface indexing
1. Run `$vuln_surface-index` if `surface_index.json` is missing or too thin.
2. Validate Gate 2.
3. Update manifest and gate state.

Operational notes:
- This phase should leave behind a usable repo map, not just a list of filenames.
- Surface indexing should prefer concrete sinks and frameworks over exhaustive low-value files.
- If multiple apps exist in a monorepo, say which app(s) are in scope and which were deprioritized.

### Phase 3 — route, dataflow, and business-logic reasoning
This phase must create observable intermediate artifacts, not only a merged summary.
1. Run `$vuln_route-enumerate` when route shape matters, when endpoint context is missing, or when the framework strongly implies centralized routing. Write `route_map.json`.
2. Run `$vuln_dataflow-trace` and require `dataflow_index.json` plus merged updates to `evidence.json`.
3. Run `$vuln_business-logic-analyze` and require `business_logic.json` plus merged updates to `evidence.json`.
4. Validate Gate 3.

Operational notes:
- Route extraction can be partial, but not invisible.
- Dataflow should focus on user-controlled paths and control-enforcement boundaries.
- Business logic should model actor transitions, ownership assumptions, approval states, counters, quotas, and sequencing.

### Phase 4 — hypothesis construction
1. Run `$vuln_hypotheses-build` using `surface_index.json`, `route_map.json`, `dataflow_index.json`, `business_logic.json`, and `evidence.json`.
2. Require ranking rationale and attack order.
3. Validate Gate 4.

Operational notes:
- Convert evidence into executable claims, not essays.
- A good hypothesis answers: what to change, where to change it, why the change may matter, what signal should prove it, and what could cause a false positive.
- When multiple hypotheses share the same sink, choose the one with the cleanest observable signal first.

### Phase 5 — prepare and verify
If `base_url` is not present:
- skip runtime verification
- still create `verification_index.json` with `attempted=false`
- final report must mark all items as `inconclusive`

If `base_url` is present:
- select up to 15 hypotheses in attack order
- for each selected HID:
  1. run the best-matching `$vuln_attack-prepare-*` skill
  2. validate Gate 5 for that HID
  3. run `$vuln_verify-attack`
  4. validate Gate 6 for that HID
  5. update `verification_index.json`

Operational notes:
- Do not spend verification budget on weak hypotheses when stronger, cleaner signals exist.
- Prefer variants that isolate one control assumption at a time.
- Where the likely issue is role-based, ownership-based, or sequence-based, make the baseline represent legitimate behavior and the modified request represent only the suspected bypass.

### Research escalation policy
Use research only when a concrete blocker exists.
- Allow up to **3** pre-research verification cycles for a hypothesis.
- If the signal still cannot be achieved and the blocker is specific, run `$vuln_research` once.
- Regenerate the attack recipe if the research materially changes assumptions.
- Allow up to **3** post-research verification cycles.
- Do not continue beyond the total cap of 6 cycles.

A blocker is concrete when it names:
- an exact library or framework feature
- an exact parser, serializer, or sanitizer behavior
- an exact WAF or client-side interaction issue
- an exact discrepancy between observed and expected behavior

"Need more ideas" is not a concrete blocker.

### Phase 6 — reporting
1. Run `$vuln_report`.
2. Require both `findings.json` and `traceability.json`.
3. Validate Gate 7.
4. Mark the run complete in `run_manifest.json`.

Operational notes:
- Reporting is not a place to re-argue unproven claims.
- Keep the main findings set conservative.
- Preserve rejected and inconclusive work as negative knowledge for future runs.

## Manager enforcement rules
- Do not treat optional artifacts as required unless the hypothesis explicitly requires them.
- Do treat all canonical and control-plane artifacts as required when their phase has been executed.
- When a skill says it updates a merged artifact, also require that the skill either writes or refreshes its dedicated source artifact in the same phase.
- Never silently skip a missing artifact that downstream skills rely on.
- If a hypothesis depends on browser or callback requirements, do not mark its verification complete until the supporting artifact exists and is referenced.
- Do not allow stale references: if a clause or artifact path is replaced, remove all direct and indirect references to the old one from manager logic and downstream instructions.
- If a skill returns prose where structured data is required, treat it as a failed artifact and rerun the skill with a schema-focused instruction.
- If an artifact is partially valid, preserve the valid parts but still fail the gate until the missing required fields are filled.
- If a downstream skill appears to succeed despite missing prerequisites, reject that success and re-run with the missing prerequisite paths named explicitly.

## Escalation and edge-case handling
Handle the following edge cases explicitly rather than leaving them implicit:

### Monorepos and multiple services
- identify which service or app owns the in-scope routes or sinks
- do not merge artifacts from unrelated apps without labels
- when shared libraries contribute sinks or business rules, cite both the service path and shared-library path

### API plus browser hybrids
- note whether the same route is reachable via XHR/fetch and browser navigation
- if a client-side token, nonce, or DOM state affects exploitability, require `client_side.json`
- avoid marking a route unreachable just because it is fronted by client logic

### Generated code or decorators
- if the framework hides routes behind decorators, registry files, or code generation, route extraction may be approximate
- approximate routes are allowed only when confidence and blocker notes are recorded

### Incomplete auth context
- static work may continue
- runtime verification may still test unauthenticated hypotheses
- hypotheses requiring privileged roles must be preserved as such, not collapsed into generic failure

### Anti-automation and caching
- record whether cache keys, rate limits, bot checks, or stale responses might confuse verification
- verification must adapt by comparing clean baselines rather than brute-forcing more requests

### State-heavy workflows
- where create → approve → access or cart → checkout → refund style flows exist, require the workflow to be modeled in `business_logic.json`
- do not test a terminal action without recording the prerequisite state transitions

## Completion criteria
A run is complete only when:
- all executed phases have validated artifacts
- skipped phases are explicitly marked skipped with reasons
- verification index matches the actual verification artifacts
- findings and traceability are aligned
- the manifest marks completion and references final report paths

If these are not true, the run is incomplete even if some findings exist.
