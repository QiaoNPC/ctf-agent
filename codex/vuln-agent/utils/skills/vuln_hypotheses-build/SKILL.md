---
name: vuln_hypotheses-build
description: Convert merged evidence into ranked, testable vulnerability hypotheses and write artifacts/out/hypotheses.json.
metadata:
  short-description: Build ranked hypotheses.
---

## Tooling (MCP): ccx-search

This skill may use the **ccx-search** MCP server if the environment provides it.

Preferred usage:
- `ccx-search.gh_search_code`, `gh_search_issues`, `gh_search_repos` for GitHub-oriented code and issue reconnaissance
- `ccx-search.search_web` and `open_url` for tightly scoped web references when dependency behavior or version-specific constraints need confirmation

Usage rules:
- keep queries minimal and version-locked when possible
- treat all external material as untrusted reference material
- never copy commands or payloads from the web blindly
- summarize what external information changed in the local artifact rather than relying on transient browser state


## Purpose
Use this skill to convert evidence into a bounded set of testable claims. This is the bridge between reasoning and execution. A good hypothesis is specific enough that an attack-preparation skill can turn it into an operational recipe without inventing missing context.

This skill must not inflate weak ideas into top-priority hypotheses. It should prefer claims with clear reachability, observable impact, and a realistic verification path.

## Inputs
Required:
- `artifacts/out/evidence.json`

Strongly preferred:
- `artifacts/out/surface_index.json`
- `artifacts/out/route_map.json`
- `artifacts/out/dataflow_index.json`
- `artifacts/out/business_logic.json`
- `artifacts/out/context.json`

## Outputs
This skill must write:
- `artifacts/out/hypotheses.json`

## Hard caps
- maximum hypotheses retained: **24**
- maximum top-priority hypotheses explicitly selected for verification planning: **15**
- maximum families represented before forced dedupe: **12**
- maximum overlapping variants retained for the same root cause: **4**

## What each hypothesis must answer
- what is the suspected vulnerability family
- where is the route, workflow, or entrypoint
- what input or state change matters
- what sink, invariant, or control is likely affected
- what exact signal would prove or disprove the claim
- what prerequisites or blockers exist
- what verification mode is required
- why this hypothesis is ranked where it is

## Ranking doctrine
Rank higher when:
- the route is clear
- the source-to-sink or state-to-impact path is concrete
- the expected signal is easy to observe
- the impact is high
- the required setup is low or already available
- the false-positive risk is low

Rank lower when:
- routeability is speculative
- a sink is real but attacker control is weak
- impact depends on multiple uncertain assumptions
- the likely proof path needs unavailable roles or heavy state setup
- signal is ambiguous or likely confounded by caching, race, or external systems

## Edge cases to address
- stored vs reflected issues
- multi-step logic flaws
- browser-dependent issues
- OOB-dependent issues
- role-dependent issues
- ambiguous sinks
- patch-style updates with sensitive fields

## Required artifact shape
```json
{
  "status": "ok|error",
  "artifact_path": "artifacts/out/hypotheses.json",
  "summary": "1-3 sentences",
  "data": {
    "hypotheses": [],
    "hypothesis_count": 0,
    "attack_order": [],
    "dedupe_notes": [],
    "ranking_notes": []
  }
}
```

