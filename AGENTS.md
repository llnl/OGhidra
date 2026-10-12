# AGENTS.md — OGhidra Wiki

This is the operating contract for the LLM-maintained wiki for **OGhidra**.
OGhidra connects large language models to Ghidra to enable conversational and automated reverse engineering of binary programs.

You are the wiki maintainer. You read from `raw/` and from source repos listed
below. You write only to `wiki/`. You never modify source code, schemas, or raw documents.

---

<!-- loreforge:begin operating-modes version=1 -->
## Operating Modes

This repository supports two explicit agent modes.

### Wiki-Maintainer Mode

This is the default mode unless the user explicitly asks for code changes.

In wiki-maintainer mode:
- You write only to `wiki/`.
- You never modify files under `raw/`.
- You never modify source code, schemas, or other artifacts outside of `wiki/` unless the user explicitly requests code changes.

### Code-Development Mode

Code-development mode is active only when the user explicitly asks to implement, fix, test, or otherwise change code.

In code-development mode:
- You may modify source code, scripts, notebooks, configs, and documentation in the host repository (`OGhidra/`) as needed to complete the task.
- If this vault also contains the primary source code, follow normal engineering practices: prefer small, testable changes and avoid committing generated data unless explicitly approved.
- If you change behavior that affects the wiki's documented semantics, update the relevant `wiki/` pages and append a concise entry to `wiki/log.md`.
<!-- loreforge:end operating-modes -->

---

## Repository Layout

```
OGhidra/           ← this repo (wiki lives here)
  AGENTS.md               ← this file
  raw/                    ← external documents with no live repo path (see Source Policy)
    specs/                ← format specs, standards documents
    papers/               ← academic/research references
    notes/                ← your own analysis notes and meeting notes
  wiki/                   ← your working area (you own this entirely)
    index.md
    log.md
    overview/
    tension/
    decision/
    concept/
    architecture/
    workflow/
    module/
    knowledge_schema/
    integration/
    benchmark/
    deployment/
    best_practice/
  <source files>          ← primary repo content also lives here
```

---

<!-- loreforge:begin source-policy version=1 -->
## Source Policy: Cite vs. Copy

**When in doubt, cite. Never copy what you can read live.**

### Cite in place — never copy into raw/

Any file that lives in a git repo you control must be cited by its live path:

```markdown
<!-- GROUND_TRUTH: path/to/file.py §section -->
```

Rationale: copied files go stale silently. A live cite is re-readable at any
time and always reflects the current state of the repo.

### Copy once into raw/ — external documents only

Only copy documents with no stable live path:
- Vendor specs and standards downloaded as PDFs
- Academic papers
- Freeform notes not committed to any repo

Every file in `raw/` must include a provenance header:

```markdown
<!-- SOURCE: <URL or citation> -->
<!-- RETRIEVED: YYYY-MM-DD -->
```

### Lint enforcement

The LINT operation flags source policy violations:
- `grounded_by` entries pointing to paths that mirror live repo files → stale copy violation
- Pages with `confidence: high` and empty `grounded_by` → unanchored claim
- Files in `raw/` missing a `<!-- SOURCE: -->` header → unprovenanced source
<!-- loreforge:end source-policy -->

---

<!-- loreforge:begin frontmatter version=1 -->
## Page Frontmatter Schema

Every wiki page **must** include this YAML frontmatter:

```yaml
---
title: "Human-readable title"
type: tension | decision | concept | architecture | workflow | module | knowledge_schema | integration | benchmark | deployment | best_practice
confidence: high | medium | low | speculative
grounded_by:
  - path/to/source
policy: agent-editable | human-review-required | immutable
last_validated: YYYY-MM-DD
status: draft | active | deprecated
owners: team-reverse-engineering | maintainer-handle
code_refs: src/cag/knowledge/common_workflows.json | pyproject.toml
stability: experimental | stable | deprecated
last_verified: 2026-10-12
tags: [reverse-engineering, binary-analysis, python, mcp, llm-orchestration, ghidra, knowledge-base, function-signatures, benchmarks, deprecated-java]
---
```

### Confidence levels
- `high` — directly grounded in source code, schema, or authoritative doc; verified
- `medium` — grounded in at least one source; minor gaps or inference involved
- `low` — inferred from context; needs verification
- `speculative` — design idea or open question; not yet implemented

### Policy levels
- `agent-editable` — update freely as new sources arrive
- `human-review-required` — flag changes with `<!-- REVIEW NEEDED: reason -->`; note in log.md
- `immutable` — finalized human-authored content; do not edit
<!-- loreforge:end frontmatter -->

---

<!-- loreforge:begin tensions version=1 -->
## Tension Pages

When you detect an unresolved design conflict, create a page in `wiki/tensions/`.

```yaml
---
title: "Tension: <short description>"
type: tension
status: open | held | resolved | dissolved
poles:
  - "First position and its rationale"
  - "Second position and its rationale"
resolution: null
confidence: medium
policy: agent-editable
last_validated: YYYY-MM-DD
---
```

Never silently overwrite a tension. Mark `status: resolved` only when a source
or explicit human decision closes it; populate `resolution:` with a citation.
<!-- loreforge:end tensions -->

---

<!-- loreforge:begin decisions version=1 -->
## Decision Pages (ADRs)

Architecture decisions go in `wiki/decisions/`. Use this format:

```yaml
---
title: "Decision: <what was decided>"
type: decision
status: proposed | accepted | superseded | deprecated
decided_on: YYYY-MM-DD
grounded_by: []
policy: human-review-required
tags: []
---
```

Sections: Context, Decision, Rationale, Consequences, Alternatives Considered.
<!-- loreforge:end decisions -->

---

## Feature Work: LLM-Assisted Feature Workflow

Use a grounded adaptive interview before drafting non-trivial feature work:

```text
Start a new feature using the LLM-assisted feature workflow: <feature name>
```

Create only useful artifacts under `wiki/work/<feature-slug>/`; only `brief.md`
is always required. Use `dev_handoff.md` for implementation handoff and
`implementation_plan.md` for the executable checklist. Record exact commands,
full output, and deviations from the handoff in `verification.md`. Long-running
research threads may use an `index.md` with dated snapshots. After behavior
stabilizes, promote durable facts into canonical wiki pages.

---

<!-- loreforge:begin operations version=1 -->
## Operations

### INGEST — when you receive a new source

1. Read the source fully before writing anything.
2. Summarize key takeaways for the human; note surprises or contradictions.
3. Write or update the relevant wiki page.
4. Identify all other pages this source touches; update each one.
5. Check for contradictions against existing pages:
   - **Soft** (framing/scope difference): `<!-- CONTRADICTION[soft]: <desc> -->`; note in log.md.
   - **Hard** (direct factual conflict): `<!-- CONTRADICTION[hard]: <desc> — REVIEW NEEDED -->`
     on both pages; set `policy: human-review-required`; note in log.md; pause updates.
6. Create tension pages for unresolved design conflicts.
7. Update `wiki/index.md`.
8. Append to `wiki/log.md`:
   ```
   ## [YYYY-MM-DD] ingest | <Source>
   Pages created: ...
   Pages updated: ...
   Contradictions flagged: ...
   ```

### QUERY — when you answer a question

1. Read `wiki/index.md` to locate relevant pages.
2. Read those pages; synthesize with citations back to wiki pages and raw sources.
3. If the answer is substantive, offer to file it as a new wiki page.

### LINT — periodic health check

**Deterministic:**
- Orphan pages (no inbound `[[wikilinks]]`)
- Broken wikilinks (reference non-existent pages)
- Missing required frontmatter fields
- Stale pages (`last_validated` > 60 days ago)
- Unresolved hard contradictions (`policy: human-review-required`)
- Source policy violations (see Source Policy section)

**Reasoning:**
- Every architecture or workflow claim must cite the relevant Python module, configuration file, schema, test, or documented entry point.
- Distinguish observed repository behavior from inferred LLM behavior, planned changes, and recommended best practices.
- Knowledge JSON documentation must identify the schema shape, required fields, valid values, loading path, and at least one concrete repository example.
- Do not present the Java/Gradle plugin as the long-term integration path; mark claims about it as transitional or deprecated where appropriate.
- Document data transformations and boundaries between the LLM, MCP layer, Python orchestration, Ghidra, and benchmark outputs.
- Pages describing workflows or evaluation must include failure modes and explain how the documented behavior can be verified.
- Flag pages whose referenced files, symbols, schemas, or workflows no longer exist in the repository.
<!-- loreforge:end operations -->
---

<!-- loreforge:begin grounding version=1 -->
## Ground Truth Anchoring

When a claim is directly traceable to source code or a schema, mark it:

```markdown
Some fact about the code.
<!-- GROUND_TRUTH: path/to/file.py §section -->
```

When a claim is your synthesis across sources, flag it:

```markdown
Some inferred conclusion.
<!-- SYNTHESIS: inferred from path/to/a and path/to/b -->
```

When a field or behavior is undefined or placeholder, flag it:

```markdown
Some undefined thing.
<!-- SPECULATIVE: source §field — reason it's undefined -->
```
<!-- loreforge:end grounding -->

---

## Domain Context

OGhidra is an AI-assisted reverse-engineering system built around Python orchestration, MCP-based interaction, Ghidra analysis workflows, and structured knowledge about tools and function signatures. This wiki exists primarily to help developers navigate the codebase, understand end-to-end binary-analysis data flow, and safely extend the orchestration and knowledge layers. It should also preserve evaluation practices and, over time, document best practices for using OGhidra effectively.

### Key research/design questions to keep surfaced

- What is the end-to-end data flow from an MCP or LLM request through Python orchestration, Ghidra analysis, tool invocation, and the returned result?
- Which Python modules own orchestration, tool discovery, workflow execution, state management, and translation between LLM-facing and Ghidra-facing representations?
- How are common workflows and function signatures represented, validated, loaded, selected, and extended in the knowledge JSON files?
- Which parts of the Java/Gradle Ghidra plugin are still required during the transition to the maintained Ghidra plugin, and what is the deprecation or removal plan?
- How do tests and benchmark evaluations measure correctness, usefulness, latency, and failure modes in AI-assisted binary analysis?
- What assumptions, limitations, and safety practices should developers follow when using OGhidra to analyze binaries?

---

<!-- loreforge:begin session-startup version=1 -->
## Session Startup

1. Read this file (AGENTS.md).
2. Read `wiki/log.md` (last 10 entries).
3. Read `wiki/index.md`.
4. Ask what to do: ingest a source, answer a question, lint, or explore.

Do not load all wiki pages at startup. Load on demand as operations require.
When referencing files in source repos, read them from their live paths directly.
Summarize and cite; never copy source code into the wiki.
<!-- loreforge:end session-startup -->
