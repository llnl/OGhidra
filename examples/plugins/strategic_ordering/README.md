# Strategic ordering example

This opt-in plugin adds staged scheduling to the `functions.analyze` workflow.
It preserves the active legacy OGhidra priority policy: entry points, hubs,
architectural components, utilities, isolated functions, then remaining functions.
Functions within a stage retain their input order; the runtime still honors their
existing priorities and dependencies. No function analysis is implemented here.

The host supplies `function_snapshot`, a callable in the run services returning an
address-keyed mapping with `callers`, `callees`, and `relationships_known` fields.
An optional `is_entry` flag identifies confirmed entries. Absent relationships
remain unknown instead of being mistaken for evidence of isolation. Function
identity uses address rather than names, so duplicate names and renaming do not
merge different functions. The pure classifier deduplicates addresses; the plan
hook preserves every host work ID. The host should deduplicate repeated analysis
requests when building its initial plan.

The plugin adds at most five `workflow.barrier` items and a linear number of
dependencies. A following stage starts after the preceding stage finishes. The
runtime rejects cycles introduced by a stage that conflicts with existing work
dependencies and retains the original valid plan. Removing or disabling this
plugin leaves the normal host workflow available.

For nested `llm.generate` work, the host propagates the `strategic_category` and
`function_address` annotations. The context hook reads successful earlier-stage
records from `run.state['analysis_records']` (address, name/new_name, summary,
status, strategic_category). It contributes at most ten brief summaries in a
2,500-character block, subject to the shared runtime context budget. Summaries
are prior model interpretations, not new evidence about the binary.

## Source and intentional differences

The scores, name patterns, thresholds, fallback exported-name detection, and
exclusive category priorities are adapted from the active
`OGhidra-gitlab/src/enumeration_processor.py` methods
`_compute_strategic_function_order`, `_categorize_functions_with_priority`, and
`_identify_*` (lines 538, 1377, and 1517–1707 in the inspected legacy checkout).
This is not the different, older algorithm duplicated in legacy `src/ui.py`.

Original copyright: **2025 Enoch Wang**. The original MIT license is retained in
[LICENSE](LICENSE). This example does not change the license of the host project.

The extraction intentionally replaces name-keyed relationship lookups with
address identity, handles unknown graph coverage explicitly, accepts confirmed
entry metadata, and leaves UI, model calls, renames, retries, persistence and
graph acquisition to the host. Other heuristics remain legacy behavior, including
broad substring matches and the exported-name fallback; categories are hints,
not validated facts or topological execution order.
