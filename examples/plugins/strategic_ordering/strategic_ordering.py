"""Function analysis stages extracted from the legacy OGhidra enumeration policy.

Derived from src/enumeration_processor.py in OGhidra-gitlab, copyright (c)
2025 Enoch Wang, MIT licensed; see the accompanying LICENSE and README.md.
The plugin depends only on the host workflow contracts and the standard library.
"""

from collections.abc import Mapping
from dataclasses import replace

from src.workflow import ContextBlock, WorkItem

PLUGIN_ID = "oghidra.strategic_ordering"
CATEGORIES = (
    "entry_points",
    "high_impact_hubs",
    "architectural_components",
    "leaf_utilities",
    "isolated_functions",
    "remaining_functions",
)
HUB_KEYWORDS = ("manager", "handler", "controller", "processor", "engine", "core", "dispatcher", "router")
ARCHITECTURE_KEYWORDS = (
    "config",
    "setup",
    "initialize",
    "create",
    "destroy",
    "connect",
    "disconnect",
    "bind",
    "unbind",
    "register",
    "unregister",
    "load",
    "unload",
    "mount",
    "unmount",
)
UTILITY_KEYWORDS = (
    "parse",
    "validate",
    "convert",
    "transform",
    "encode",
    "decode",
    "encrypt",
    "decrypt",
    "hash",
    "checksum",
    "compress",
    "decompress",
    "serialize",
    "deserialize",
    "format",
    "print",
    "log",
    "copy",
    "move",
    "search",
    "find",
    "replace",
    "split",
    "join",
    "trim",
    "clean",
    "sort",
    "filter",
    "map",
    "reduce",
)
GUIDANCE = {
    "entry_points": "Examine initialization and the main execution flow.",
    "high_impact_hubs": "Examine how this function coordinates other components.",
    "architectural_components": "Examine lifecycle, configuration, and component management.",
    "leaf_utilities": "Examine this function's specific operation and its callers.",
    "isolated_functions": "No relationships were observed in the supplied snapshot; inspect the code's purpose.",
    "remaining_functions": "Use the code and direct relationships to establish this function's role.",
}


def canonical_address(address):
    """Normalize hex addresses, preserving non-hex address-space identifiers."""
    value = str(address or "").strip().lower()
    try:
        return format(int(value, 16), "x") if value else ""
    except ValueError:
        return value


def function_key(function):
    address = canonical_address(function.get("address"))
    return ("address", address) if address else ("id", str(function.get("id", function.get("name", ""))))


def _likely_exported(name):
    if name.startswith(("FUN_", "sub_", "loc_", "unk_", "j_", "_")):
        return False
    if any(pattern in name for pattern in ("main", "Init", "Create", "Start", "Stop", "Process", "Handle")):
        return True
    return len(name) > 8 and any(character.isupper() for character in name[1:])


def classify_functions(functions, snapshot=None):
    """Return stable, unique classifications in legacy category priority order.

    Inputs are mappings with name/address (optional id when address is absent).
    Name patterns and thresholds match the active legacy processor. Two explicit
    fixes are address identity and distinguishing missing edges from known zero
    edges. The host may additionally supply a confirmed is_entry flag.
    """
    graph = {canonical_address(address): data for address, data in (snapshot or {}).items()}
    rows = []
    seen = set()
    for function in functions:
        key = function_key(function)
        if key in seen:
            continue
        seen.add(key)
        name = str(function.get("name") or str(function.get("function", "")).split(" at ")[0]).strip()
        lower = name.lower()
        metadata = graph.get(canonical_address(function.get("address")), {})
        known = metadata.get("relationships_known") is True
        callers = len(metadata.get("callers", ())) if known else 0
        callees = len(metadata.get("callees", ())) if known else 0

        entry = 100 if "main" in lower else 0
        entry += 80 if "entry" in lower or "start" in lower else 0
        entry += 70 if "init" in lower or "initialize" in lower else 0
        entry += 90 if "dll" in lower and "main" in lower else 0
        entry += 60 if name.startswith("_") or name.endswith("_main") else 0
        entry += 50 if known and callers == 0 and callees > 0 else 0
        if metadata.get("is_entry") is True:
            entry = max(100, entry)

        hub = 80 if callers >= 3 and callees >= 3 else 60 if callers >= 2 and callees >= 2 else 0
        hub += 40 if any(keyword in lower for keyword in HUB_KEYWORDS) else 0
        architecture = 30 * sum(keyword in lower for keyword in ARCHITECTURE_KEYWORDS)
        architecture += 20 if 1 <= callers <= 4 and 1 <= callees <= 4 else 0
        utility = 40 if any(keyword in lower for keyword in UTILITY_KEYWORDS) else 0
        utility += 30 if callers >= 1 and callees <= 2 else 0
        rows.append((function, name, known, callers, callees, entry, hub, architecture, utility))

    use_export_fallback = not any(row[5] >= 50 for row in rows)
    buckets = {category: [] for category in CATEGORIES}
    for function, name, known, callers, callees, entry, hub, architecture, utility in rows:
        if entry >= 50:
            category, reason = "entry_points", f"Entry heuristic score {entry} (threshold 50)"
        elif use_export_fallback and _likely_exported(name):
            category, reason = "entry_points", "Legacy exported-name fallback; no stronger entry candidate"
        elif hub >= 50:
            category, reason = "high_impact_hubs", f"Hub heuristic score {hub} (threshold 50)"
        elif architecture >= 30:
            category, reason = "architectural_components", f"Architecture heuristic score {architecture} (threshold 30)"
        elif utility >= 40:
            category, reason = "leaf_utilities", f"Utility heuristic score {utility} (threshold 40)"
        elif known and callers == 0 and callees == 0:
            category, reason = "isolated_functions", "Snapshot reports known zero callers and callees"
        else:
            category = "remaining_functions"
            reason = "No higher-priority heuristic matched" if known else "Relationships unknown; no name heuristic matched"
        buckets[category].append({"function": function, "category": category, "reason": reason})
    return [row for category in CATEGORIES for row in buckets[category]]


def plan_functions(plan, run):
    """Add category annotations and linear-size stage barriers; preserve work IDs."""
    if plan.workflow != "functions.analyze" or any(item.annotations.get("strategic_barrier") for item in plan.items):
        return plan
    candidates = [item for item in plan.items if item.operation == "function.analyze"]
    if not candidates:
        return plan
    provider = run.services.get("function_snapshot")
    snapshot = provider() if callable(provider) else {}
    records = [dict(item.input, id=item.id) for item in candidates]
    classifications = {function_key(row["function"]): row for row in classify_functions(records, snapshot)}
    stages = {category: [] for category in CATEGORIES}
    for item, record in zip(candidates, records):
        classification = classifications[function_key(record)]
        annotations = dict(
            item.annotations, strategic_category=classification["category"], strategic_reason=classification["reason"]
        )
        stages[classification["category"]].append(replace(item, annotations=annotations))

    output = [item for item in plan.items if item.operation != "function.analyze"]
    occupied = {item.id for item in plan.items}
    previous_barrier = None
    nonempty = [(category, items) for category, items in stages.items() if items]
    for index, (category, items) in enumerate(nonempty):
        for item in items:
            dependencies = tuple(item.depends_on)
            if previous_barrier is not None and previous_barrier not in dependencies:
                dependencies += (previous_barrier,)
            output.append(replace(item, depends_on=dependencies))
        if index < len(nonempty) - 1:
            barrier_id = f"{PLUGIN_ID}.barrier.{index}"
            while barrier_id in occupied:
                barrier_id += "_"
            occupied.add(barrier_id)
            output.append(
                WorkItem(
                    id=barrier_id,
                    operation="workflow.barrier",
                    depends_on=tuple(item.id for item in items),
                    annotations={"strategic_barrier": True, "strategic_category": category, "dependency_policy": "settled"},
                )
            )
            previous_barrier = barrier_id
    return replace(plan, items=output, annotations=dict(plan.annotations, strategic_ordering=PLUGIN_ID))


def collect_context(item, context):
    """Contribute bounded guidance and completed earlier-stage summaries."""
    category = item.annotations.get("strategic_category")
    if item.operation != "llm.generate" or category not in CATEGORIES:
        return []
    # The shared runtime applies the final token budget to all contributors.
    limit = min(2500, max(0, int(context.run.context_budget)) * 4)
    if limit == 0:
        return []
    lines = [
        f"Strategic category (heuristic): {category}.",
        GUIDANCE[category],
        "Prior analyses are fallible context; verify claims against code and direct relationships.",
    ]
    records = context.run.state.get("analysis_records", {})
    records = tuple(records.values()) if isinstance(records, Mapping) else tuple(records)
    earlier = set(CATEGORIES[: CATEGORIES.index(category)])
    count = 0
    for record in records:
        if not isinstance(record, Mapping) or record.get("status") not in (
            "completed",
            "success",
            "success_rename",
            "success_enumerate",
        ):
            continue
        if record.get("strategic_category") not in earlier or not record.get("summary"):
            continue
        address = str(record.get("address", ""))
        if canonical_address(address) == canonical_address(item.annotations.get("function_address")) and address:
            continue
        name = str(record.get("new_name") or record.get("name") or address)
        summary = " ".join(str(record["summary"]).split())[:400]
        lines.append(f"Earlier analysis {name} at {address}: {summary}")
        count += 1
        if count >= 10:
            break
    text = "\n".join(lines)[:limit]
    return [ContextBlock(text=text, source=PLUGIN_ID, priority=10, kind="evidence")]


def activate(api):
    api.add_hook("workflow.plan", plan_functions)
    api.add_hook("context.collect", collect_context)
