---
title: "Session Memory and Cache-Augmented Generation"
type: module
confidence: high
grounded_by:
  - src/cag/manager.py
  - src/memory_manager.py
  - src/models/memory.py
  - src/cag/vector_store.py
  - src/context_manager.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/cag/manager.py | src/memory_manager.py | src/models/memory.py | src/cag/vector_store.py | src/context_manager.py
stability: experimental
last_verified: 2026-10-12
tags: [python, cag, memory, rag, sessions, vector-search]
---

# Session Memory and Cache-Augmented Generation

OGhidra has two related context systems: per-run session memory and reusable CAG/RAG retrieval. Session memory preserves the current investigation; CAG retrieves static knowledge or semantically similar documents to augment prompts.

## Session State

`SessionMemory` stores conversation messages, tool executions, analysis state, user preferences, and `KnowledgeArtifact` records. Artifacts are simple key/value/category/tag entries formatted into prompt text. Execution results can also be represented as ranked results, correlation hints, and cycle conclusions for planning continuity.
<!-- GROUND_TRUTH: src/models/memory.py §338-432, §472-549 -->

`MemoryManager` persists completed sessions, tracks active sessions, optionally embeds sessions, and can search for similar historical sessions. The default storage is JSONL under `data/`, while vector storage is separately configured.
<!-- GROUND_TRUTH: src/memory_manager.py §21-60, §112-180 -->
<!-- GROUND_TRUTH: src/config.py §1422-1430 -->

## CAG Retrieval

`CAGManager` lazily initializes a vector store when Ollama embeddings are available. It prioritizes malware-pattern alerts, allocates a phase-dependent knowledge budget, optionally uses hybrid keyword/semantic search, falls back to semantic retrieval, and then appends session context if budget remains.
<!-- GROUND_TRUTH: src/cag/manager.py §37-78, §80-188 -->

The simple vector store uses embeddings supplied through `Bridge`, searches up to three documents, and approximates token limits as four characters per token. FAISS is optional; without it, cosine similarity is computed directly.
<!-- GROUND_TRUTH: src/cag/vector_store.py §23-110, §290-343 -->

## Context Risks

- Vector retrieval depends on an available embedding model and compatible embedding dimensions.
- Token budgets are rough estimates, not tokenizer measurements.
- Session context can contain sensitive binary findings and is eligible for prompt injection.
- Cached or summarized results may omit detail; use `get_cached_result` or repeat a targeted query when exact output is needed.
- CAG is disabled for the benchmark runner to reduce confounding context.
<!-- GROUND_TRUTH: src/cag/vector_store.py §301-332 -->
<!-- GROUND_TRUTH: benchmark/cli.py §91-105 -->
