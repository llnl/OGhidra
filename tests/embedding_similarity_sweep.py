#!/usr/bin/env python3
"""Embedding similarity sweep for a saved analysis session.

This is a lightweight, throwaway-friendly utility placed under tests/.

Goal:
- Compare Ollama embedding models by cosine similarity between each query prompt
  and the target function's behavior summary (default: lua_reset_state @ 00444df0).

Notes:
- By default, this does NOT embed every function in the session (fast).
- If you want to approximate retrieval behavior, pass --rank to embed all
  functions and compute the target's rank among them (slow).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import requests


# Roughly matches src/ollama_client.py defaults.
MAX_EMBED_TOKENS = 8192
CHARS_PER_TOKEN = 4
MAX_EMBED_CHARS = int(MAX_EMBED_TOKENS * CHARS_PER_TOKEN * 0.95)


def _chunk_text(text: str, max_chars: int = MAX_EMBED_CHARS, overlap: int = 500) -> List[str]:
    if not text:
        return [""]
    if len(text) <= max_chars:
        return [text]

    chunks: List[str] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + max_chars, n)
        if end < n:
            search_start = max(start, end - 2000)
            double_nl = text.rfind("\n\n", search_start, end)
            if double_nl > start + (max_chars // 2):
                end = double_nl + 2
            else:
                single_nl = text.rfind("\n", search_start, end)
                if single_nl > start + (max_chars // 2):
                    end = single_nl + 1
                else:
                    sentence_end = max(
                        text.rfind(". ", search_start, end),
                        text.rfind(".\n", search_start, end),
                        text.rfind(";\n", search_start, end),
                        text.rfind("}\n", search_start, end),
                    )
                    if sentence_end > start + (max_chars // 2):
                        end = sentence_end + 2

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= n:
            break
        start = max(start + 1, end - overlap)
    return chunks if chunks else [text[:max_chars]]


def _average_embeddings(embs: List[List[float]]) -> List[float]:
    if not embs:
        return []
    if len(embs) == 1:
        return embs[0]
    dim = len(embs[0])
    out = [0.0] * dim
    for e in embs:
        if len(e) != dim:
            raise ValueError(f"Embedding dimension mismatch: expected {dim}, got {len(e)}")
        for i, v in enumerate(e):
            out[i] += float(v)
    inv = 1.0 / float(len(embs))
    return [v * inv for v in out]


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na == 0.0 or nb == 0.0:
        return float("nan")
    return float(np.dot(a, b) / (na * nb))


class OllamaEmbedder:
    def __init__(self, base_url: str, timeout_s: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        # Cache embedding API mode per model, since some Ollama builds/models may
        # only support the legacy endpoint.
        self._api_mode_by_model: Dict[str, str] = {}  # model -> "new"|"old"

    def list_models(self) -> List[Dict[str, Any]]:
        resp = requests.get(f"{self.base_url}/api/tags", timeout=self.timeout_s)
        resp.raise_for_status()
        data = resp.json()
        return data.get("models", [])

    def embed(self, text: str, model: str) -> np.ndarray:
        chunks = _chunk_text(text)
        if len(chunks) == 1:
            emb = self._embed_single(chunks[0], model)
            return np.asarray(emb, dtype=np.float32)
        embs = [self._embed_single(c, model) for c in chunks]
        return np.asarray(_average_embeddings(embs), dtype=np.float32)

    def _embed_single(self, text: str, model: str) -> List[float]:
        mode = self._api_mode_by_model.get(model)
        if mode == "new":
            return self._embed_new(text, model)
        if mode == "old":
            return self._embed_old(text, model)

        # Auto-detect for this model - prefer new API first.
        try:
            emb = self._embed_new(text, model)
            self._api_mode_by_model[model] = "new"
            return emb
        except Exception:
            emb = self._embed_old(text, model)
            self._api_mode_by_model[model] = "old"
            return emb

    def _embed_new(self, text: str, model: str) -> List[float]:
        url = f"{self.base_url}/api/embed"
        payload = {"model": model, "input": [text]}
        resp = requests.post(url, json=payload, timeout=self.timeout_s)
        resp.raise_for_status()
        data = resp.json()
        # New API may return embeddings[] or embedding
        embs = data.get("embeddings", [])
        if isinstance(embs, list) and embs:
            return embs[0]
        emb = data.get("embedding", [])
        return emb

    def _embed_old(self, text: str, model: str) -> List[float]:
        url = f"{self.base_url}/api/embeddings"
        payload = {"model": model, "prompt": text}
        resp = requests.post(url, json=payload, timeout=self.timeout_s)
        resp.raise_for_status()
        data = resp.json()
        return data.get("embedding", [])


def looks_like_embedding_model(model_info: Dict[str, Any]) -> bool:
    """Heuristic: include likely embedding models from /api/tags."""
    name = str(model_info.get("name", ""))
    details = model_info.get("details", {}) or {}
    family = str(details.get("family", ""))
    families = details.get("families", []) or []
    families = [str(x) for x in families]
    name_l = name.lower()
    family_l = family.lower()
    families_l = {f.lower() for f in families}

    # Common signals.
    if "embed" in name_l:
        return True
    if name_l.startswith("bge-"):
        return True
    if "bert" in family_l or "bert" in families_l:
        return True
    if "nomic-bert" in family_l or "nomic-bert" in families_l:
        return True

    return False


def normalize_model_name(name: str) -> str:
    # Convenience: allow passing "nomic-embed-text" while tags returns "...:latest".
    if ":" in name:
        return name
    return name + ":latest"


def load_session_functions(session_path: Path) -> Dict[str, Dict[str, Any]]:
    data = json.loads(session_path.read_text(encoding="utf-8"))
    funcs = data.get("analyzed_functions", {})
    if not isinstance(funcs, dict):
        raise ValueError("session.json missing analyzed_functions dict")
    return funcs


def build_function_text(entry: Dict[str, Any], include_name: bool) -> str:
    name = str(entry.get("new_name") or entry.get("old_name") or "")
    summary = str(entry.get("behavior_summary") or "")
    if include_name and name:
        return f"Function: {name}\n\n{summary}"
    return summary


def default_prompts() -> List[str]:
    # Intentionally general: try to describe behavior rather than matching exact strings.
    return [
        "Find a function that reads or parses the Unix password hash file to extract credentials.",
        "Identify a function that accesses a sensitive system password file and processes entries with hashed passwords.",
        "Locate code that constructs a sensitive file path at runtime (string building / obfuscation) and then opens and reads it.",
        "Find a misleadingly named function that performs credential harvesting by reading a privileged system file.",
        "Find code that reads a protected authentication file line-by-line and filters entries with password hashes.",
        "Find functionality that resolves a sensitive system path (like /etc/shadow) in an obfuscated way and then reads it.",
    ]


def expand_prompt_variants(base: str) -> List[str]:
    """Small, fixed expansion set for quick prompt tweaking."""
    base = base.strip()
    if not base:
        return []

    variants = [base]

    # Add mild clarifiers without making it overly specific.
    addons = [
        " The name may be misleading.",
        " The path may be built dynamically to evade string search.",
        " Focus on semantic behavior, not exact strings.",
        " Look for credential or password-hash related parsing.",
    ]
    for a in addons:
        variants.append(base + a)

    # A few alternate phrasings.
    variants.append(base.replace("sensitive", "privileged"))
    variants.append(base.replace("reads", "opens and reads"))
    variants.append(base.replace("password", "authentication"))

    # Dedupe while preserving order.
    seen = set()
    out: List[str] = []
    for v in variants:
        key = " ".join(v.split())
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


@dataclass
class SweepRow:
    model: str
    prompt: str
    score: float
    target_rank: Optional[int] = None
    total_ranked: Optional[int] = None


def compute_rank(
    query_emb: np.ndarray,
    corpus_embs: np.ndarray,
    corpus_addrs: Sequence[str],
    target_addr: str,
) -> Tuple[int, int]:
    # Normalize for dot-product cosine.
    q = query_emb.astype(np.float32)
    qn = np.linalg.norm(q)
    if qn == 0.0:
        return (len(corpus_addrs) + 1, len(corpus_addrs))
    q = q / qn

    m = corpus_embs
    # assumes m is already normalized row-wise
    sims = m @ q

    # Rank is 1 + count of sims strictly greater.
    idx = None
    for i, a in enumerate(corpus_addrs):
        if a.lower() == target_addr.lower():
            idx = i
            break
    if idx is None:
        raise ValueError(f"Target address {target_addr} not found in corpus")

    target_sim = float(sims[idx])
    rank = int(1 + int(np.sum(sims > target_sim)))
    return (rank, len(corpus_addrs))


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Compare Ollama embedding models for prompt similarity")
    p.add_argument(
        "--session",
        default=str(
            Path("analysis_sessions")
            / "session_1771713926_c8f3fc0f"
            / "session.json"
        ),
        help="Path to session.json",
    )
    p.add_argument(
        "--ollama-url",
        default=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        help="Ollama base URL (default: env OLLAMA_BASE_URL or http://localhost:11434)",
    )
    p.add_argument(
        "--target-addr",
        default="00444df0",
        help="Target function address (default: 00444df0)",
    )
    p.add_argument(
        "--prompts-file",
        default="",
        help="Optional path to a text file (one prompt per line)",
    )
    p.add_argument(
        "--expand",
        action="store_true",
        help="Expand prompts into small variant set (for quick prompt tuning)",
    )
    p.add_argument(
        "--include-name",
        action="store_true",
        help="Include function name in embedded text (may help some models)",
    )
    p.add_argument(
        "--rank",
        action="store_true",
        help="Also embed all functions and compute target rank (slow)",
    )
    p.add_argument(
        "--limit-models",
        default="",
        help="Comma-separated allowlist of model names (exact match)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="HTTP timeout in seconds (default: 120)",
    )
    p.add_argument(
        "--top-per-model",
        type=int,
        default=5,
        help="How many top prompts to show per model (default: 5)",
    )
    args = p.parse_args(argv)

    session_path = Path(args.session)
    if not session_path.exists():
        print(f"ERROR: session.json not found: {session_path}", file=sys.stderr)
        return 2

    embedder = OllamaEmbedder(args.ollama_url, timeout_s=args.timeout)

    models_raw = embedder.list_models()
    models = [m["name"] for m in models_raw if looks_like_embedding_model(m)]
    models.sort()

    if args.limit_models:
        allow_raw = [x.strip() for x in args.limit_models.split(",") if x.strip()]
        allow = {normalize_model_name(x) for x in allow_raw}
        models = [m for m in models if m in allow]

    if not models:
        print("ERROR: No embedding models detected from /api/tags", file=sys.stderr)
        return 2

    funcs = load_session_functions(session_path)
    target_entry = funcs.get(args.target_addr)
    if target_entry is None:
        # Some sessions may store addresses without leading zeros; attempt a lenient match.
        ta = args.target_addr.lower().lstrip("0")
        for k, v in funcs.items():
            if str(k).lower().lstrip("0") == ta:
                target_entry = v
                args.target_addr = str(k)
                break
    if target_entry is None:
        print(f"ERROR: Target address not found in session: {args.target_addr}", file=sys.stderr)
        return 2

    target_text = build_function_text(target_entry, include_name=args.include_name)
    if not target_text.strip():
        print("ERROR: Target function has empty behavior_summary", file=sys.stderr)
        return 2

    prompts: List[str]
    if args.prompts_file:
        pf = Path(args.prompts_file)
        prompts = []
        for ln in pf.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if not s:
                continue
            if s.startswith("#"):
                continue
            prompts.append(s)
    else:
        prompts = default_prompts()

    if args.expand:
        expanded: List[str] = []
        for pr in prompts:
            expanded.extend(expand_prompt_variants(pr))
        prompts = expanded

    # Optionally build corpus for ranking.
    corpus_addrs: List[str] = []
    corpus_texts: List[str] = []
    if args.rank:
        for addr, entry in funcs.items():
            txt = build_function_text(entry, include_name=args.include_name)
            if not txt.strip():
                continue
            corpus_addrs.append(str(addr))
            corpus_texts.append(txt)

    rows: List[SweepRow] = []

    print(f"Session: {session_path}")
    print(f"Ollama:  {embedder.base_url}")
    print(f"Target:  {target_entry.get('new_name') or target_entry.get('old_name')} @ {args.target_addr}")
    print(f"Models:  {len(models)}")
    for m in models:
        print(f"  - {m}")
    print(f"Prompts: {len(prompts)}" + (" (expanded)" if args.expand else ""))
    print("")

    # Precompute target embedding per model.
    target_emb_by_model: Dict[str, np.ndarray] = {}
    corpus_embs_by_model: Dict[str, Tuple[np.ndarray, List[str]]] = {}

    for model in models:
        t0 = time.time()
        try:
            target_emb = embedder.embed(target_text, model=model)
        except Exception as e:
            print(f"WARN: embed failed for model={model}: {e}", file=sys.stderr)
            continue

        target_emb_by_model[model] = target_emb

        if args.rank:
            # Embed full corpus for this model.
            embs: List[np.ndarray] = []
            kept_addrs: List[str] = []
            for addr, txt in zip(corpus_addrs, corpus_texts):
                try:
                    e = embedder.embed(txt, model=model)
                except Exception:
                    continue
                embs.append(e)
                kept_addrs.append(addr)

            if not embs:
                print(f"WARN: no corpus embeddings produced for model={model}", file=sys.stderr)
            else:
                mat = np.vstack([x.astype(np.float32) for x in embs])
                # Normalize rows.
                norms = np.linalg.norm(mat, axis=1)
                norms[norms == 0.0] = 1.0
                mat = mat / norms[:, None]
                corpus_embs_by_model[model] = (mat, kept_addrs)

        elapsed = time.time() - t0
        print(f"Embedded target for {model} ({len(target_emb)} dims) in {elapsed:.2f}s")

    print("")

    if not target_emb_by_model:
        print("ERROR: No embeddings produced for any model", file=sys.stderr)
        return 2

    # Score all prompts.
    for model, target_emb in target_emb_by_model.items():
        for prompt in prompts:
            try:
                q_emb = embedder.embed(prompt, model=model)
                score = cosine_similarity(q_emb, target_emb)
            except Exception as e:
                print(f"WARN: query embed failed for model={model}: {e}", file=sys.stderr)
                continue

            row = SweepRow(model=model, prompt=prompt, score=score)
            if args.rank and model in corpus_embs_by_model:
                mat, addrs = corpus_embs_by_model[model]
                try:
                    r, total = compute_rank(q_emb, mat, addrs, args.target_addr)
                    row.target_rank = r
                    row.total_ranked = total
                except Exception as e:
                    print(f"WARN: rank compute failed for model={model}: {e}", file=sys.stderr)
            rows.append(row)

    # Print summary: best prompt per model.
    print("Per-model stats (cosine similarity to target):")
    models_in_rows = sorted({r.model for r in rows})
    for model in models_in_rows:
        scores = np.asarray([r.score for r in rows if r.model == model and not math.isnan(r.score)], dtype=np.float32)
        if scores.size == 0:
            continue
        mx = float(np.max(scores))
        mn = float(np.min(scores))
        mean = float(np.mean(scores))
        med = float(np.median(scores))
        std = float(np.std(scores))
        print(f"- {model}: n={int(scores.size)} min={mn:.4f} mean={mean:.4f} median={med:.4f} std={std:.4f} max={mx:.4f}")

        mrows = [r for r in rows if r.model == model and not math.isnan(r.score)]
        mrows_sorted = sorted(mrows, key=lambda r: r.score, reverse=True)
        topn = max(1, int(args.top_per_model))
        for r in mrows_sorted[:topn]:
            rank_s = ""
            if r.target_rank is not None and r.total_ranked is not None:
                rank_s = f" rank {r.target_rank}/{r.total_ranked}"
            print(f"  {r.score:.4f}{rank_s} | {r.prompt}")

    # Optional: dump a top-N table for the overall best scores.
    rows_sorted = sorted([r for r in rows if not math.isnan(r.score)], key=lambda r: r.score, reverse=True)
    top_n = min(20, len(rows_sorted))
    if top_n:
        print("")
        print(f"Top {top_n} (model,prompt) pairs overall:")
        for r in rows_sorted[:top_n]:
            rank_s = ""
            if r.target_rank is not None and r.total_ranked is not None:
                rank_s = f" rank {r.target_rank}/{r.total_ranked}"
            print(f"- {r.model}: {r.score:.4f}{rank_s} | {r.prompt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
