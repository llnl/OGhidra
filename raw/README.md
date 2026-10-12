# raw/

**External documents only.** This directory holds source material with no
stable live path in a git repo — specs, papers, and freeform notes.

Do not copy files here from source repos. Those are cited directly by live path.
See the Source Policy section in `../AGENTS.md`.

## Required header for every file in raw/

```markdown
<!-- SOURCE: <URL or citation> -->
<!-- RETRIEVED: YYYY-MM-DD -->
```

Files missing this header will be flagged by lint as unprovenanced sources.

## What is cited in place (not copied here)

| `../` | primary repo; read live — never copy |

## What belongs here

- `specs/` — vendor format specs, standards documents (PDFs converted to markdown)
- `papers/` — academic papers, research references
- `notes/` — your own freeform design notes and meeting notes
