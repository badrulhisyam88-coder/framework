# Cybersecurity Knowledge Vault

A deterministic, markdown-first knowledge base for offensive and defensive security research.

## Design Principles

- **Human-readable first** — every file is plain markdown, no runtime dependencies
- **Markdown is the source of truth** — no databases, no vector stores, no sync daemons
- **Deterministic naming** — all files follow strict naming conventions for reproducibility
- **Tool-agnostic** — works with Obsidian, NotebookLM, any text editor, local RAG systems

## Vault Layout

```
knowledge-vault/
├── findings/          # Vulnerability findings by category
│   ├── web/
│   ├── api/
│   ├── network/
│   └── cloud/
├── labs/              # Lab walkthroughs (HackTheBox, TryHackMe, CTFs)
├── learning-paths/    # Structured learning roadmaps
├── blue-team/         # Detection, SOC analysis, DFIR notes
├── remediation/       # Remediation playbooks and fix references
├── attack-chains/     # Multi-stage attack narratives
├── concepts/          # Core security concepts and reference notes
├── journals/          # Daily/weekly study and practice journals
├── reports/           # Formatted pentest/assessment reports
├── templates/         # Canonical templates for each content type
└── exports/           # Timestamped exports for sharing or archival
```

## Quick Start

1. Copy the relevant template from `templates/` for the content type you are writing.
2. Fill in the YAML frontmatter — every field is required unless marked optional.
3. Save the file using the deterministic naming convention from `EXPORT_STANDARDS.md`.
4. Cross-link to related findings, concepts, and labs using `[[wikilink]]` or relative paths.

## Standards Documents

| Document | Purpose |
|---|---|
| [VAULT_STRUCTURE.md](VAULT_STRUCTURE.md) | Folder conventions, file placement rules |
| [EXPORT_STANDARDS.md](EXPORT_STANDARDS.md) | Naming conventions, ID formats, export rules |
| [templates/](templates/) | All canonical templates |

## Compatible Tools

- **Obsidian** — open vault root directly; wikilinks and graph view work natively
- **NotebookLM** — upload individual markdown files or export bundles
- **VS Code** — full editing with Markdown Preview Enhanced
- **Local RAG** — YAML frontmatter fields are structured for future embedding pipelines
- **CLI** — `grep`, `find`, `fzf` on frontmatter fields for fast lookups
