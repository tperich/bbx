![bbx logo](assets/logo.png)

# bbx toolkit

[![CI](https://github.com/tperich/bbx/actions/workflows/ci.yml/badge.svg)](https://github.com/tperich/bbx/actions/workflows/ci.yml)
[![Security Audit](https://github.com/tperich/bbx/actions/workflows/security-audit.yml/badge.svg)](https://github.com/tperich/bbx/actions/workflows/security-audit.yml)
[![Release](https://github.com/tperich/bbx/actions/workflows/release.yml/badge.svg)](https://github.com/tperich/bbx/actions/workflows/release.yml)

**From noisy recon to actionable signal.**

`bbx` is a SQLite-backed CLI for organizing bug bounty artifacts (HAR, crawl output, request data), ranking interesting rows, tagging findings, and exporting useful views.

---

## Table of Contents

- [Why bbx](#why-bbx)
- [Quickstart](#quickstart)
- [Core Commands](#core-commands)
- [Filtering & Presets](#filtering--presets)
- [Lab-only Scan Framework](#lab-only-scan-framework)
- [Output Formats](#output-formats)
- [Project Layout](#project-layout)
- [Reliability Commands](#reliability-commands)
- [Safety Guardrails](#safety-guardrails)
- [Docs](#docs)

---

## Why bbx

Bug bounty workflows generate fragmented data fast. `bbx` helps you:

- ingest artifact outputs into one SQLite workspace
- rank and query likely-interesting requests quickly
- attach tags/findings and preserve context
- export/share filtered data (`text`, `json`, `csv`)
- generate graph views for correlation

---

## Quickstart

```bash
python3 -m pip install .
python3 bbx.py init acme
python3 bbx.py import-har acme samples/session.har
python3 bbx.py rank acme
python3 bbx.py top acme --limit 5 --format json
```

---

## Core Commands

| Command | Purpose |
|---|---|
| `init` | Create a new workspace |
| `import-har` | Import HAR request/response data |
| `rank` | Score/imported items for triage |
| `top` | Show top-ranked items |
| `interesting-urls` | Pull useful URL candidates |
| `new-finding` / `list-findings` | Track findings in workspace |
| `tag-add` / `tags` | Add/query tags |
| `graph` | Export relationship/correlation view |
| `export` | Export table views in chosen format |

---

## Filtering & Presets

### Filter flags
The following filters are supported across key analysis/export commands:

- `--tag`
- `--host`
- `--min-score`
- `--tool`
- `--contains`
- `--path-prefix`
- `--status`

### Presets
Save reusable filter sets and apply them later:

```bash
python3 bbx.py preset-save acme authz --tag authz --min-score 20 --path-prefix /api/
python3 bbx.py preset-list acme
python3 bbx.py top acme --preset authz
python3 bbx.py interesting-urls acme --preset authz --format csv
```

---

## Lab-only Scan Framework

`bbx` includes a queue-driven scan layer for personal labs and explicitly allowlisted assets.

```bash
python3 bbx.py scan-register-url acme http://127.0.0.1:8000/api/health
python3 bbx.py scan-plan acme --profile safe-recon --from-table web_targets --limit 10
python3 bbx.py scan-run acme --limit 10
python3 bbx.py scan-results acme --format json
python3 bbx.py scan-findings acme --format json
```

---

## Output Formats

Where supported, command output is standardized to:

- `text`
- `json`
- `csv`

---

## Project Layout

`bbx.py` is a thin entrypoint.

Core logic is modularized:

- `bbx/cli.py`
- `bbx/core.py`
- `bbx/paths.py`
- `bbx/output.py`
- `bbx/scoring.py`

Command modules:

- `bbx/commands/workspace.py`
- `bbx/commands/imports.py`
- `bbx/commands/analysis.py`
- `bbx/commands/findings.py`
- `bbx/commands/tags.py`
- `bbx/commands/exports.py`
- `bbx/commands/presets.py`
- `bbx/commands/scan.py`

---

## Reliability Commands

- `bbx doctor <workspace>`
  - checks workspace layout, DB presence, allowlist, scan profiles, and presets
- `bbx validate-import <kind> <file>`
  - validates import file shape before ingest

---

## Safety Guardrails

- Active checks run only against hosts in `config/allowlist.txt`
- Scan profiles live in `config/scan_profiles.yaml`
- Built-in checks remain intentionally lightweight:
  - `http_probe`
  - `openapi_fetch`
  - `method_diff`
  - `reflection_check`

---

## Docs

- Full command usage: [`USAGE.md`](USAGE.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- License: [`LICENSE`](LICENSE)
