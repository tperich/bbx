# USAGE

## Quick start

```bash
python3 -m pip install .
python3 bbx.py init ~/bbx/acme
python3 bbx.py import-har acme samples/session.har
python3 bbx.py rank acme
python3 bbx.py top acme --limit 10 --format json
```

## Importing common tool outputs

```bash
python3 bbx.py ingest-subfinder acme samples/subfinder.txt
python3 bbx.py ingest-httpx acme samples/httpx.jsonl
python3 bbx.py ingest-katana acme samples/katana.jsonl
python3 bbx.py ingest-gau acme samples/gau.txt
python3 bbx.py ingest-wayback acme samples/wayback.txt
python3 bbx.py ingest-naabu acme samples/naabu.txt
python3 bbx.py ingest-ffuf acme samples/ffuf.json
python3 bbx.py ingest-nuclei acme samples/nuclei.jsonl
```

## Output formats

Commands that support formatting accept `--format text|json|csv`.

Examples:

```bash
python3 bbx.py top acme --limit 5 --format csv
python3 bbx.py interesting-urls acme --limit 20 --format json
python3 bbx.py summarize acme --format csv
python3 bbx.py db-stats acme --format json
```

## Tagging workflow

Tag interesting rows so you can revisit them later.

```bash
python3 bbx.py tag-add acme request 1 authz --note "Check cross-tenant behavior"
python3 bbx.py tag-add acme url 3 export
python3 bbx.py tags acme --format json
python3 bbx.py tag-remove acme url 3 export
```

Supported entity types:
- `request`
- `host`
- `url`
- `web`
- `port`
- `finding`

## Findings workflow

```bash
python3 bbx.py new-finding acme idor_invoice_access --title "Cross-account invoice access"
python3 bbx.py set-finding-status acme idor_invoice_access validated
python3 bbx.py list-findings acme --format csv
```

## Correlation graph

### Mermaid
```bash
python3 bbx.py graph acme --format mermaid
```

### Graphviz DOT
```bash
python3 bbx.py graph acme --format dot
```

### JSON graph export
```bash
python3 bbx.py graph acme --format json --out /tmp/acme_graph.json
```

## Exporting raw tables

```bash
python3 bbx.py export acme requests --format csv
python3 bbx.py export acme urls_discovered --format json
python3 bbx.py export acme tags --format csv
```

## Sample flows

See:
- `flows/01_har_first.md`
- `flows/02_recon_blend.md`


## Filtering
Use these flags to cut noise:

```bash
python3 bbx.py top acme --tag authz --min-score 20
python3 bbx.py interesting-urls acme --host api.acme.test --tool katana --format csv
python3 bbx.py export acme urls_discovered --tag review --min-score 30 --format json
python3 bbx.py graph acme --host api.acme.test --tool gau --format mermaid
```

## Text filters

These commands now support additional filters:
- `--contains` case-insensitive substring match across key text fields
- `--path-prefix` only keep rows whose path starts with a prefix
- `--status` exact status filter where available

Examples:
```bash
python3 bbx.py top acme --contains admin --path-prefix /api/
python3 bbx.py interesting-urls acme --contains graphql --path-prefix /api/
python3 bbx.py export acme web_targets --status 200 --format csv
python3 bbx.py list-findings acme --status submitted --format json
```


## Saved presets

Use presets when you keep running the same filters.

```bash
python3 bbx.py preset-save acme authz --tag authz --min-score 20 --path-prefix /api/
python3 bbx.py preset-save acme recon-api --tool katana --host api.acme.test --contains graphql
python3 bbx.py preset-list acme
python3 bbx.py preset-show acme authz --format json
python3 bbx.py top acme --preset authz
python3 bbx.py export acme urls_discovered --preset recon-api --format csv
python3 bbx.py preset-delete acme recon-api
```

Supported preset fields:
- `tag`
- `host`
- `min_score`
- `tool`
- `contains`
- `path_prefix`
- `status`
- `limit`


## Lab-only active scan usage

Initialize a workspace and review the generated config files:

```bash
python3 bbx.py init ~/bbx/acme
cat ~/bbx/acme/config/allowlist.txt
cat ~/bbx/acme/config/scan_profiles.yaml
```

Register a URL manually:

```bash
python3 bbx.py scan-register-url acme http://127.0.0.1:8000/api/health
```

Queue checks from imported assets:

```bash
python3 bbx.py scan-plan acme --profile safe-recon --from-table web_targets --limit 10
```

Run queued checks with optional auth headers:

```bash
python3 bbx.py scan-run acme --limit 10 \
  --auth-header "Authorization: Bearer LABTOKEN"
```

Read results:

```bash
python3 bbx.py scan-results acme --format json
python3 bbx.py scan-findings acme --format json
```


## Layout note

`bbx.py` is now a tiny entrypoint. The CLI logic lives in `bbx/cli.py`, path helpers in `bbx/paths.py`, output helpers in `bbx/output.py`, and scoring logic in `bbx/scoring.py`.


## Modular layout

The CLI is now split into command modules under `bbx/commands/`:
- `workspace.py`
- `imports.py`
- `analysis.py`
- `findings.py`
- `tags.py`
- `exports.py`
- `presets.py`
- `scan.py`

Shared command implementation remains in `bbx/core.py`, while `bbx/cli.py` is now a small parser/dispatcher entrypoint.


## New reliability commands

- `bbx doctor <workspace>` checks workspace layout, DB presence, allowlist, scan profiles, and presets.
- `bbx validate-import <kind> <file>` validates supported import file shapes before ingest.
- CLI output formats now consistently use `text`, `json`, or `csv`.
