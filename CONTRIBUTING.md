# CONTRIBUTING

## Dev setup

Python 3.10+ is enough. Make sure you run `pip install .`.

```bash
git clone <your-fork>
cd bbx
python3 -m pip install .
python3 -m compileall bbx.py
```

## Style

- Keep the tool single-file unless there is a strong reason not to.
- Prefer boring, dependency-free Python.
- Keep output stable for shell usage.
- New commands should support `--format` when that makes sense.

## Testing checklist

Before opening a PR:

```bash
python3 -m compileall bbx.py
python3 bbx.py init testprog
python3 bbx.py import-har testprog samples/session.har
python3 bbx.py rank testprog
python3 bbx.py top testprog --limit 3 --format json
python3 bbx.py graph testprog --format json
python3 bbx.py export testprog requests --format csv
```

## What to contribute

Good additions:
- new importers for safe artifact formats
- more export views
- better scoring heuristics
- graph filtering
- table-level summary improvements

Bad additions:
- active scanning
- exploit logic
- automated payload spraying
- anything that turns the tool into a live-target cannon


## Scan checks

Lab-only checks live in `bbx/checks/`. Keep them small, deterministic, and safe by default. New checks should:
- require explicit allowlisting
- save evidence into `evidence/`
- avoid high-volume fuzzing
- expose their results through SQLite tables


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
