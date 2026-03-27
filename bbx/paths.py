from __future__ import annotations

from pathlib import Path
import argparse


def ensure_dirs(base: Path) -> None:
    for rel in ["raw", "processed", "findings", "notes", "imports", "graphs", "exports", "config", "evidence"]:
        (base / rel).mkdir(parents=True, exist_ok=True)


def resolve_base(value: str, workspace: str | None = None) -> Path:
    p = Path(value).expanduser()
    if p.is_absolute() or any(sep in value for sep in ('/', '\\')) or value.startswith('.') or p.exists():
        return p
    if workspace:
        return Path(workspace).expanduser() / value
    return p


def get_base(args: argparse.Namespace) -> Path:
    workspace = getattr(args, 'workspace', None)
    target = getattr(args, 'program', None) or getattr(args, 'path', None)
    if target is None:
        raise ValueError('Missing program/path argument')
    return resolve_base(target, workspace)
