from __future__ import annotations

import csv
import json
import sqlite3
import sys
from typing import Any

ALLOWED_FORMATS = {"text", "json", "csv", "table"}


def normalize_format(fmt: str | None) -> str:
    if not fmt:
        return "text"
    return "text" if fmt == "table" else fmt


def serialize_rows(rows: list[sqlite3.Row | dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        out.append(dict(row) if not isinstance(row, dict) else row)
    return out


def emit(rows: list[dict[str, Any]], fmt: str, headers: list[str] | None = None) -> None:
    fmt = normalize_format(fmt)
    if fmt not in {"text", "json", "csv"}:
        raise ValueError(f"Unsupported format: {fmt}")
    if fmt == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    if fmt == "csv":
        if not rows:
            return
        if headers is None:
            headers = list(rows[0].keys())
        writer = csv.DictWriter(sys.stdout, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
        return
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))
