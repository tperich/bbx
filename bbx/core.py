#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import requests
from urllib.parse import parse_qs, urlparse
from bbx.paths import ensure_dirs, get_base
from bbx.output import emit, serialize_rows, ALLOWED_FORMATS, normalize_format
from bbx.scoring import SKIP_EXT, KEYWORDS, ID_KEYS, score_item, score_url

ENTITY_TABLES = {
    "request": ("requests", "id", "url"),
    "host": ("hosts_discovered", "id", "host"),
    "url": ("urls_discovered", "id", "url"),
    "web": ("web_targets", "id", "url"),
    "port": ("ports_discovered", "id", "host || ':' || port"),
    "finding": ("findings", "id", "slug"),
}

FINDING_TEMPLATE = """# TITLE\n\n## Summary\n-\n\n## Asset\n-\n\n## Steps to Reproduce\n1.\n2.\n3.\n\n## Impact\n-\n\n## Evidence\n- Request:\n- Response:\n- Screenshot:\n\n## Remediation\n-\n"""

README = """# bbx toolkit 

A SQLite-backed CLI for organizing bug bounty artifacts.

This toolkit imports **existing** outputs and captured traffic, ranks likely-interesting assets, adds lightweight tagging, and can export host/URL/request relationships as a correlation graph.

It also ships with a **lab-only scan framework** for queue-driven active checks against your own allowlisted assets.

See:
- `USAGE.md`
- `CONTRIBUTING.md`
- `bb.1`
"""


def fail(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _arg_file(args: argparse.Namespace) -> str:
    return getattr(args, "file", None) or getattr(args, "path", None) or getattr(args, "har", None)


def _arg_dataset(args: argparse.Namespace) -> str:
    return getattr(args, "dataset", None) or getattr(args, "table", None)


def _normalize_args_format(args: argparse.Namespace) -> None:
    if hasattr(args, "format"):
        args.format = normalize_format(getattr(args, "format", None))


def db_path(base: Path) -> Path:
    return base / "bbx.sqlite3"


def connect(base: Path) -> sqlite3.Connection:
    ensure_dirs(base)
    conn = sqlite3.connect(db_path(base))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            headers_json TEXT,
            params_json TEXT,
            body_json TEXT,
            data_text TEXT,
            score INTEGER DEFAULT 0,
            source_file TEXT,
            dedupe_key TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ffuf_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT,
            status INTEGER,
            length INTEGER,
            words INTEGER,
            lines INTEGER,
            url TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS nuclei_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT,
            severity TEXT,
            name TEXT,
            matched TEXT,
            template TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS hosts_discovered (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            host TEXT NOT NULL,
            source_file TEXT,
            extra_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tool, host)
        );

        CREATE TABLE IF NOT EXISTS web_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT,
            status INTEGER,
            title TEXT,
            tech_json TEXT,
            source_file TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tool, url)
        );

        CREATE TABLE IF NOT EXISTS urls_discovered (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT,
            path TEXT,
            score INTEGER DEFAULT 0,
            source_file TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tool, url)
        );

        CREATE TABLE IF NOT EXISTS ports_discovered (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            host TEXT NOT NULL,
            ip TEXT,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            source_file TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tool, host, port, protocol)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            path TEXT NOT NULL,
            title TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            tag TEXT NOT NULL,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(entity_type, entity_id, tag)
        );

        CREATE TABLE IF NOT EXISTS scan_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            value TEXT NOT NULL,
            host TEXT,
            path TEXT,
            source_table TEXT,
            source_id INTEGER,
            tags TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_type, value)
        );

        CREATE TABLE IF NOT EXISTS scan_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            check_name TEXT NOT NULL,
            profile_name TEXT,
            status TEXT NOT NULL DEFAULT 'queued',
            priority INTEGER NOT NULL DEFAULT 100,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT,
            error TEXT,
            FOREIGN KEY(asset_id) REFERENCES scan_assets(id)
        );

        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            check_name TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT,
            request_count INTEGER NOT NULL DEFAULT 0,
            evidence_path TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(queue_id) REFERENCES scan_queue(id),
            FOREIGN KEY(asset_id) REFERENCES scan_assets(id)
        );

        CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            check_name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id),
            FOREIGN KEY(asset_id) REFERENCES scan_assets(id)
        );

        CREATE TABLE IF NOT EXISTS scan_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id),
            FOREIGN KEY(asset_id) REFERENCES scan_assets(id)
        );

        CREATE TABLE IF NOT EXISTS scan_kv (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id),
            FOREIGN KEY(asset_id) REFERENCES scan_assets(id)
        );

        CREATE INDEX IF NOT EXISTS idx_requests_score ON requests(score DESC);
        CREATE INDEX IF NOT EXISTS idx_requests_url ON requests(url);
        CREATE INDEX IF NOT EXISTS idx_ffuf_status ON ffuf_results(status);
        CREATE INDEX IF NOT EXISTS idx_nuclei_severity ON nuclei_results(severity);
        CREATE INDEX IF NOT EXISTS idx_hosts_tool ON hosts_discovered(tool, host);
        CREATE INDEX IF NOT EXISTS idx_web_targets_tool ON web_targets(tool, host);
        CREATE INDEX IF NOT EXISTS idx_urls_score ON urls_discovered(score DESC, host);
        CREATE INDEX IF NOT EXISTS idx_ports_host ON ports_discovered(host, port);
        CREATE INDEX IF NOT EXISTS idx_tags_lookup ON tags(entity_type, entity_id, tag);
        CREATE INDEX IF NOT EXISTS idx_scan_assets_host ON scan_assets(host, asset_type);
        CREATE INDEX IF NOT EXISTS idx_scan_queue_status ON scan_queue(status, priority);
        CREATE INDEX IF NOT EXISTS idx_scan_runs_asset ON scan_runs(asset_id, check_name);
        CREATE INDEX IF NOT EXISTS idx_scan_findings_asset ON scan_findings(asset_id, severity);
        """
    )
    conn.commit()


def keep_url(url: str, content_type: str = "") -> bool:
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXT):
        return False
    if any(x in path for x in ["/api/", "/graphql", "/admin", "/account", "/settings"]):
        return True
    ctype = content_type.lower()
    return "json" in ctype or "html" in ctype




def load_json_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def copy_import(base: Path, src_str: str, prefix: str) -> Path:
    src = Path(src_str).expanduser()
    if not src.exists():
        raise FileNotFoundError(src)
    dst = base / "imports" / f"{prefix}_{src.name}"
    if src.resolve() != dst.resolve():
        shutil.copy2(src, dst)
    return dst


def iter_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]




def presets_path(base: Path) -> Path:
    return base / "presets.json"


def load_presets(base: Path) -> dict[str, Any]:
    p = presets_path(base)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_presets(base: Path, presets: dict[str, Any]) -> None:
    presets_path(base).write_text(json.dumps(presets, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def apply_preset_args(args: argparse.Namespace) -> None:
    preset_name = getattr(args, "preset", None)
    if not preset_name or not hasattr(args, "program"):
        return
    base = get_base(args)
    presets = load_presets(base)
    preset = presets.get(preset_name)
    if not preset:
        raise SystemExit(f"Unknown preset: {preset_name}")
    allowed = {"tag", "host", "min_score", "tool", "contains", "path_prefix", "status", "limit", "format"}
    for key, value in preset.items():
        if key in allowed and getattr(args, key, None) in (None, 0, "", False):
            setattr(args, key, value)




def scan_config_dir(base: Path) -> Path:
    return base / "config"


def default_allowlist_path(base: Path) -> Path:
    return scan_config_dir(base) / "allowlist.txt"


def default_profiles_path(base: Path) -> Path:
    return scan_config_dir(base) / "scan_profiles.yaml"


def ensure_scan_config(base: Path) -> None:
    cfg = scan_config_dir(base)
    cfg.mkdir(parents=True, exist_ok=True)
    allow = default_allowlist_path(base)
    if not allow.exists():
        allow.write_text("# One host per line. Only these hosts may be actively checked.\n127.0.0.1\nlocalhost\n", encoding="utf-8")
    prof = default_profiles_path(base)
    if not prof.exists():
        prof.write_text("""profiles:
  safe-recon:
    checks:
      - http_probe
      - openapi_fetch
      - method_diff
    timeout: 10
    delay_seconds: 0.5
    max_requests_per_run: 10

  reflection-lite:
    checks:
      - http_probe
      - reflection_check
    timeout: 10
    delay_seconds: 0.7
    max_requests_per_run: 5
""", encoding="utf-8")


def load_allowlist(base: Path, path_override: str | None = None) -> set[str]:
    path = Path(path_override).expanduser() if path_override else default_allowlist_path(base)
    if not path.exists():
        return set()
    hosts = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        hosts.add(line)
    return hosts


def _simple_yaml_value(raw: str):
    raw = raw.strip()
    if raw in {'true', 'false'}:
        return raw == 'true'
    try:
        if '.' in raw:
            return float(raw)
        return int(raw)
    except Exception:
        return raw.strip("\"'")


def load_scan_profiles(base: Path) -> dict[str, Any]:
    path = default_profiles_path(base)
    if not path.exists():
        return {}
    # Tiny parser for the limited bundled YAML structure.
    profiles: dict[str, Any] = {}
    current = None
    in_checks = False
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if not line.strip() or line.strip().startswith('#'):
            continue
        if line.startswith('profiles:'):
            continue
        if re.match(r'^\s{2}[A-Za-z0-9_-]+:\s*$', line):
            name = line.strip().rstrip(':')
            current = profiles.setdefault(name, {})
            in_checks = False
            continue
        if current is None:
            continue
        if re.match(r'^\s{4}checks:\s*$', line):
            current['checks'] = []
            in_checks = True
            continue
        if in_checks and re.match(r'^\s{6}-\s+', line):
            current['checks'].append(line.split('-', 1)[1].strip())
            continue
        m = re.match(r'^\s{4}([A-Za-z0-9_]+):\s*(.+?)\s*$', line)
        if m:
            current[m.group(1)] = _simple_yaml_value(m.group(2))
            in_checks = False
    return profiles


def register_scan_asset(conn: sqlite3.Connection, *, asset_type: str, value: str, source_table: str | None = None, source_id: int | None = None) -> int:
    parsed = urlparse(value) if asset_type in {'url', 'endpoint'} else None
    host = parsed.hostname if parsed else value
    path = parsed.path if parsed else None
    conn.execute(
        """
        INSERT OR IGNORE INTO scan_assets (asset_type, value, host, path, source_table, source_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (asset_type, value, host, path, source_table, source_id),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM scan_assets WHERE asset_type = ? AND value = ?", (asset_type, value)).fetchone()
    return int(row['id'])


def queue_scan(conn: sqlite3.Connection, *, asset_id: int, check_name: str, profile_name: str | None = None, priority: int = 100) -> None:
    conn.execute(
        """
        INSERT INTO scan_queue (asset_id, check_name, profile_name, priority)
        VALUES (?, ?, ?, ?)
        """,
        (asset_id, check_name, profile_name, priority),
    )
    conn.commit()


def save_scan_evidence(base: Path, conn: sqlite3.Connection, run_id: int, asset_id: int, name: str, payload: Any, kind: str) -> str:
    evidence_dir = base / 'evidence'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    suffix = '.json' if isinstance(payload, (dict, list)) else '.txt'
    path = evidence_dir / f'run_{run_id}_{asset_id}_{name}{suffix}'
    if isinstance(payload, (dict, list)):
        path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    else:
        path.write_text(str(payload), encoding='utf-8', errors='ignore')
    conn.execute("INSERT INTO scan_evidence (run_id, asset_id, kind, file_path) VALUES (?, ?, ?, ?)", (run_id, asset_id, kind, str(path)))
    conn.commit()
    return str(path)


def add_scan_run(conn: sqlite3.Connection, *, queue_id: int, asset_id: int, check_name: str, status: str, summary: str, request_count: int, evidence_path: str | None = None) -> int:
    cur = conn.execute(
        """
        INSERT INTO scan_runs (queue_id, asset_id, check_name, status, summary, request_count, evidence_path)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (queue_id, asset_id, check_name, status, summary, request_count, evidence_path),
    )
    conn.commit()
    return int(cur.lastrowid)


def add_scan_finding_row(conn: sqlite3.Connection, *, run_id: int, asset_id: int, check_name: str, severity: str, title: str, details: str) -> None:
    conn.execute(
        "INSERT INTO scan_findings (run_id, asset_id, check_name, severity, title, details) VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, asset_id, check_name, severity, title, details),
    )
    conn.commit()


def add_scan_kv_row(conn: sqlite3.Connection, *, run_id: int, asset_id: int, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO scan_kv (run_id, asset_id, key, value) VALUES (?, ?, ?, ?)",
        (run_id, asset_id, key, value),
    )
    conn.commit()


def common_asset_where(args: argparse.Namespace, table_alias: str = '') -> tuple[str, list[Any]]:
    where, params = [], []
    prefix = f'{table_alias}.' if table_alias else ''
    if getattr(args, 'host', None):
        where.append(f"{prefix}host = ?")
        params.append(args.host)
    if getattr(args, 'contains', None):
        where.append(f"{prefix}value LIKE ?")
        params.append(f"%{args.contains}%")
    if getattr(args, 'path_prefix', None):
        where.append(f"COALESCE({prefix}path, '') LIKE ?")
        params.append(f"{args.path_prefix}%")
    clause = '' if not where else ' WHERE ' + ' AND '.join(where)
    return clause, params

def cmd_init(args: argparse.Namespace) -> int:
    base = get_base(args)
    ensure_dirs(base)
    (base / "README.md").write_text(README, encoding="utf-8")
    (base / "notes" / "daily.md").touch()
    ensure_scan_config(base)
    conn = connect(base)
    conn.close()
    print(base)
    return 0


def _validate_import(kind: str, path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"kind": kind, "path": str(path), "ok": False, "details": {}}
    if not path.exists():
        result["details"] = {"error": "file does not exist"}
        return result
    try:
        if kind == "har":
            payload = json.loads(path.read_text(encoding="utf-8"))
            entries = payload.get("log", {}).get("entries", [])
            result["ok"] = isinstance(entries, list)
            result["details"] = {"entries": len(entries)}
        elif kind in {"ffuf", "nuclei", "httpx", "katana"}:
            records = load_json_records(path)
            result["ok"] = len(records) > 0
            sample_keys = sorted(records[0].keys()) if records else []
            result["details"] = {"records": len(records), "sample_keys": sample_keys}
        elif kind in {"subfinder", "amass", "gau", "wayback", "naabu"}:
            lines = iter_lines(path)
            result["ok"] = len(lines) > 0
            result["details"] = {"lines": len(lines), "sample": lines[:3]}
        else:
            result["details"] = {"error": f"unsupported kind: {kind}"}
    except Exception as exc:
        result["details"] = {"error": str(exc)}
    return result


def cmd_validate_import(args: argparse.Namespace) -> int:
    result = _validate_import(args.kind, Path(args.file).expanduser())
    ok = result.get("ok", False)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if ok else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    base = get_base(args)
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    add("workspace_exists", base.exists(), str(base))
    for rel in ["raw", "processed", "findings", "notes", "imports", "graphs", "exports", "config", "evidence"]:
        add(f"dir:{rel}", (base / rel).exists(), str(base / rel))
    db = db_path(base)
    add("database", db.exists(), str(db))
    if db.exists():
        try:
            conn = connect(base)
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
            add("database_tables", True, ", ".join(tables[:12]) + (" ..." if len(tables) > 12 else ""))
            conn.close()
        except Exception as exc:
            add("database_tables", False, str(exc))
    allow = default_allowlist_path(base)
    add("allowlist", allow.exists(), str(allow))
    profiles = default_profiles_path(base)
    add("scan_profiles", profiles.exists(), str(profiles))
    if profiles.exists():
        try:
            loaded = load_scan_profiles(base)
            add("scan_profiles_parse", bool(loaded), f"profiles={','.join(sorted(loaded.keys()))}")
        except Exception as exc:
            add("scan_profiles_parse", False, str(exc))
    presets = presets_path(base)
    if presets.exists():
        try:
            loaded = load_presets(base)
            add("presets_parse", True, f"count={len(loaded)}")
        except Exception as exc:
            add("presets_parse", False, str(exc))
    else:
        add("presets_parse", True, "no presets file yet")

    if args.format == "text":
        for row in checks:
            status = "OK" if row["ok"] else "FAIL"
            print(f"[{status}] {row['check']}: {row['detail']}")
    else:
        emit(checks, args.format, headers=["check", "ok", "detail"])
    return 0 if all(c["ok"] for c in checks if c["check"] != "presets_parse") else 1


def cmd_import_har(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    raw_copy = copy_import(base, _arg_file(args), "har")
    har = json.loads(raw_copy.read_text(encoding="utf-8"))

    inserted = 0
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        res = entry.get("response", {})
        method = req.get("method", "GET").upper()
        url = req.get("url", "")
        ctype = ""
        for h in res.get("headers", []):
            if h.get("name", "").lower() == "content-type":
                ctype = h.get("value", "")
                break
        if not keep_url(url, ctype):
            continue
        parsed = urlparse(url)
        headers = {
            h["name"]: h["value"]
            for h in req.get("headers", [])
            if h.get("name", "").lower() not in {"cookie", "authorization", "content-length", "host"}
        }
        params = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(parsed.query).items()}
        body_text = req.get("postData", {}).get("text")
        json_body = None
        data_body = None
        if body_text:
            try:
                json_body = json.loads(body_text)
            except Exception:
                data_body = body_text

        item: dict[str, Any] = {
            "name": f"{method}_{parsed.path}".replace("/", "_")[:120],
            "method": method,
            "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "headers": headers,
            "params": params,
        }
        if json_body is not None:
            item["json"] = json_body
        if data_body is not None:
            item["data"] = data_body

        dedupe_key = json.dumps([
            item["method"], item["url"], sorted(item.get("params", {}).keys())
        ], separators=(",", ":"), sort_keys=True)

        conn.execute(
            """
            INSERT INTO requests (
                name, method, url, headers_json, params_json, body_json, data_text,
                score, source_file, dedupe_key, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(dedupe_key) DO UPDATE SET
                name=excluded.name,
                headers_json=excluded.headers_json,
                params_json=excluded.params_json,
                body_json=excluded.body_json,
                data_text=excluded.data_text,
                source_file=excluded.source_file,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                item["name"],
                item["method"],
                item["url"],
                json.dumps(item.get("headers", {}), ensure_ascii=False),
                json.dumps(item.get("params", {}), ensure_ascii=False),
                json.dumps(item.get("json"), ensure_ascii=False) if item.get("json") is not None else None,
                item.get("data"),
                score_item(item),
                raw_copy.name,
                dedupe_key,
            )
        )
        inserted += 1

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    conn.close()
    print(f"processed {inserted} HAR entries; requests table now has {total} rows")
    return 0


def export_ranked_jsonl(base: Path, conn: sqlite3.Connection) -> Path:
    dst = base / "processed" / "ranked.jsonl"
    rows = conn.execute(
        "SELECT id, name, method, url, headers_json, params_json, body_json, data_text, score FROM requests ORDER BY score DESC, url ASC"
    ).fetchall()
    with dst.open("w", encoding="utf-8") as f:
        for row in rows:
            item = {
                "id": row["id"],
                "name": row["name"],
                "method": row["method"],
                "url": row["url"],
                "headers": json.loads(row["headers_json"] or "{}"),
                "params": json.loads(row["params_json"] or "{}"),
                "score": row["score"],
            }
            if row["body_json"]:
                item["json"] = json.loads(row["body_json"])
            if row["data_text"]:
                item["data"] = row["data_text"]
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    return dst


def cmd_rank(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    rows = conn.execute("SELECT id, url, params_json, body_json FROM requests").fetchall()
    for row in rows:
        item = {
            "url": row["url"],
            "params": json.loads(row["params_json"] or "{}"),
            "json": json.loads(row["body_json"]) if row["body_json"] else {},
        }
        conn.execute("UPDATE requests SET score=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (score_item(item), row["id"]))
    url_rows = conn.execute("SELECT id, url FROM urls_discovered").fetchall()
    for row in url_rows:
        conn.execute("UPDATE urls_discovered SET score=? WHERE id=?", (score_url(row["url"]), row["id"]))
    conn.commit()
    dst = export_ranked_jsonl(base, conn)
    total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    conn.close()
    print(f"ranked {total} requests -> {dst}")
    return 0


def fetch_tag_map(conn: sqlite3.Connection, entity_type: str) -> dict[str, list[str]]:
    rows = conn.execute(
        "SELECT entity_id, tag FROM tags WHERE entity_type=? ORDER BY tag ASC", (entity_type,)
    ).fetchall()
    out: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        out[str(row["entity_id"])].append(row["tag"])
    return out


def matches_common_filters(item: dict[str, Any], args: argparse.Namespace) -> bool:
    tags = item.get("tags", []) or []
    host = str(item.get("host") or "")
    tool = str(item.get("tool") or "")
    score = int(item.get("score", 0) or 0)
    contains = str(getattr(args, "contains", "") or "").lower()
    path_prefix = str(getattr(args, "path_prefix", "") or "")
    status_filter = getattr(args, "status", None)

    if getattr(args, "tag", None) and getattr(args, "tag") not in tags:
        return False
    if getattr(args, "host", None) and getattr(args, "host") != host:
        return False
    if getattr(args, "tool", None) and getattr(args, "tool") != tool:
        return False
    if score < int(getattr(args, "min_score", 0) or 0):
        return False

    haystack_parts = []
    for key in ("url", "path", "title", "name", "method", "severity", "matched", "slug", "status"):
        value = item.get(key)
        if value is not None:
            haystack_parts.append(str(value))
    if contains and contains not in " ".join(haystack_parts).lower():
        return False

    if path_prefix:
        path = str(item.get("path") or "")
        if not path and item.get("url"):
            try:
                path = urlparse(str(item.get("url"))).path
            except Exception:
                path = ""
        if not path.startswith(path_prefix):
            return False

    if status_filter is not None:
        item_status = item.get("status")
        if item_status is None:
            return False
        if str(item_status) != str(status_filter):
            return False

    return True


def emit_filtered(rows: list[dict[str, Any]], args: argparse.Namespace, headers: list[str]) -> None:
    out = [row for row in rows if matches_common_filters(row, args)]
    if getattr(args, "limit", None):
        out = out[: args.limit]
    emit(out, args.format, headers=headers)


def cmd_top(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    rows = conn.execute(
        "SELECT id, method, url, params_json, score FROM requests ORDER BY score DESC, url ASC"
    ).fetchall()
    tag_map = fetch_tag_map(conn, "request")
    out = []
    for row in rows:
        host = urlparse(row["url"]).netloc
        out.append({
            "id": row["id"],
            "score": row["score"],
            "method": row["method"],
            "host": host,
            "url": row["url"],
            "params": list(json.loads(row["params_json"] or "{}").keys()),
            "tags": tag_map.get(str(row["id"]), []),
        })
    emit_filtered(out, args, headers=["id", "score", "method", "host", "url", "params", "tags"])
    conn.close()
    return 0


def cmd_interesting_urls(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    rows = conn.execute(
        "SELECT id, tool, url, host, score FROM urls_discovered ORDER BY score DESC, url ASC"
    ).fetchall()
    tag_map = fetch_tag_map(conn, "url")
    out = [{"id": r["id"], "tool": r["tool"], "host": r["host"], "score": r["score"], "url": r["url"], "tags": tag_map.get(str(r["id"]), [])} for r in rows]
    emit_filtered(out, args, headers=["id", "tool", "host", "score", "url", "tags"])
    conn.close()
    return 0


def cmd_new_finding(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    out = base / "findings" / f"{args.slug}.md"
    if out.exists() and not args.force:
        return fail(f"{out} already exists; use --force to overwrite")
    out.write_text(FINDING_TEMPLATE, encoding="utf-8")
    conn.execute(
        """
        INSERT INTO findings (slug, path, title, status, updated_at)
        VALUES (?, ?, ?, 'draft', CURRENT_TIMESTAMP)
        ON CONFLICT(slug) DO UPDATE SET path=excluded.path, updated_at=CURRENT_TIMESTAMP
        """,
        (args.slug, str(out), args.title or args.slug.replace("_", " ").replace("-", " ").title())
    )
    conn.commit()
    conn.close()
    print(out)
    return 0


def cmd_set_finding_status(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    cur = conn.execute("UPDATE findings SET status=?, updated_at=CURRENT_TIMESTAMP WHERE slug=?", (args.status, args.slug))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return fail(f"finding not found: {args.slug}")
    print(f"updated {args.slug} -> {args.status}")
    return 0


def cmd_list_findings(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    rows = serialize_rows(conn.execute("SELECT id, slug, title, status, path, created_at, updated_at FROM findings ORDER BY updated_at DESC").fetchall())
    emit_filtered(rows, args, headers=["id", "slug", "title", "status", "path", "created_at", "updated_at"])
    conn.close()
    return 0


def cmd_ingest_ffuf(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    dst = copy_import(base, _arg_file(args), "ffuf")
    records = load_json_records(dst)
    conn.execute("DELETE FROM ffuf_results WHERE source_file = ?", (dst.name,))
    count = 0
    for rec in records:
        url = rec.get("url") or rec.get("input", {}).get("FUZZ") or rec.get("host", "")
        conn.execute(
            "INSERT INTO ffuf_results (source_file, status, length, words, lines, url) VALUES (?, ?, ?, ?, ?, ?)",
            (dst.name, rec.get("status"), rec.get("length"), rec.get("words"), rec.get("lines"), url)
        )
        count += 1
    conn.commit()
    rows = conn.execute("SELECT status, length, words, lines, url FROM ffuf_results ORDER BY id DESC").fetchall()
    (base / "processed" / "ffuf_summary.json").write_text(json.dumps(serialize_rows(rows), indent=2), encoding="utf-8")
    conn.close()
    print(f"ingested {count} ffuf records")
    return 0


def cmd_ingest_nuclei(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    dst = copy_import(base, _arg_file(args), "nuclei")
    records = load_json_records(dst)
    conn.execute("DELETE FROM nuclei_results WHERE source_file = ?", (dst.name,))
    count = 0
    for rec in records:
        info = rec.get("info", {})
        conn.execute(
            "INSERT INTO nuclei_results (source_file, severity, name, matched, template) VALUES (?, ?, ?, ?, ?)",
            (
                dst.name,
                info.get("severity") or rec.get("severity"),
                info.get("name") or rec.get("template-id") or rec.get("templateID"),
                rec.get("matched-at") or rec.get("matched") or rec.get("host"),
                rec.get("template-id") or rec.get("templateID"),
            )
        )
        count += 1
    conn.commit()
    rows = conn.execute("SELECT severity, name, matched, template FROM nuclei_results ORDER BY id DESC").fetchall()
    (base / "processed" / "nuclei_summary.json").write_text(json.dumps(serialize_rows(rows), indent=2), encoding="utf-8")
    conn.close()
    print(f"ingested {count} nuclei records")
    return 0


def ingest_host_list(base: Path, path_str: str, tool: str) -> int:
    conn = connect(base)
    dst = copy_import(base, path_str, tool)
    lines = iter_lines(dst)
    count = 0
    for line in lines:
        host = line
        extra = None
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                host = rec.get("host") or rec.get("name") or rec.get("input") or ""
                extra = json.dumps(rec, ensure_ascii=False)
            except Exception:
                pass
        host = host.strip()
        if not host:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO hosts_discovered (tool, host, source_file, extra_json) VALUES (?, ?, ?, ?)",
            (tool, host, dst.name, extra)
        )
        count += 1
    conn.commit()
    conn.close()
    print(f"ingested {count} {tool} hosts")
    return 0


def cmd_ingest_subfinder(args: argparse.Namespace) -> int:
    return ingest_host_list(get_base(args), _arg_file(args), "subfinder")


def cmd_ingest_amass(args: argparse.Namespace) -> int:
    return ingest_host_list(get_base(args), _arg_file(args), "amass")


def cmd_ingest_httpx(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    dst = copy_import(base, _arg_file(args), "httpx")
    records = load_json_records(dst)
    count = 0
    for rec in records:
        url = rec.get("url") or rec.get("input") or rec.get("host")
        if not url:
            continue
        parsed = urlparse(url)
        host = parsed.netloc or rec.get("host") or rec.get("input")
        tech = rec.get("tech") or rec.get("technologies") or rec.get("webserver")
        conn.execute(
            """
            INSERT OR REPLACE INTO web_targets (tool, url, host, status, title, tech_json, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "httpx", url, host,
                rec.get("status_code") or rec.get("status-code") or rec.get("status"),
                rec.get("title"),
                json.dumps(tech, ensure_ascii=False) if tech is not None else None,
                dst.name,
            )
        )
        count += 1
    conn.commit()
    rows = conn.execute("SELECT url, status, title, tech_json FROM web_targets WHERE tool='httpx' ORDER BY id DESC").fetchall()
    (base / "processed" / "httpx_summary.json").write_text(json.dumps(serialize_rows(rows), indent=2), encoding="utf-8")
    conn.close()
    print(f"ingested {count} httpx records")
    return 0


def ingest_url_list(base: Path, path_str: str, tool: str) -> int:
    conn = connect(base)
    dst = copy_import(base, path_str, tool)
    count = 0
    for line in iter_lines(dst):
        url = line
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                url = rec.get("url") or rec.get("request", {}).get("endpoint") or rec.get("endpoint") or rec.get("matched") or ""
            except Exception:
                pass
        if not url.startswith(("http://", "https://")):
            continue
        parsed = urlparse(url)
        conn.execute(
            "INSERT OR REPLACE INTO urls_discovered (tool, url, host, path, score, source_file) VALUES (?, ?, ?, ?, ?, ?)",
            (tool, url, parsed.netloc, parsed.path, score_url(url), dst.name)
        )
        count += 1
    conn.commit()
    conn.close()
    print(f"ingested {count} {tool} urls")
    return 0


def cmd_ingest_katana(args: argparse.Namespace) -> int:
    return ingest_url_list(get_base(args), _arg_file(args), "katana")


def cmd_ingest_gau(args: argparse.Namespace) -> int:
    return ingest_url_list(get_base(args), _arg_file(args), "gau")


def cmd_ingest_wayback(args: argparse.Namespace) -> int:
    return ingest_url_list(get_base(args), _arg_file(args), "wayback")


def cmd_ingest_naabu(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    dst = copy_import(base, _arg_file(args), "naabu")
    count = 0
    for line in iter_lines(dst):
        host = ""
        port = None
        ip = None
        protocol = "tcp"
        if line.startswith("{"):
            rec = json.loads(line)
            host = rec.get("host") or rec.get("ip") or ""
            port = rec.get("port")
            ip = rec.get("ip")
            protocol = rec.get("protocol") or "tcp"
        else:
            if ":" in line:
                host, port_str = line.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue
        if not host or port is None:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO ports_discovered (tool, host, ip, port, protocol, source_file) VALUES (?, ?, ?, ?, ?, ?)",
            ("naabu", host, ip, int(port), protocol, dst.name)
        )
        count += 1
    conn.commit()
    conn.close()
    print(f"ingested {count} naabu ports")
    return 0


def entity_exists(conn: sqlite3.Connection, entity_type: str, entity_id: str) -> bool:
    if entity_type not in ENTITY_TABLES:
        raise ValueError(f"Unsupported entity type: {entity_type}")
    table, pk, _label = ENTITY_TABLES[entity_type]
    row = conn.execute(f"SELECT 1 FROM {table} WHERE {pk} = ? LIMIT 1", (entity_id,)).fetchone()
    return row is not None


def cmd_tag_add(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    try:
        ok = entity_exists(conn, args.entity_type, args.entity_id)
    except ValueError as e:
        conn.close()
        return fail(str(e))
    if not ok:
        conn.close()
        return fail(f"entity not found: {args.entity_type}:{args.entity_id}")
    conn.execute(
        "INSERT OR REPLACE INTO tags (entity_type, entity_id, tag, note) VALUES (?, ?, ?, ?)",
        (args.entity_type, args.entity_id, args.tag, args.note)
    )
    conn.commit()
    conn.close()
    print(f"tagged {args.entity_type}:{args.entity_id} with {args.tag}")
    return 0


def cmd_tag_remove(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    cur = conn.execute(
        "DELETE FROM tags WHERE entity_type=? AND entity_id=? AND tag=?",
        (args.entity_type, args.entity_id, args.tag)
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return fail("tag not found")
    print("tag removed")
    return 0


def cmd_tags(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    base = get_base(args)
    conn = connect(base)
    query = "SELECT entity_type, entity_id, tag, note, created_at FROM tags"
    clauses = []
    params: list[Any] = []
    if args.entity_type:
        clauses.append("entity_type = ?")
        params.append(args.entity_type)
    if args.tag:
        clauses.append("tag = ?")
        params.append(args.tag)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC"
    rows = serialize_rows(conn.execute(query, params).fetchall())
    emit(rows, args.format, headers=["entity_type", "entity_id", "tag", "note", "created_at"])
    conn.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    allowed = {
        "requests", "hosts_discovered", "web_targets", "urls_discovered", "ports_discovered",
        "ffuf_results", "nuclei_results", "tags", "findings"
    }
    dataset = _arg_dataset(args)
    if dataset not in allowed:
        conn.close()
        return fail(f"unsupported dataset: {dataset}")
    rows = serialize_rows(conn.execute(f"SELECT * FROM {dataset}").fetchall())

    if dataset == "requests":
        tag_map = fetch_tag_map(conn, "request")
        norm = []
        for row in rows:
            row["host"] = urlparse(row.get("url", "")).netloc
            row["tags"] = tag_map.get(str(row.get("id")), [])
            norm.append(row)
        rows = norm
    elif dataset == "urls_discovered":
        tag_map = fetch_tag_map(conn, "url")
        for row in rows:
            row["tags"] = tag_map.get(str(row.get("id")), [])
    elif dataset == "hosts_discovered":
        tag_map = fetch_tag_map(conn, "host")
        for row in rows:
            row["tags"] = tag_map.get(str(row.get("id")), [])
    elif dataset == "web_targets":
        tag_map = fetch_tag_map(conn, "web")
        for row in rows:
            row["tags"] = tag_map.get(str(row.get("id")), [])
    elif dataset == "ports_discovered":
        tag_map = fetch_tag_map(conn, "port")
        for row in rows:
            row["tags"] = tag_map.get(str(row.get("id")), [])

    rows = [row for row in rows if matches_common_filters(row, args)]
    if args.limit:
        rows = rows[: args.limit]

    out = base / "exports" / f"{dataset}.{args.format}"
    if args.format == "json":
        out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    elif args.format == "csv":
        with out.open("w", encoding="utf-8", newline="") as f:
            if rows:
                fieldnames = []
                seen = set()
                for row in rows:
                    for key in row.keys():
                        if key not in seen:
                            seen.add(key)
                            fieldnames.append(key)
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            else:
                f.write("")
    else:
        conn.close()
        return fail("export only supports json or csv")
    conn.close()
    print(out)
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    rows = []
    tables = [
        ("requests", "requests"),
        ("hosts_discovered", "hosts"),
        ("web_targets", "web_targets"),
        ("urls_discovered", "urls"),
        ("ports_discovered", "ports"),
        ("ffuf_results", "ffuf_results"),
        ("nuclei_results", "nuclei_results"),
        ("findings", "findings"),
        ("tags", "tags"),
    ]
    for table, name in tables:
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        rows.append({"name": name, "count": count})

    if args.format == "text":
        print(f"Program: {args.program}\n")
        for row in rows:
            print(f"- {row['name']}: {row['count']}")
        top_requests = serialize_rows(conn.execute("SELECT id, score, method, url FROM requests ORDER BY score DESC, url ASC LIMIT 10").fetchall())
        if top_requests:
            print("\nTop requests:")
            for row in top_requests:
                print(f"- [#{row['id']} score={row['score']}] {row['method']} {row['url']}")
        top_urls = serialize_rows(conn.execute("SELECT id, tool, score, url FROM urls_discovered ORDER BY score DESC, url ASC LIMIT 10").fetchall())
        if top_urls:
            print("\nTop discovered URLs:")
            for row in top_urls:
                print(f"- [#{row['id']} {row['tool']} score={row['score']}] {row['url']}")
    else:
        emit(rows, args.format, headers=["name", "count"])
    conn.close()
    return 0


def cmd_db_stats(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    top_hosts = Counter(urlparse(r[0]).netloc for r in conn.execute("SELECT url FROM requests").fetchall())
    top_hosts.update(r[0] for r in conn.execute("SELECT host FROM hosts_discovered WHERE host IS NOT NULL AND host != ''").fetchall())
    top_hosts.update(r[0] for r in conn.execute("SELECT host FROM web_targets WHERE host IS NOT NULL AND host != ''").fetchall())
    rows = []
    for table in ["requests", "hosts_discovered", "web_targets", "urls_discovered", "ports_discovered", "ffuf_results", "nuclei_results", "findings", "tags"]:
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        rows.append({"table": table, "count": count})
    if args.format == "text":
        print(f"Database: {db_path(base)}")
        for row in rows:
            print(f"- {row['table']}: {row['count']}")
        if top_hosts:
            print("Top hosts:")
            for host, n in top_hosts.most_common(10):
                print(f"- {host}: {n}")
    else:
        emit(rows, args.format, headers=["table", "count"])
    conn.close()
    return 0


def build_graph(conn: sqlite3.Connection, limit: int = 200) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    nodes: dict[str, dict[str, str]] = {}
    edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, label: str, kind: str) -> None:
        nodes[node_id] = {"id": node_id, "label": label, "kind": kind}

    def add_edge(src: str, dst: str, kind: str) -> None:
        edges.add((src, dst, kind))

    request_rows = conn.execute("SELECT id, method, url FROM requests ORDER BY score DESC, id ASC LIMIT ?", (limit,)).fetchall()
    for row in request_rows:
        parsed = urlparse(row["url"])
        host = parsed.netloc
        req_node = f"request:{row['id']}"
        host_node = f"host:{host}"
        url_node = f"url:{row['url']}"
        add_node(host_node, host, "host")
        add_node(url_node, row["url"], "url")
        add_node(req_node, f"#{row['id']} {row['method']}", "request")
        add_edge(host_node, url_node, "serves")
        add_edge(url_node, req_node, "captured")

    url_rows = conn.execute("SELECT id, host, url FROM urls_discovered ORDER BY score DESC, id ASC LIMIT ?", (limit,)).fetchall()
    for row in url_rows:
        if not row["host"]:
            continue
        host_node = f"host:{row['host']}"
        url_node = f"url:{row['url']}"
        add_node(host_node, row['host'], "host")
        add_node(url_node, row['url'], "url")
        add_edge(host_node, url_node, "discovers")

    port_rows = conn.execute("SELECT host, port, protocol FROM ports_discovered ORDER BY host ASC, port ASC LIMIT ?", (limit,)).fetchall()
    for row in port_rows:
        host_node = f"host:{row['host']}"
        port_label = f"{row['port']}/{row['protocol']}"
        port_node = f"port:{row['host']}:{row['port']}/{row['protocol']}"
        add_node(host_node, row['host'], "host")
        add_node(port_node, port_label, "port")
        add_edge(host_node, port_node, "exposes")

    web_rows = conn.execute("SELECT id, host, url FROM web_targets ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    for row in web_rows:
        if not row["host"]:
            continue
        host_node = f"host:{row['host']}"
        web_node = f"web:{row['id']}"
        add_node(host_node, row['host'], "host")
        add_node(web_node, row['url'], "web")
        add_edge(host_node, web_node, "alive")

    tag_rows = conn.execute("SELECT entity_type, entity_id, tag FROM tags ORDER BY id ASC").fetchall()
    for row in tag_rows:
        tag_node = f"tag:{row['tag']}"
        add_node(tag_node, row['tag'], "tag")
        entity_node = f"{row['entity_type']}:{row['entity_id']}"
        if entity_node in nodes:
            add_edge(entity_node, tag_node, "tagged")

    return list(nodes.values()), [{"source": s, "target": d, "kind": k} for s, d, k in sorted(edges)]


def render_mermaid(nodes: list[dict[str, str]], edges: list[dict[str, str]]) -> str:
    lines = ["graph TD"]
    for node in nodes:
        safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", node["id"])
        label = node["label"].replace('"', '\\"')
        lines.append(f'    {safe_id}["{label}"]')
    for edge in edges:
        src = re.sub(r"[^a-zA-Z0-9_]", "_", edge["source"])
        dst = re.sub(r"[^a-zA-Z0-9_]", "_", edge["target"])
        lines.append(f"    {src} -->|{edge['kind']}| {dst}")
    return "\n".join(lines) + "\n"


def render_dot(nodes: list[dict[str, str]], edges: list[dict[str, str]]) -> str:
    lines = ["digraph bbx {", "  rankdir=LR;"]
    for node in nodes:
        safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", node["id"])
        label = node["label"].replace('"', '\\"')
        lines.append(f'  {safe_id} [label="{label}"];')
    for edge in edges:
        src = re.sub(r"[^a-zA-Z0-9_]", "_", edge["source"])
        dst = re.sub(r"[^a-zA-Z0-9_]", "_", edge["target"])
        lines.append(f'  {src} -> {dst} [label="{edge["kind"]}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def cmd_graph(args: argparse.Namespace) -> int:
    apply_preset_args(args)
    base = get_base(args)
    conn = connect(base)
    hosts = serialize_rows(conn.execute("SELECT host FROM hosts_discovered ORDER BY host ASC").fetchall())
    webs = serialize_rows(conn.execute("SELECT id, host, url FROM web_targets ORDER BY id ASC").fetchall())
    urls = serialize_rows(conn.execute("SELECT id, host, url, tool, score FROM urls_discovered ORDER BY score DESC, id ASC").fetchall())
    tag_map = fetch_tag_map(conn, "url")
    nodes = []
    edges = []
    allowed_hosts = set()
    for h in hosts:
        item = {"kind": "host", "id": f"host:{h['host']}", "label": h["host"], "host": h["host"], "score": 0, "tags": []}
        if matches_common_filters(item, args):
            nodes.append(item)
            allowed_hosts.add(h["host"])
    for w in webs:
        item = {"kind": "web", "id": f"web:{w['id']}", "label": w["url"], "host": w["host"], "tool": "httpx", "score": 0, "tags": []}
        if (not allowed_hosts or w["host"] in allowed_hosts) and matches_common_filters(item, args):
            nodes.append(item)
            edges.append({"from": f"host:{w['host']}", "to": item["id"], "type": "serves"})
    count = 0
    for u in urls:
        item = {"kind": "url", "id": f"url:{u['id']}", "label": u["url"], "host": u["host"], "tool": u.get("tool") or "", "score": u.get("score", 0), "tags": tag_map.get(str(u['id']), [])}
        if (not allowed_hosts or u["host"] in allowed_hosts) and matches_common_filters(item, args):
            nodes.append(item)
            edges.append({"from": f"host:{u['host']}", "to": item["id"], "type": "contains"})
            count += 1
            if count >= args.limit:
                break
    payload = {"nodes": nodes, "edges": edges}
    rendered = ""
    if args.format == "json":
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    elif args.format == "dot":
        parts = ["digraph bbx {"]
        for n in nodes:
            nid = n["id"].replace(":", "_").replace("-", "_").replace("/", "_")
            label = n["label"].replace('"', "'")
            parts.append(f'  {nid} [label="{label}"];')
        for e in edges:
            src = e["from"].replace(":", "_").replace("-", "_").replace("/", "_")
            dst = e["to"].replace(":", "_").replace("-", "_").replace("/", "_")
            parts.append(f"  {src} -> {dst};")
        parts.append("}")
        rendered = "\n".join(parts)
    else:
        parts = ["graph TD"]
        for e in edges:
            src = e["from"].replace(":", "_").replace("-", "_").replace("/", "_")
            dst = e["to"].replace(":", "_").replace("-", "_").replace("/", "_")
            parts.append(f"  {src}[{e['from']}] --> {dst}[{e['to']}]")
        rendered = "\n".join(parts)
    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print(args.out)
    else:
        print(rendered)
    conn.close()
    return 0




def add_common_filter_args(parser: argparse.ArgumentParser, *, include_status: bool = False) -> None:
    parser.add_argument("--preset", help="Apply a saved preset of common filters")
    parser.add_argument("--tag")
    parser.add_argument("--host")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--tool")
    parser.add_argument("--contains", help="Case-insensitive substring match across key text fields")
    parser.add_argument("--path-prefix", help="Only keep rows whose path starts with this prefix")
    if include_status:
        parser.add_argument("--status", help="Filter by exact status value when available")

def cmd_preset_save(args: argparse.Namespace) -> int:
    base = get_base(args)
    ensure_dirs(base)
    conn = connect(base)
    conn.close()
    data = {
        "tag": args.tag,
        "host": args.host,
        "min_score": args.min_score,
        "tool": args.tool,
        "contains": args.contains,
        "path_prefix": args.path_prefix,
        "status": args.status,
        "limit": args.limit,
    }
    data = {k: v for k, v in data.items() if v not in (None, "", 0)}
    presets = load_presets(base)
    presets[args.name] = data
    save_presets(base, presets)
    print(f"Saved preset '{args.name}' to {presets_path(base)}")
    return 0


def cmd_preset_list(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    base = get_base(args)
    presets = load_presets(base)
    rows = [{"name": k, **v} for k, v in sorted(presets.items())]
    emit(rows, getattr(args, "format", "text"), headers=["name", "tag", "host", "min_score", "tool", "contains", "path_prefix", "status", "limit"])
    return 0


def cmd_preset_show(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    base = get_base(args)
    presets = load_presets(base)
    row = presets.get(args.name)
    if row is None:
        return fail(f"Preset not found: {args.name}")
    emit([{"name": args.name, **row}], getattr(args, "format", "text"), headers=["name", "tag", "host", "min_score", "tool", "contains", "path_prefix", "status", "limit"])
    return 0


def cmd_preset_delete(args: argparse.Namespace) -> int:
    base = get_base(args)
    presets = load_presets(base)
    if args.name not in presets:
        return fail(f"Preset not found: {args.name}")
    del presets[args.name]
    save_presets(base, presets)
    print(f"Deleted preset '{args.name}'")
    return 0




def cmd_scan_register_url(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    asset_id = register_scan_asset(conn, asset_type='url', value=args.url, source_table='manual')
    print(asset_id)
    return 0


def cmd_scan_plan(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    profiles = load_scan_profiles(base)
    profile = profiles.get(args.profile)
    if not profile:
        return fail(f"Unknown scan profile: {args.profile}")
    table = args.from_table
    if table not in {'web_targets', 'urls_discovered'}:
        return fail('from-table must be web_targets or urls_discovered')
    if table == 'web_targets':
        value_expr = 'url'
        host_expr = 'host'
        path_expr = "substr(url, instr(substr(url, instr(url, '//') + 2), '/'))"
    else:
        value_expr = 'url'
        host_expr = 'host'
        path_expr = 'path'
    where, params = [], []
    if args.host:
        where.append(f"{host_expr} = ?")
        params.append(args.host)
    if args.tool:
        where.append("tool = ?")
        params.append(args.tool)
    if args.contains:
        where.append(f"{value_expr} LIKE ?")
        params.append(f"%{args.contains}%")
    if args.path_prefix:
        where.append(f"COALESCE({path_expr}, '') LIKE ?")
        params.append(f"{args.path_prefix}%")
    if getattr(args, 'min_score', 0):
        if table == 'urls_discovered':
            where.append('score >= ?')
            params.append(args.min_score)
    sql = f"SELECT id, {value_expr} AS value FROM {table}" + (" WHERE " + " AND ".join(where) if where else '') + " ORDER BY id ASC"
    if args.limit:
        sql += f" LIMIT {int(args.limit)}"
    rows = conn.execute(sql, params).fetchall()
    queued = 0
    for row in rows:
        asset_id = register_scan_asset(conn, asset_type='url', value=row['value'], source_table=table, source_id=row['id'])
        for check_name in profile.get('checks', []):
            queue_scan(conn, asset_id=asset_id, check_name=check_name, profile_name=args.profile, priority=args.priority)
            queued += 1
    print(json.dumps({'assets': len(rows), 'queued_checks': queued, 'profile': args.profile}, indent=2))
    return 0


def cmd_scan_queue(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    queue_scan(conn, asset_id=args.asset_id, check_name=args.check, profile_name=args.profile, priority=args.priority)
    print('queued')
    return 0


def run_check(base: Path, conn: sqlite3.Connection, asset: sqlite3.Row, check_name: str, *, allowlist: set[str], timeout: int, delay_seconds: float, max_requests: int, auth_headers: dict[str, str]) -> tuple[str, str, int, list[dict[str, str]], dict[str, str], list[dict[str, str]]]:
    url = asset['value']
    parsed = urlparse(url)
    host = parsed.hostname or asset['host'] or ''
    if host not in allowlist:
        raise RuntimeError(f'Host not in allowlist: {host}')
    s = requests.Session()
    s.headers.update({'User-Agent': 'bb-toolkit-lab/1.0'})
    if auth_headers:
        s.headers.update(auth_headers)
    findings = []
    kv = {}
    evid = []
    count = 0
    def bump():
        nonlocal count
        count += 1
        if count > max_requests:
            raise RuntimeError('max_requests_per_run exceeded')
    if check_name == 'http_probe':
        bump(); resp = s.get(url, timeout=timeout, allow_redirects=False); time.sleep(delay_seconds)
        kv = {
            'status_code': str(resp.status_code),
            'content_type': resp.headers.get('Content-Type', ''),
            'server': resp.headers.get('Server', ''),
            'title_hint': resp.text[:120].replace('\n', ' '),
        }
        return 'done', f"{resp.status_code} {resp.headers.get('Content-Type', '')}", count, findings, kv, evid
    if check_name == 'openapi_fetch':
        for path in ['/openapi.json','/swagger.json','/api-docs','/v3/api-docs']:
            bump(); resp = s.get(url.rstrip('/') + path, timeout=timeout, allow_redirects=False); time.sleep(delay_seconds)
            ctype = resp.headers.get('Content-Type','')
            if resp.status_code == 200 and ('json' in ctype.lower() or 'openapi' in resp.text.lower()):
                findings.append({'severity':'info','title':f'Potential API docs exposed at {path}','details':f'Status {resp.status_code}, content-type {ctype}'})
        return 'done', 'checked common API doc paths', count, findings, kv, evid
    if check_name == 'method_diff':
        statuses = {}
        for method in ['GET','HEAD','OPTIONS','POST']:
            bump(); resp = s.request(method, url, timeout=timeout, allow_redirects=False); time.sleep(delay_seconds)
            statuses[method]=resp.status_code
        kv = {f'status_{k.lower()}': str(v) for k,v in statuses.items()}
        if statuses.get('GET') in {401,403} and statuses.get('HEAD') == 200:
            findings.append({'severity':'low','title':'HEAD differs from GET','details':json.dumps(statuses)})
        return 'done', json.dumps(statuses), count, findings, kv, evid
    if check_name == 'reflection_check':
        bump(); marker='bbmarker123xyz'; join='&' if parsed.query else '?'; target=url + f'{join}bb_test={marker}'; resp=s.get(target, timeout=timeout, allow_redirects=False); time.sleep(delay_seconds)
        reflected = marker in resp.text
        kv = {'reflected': str(reflected).lower()}
        if reflected:
            findings.append({'severity':'info','title':'Marker reflected in response','details':f'Marker found in response body for {target}'})
        return 'done', 'reflected' if reflected else 'not reflected', count, findings, kv, evid
    raise RuntimeError(f'Unknown check: {check_name}')


def parse_header_args(items: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if ':' not in item:
            continue
        k, v = item.split(':', 1)
        out[k.strip()] = v.strip()
    return out


def cmd_scan_run(args: argparse.Namespace) -> int:
    base = get_base(args)
    conn = connect(base)
    allowlist = load_allowlist(base, args.allowlist)
    auth_headers = parse_header_args(args.auth_header)
    limit = args.limit
    processed = 0
    while processed < limit:
        row = conn.execute("""
            SELECT q.*, a.value, a.host, a.path
            FROM scan_queue q
            JOIN scan_assets a ON a.id = q.asset_id
            WHERE q.status = 'queued'
            ORDER BY q.priority ASC, q.id ASC
            LIMIT 1
        """).fetchone()
        if not row:
            break
        conn.execute("UPDATE scan_queue SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ?", (row['id'],))
        conn.commit()
        try:
            profiles = load_scan_profiles(base)
            profile = profiles.get(row['profile_name'] or '', {})
            timeout = args.timeout or int(profile.get('timeout', 10))
            delay_seconds = args.delay if args.delay is not None else float(profile.get('delay_seconds', 0.5))
            max_requests = args.max_requests or int(profile.get('max_requests_per_run', 10))
            status, summary, request_count, findings, kv, evid = run_check(base, conn, row, row['check_name'], allowlist=allowlist, timeout=timeout, delay_seconds=delay_seconds, max_requests=max_requests, auth_headers=auth_headers)
            run_id = add_scan_run(conn, queue_id=row['id'], asset_id=row['asset_id'], check_name=row['check_name'], status=status, summary=summary, request_count=request_count)
            save_scan_evidence(base, conn, run_id, row['asset_id'], row['check_name'] + '_summary', {'summary': summary, 'kv': kv, 'findings': findings}, 'json')
            for key, value in kv.items():
                add_scan_kv_row(conn, run_id=run_id, asset_id=row['asset_id'], key=key, value=value)
            for finding in findings:
                add_scan_finding_row(conn, run_id=run_id, asset_id=row['asset_id'], check_name=row['check_name'], severity=finding.get('severity','info'), title=finding['title'], details=finding.get('details',''))
            conn.execute("UPDATE scan_queue SET status = 'done', finished_at = CURRENT_TIMESTAMP WHERE id = ?", (row['id'],))
            conn.commit()
        except Exception as e:
            add_scan_run(conn, queue_id=row['id'], asset_id=row['asset_id'], check_name=row['check_name'], status='failed', summary=str(e), request_count=0)
            conn.execute("UPDATE scan_queue SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?", (str(e), row['id']))
            conn.commit()
        processed += 1
    print(json.dumps({'processed': processed}, indent=2))
    return 0


def cmd_scan_results(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    base = get_base(args)
    conn = connect(base)
    rows = conn.execute("""
        SELECT r.id, r.check_name, r.status, r.summary, r.request_count, r.created_at, a.value AS asset, a.host
        FROM scan_runs r JOIN scan_assets a ON a.id = r.asset_id
        ORDER BY r.id DESC LIMIT ?
    """, (args.limit,)).fetchall()
    emit(serialize_rows(rows), args.format)
    conn.close()
    return 0

def cmd_scan_findings(args: argparse.Namespace) -> int:
    _normalize_args_format(args)
    base = get_base(args)
    conn = connect(base)
    rows = conn.execute("""
        SELECT f.id, f.check_name, f.severity, f.title, f.details, f.created_at, a.value AS asset, a.host
        FROM scan_findings f JOIN scan_assets a ON a.id = f.asset_id
        ORDER BY f.id DESC LIMIT ?
    """, (args.limit,)).fetchall()
    emit(serialize_rows(rows), args.format)
    conn.close()
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bb", description="Safe bug bounty workspace CLI (SQLite pro edition)")
    p.add_argument("--workspace", default="~/bb", help="Base workspace directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("preset-save")
    s.add_argument("program")
    s.add_argument("name")
    s.add_argument("--limit", type=int, default=0)
    add_common_filter_args(s, include_status=True)
    s.set_defaults(func=cmd_preset_save)

    s = sub.add_parser("preset-list")
    s.add_argument("program")
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_preset_list)

    s = sub.add_parser("preset-show")
    s.add_argument("program")
    s.add_argument("name")
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_preset_show)

    s = sub.add_parser("preset-delete")
    s.add_argument("program")
    s.add_argument("name")
    s.set_defaults(func=cmd_preset_delete)

    s = sub.add_parser("init")
    s.add_argument("program")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("import-har")
    s.add_argument("program")
    s.add_argument("har")
    s.set_defaults(func=cmd_import_har)

    s = sub.add_parser("rank")
    s.add_argument("program")
    s.set_defaults(func=cmd_rank)

    s = sub.add_parser("top")
    s.add_argument("program")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    add_common_filter_args(s)
    s.set_defaults(func=cmd_top)

    s = sub.add_parser("interesting-urls")
    s.add_argument("program")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    add_common_filter_args(s)
    s.set_defaults(func=cmd_interesting_urls)

    s = sub.add_parser("new-finding")
    s.add_argument("program")
    s.add_argument("slug")
    s.add_argument("--title")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_new_finding)

    s = sub.add_parser("set-finding-status")
    s.add_argument("program")
    s.add_argument("slug")
    s.add_argument("status", choices=["draft", "validated", "duplicate", "submitted", "closed"])
    s.set_defaults(func=cmd_set_finding_status)

    s = sub.add_parser("list-findings")
    s.add_argument("program")
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    add_common_filter_args(s, include_status=True)
    s.set_defaults(func=cmd_list_findings)

    for name, func in [
        ("ingest-ffuf", cmd_ingest_ffuf),
        ("ingest-nuclei", cmd_ingest_nuclei),
        ("ingest-httpx", cmd_ingest_httpx),
        ("ingest-subfinder", cmd_ingest_subfinder),
        ("ingest-amass", cmd_ingest_amass),
        ("ingest-katana", cmd_ingest_katana),
        ("ingest-gau", cmd_ingest_gau),
        ("ingest-wayback", cmd_ingest_wayback),
        ("ingest-naabu", cmd_ingest_naabu),
    ]:
        s = sub.add_parser(name)
        s.add_argument("program")
        s.add_argument("path")
        s.set_defaults(func=func)

    s = sub.add_parser("tag-add")
    s.add_argument("program")
    s.add_argument("entity_type", choices=sorted(ENTITY_TABLES.keys()))
    s.add_argument("entity_id")
    s.add_argument("tag")
    s.add_argument("--note")
    s.set_defaults(func=cmd_tag_add)

    s = sub.add_parser("tag-remove")
    s.add_argument("program")
    s.add_argument("entity_type", choices=sorted(ENTITY_TABLES.keys()))
    s.add_argument("entity_id")
    s.add_argument("tag")
    s.set_defaults(func=cmd_tag_remove)

    s = sub.add_parser("tags")
    s.add_argument("program")
    s.add_argument("--entity-type", choices=sorted(ENTITY_TABLES.keys()))
    s.add_argument("--tag")
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_tags)

    s = sub.add_parser("graph")
    s.add_argument("program")
    s.add_argument("--limit", type=int, default=200)
    s.add_argument("--format", default="mermaid", choices=["json", "dot", "mermaid"])
    s.add_argument("--out")
    add_common_filter_args(s)
    s.set_defaults(func=cmd_graph)

    s = sub.add_parser("export")
    s.add_argument("program")
    s.add_argument("table")
    s.add_argument("--format", default="json", choices=["json", "csv"])
    s.add_argument("--limit", type=int, default=0)
    add_common_filter_args(s, include_status=True)
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("summarize")
    s.add_argument("program")
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_summarize)

    s = sub.add_parser("db-stats")
    s.add_argument("program")
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_db_stats)

    s = sub.add_parser("scan-register-url")
    s.add_argument("program")
    s.add_argument("url")
    s.set_defaults(func=cmd_scan_register_url)

    s = sub.add_parser("scan-plan")
    s.add_argument("program")
    s.add_argument("--profile", default="safe-recon")
    s.add_argument("--from-table", default="web_targets", choices=["web_targets", "urls_discovered"])
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--priority", type=int, default=100)
    s.add_argument("--host")
    s.add_argument("--tool")
    s.add_argument("--contains")
    s.add_argument("--path-prefix")
    s.add_argument("--min-score", type=int, default=0)
    s.set_defaults(func=cmd_scan_plan)

    s = sub.add_parser("scan-queue")
    s.add_argument("program")
    s.add_argument("--asset-id", type=int, required=True)
    s.add_argument("--check", required=True, choices=["http_probe", "openapi_fetch", "method_diff", "reflection_check"])
    s.add_argument("--profile")
    s.add_argument("--priority", type=int, default=100)
    s.set_defaults(func=cmd_scan_queue)

    s = sub.add_parser("scan-run")
    s.add_argument("program")
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--allowlist")
    s.add_argument("--timeout", type=int)
    s.add_argument("--delay", type=float)
    s.add_argument("--max-requests", type=int)
    s.add_argument("--auth-header", action="append", default=[])
    s.set_defaults(func=cmd_scan_run)

    s = sub.add_parser("scan-results")
    s.add_argument("program")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_scan_results)

    s = sub.add_parser("scan-findings")
    s.add_argument("program")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--format", default="text", choices=sorted(ALLOWED_FORMATS))
    s.set_defaults(func=cmd_scan_findings)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
