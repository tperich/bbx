from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BB = [sys.executable, str(ROOT / "bbx.py")]
SAMPLES = ROOT / "samples"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(BB + list(args), cwd=ROOT, text=True, capture_output=True, check=check)


def test_init_import_rank_top(tmp_path: Path):
    ws = tmp_path / "acme"
    out = run("init", str(ws))
    assert str(ws) in out.stdout

    run("import-har", str(ws), str(SAMPLES / "session.har"))
    run("rank", str(ws))
    top = run("top", str(ws), "--format", "json")
    data = json.loads(top.stdout)
    assert len(data) >= 1
    assert "url" in data[0]


def test_new_finding_and_tags(tmp_path: Path):
    ws = tmp_path / "acme2"
    run("init", str(ws))
    run("import-har", str(ws), str(SAMPLES / "session.har"))
    run("new-finding", str(ws), "sample_issue", "--title", "Sample Issue")
    findings = run("list-findings", str(ws), "--format", "json")
    data = json.loads(findings.stdout)
    assert data[0]["slug"] == "sample_issue"

    run("tag-add", str(ws), "request", "1", "authz")
    tags = run("tags", str(ws), "--entity-type", "request", "--format", "json")
    tag_rows = json.loads(tags.stdout)
    assert tag_rows[0]["tag"] == "authz"


def test_doctor_and_validate_import(tmp_path: Path):
    ws = tmp_path / "acme3"
    run("init", str(ws))
    doctor = run("doctor", str(ws), "--format", "json")
    doctor_rows = json.loads(doctor.stdout)
    assert any(row["check"] == "database" and row["ok"] for row in doctor_rows)

    valid = run("validate-import", "har", str(SAMPLES / "session.har"))
    payload = json.loads(valid.stdout)
    assert payload["ok"] is True
