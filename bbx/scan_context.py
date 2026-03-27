
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests


@dataclass
class ScanContext:
    db: Any
    program: str
    allowlist: set[str]
    evidence_dir: Path
    timeout: int = 10
    delay_seconds: float = 0.5
    user_agent: str = "bb-toolkit-lab/1.0"
    max_requests_per_run: int = 10
    auth_headers: dict[str, str] = field(default_factory=dict)
    request_count: int = 0

    def ensure_allowed(self, host: str) -> None:
        if host not in self.allowlist:
            raise ValueError(f"Host not in allowlist: {host}")

    def session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.user_agent})
        s.headers.update(self.auth_headers)
        return s

    def throttle(self) -> None:
        time.sleep(self.delay_seconds)

    def bump(self) -> None:
        self.request_count += 1
        if self.request_count > self.max_requests_per_run:
            raise RuntimeError("max_requests_per_run exceeded")

    def save_payload(self, name: str, payload: dict | list | str) -> Path:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        suffix = '.json' if isinstance(payload, (dict, list)) else '.txt'
        path = self.evidence_dir / f"{name}{suffix}"
        if isinstance(payload, (dict, list)):
            path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        else:
            path.write_text(str(payload), encoding='utf-8', errors='ignore')
        return path
