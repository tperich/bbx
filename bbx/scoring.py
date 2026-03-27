from __future__ import annotations

import json
import re
from typing import Any

SKIP_EXT = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
    ".ico", ".map", ".mp4", ".webm", ".avif", ".pdf"
}

KEYWORDS = {
    "admin": 10,
    "api": 8,
    "graphql": 8,
    "user": 7,
    "users": 7,
    "account": 7,
    "org": 7,
    "tenant": 7,
    "project": 6,
    "invoice": 8,
    "billing": 8,
    "payment": 8,
    "file": 6,
    "export": 9,
    "report": 8,
    "settings": 5,
    "role": 9,
    "permission": 9,
    "debug": 8,
    "internal": 9,
    "private": 8,
    "staging": 7,
    "dev": 6,
    "auth": 8,
    "login": 8,
    "callback": 7,
    "redirect": 7,
    "webhook": 8,
    "token": 8,
}
ID_KEYS = {"id", "user_id", "account_id", "org_id", "tenant_id", "project_id", "invoice_id", "file_id", "uuid"}

NUMERIC_SEGMENT_RE = re.compile(r"/\d+\b")
API_SEGMENT_RE = re.compile(r"/(v\d+|api|graphql)\b")


def score_item(item: dict[str, Any]) -> int:
    score = 0
    text = (item.get("url", "") + " " + json.dumps(item.get("params", {})) + " " + json.dumps(item.get("json", {}))).lower()
    for k, pts in KEYWORDS.items():
        if k in text:
            score += pts
    for k in item.get("params", {}).keys():
        if k.lower() in ID_KEYS:
            score += 10
    if isinstance(item.get("json"), dict):
        for k in item["json"].keys():
            lk = k.lower()
            if lk in ID_KEYS:
                score += 10
            if lk in {"role", "isadmin", "is_admin", "verified", "ownerid", "owner_id", "permission"}:
                score += 12
    if NUMERIC_SEGMENT_RE.search(item.get("url", "")):
        score += 8
    return score


def score_url(url: str) -> int:
    score = 0
    text = url.lower()
    for k, pts in KEYWORDS.items():
        if k in text:
            score += pts
    if NUMERIC_SEGMENT_RE.search(text):
        score += 8
    if API_SEGMENT_RE.search(text):
        score += 8
    return score
